package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sessionIndexKey is the SET holding every issued login-session token.
const sessionIndexKey = "auth:sessions"

// tokenIDRe matches the 64-hex-char session token; anything else is stale.
var tokenIDRe = regexp.MustCompile(`(?i)^[a-f0-9]{64}$`)

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sessionHashKey(token string) string { return "auth:session:" + token }

// normalizeSubject maps the historical identity labels onto the configured
// subject so every channel agrees.
func (s *Server) normalizeSubject(stored string) string {
	if stored == "" {
		return s.subject
	}
	if s.legacySubjects[stored] {
		return s.subject
	}
	return stored
}

// deviceNameFromUA mirrors the login page's device heuristic.
func deviceNameFromUA(ua string) string {
	if ua == "" {
		return ""
	}
	name := []string{}
	if m := regexp.MustCompile(`Edg/([\d.]+)`).FindStringSubmatch(ua); m != nil {
		name = append(name, "Edge "+m[1])
	} else if strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera") {
		name = append(name, "Opera")
	} else if m := regexp.MustCompile(`Firefox/([\d.]+)`).FindStringSubmatch(ua); m != nil {
		name = append(name, "Firefox "+m[1])
	} else if strings.Contains(ua, "SamsungBrowser/") {
		name = append(name, "Samsung Browser")
	} else if strings.Contains(ua, "MicroMessenger/") {
		name = append(name, "WeChat")
	} else if m := regexp.MustCompile(`CriOS/([\d.]+)`).FindStringSubmatch(ua); m != nil {
		name = append(name, "Chrome "+m[1])
	} else if m := regexp.MustCompile(`Chrome/([\d.]+)`).FindStringSubmatch(ua); m != nil {
		name = append(name, "Chrome "+m[1])
	} else if strings.Contains(ua, "Safari/") {
		name = append(name, "Safari")
	}
	switch {
	case strings.Contains(ua, "Windows NT"):
		name = append(name, "Windows")
	case regexp.MustCompile(`iPhone|iPad|iPod`).MatchString(ua):
		name = append(name, "iOS")
	case strings.Contains(ua, "Mac OS X"):
		name = append(name, "macOS")
	case strings.Contains(ua, "Android"):
		name = append(name, "Android")
	case strings.Contains(ua, "CrOS"):
		name = append(name, "ChromeOS")
	case strings.Contains(ua, "Linux"):
		name = append(name, "Linux")
	}
	out := strings.Join(name, " · ")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// registerSessionMeta records the device metadata for a fresh login and kicks
// off the asynchronous location lookup.
func (s *Server) registerSessionMeta(ctx context.Context, token, deviceName, ua string, r *http.Request, remember bool) error {
	ip := clientIP(r)
	if deviceName == "" {
		deviceName = deviceNameFromUA(ua)
	}
	deviceName = truncateRunes(deviceName, 64)
	now := time.Now().UnixMilli()
	nowStr := strconv.FormatInt(now, 10)
	hashKey := sessionHashKey(token)
	c := s.store.Client()
	if err := c.SAdd(ctx, sessionIndexKey, token).Err(); err != nil {
		return err
	}
	local := "0"
	if isPrivateIP(ip) {
		local = "1"
	}
	fields := map[string]any{
		"user":       s.subject,
		"deviceName": deviceName,
		"ip":         ip,
		"location":   "",
		"isLocal":    local,
		"userAgent":  truncateRunes(ua, 300),
		"createdAt":  nowStr,
		"lastSeenAt": nowStr,
		"remember":   rememberFlag(remember),
	}
	if err := c.HSet(ctx, hashKey, fields).Err(); err != nil {
		return err
	}
	if err := c.Expire(ctx, hashKey, sessionTTLFor(s.cfg, remember)).Err(); err != nil {
		return err
	}
	s.geo.resolveLocation(hashKey, ip)
	return nil
}

// rememberFlag is the stored form of the remember flag.
func rememberFlag(remember bool) string {
	if remember {
		return "1"
	}
	return "0"
}

// metaRemember reads the flag from session metadata. A missing field is an
// older session and keeps the legacy sliding behaviour.
func metaRemember(meta map[string]string) bool {
	v, ok := meta["remember"]
	return !ok || v == "" || v == "1"
}

// revokeSession deletes a token, its index/metadata entries and every SSO and
// sid-scoped token derived from it (logout / device delete / dedup share this).
func (s *Server) revokeSession(ctx context.Context, token string) (string, string, bool) {
	sid, sub, ok := s.oidc.SidForToken(ctx, token)
	c := s.store.Client()
	_ = c.Del(ctx, token).Err()
	_ = c.SRem(ctx, sessionIndexKey, token).Err()
	_ = c.Del(ctx, sessionHashKey(token)).Err()
	s.oidc.RevokeSsoForToken(ctx, token)
	if ok {
		s.oidc.RevokeSid(ctx, sid)
	}
	return sid, sub, ok
}

// dedupSameDeviceSessions revokes older sessions with the same IP + user-agent
// fingerprint. Metadata-less legacy sessions are skipped; failures are ignored
// by the caller.
func (s *Server) dedupSameDeviceSessions(ctx context.Context, newToken string, r *http.Request) error {
	ip := clientIP(r)
	ua := truncateRunes(r.Header.Get("User-Agent"), 300)
	members, err := s.store.Client().SMembers(ctx, sessionIndexKey).Result()
	if err != nil {
		return err
	}
	for _, t := range members {
		if t == newToken || !tokenIDRe.MatchString(t) {
			continue
		}
		meta, err := s.store.Client().HGetAll(ctx, sessionHashKey(t)).Result()
		if err != nil || len(meta) == 0 {
			continue
		}
		if meta["ip"] == ip && meta["userAgent"] == ua {
			s.revokeSession(ctx, t)
		}
	}
	return nil
}

// lastSeenWrites throttles lastSeenAt writes to one per token per minute.
var lastSeenWrites struct {
	mu   sync.Mutex
	seen map[string]int64
}

// touchSession throttles lastSeenAt updates and lazily recreates missing
// metadata for legacy sessions.
func (s *Server) touchSession(ctx context.Context, token string, r *http.Request) {
	now := time.Now().UnixMilli()
	lastSeenWrites.mu.Lock()
	if lastSeenWrites.seen == nil {
		lastSeenWrites.seen = map[string]int64{}
	}
	last, ok := lastSeenWrites.seen[token]
	if ok && now-last < 60000 {
		lastSeenWrites.mu.Unlock()
		return
	}
	if len(lastSeenWrites.seen) > 20000 {
		lastSeenWrites.seen = map[string]int64{}
	}
	lastSeenWrites.seen[token] = now
	lastSeenWrites.mu.Unlock()

	hashKey := sessionHashKey(token)
	c := s.store.Client()
	remember := s.sessionRemember(ctx, token)
	exists, err := c.Exists(ctx, hashKey).Result()
	if err != nil {
		s.log().Error("touchSession exists 查询失败", "error", err)
		return
	}
	if exists == 1 {
		_ = c.HSet(ctx, hashKey, "lastSeenAt", strconv.FormatInt(now, 10)).Err()
		if !remember {
			// Short sessions expire absolutely: only lastSeenAt may change.
			return
		}
		_ = c.Expire(ctx, hashKey, sessionTTL(s.cfg)).Err()
		_ = c.Expire(ctx, token, sessionTTL(s.cfg)).Err()
		return
	}
	ip := clientIP(r)
	local := "0"
	if isPrivateIP(ip) {
		local = "1"
	}
	nowStr := strconv.FormatInt(now, 10)
	_ = c.SAdd(ctx, sessionIndexKey, token).Err()
	_ = c.HSet(ctx, hashKey, map[string]any{
		"user":       s.subject,
		"deviceName": "",
		"ip":         ip,
		"location":   "",
		"isLocal":    local,
		"userAgent":  truncateRunes(r.Header.Get("User-Agent"), 300),
		"createdAt":  nowStr,
		"lastSeenAt": nowStr,
		"remember":   "1",
	}).Err()
	_ = c.Expire(ctx, hashKey, sessionTTL(s.cfg)).Err()
	_ = c.Expire(ctx, token, sessionTTL(s.cfg)).Err()
	s.geo.resolveLocation(hashKey, ip)
}

// sessionInfo is one entry of the device session list. Field order matches the
// legacy JSON response.
type sessionInfo struct {
	ID         string `json:"id"`
	DeviceName string `json:"deviceName"`
	IP         string `json:"ip"`
	Location   string `json:"location"`
	IsLocal    bool   `json:"isLocal"`
	UserAgent  string `json:"userAgent"`
	CreatedAt  int64  `json:"createdAt"`
	LastSeenAt int64  `json:"lastSeenAt"`
	ExpiresAt  int64  `json:"expiresAt"`
	IsCurrent  bool   `json:"isCurrent"`
}

// collectSessions lists live sessions, purging stale index members. sub filters
// to one user (empty means all); currentToken marks isCurrent.
func (s *Server) collectSessions(ctx context.Context, currentToken, sub string) ([]sessionInfo, error) {
	c := s.store.Client()
	nowSec := time.Now().Unix()
	members, err := c.SMembers(ctx, sessionIndexKey).Result()
	if err != nil {
		return nil, err
	}
	sessions := []sessionInfo{}
	stale := []string{}
	for _, t := range members {
		if !tokenIDRe.MatchString(t) {
			stale = append(stale, t)
			continue
		}
		exists, err := c.Exists(ctx, t).Result()
		if err != nil {
			continue
		}
		if exists != 1 {
			stale = append(stale, t)
			_ = c.Del(ctx, sessionHashKey(t)).Err()
			continue
		}
		meta, err := c.HGetAll(ctx, sessionHashKey(t)).Result()
		if err != nil {
			continue
		}
		if len(meta) == 0 {
			stale = append(stale, t)
			continue
		}
		if sub != "" && s.normalizeSubject(meta["user"]) != sub {
			continue
		}
		ttl := int64(0)
		if d, err := c.TTL(ctx, t).Result(); err == nil {
			ttl = int64(d / time.Second)
			if ttl < 0 {
				ttl = 0
			}
		}
		sessions = append(sessions, sessionInfo{
			ID:         t,
			DeviceName: meta["deviceName"],
			IP:         meta["ip"],
			Location:   meta["location"],
			IsLocal:    meta["isLocal"] == "1",
			UserAgent:  meta["userAgent"],
			CreatedAt:  parseInt64(meta["createdAt"]),
			LastSeenAt: parseInt64(meta["lastSeenAt"]),
			ExpiresAt:  nowSec + ttl,
			IsCurrent:  currentToken != "" && t == currentToken,
		})
	}
	if len(stale) > 0 {
		_ = c.SRem(ctx, sessionIndexKey, toAny(stale)...).Err()
	}
	sort.SliceStable(sessions, func(i, j int) bool {
		return sessions[i].LastSeenAt > sessions[j].LastSeenAt
	})
	return sessions, nil
}

func parseInt64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func toAny(list []string) []any {
	out := make([]any, len(list))
	for i, v := range list {
		out[i] = v
	}
	return out
}
