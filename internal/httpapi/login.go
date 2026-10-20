package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"auth-server-go/internal/config"
	"auth-server-go/internal/jsonx"
	"auth-server-go/internal/totp"
)

// sessionTTL is the sliding "remember me" session lifetime as a duration.
func sessionTTL(cfg *config.Config) time.Duration {
	return time.Duration(cfg.SessionTTL) * time.Second
}

// sessionTTLFor picks the lifetime for a new session. Sessions without
// "remember me" get the short absolute TTL and are never renewed.
func sessionTTLFor(cfg *config.Config, remember bool) time.Duration {
	if remember {
		return sessionTTL(cfg)
	}
	return time.Duration(cfg.SessionShortTTL) * time.Second
}

// sessionRemember reports whether a session opted into "remember me". A missing
// field means an older session, which keeps the legacy sliding behaviour.
func (s *Server) sessionRemember(ctx context.Context, token string) bool {
	v, err := s.store.Client().HGet(ctx, sessionHashKey(token), "remember").Result()
	if err != nil || v == "" {
		return true
	}
	return v == "1"
}

// tokenFrom reads a client token in the legacy precedence: ?token=, the
// X-Auth-Token probe header, then a Bearer Authorization header.
func tokenFrom(r *http.Request) string {
	if q := r.URL.Query().Get("token"); q != "" {
		return strings.TrimSpace(q)
	}
	if x := r.Header.Get("X-Auth-Token"); x != "" {
		return strings.TrimSpace(x)
	}
	if tok := bearerToken(r.Header.Get("Authorization")); tok != "" {
		return tok
	}
	return ""
}

func bearerToken(header string) string {
	h := strings.TrimSpace(header)
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// requireSession validates a login-session token. Only "remember me" sessions
// slide their TTL; short sessions expire absolutely.
func (s *Server) requireSession(ctx context.Context, r *http.Request) (string, bool) {
	token := tokenFrom(r)
	if token == "" || !s.store.Available() {
		return "", false
	}
	stored, err := s.store.Client().Get(ctx, token).Result()
	if err != nil || stored == "" {
		return "", false
	}
	if s.sessionRemember(ctx, token) {
		_ = s.store.Client().Expire(ctx, token, sessionTTL(s.cfg)).Err()
	}
	return s.normalizeSubject(stored), true
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type verifyBody struct {
	Ok   bool   `json:"ok"`
	User string `json:"user"`
	Exp  int64  `json:"exp"`
}

// handleVerify is the compatibility probe: session token first, then the
// first-party SSO cookie token, then an API token.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	token := tokenFrom(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "unauthorized", Message: "Missing token"})
		return
	}
	if !s.store.Available() {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Code: "redis_unavailable", Message: "Session store unavailable"})
		return
	}
	ctx := r.Context()
	stored, err := s.store.Client().Get(ctx, token).Result()
	if err != nil || stored == "" {
		if user, exp, ok := s.oidc.VerifySsoToken(ctx, token); ok {
			w.Header().Set("X-Auth-User", user)
			writeJSON(w, http.StatusOK, verifyBody{Ok: true, User: user, Exp: exp})
			return
		}
		if api, ok := s.verifyAPIToken(ctx, token); ok {
			hdr := asciiHeaderValue(api.User)
			if hdr == "" {
				hdr = "api-token"
			}
			w.Header().Set("X-Auth-User", hdr)
			writeJSON(w, http.StatusOK, api)
			return
		}
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "invalid_token", Message: "Invalid or expired session"})
		return
	}
	s.touchSession(ctx, token, r)
	ttl, _ := s.store.Client().TTL(ctx, token).Result()
	if ttl < 0 {
		ttl = 0
	}
	exp := time.Now().Unix() + int64(ttl/time.Second)
	user := s.normalizeSubject(stored)
	w.Header().Set("X-Auth-User", user)
	writeJSON(w, http.StatusOK, verifyBody{Ok: true, User: user, Exp: exp})
}

// handleLogout revokes a session and notifies the gateway's back-channel. The
// token may come from the standard channels or, for the landing page, straight
// from the HttpOnly HomeAuth cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Expire the browser copy even when the store is down: a dead cookie must
	// not keep the login page in its "signed in" state.
	s.oidc.ClearSessionCookie(w)
	if !s.store.Available() {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Code: "redis_unavailable", Message: "Session store unavailable"})
		return
	}
	token := tokenFrom(r)
	if token == "" {
		token = strings.TrimSpace(bodyString(readJSONBody(r), "token"))
	}
	if token == "" {
		token = s.oidc.CookieToken(r)
	}
	if token != "" {
		sid, _, ok := s.revokeSession(r.Context(), token)
		if ok {
			go s.oidc.NotifyBackchannel(sid, s.subject)
		}
	}
	writeJSON(w, http.StatusOK, okMessageBody{OK: true, Message: "Session revoked"})
}

type loginBody struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expiresIn"`
}

// handleLogin is the app-level TOTP login: rate-limit by real client IP and
// browser device in parallel, verify TOTP, then issue a sliding Redis session
// token.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body := readJSONBody(r)
	ip := clientIP(r)
	dev := DeviceIdentityFromRequest(w, r)
	if locked, retryAfter := s.loginLockStatus(s.appLimiter, ip, dev); locked {
		writeJSON(w, http.StatusTooManyRequests, newRateLimitBody(retryAfter))
		return
	}
	secret, ok := s.secrets.Load()
	if !ok {
		writeJSON(w, http.StatusForbidden, errorBody{Code: "totp_setup_required", Message: "TOTP is not configured yet"})
		return
	}
	code := strings.TrimSpace(bodyString(body, "code"))
	if !totp.Verify(secret, code, totp.DefaultWindow) {
		s.recordLoginFailure(s.appLimiter, ip, dev)
		writeJSON(w, http.StatusUnauthorized, errorBody{Code: "invalid_code", Message: "Invalid TOTP code"})
		return
	}
	s.clearLoginFailures(s.appLimiter, ip, dev)

	if !s.store.Available() {
		s.log().Error("login: redis 不可用，拒绝签发会话")
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "redis_unavailable", Message: "Session store unavailable"})
		return
	}
	token := newSessionToken()
	ctx := r.Context()
	remember := bodyBool(body, "remember")
	ttl := sessionTTLFor(s.cfg, remember)
	if err := s.store.Client().Set(ctx, token, s.subject, ttl).Err(); err != nil {
		s.log().Error("login: redis SET 失败", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "redis_unavailable", Message: "Session store unavailable"})
		return
	}
	deviceName := strings.TrimSpace(bodyString(body, "deviceName"))
	if err := s.registerSessionMeta(ctx, token, deviceName, r.Header.Get("User-Agent"), r, remember); err != nil {
		s.log().Error("login: 会话元数据写入失败", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "redis_unavailable", Message: "Session store unavailable"})
		return
	}
	if err := s.dedupSameDeviceSessions(ctx, token, r); err != nil {
		s.log().Error("login: 同设备去重失败", "error", err)
	}
	writeJSON(w, http.StatusOK, loginBody{Token: token, ExpiresIn: int(ttl / time.Second)})
}

// newSessionToken returns the 64-hex-char opaque session token.
func newSessionToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("httpapi: crypto/rand 不可用: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// apiTokenResult is the /api/verify response for an API token.
type apiTokenResult struct {
	Ok   bool   `json:"ok"`
	User string `json:"user"`
	Exp  int64  `json:"exp"`
}

// verifyAPIToken validates a hashed API token record. Tokens expire on a fixed
// TTL and are intentionally isolated from device-session metadata.
func (s *Server) verifyAPIToken(ctx context.Context, token string) (apiTokenResult, bool) {
	key := "api:token:" + sha256hex(token)
	raw, err := s.store.Client().Get(ctx, key).Result()
	if err != nil || raw == "" {
		return apiTokenResult{}, false
	}
	var meta map[string]any
	if json.Unmarshal([]byte(raw), &meta) != nil {
		return apiTokenResult{}, false
	}
	name, _ := meta["name"].(string)
	if name == "" {
		return apiTokenResult{}, false
	}
	now := time.Now().UnixMilli()
	expiresAt := numToInt64(meta["expiresAt"])
	if expiresAt <= now {
		return apiTokenResult{}, false
	}
	lastUsed := numToInt64(meta["lastUsedAt"])
	if now-lastUsed > 3600_000 {
		meta["lastUsedAt"] = now
		ttl := (expiresAt - now) / 1000
		if ttl < 1 {
			ttl = 1
		}
		if body, err := jsonx.Marshal(meta); err == nil {
			_ = s.store.Client().Set(ctx, key, body, time.Duration(ttl)*time.Second).Err()
		}
	}
	return apiTokenResult{Ok: true, User: name, Exp: expiresAt}, true
}

func numToInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, _ := n.Int64()
		return i
	default:
		return 0
	}
}
