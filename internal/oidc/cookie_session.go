package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// errStoreUnavailable is returned by ReadCookieSession when the readiness probe
// says Redis is down. Callers surface it as "not authenticated", never as 500.
var errStoreUnavailable = errors.New("session store unavailable")

// CookieSession is a read-only snapshot of the first-party login cookie. It
// deliberately carries no token: callers only need display-safe fields.
type CookieSession struct {
	Subject   string
	CreatedAt int64
	ExpiresAt int64
	Remember  bool
}

// CookieToken returns the raw HomeAuth cookie value, or "" when absent.
func (p *Provider) CookieToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	return ParseCookies(r.Header.Get("Cookie"))[p.cookieName]
}

// ReadCookieSession validates the HomeAuth cookie without creating, renewing or
// otherwise mutating the session. A missing or unknown cookie is (nil, nil);
// Redis failures are reported so the caller can log them.
func (p *Provider) ReadCookieSession(ctx context.Context, r *http.Request) (*CookieSession, error) {
	token := p.CookieToken(r)
	if token == "" {
		return nil, nil
	}
	if !p.available() {
		return nil, errStoreUnavailable
	}
	c := p.rdb().Client()

	// 1) Legacy login session stored under the raw token.
	user, err := c.Get(ctx, token).Result()
	if err == nil && user != "" {
		meta, _ := c.HGetAll(ctx, "auth:session:"+token).Result()
		remember := true
		if v, ok := meta["remember"]; ok && v != "" {
			remember = v == "1"
		}
		createdAt := int64(0)
		if ms, err := strconv.ParseInt(meta["createdAt"], 10, 64); err == nil && ms > 0 {
			createdAt = ms / 1000
		}
		ttl := p.readTTL(ctx, token, remember)
		return &CookieSession{
			Subject:   p.normalizeSub(user),
			CreatedAt: createdAt,
			ExpiresAt: p.now() + int64(ttl),
			Remember:  remember,
		}, nil
	}
	if err != nil && !errors.Is(err, goredis.Nil) {
		return nil, err
	}

	// 2) Shared SSO cookie record (hashed key).
	key := ssoPrefix + SHA256Hex(token)
	raw, err := c.Get(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec ssoRecord
	if json.Unmarshal([]byte(raw), &rec) != nil || rec.Sub == "" {
		return nil, nil
	}
	remember := rec.remember()
	ttl := p.readTTL(ctx, key, remember)
	return &CookieSession{
		Subject:   p.normalizeSub(rec.Sub),
		CreatedAt: rec.AuthTime,
		ExpiresAt: p.now() + int64(ttl),
		Remember:  remember,
	}, nil
}

// readTTL returns the key's remaining lifetime in seconds. Missing expiry or a
// failed query falls back to the configured lifetime for the remember flag.
func (p *Provider) readTTL(ctx context.Context, key string, remember bool) int {
	d, err := p.rdb().Client().TTL(ctx, key).Result()
	if err != nil || d < 0 {
		return p.ttlFor(remember)
	}
	n := int(d / time.Second)
	if n < 1 {
		return 1
	}
	return n
}

// ClearSessionCookie expires the HomeAuth cookie on the current host. Logout
// calls it even when Redis is down so the browser stops presenting a dead token.
func (p *Provider) ClearSessionCookie(w http.ResponseWriter) {
	p.clearSsoCookie(w, "")
}
