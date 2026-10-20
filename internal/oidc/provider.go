// Package oidc implements the OpenID Connect / OAuth 2.1 provider: discovery,
// authorize, token, userinfo, jwks, introspect, end_session and revoke, plus the
// SSO session records and the two-phase TOTP-facing session semantics shared
// with the legacy service.
//
// Redis is the single source of truth for session validity: every access token
// is a JWT for wire compatibility, but its "active" state is decided by the
// presence of an oidc:at:<hash> record, never by the signature alone.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"auth-server-go/internal/jsonx"
	"auth-server-go/internal/jwt"
	"auth-server-go/internal/redis"
)

// Redis key prefixes. These are wire contracts with the running legacy service
// and must not change.
const (
	codePrefix      = "oidc:code:"
	atPrefix        = "oidc:at:"
	rtPrefix        = "oidc:rt:"
	rtChainPrefix   = "oidc:rtchain:"
	ssoPrefix       = "oidc:sso:"
	ssoSessionIndex = "oidc:sso-session:"
	sidPrefix       = "oidc:sid:"
)

// CodeTTL is the authorization-code lifetime in seconds.
const CodeTTL = 60

// RefreshTTL is the refresh-token lifetime in seconds (30 days).
const RefreshTTL = 30 * 86400

// Options assembles a Provider.
type Options struct {
	Store          *redis.Store
	DataDir        string
	Issuer         string
	Subject        string
	DisplayName    string
	LegacySubjects []string
	SessionTTL     int
	// SessionShortTTL is the absolute lifetime for sessions without "remember
	// me"; zero falls back to 900 seconds.
	SessionShortTTL int
	CookieName      string
	AccessTTL       int
	BackchannelURL  string
	InternalToken   string
	Logger          *slog.Logger
}

// Provider is the assembled OIDC implementation.
type Provider struct {
	store           *redis.Store
	keyStore        *jwt.KeyStore
	registry        *ClientRegistry
	issuer          string
	issuerOrigin    string
	subject         string
	displayName     string
	legacy          map[string]bool
	sessionTTL      int
	shortSessionTTL int
	cookieName      string
	secureCookies   bool
	accessTTL       int
	refreshTTL      int
	sidTTL          int
	backchannelURL  string
	internalToken   string
	logger          *slog.Logger
	httpClient      *http.Client
	// loginPage is injected by the http layer: the embedded /auth login page.
	loginPage http.Handler
}

// New assembles the provider, loading the ES256 key store and the client
// registry from dataDir.
func New(opts Options) (*Provider, error) {
	keyStore, err := jwt.LoadKeyStore(filepath.Join(opts.DataDir, "oidc-keys.json"))
	if err != nil {
		return nil, err
	}
	registry := NewClientRegistry(filepath.Join(opts.DataDir, "clients.json"))
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	for _, w := range registry.Warnings() {
		logger.Warn("oidc 客户端注册表警告", "detail", w)
	}

	issuer := strings.TrimRight(opts.Issuer, "/")
	origin := issuer
	if u, err := url.Parse(issuer); err == nil && u.Scheme != "" && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	accessTTL := opts.AccessTTL
	if accessTTL < 60 {
		accessTTL = 900
	}
	shortSessionTTL := opts.SessionShortTTL
	if shortSessionTTL <= 0 {
		shortSessionTTL = 900
	}
	legacy := map[string]bool{}
	for _, s := range opts.LegacySubjects {
		legacy[s] = true
	}
	cookieName := opts.CookieName
	if cookieName == "" {
		cookieName = "HomeAuth"
	}
	return &Provider{
		store:           opts.Store,
		keyStore:        keyStore,
		registry:        registry,
		issuer:          issuer,
		issuerOrigin:    origin,
		subject:         opts.Subject,
		displayName:     opts.DisplayName,
		legacy:          legacy,
		sessionTTL:      opts.SessionTTL,
		shortSessionTTL: shortSessionTTL,
		cookieName:      cookieName,
		secureCookies:   strings.HasPrefix(issuer, "https://"),
		accessTTL:       accessTTL,
		refreshTTL:      RefreshTTL,
		sidTTL:          maxInt(accessTTL, RefreshTTL),
		backchannelURL:  strings.TrimSpace(opts.BackchannelURL),
		internalToken:   opts.InternalToken,
		logger:          logger,
		httpClient:      &http.Client{Timeout: 2 * time.Second},
	}, nil
}

// KeyStore exposes the ES256 key store (used by the JWKS endpoint).
func (p *Provider) KeyStore() *jwt.KeyStore { return p.keyStore }

// Registry exposes the client registry.
func (p *Provider) Registry() *ClientRegistry { return p.registry }

// Issuer returns the configured issuer.
func (p *Provider) Issuer() string { return p.issuer }

func (p *Provider) available() bool { return p.store.Available() }

func (p *Provider) rdb() *redis.Store { return p.store }

func (p *Provider) now() int64 { return time.Now().Unix() }

// normalizeSub maps historical identity labels onto the configured subject so
// both identity channels agree.
func (p *Provider) normalizeSub(s string) string {
	if s == "" {
		return p.subject
	}
	if p.legacy[s] {
		return p.subject
	}
	return s
}

/* ---------------- 会话解析 ---------------- */

// ResolvedSession is a validated session in one of its three forms.
type ResolvedSession struct {
	Sub      string
	AuthTime int64
	SID      string
	Source   string // legacy | sso | access
	Raw      string
	// Remember mirrors the session flag. A missing flag on an older record
	// means true, so old sessions keep sliding.
	Remember bool
	// RemainingTTL is the session lifetime left in seconds at resolve time.
	RemainingTTL int
}

// ttlFor returns the configured lifetime for a remember flag.
func (p *Provider) ttlFor(remember bool) int {
	if remember {
		return p.sessionTTL
	}
	return p.shortSessionTTL
}

// keyTTLSeconds reads a Redis key TTL, falling back to the configured lifetime
// when the key has no expiry or the query fails.
func (p *Provider) keyTTLSeconds(ctx context.Context, key string, fallback int) int {
	d, err := p.rdb().Client().TTL(ctx, key).Result()
	if err != nil || d < 0 {
		return fallback
	}
	n := int(d / time.Second)
	if n < 1 {
		return 1
	}
	return n
}

// legacyRemember reads auth:session:<token>.remember. Missing means true.
func (p *Provider) legacyRemember(ctx context.Context, token string) bool {
	v, err := p.rdb().Client().HGet(ctx, "auth:session:"+token, "remember").Result()
	if err != nil || v == "" {
		return true
	}
	return v == "1"
}

// ValidateToken resolves a token against Redis. Legacy login sessions, SSO
// cookies and OIDC access tokens are accepted (in that order).
func (p *Provider) ValidateToken(ctx context.Context, tok string) *ResolvedSession {
	if tok == "" || !p.available() {
		return nil
	}
	c := p.rdb().Client()

	// 1) legacy login session (raw key)
	if user, err := c.Get(ctx, tok).Result(); err == nil && user != "" {
		remember := p.legacyRemember(ctx, tok)
		remaining := p.keyTTLSeconds(ctx, tok, p.ttlFor(remember))
		if remember {
			_ = c.Expire(ctx, tok, seconds(p.sessionTTL)).Err()
			remaining = p.sessionTTL
		}
		// Raw matters: EnsureSsoSession hashes it into the reverse index so that
		// /api/logout and device kicks revoke the shared cookie immediately.
		return &ResolvedSession{Sub: p.normalizeSub(user), AuthTime: p.now(), SID: SHA256Hex(tok)[:16], Source: "legacy", Raw: tok, Remember: remember, RemainingTTL: remaining}
	}
	// 2) first-party SSO cookie (hashed record)
	if s, ok := p.getSSO(ctx, tok); ok {
		remember := s.remember()
		remaining := p.keyTTLSeconds(ctx, ssoPrefix+SHA256Hex(tok), p.ttlFor(remember))
		return &ResolvedSession{Sub: p.normalizeSub(s.Sub), AuthTime: s.AuthTime, SID: s.SID, Source: "sso", Raw: tok, Remember: remember, RemainingTTL: remaining}
	}
	// 3) OIDC access token
	if raw, err := c.Get(ctx, atPrefix+SHA256Hex(tok)).Result(); err == nil && raw != "" {
		var a accessRecord
		if json.Unmarshal([]byte(raw), &a) == nil {
			remember := a.remember()
			remaining := p.keyTTLSeconds(ctx, atPrefix+SHA256Hex(tok), p.accessTTL)
			return &ResolvedSession{Sub: p.normalizeSub(a.Sub), AuthTime: a.AuthTime, SID: a.SID, Source: "access", Remember: remember, RemainingTTL: remaining}
		}
	}
	return nil
}

// ResolveSession looks for a session in the cookie, the ?token= query and the
// Bearer header, in that order.
func (p *Provider) ResolveSession(r *http.Request) *ResolvedSession {
	candidates := []string{}
	if cookie := ParseCookies(r.Header.Get("Cookie"))[p.cookieName]; cookie != "" {
		candidates = append(candidates, cookie)
	}
	if q := QueryStr(r.URL.Query(), "token"); q != "" {
		candidates = append(candidates, q)
	}
	if tok := BearerFromHeader(r.Header.Get("Authorization")); tok != "" {
		candidates = append(candidates, tok)
	}
	for _, tok := range candidates {
		if s := p.ValidateToken(r.Context(), tok); s != nil {
			return s
		}
	}
	return nil
}

/* ---------------- SSO 记录 ---------------- */

func (p *Provider) getSSO(ctx context.Context, token string) (*ssoRecord, bool) {
	raw, err := p.rdb().Client().Get(ctx, ssoPrefix+SHA256Hex(token)).Result()
	if err != nil || raw == "" {
		return nil, false
	}
	var rec ssoRecord
	if json.Unmarshal([]byte(raw), &rec) != nil || rec.Sub == "" {
		return nil, false
	}
	return &rec, true
}

// EnsureSsoSession creates (or renews) the first-party shared cookie record and
// returns the opaque SSO token plus the lifetime the cookie should carry. It
// also maintains the reverse index from the originating login session so logout
// can revoke the cookie immediately.
func (p *Provider) EnsureSsoSession(ctx context.Context, session *ResolvedSession, client *ClientRecord) (string, int, error) {
	c := p.rdb().Client()
	remember := session.Remember
	if session.Source == "sso" && session.Raw != "" {
		h := SHA256Hex(session.Raw)
		ttl := session.RemainingTTL
		if remember {
			ttl = p.sessionTTL
			_ = c.Expire(ctx, ssoPrefix+h, seconds(p.sessionTTL)).Err()
			if rec, ok := p.getSSO(ctx, session.Raw); ok && rec.SessionHash != "" {
				_ = c.Expire(ctx, ssoSessionIndex+rec.SessionHash, seconds(p.sessionTTL)).Err()
			}
		}
		if ttl <= 0 {
			ttl = p.ttlFor(remember)
		}
		p.registerSidToken(ctx, session.SID, h)
		return session.Raw, ttl, nil
	}

	ttl := p.ttlFor(remember)
	token := RandomToken(32)
	h := SHA256Hex(token)
	rec := ssoRecord{
		Sub:      session.Sub,
		AuthTime: firstNonZero(session.AuthTime, p.now()),
		SID:      firstNonEmpty(session.SID, h[:16]),
		ClientID: client.ClientID,
		Remember: boolValue(remember),
	}
	sessionHash := ""
	if session.Source == "legacy" && session.Raw != "" {
		sessionHash = SHA256Hex(session.Raw)
		rec.SessionHash = sessionHash
	}
	raw, _ := jsonx.Marshal(rec)
	if err := c.Set(ctx, ssoPrefix+h, raw, seconds(ttl)).Err(); err != nil {
		return "", 0, err
	}
	if sessionHash != "" {
		idxKey := ssoSessionIndex + sessionHash
		_ = c.SAdd(ctx, idxKey, h).Err()
		_ = c.Expire(ctx, idxKey, seconds(ttl)).Err()
	}
	p.registerSidToken(ctx, rec.SID, h)
	return token, ttl, nil
}

// VerifySsoToken validates a first-party SSO token for /api/verify. Only
// "remember me" SSO sessions slide; short ones keep their absolute deadline.
func (p *Provider) VerifySsoToken(ctx context.Context, token string) (string, int64, bool) {
	if token == "" || !p.available() {
		return "", 0, false
	}
	rec, ok := p.getSSO(ctx, token)
	if !ok {
		return "", 0, false
	}
	c := p.rdb().Client()
	key := ssoPrefix + SHA256Hex(token)
	if rec.remember() {
		_ = c.Expire(ctx, key, seconds(p.sessionTTL)).Err()
		if rec.SessionHash != "" {
			_ = c.Expire(ctx, ssoSessionIndex+rec.SessionHash, seconds(p.sessionTTL)).Err()
		}
	}
	ttl, _ := c.TTL(ctx, key).Result()
	exp := p.now() + maxInt64(0, int64(ttl.Seconds()))
	return p.normalizeSub(rec.Sub), exp, true
}

// RevokeSsoForToken deletes an SSO token and every SSO token indexed against it
// (when the argument is an originating login-session token).
func (p *Provider) RevokeSsoForToken(ctx context.Context, token string) {
	if token == "" || !p.available() {
		return
	}
	c := p.rdb().Client()
	h := SHA256Hex(token)
	_ = c.Del(ctx, ssoPrefix+h).Err()
	idxKey := ssoSessionIndex + h
	members, _ := c.SMembers(ctx, idxKey).Result()
	for _, m := range members {
		_ = c.Del(ctx, ssoPrefix+m).Err()
	}
	if len(members) > 0 {
		_ = c.Del(ctx, idxKey).Err()
	}
}

/* ---------------- sid 索引 ---------------- */

func (p *Provider) registerSidToken(ctx context.Context, sid, hash string) {
	if sid == "" || hash == "" || !p.available() {
		return
	}
	c := p.rdb().Client()
	key := sidPrefix + sid
	_ = c.SAdd(ctx, key, hash).Err()
	_ = c.Expire(ctx, key, seconds(p.sidTTL)).Err()
}

// RevokeSid revokes every token minted during one login (access, the whole
// refresh chain and the SSO cookie).
func (p *Provider) RevokeSid(ctx context.Context, sid string) {
	if sid == "" || !p.available() {
		return
	}
	c := p.rdb().Client()
	key := sidPrefix + sid
	members, _ := c.SMembers(ctx, key).Result()
	for _, h := range members {
		_ = c.Del(ctx, atPrefix+h).Err()
		if raw, err := c.Get(ctx, rtPrefix+h).Result(); err == nil && raw != "" {
			var rec refreshRecord
			if json.Unmarshal([]byte(raw), &rec) == nil {
				p.revokeChain(ctx, rec.Chain)
			}
		}
		_ = c.Del(ctx, rtPrefix+h).Err()
		_ = c.Del(ctx, ssoPrefix+h).Err()
	}
	if len(members) > 0 {
		_ = c.Del(ctx, key).Err()
	}
}

// SidForToken finds the sid (and subject) behind any token: access, refresh and
// SSO hit directly; a legacy login session is resolved through the reverse
// index. Unknown tokens return ok=false — we never guess.
func (p *Provider) SidForToken(ctx context.Context, token string) (sid, sub string, ok bool) {
	if token == "" || !p.available() {
		return "", "", false
	}
	c := p.rdb().Client()
	h := SHA256Hex(token)
	if raw, err := c.Get(ctx, atPrefix+h).Result(); err == nil && raw != "" {
		var a accessRecord
		if json.Unmarshal([]byte(raw), &a) == nil && a.SID != "" {
			return a.SID, p.normalizeSub(a.Sub), true
		}
	}
	if raw, err := c.Get(ctx, rtPrefix+h).Result(); err == nil && raw != "" {
		var r refreshRecord
		if json.Unmarshal([]byte(raw), &r) == nil && r.SID != "" {
			return r.SID, p.normalizeSub(r.Sub), true
		}
	}
	if rec, ok := p.getSSO(ctx, token); ok && rec.SID != "" {
		return rec.SID, p.normalizeSub(rec.Sub), true
	}
	members, _ := c.SMembers(ctx, ssoSessionIndex+h).Result()
	for _, m := range members {
		raw, err := c.Get(ctx, ssoPrefix+m).Result()
		if err != nil || raw == "" {
			continue
		}
		var s ssoRecord
		if json.Unmarshal([]byte(raw), &s) == nil && s.SID != "" {
			return s.SID, p.normalizeSub(s.Sub), true
		}
	}
	return "", "", false
}

// NotifyBackchannel tells the gateway a sid has been fully revoked. Best effort:
// <=2s per attempt, one retry, failures are only logged.
func (p *Provider) NotifyBackchannel(sid, sub string) {
	if sid == "" || p.backchannelURL == "" || p.internalToken == "" {
		return
	}
	body := fmt.Sprintf(`{"sid":%s,"sub":%s}`, jsonString(sid), jsonString(sub))
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodPost, p.backchannelURL, strings.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Internal-Token", p.internalToken)
		resp, err := p.httpClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return
			}
		}
	}
	p.logger.Warn("oidc back-channel 通知失败（网关不可达或拒绝）")
}

/* ---------------- 令牌签发 ---------------- */

type accessRecord struct {
	Sub      string `json:"sub"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	SID      string `json:"sid"`
	AuthTime int64  `json:"auth_time"`
	Exp      int64  `json:"exp"`
	Remember *bool  `json:"remember,omitempty"`
}

type ssoRecord struct {
	Sub         string `json:"sub"`
	AuthTime    int64  `json:"auth_time"`
	SID         string `json:"sid"`
	ClientID    string `json:"client_id"`
	SessionHash string `json:"session_hash,omitempty"`
	Remember    *bool  `json:"remember,omitempty"`
}

type refreshRecord struct {
	Sub              string `json:"sub"`
	ClientID         string `json:"client_id"`
	Scope            string `json:"scope"`
	SID              string `json:"sid"`
	AuthTime         int64  `json:"auth_time"`
	Chain            string `json:"chain"`
	Used             bool   `json:"used"`
	Remember         *bool  `json:"remember,omitempty"`
	SessionExpiresAt int64  `json:"session_expires_at,omitempty"`
}

type codeRecord struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Nonce               string `json:"nonce,omitempty"`
	Sub                 string `json:"sub"`
	AuthTime            int64  `json:"auth_time"`
	Scope               string `json:"scope"`
	SID                 string `json:"sid"`
	Remember            *bool  `json:"remember,omitempty"`
	SessionExpiresAt    int64  `json:"session_expires_at,omitempty"`
}

type issueParams struct {
	Sub      string
	Client   *ClientRecord
	Scope    string
	Nonce    string
	AuthTime int64
	SID      string
	Chain    string
	Remember bool
	// ExpiresIn is the session lifetime advertised to the caller. It is not the
	// access_token lifetime, which stays at accessTTL.
	ExpiresIn int
	// SessionExpiresAt is the absolute session deadline (Unix seconds).
	SessionExpiresAt int64
}

// boolValue returns a stable pointer for JSON records. A nil pointer on read
// means the record predates the remember flag, i.e. remember=1.
func boolValue(v bool) *bool { return &v }

func (r *accessRecord) remember() bool {
	return r == nil || r.Remember == nil || *r.Remember
}

func (r *ssoRecord) remember() bool {
	return r == nil || r.Remember == nil || *r.Remember
}

func (r *refreshRecord) remember() bool {
	return r == nil || r.Remember == nil || *r.Remember
}

func (r *codeRecord) remember() bool {
	return r == nil || r.Remember == nil || *r.Remember
}

// TokenSet is the /token response body. Field order matches the legacy
// implementation.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type accessClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Jti      string `json:"jti"`
	SID      string `json:"sid"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
}

type idClaims struct {
	Iss               string `json:"iss"`
	Sub               string `json:"sub"`
	Aud               string `json:"aud"`
	Exp               int64  `json:"exp"`
	Iat               int64  `json:"iat"`
	AuthTime          int64  `json:"auth_time"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Nonce             string `json:"nonce,omitempty"`
	SID               string `json:"sid,omitempty"`
	Remember          bool   `json:"remember"`
}

func (p *Provider) issueTokens(ctx context.Context, params issueParams) (*TokenSet, error) {
	c := p.rdb().Client()
	t := p.now()
	scope := params.Scope
	if scope == "" {
		scope = "openid"
	}

	access := accessClaims{
		Iss: p.issuer, Sub: params.Sub, Aud: params.Client.ClientID,
		Exp: t + int64(p.accessTTL), Iat: t, Jti: RandomToken(16),
		SID: params.SID, Scope: scope, ClientID: params.Client.ClientID,
	}
	accessToken, err := p.keyStore.SignJWT(access)
	if err != nil {
		return nil, err
	}
	atRec := accessRecord{Sub: params.Sub, ClientID: params.Client.ClientID, Scope: scope, SID: params.SID, AuthTime: params.AuthTime, Exp: t + int64(p.accessTTL), Remember: boolValue(params.Remember)}
	atRaw, _ := jsonx.Marshal(atRec)
	if err := c.Set(ctx, atPrefix+SHA256Hex(accessToken), atRaw, seconds(p.accessTTL)).Err(); err != nil {
		return nil, err
	}
	p.registerSidToken(ctx, params.SID, SHA256Hex(accessToken))

	idPayload := idClaims{
		Iss: p.issuer, Sub: params.Sub, Aud: params.Client.ClientID,
		Exp: t + int64(p.accessTTL), Iat: t, AuthTime: firstNonZero(params.AuthTime, t),
		PreferredUsername: p.subject, Name: p.displayName, Nonce: params.Nonce,
		Remember: params.Remember,
	}
	if params.SID != "" {
		idPayload.SID = params.SID
	}
	idToken, err := p.keyStore.SignJWT(idPayload)
	if err != nil {
		return nil, err
	}

	expiresIn := params.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = p.ttlFor(params.Remember)
	}
	sessionExpiresAt := params.SessionExpiresAt
	if sessionExpiresAt <= 0 {
		sessionExpiresAt = t + int64(expiresIn)
	}
	out := &TokenSet{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: expiresIn, IDToken: idToken, Scope: scope}

	if p.registry.AllowsGrant(params.Client, "refresh_token") {
		refreshToken := RandomToken(32)
		chain := params.Chain
		if chain == "" {
			chain = RandomToken(16)
		}
		rtRec := refreshRecord{Sub: params.Sub, ClientID: params.Client.ClientID, Scope: scope, SID: params.SID, AuthTime: params.AuthTime, Chain: chain, Used: false, Remember: boolValue(params.Remember), SessionExpiresAt: sessionExpiresAt}
		rtRaw, _ := jsonx.Marshal(rtRec)
		rh := SHA256Hex(refreshToken)
		if err := c.Set(ctx, rtPrefix+rh, rtRaw, seconds(p.refreshTTL)).Err(); err != nil {
			return nil, err
		}
		_ = c.SAdd(ctx, rtChainPrefix+chain, rh).Err()
		_ = c.Expire(ctx, rtChainPrefix+chain, seconds(p.refreshTTL)).Err()
		p.registerSidToken(ctx, params.SID, rh)
		out.RefreshToken = refreshToken
	}
	return out, nil
}

func (p *Provider) revokeChain(ctx context.Context, chain string) {
	if chain == "" {
		return
	}
	c := p.rdb().Client()
	members, _ := c.SMembers(ctx, rtChainPrefix+chain).Result()
	for _, h := range members {
		_ = c.Del(ctx, rtPrefix+h).Err()
	}
	if len(members) > 0 {
		_ = c.Del(ctx, rtChainPrefix+chain).Err()
	}
}

type exchangeParams struct {
	Code         string
	ClientID     string
	RedirectURI  string
	CodeVerifier string
	Client       *ClientRecord
}

// OAuthError carries the RFC 6749 error code for a failed exchange.
type OAuthError struct {
	Code        string
	Description string
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

func oauthErr(code, desc string) error { return &OAuthError{Code: code, Description: desc} }

func (p *Provider) exchangeCode(ctx context.Context, params exchangeParams) (*TokenSet, error) {
	raw, err := p.rdb().Client().GetDel(ctx, codePrefix+SHA256Hex(params.Code)).Result()
	if err != nil || raw == "" {
		return nil, oauthErr("invalid_grant", "授权码无效、已使用或已过期")
	}
	var rec codeRecord
	if json.Unmarshal([]byte(raw), &rec) != nil {
		return nil, oauthErr("invalid_grant", "授权码记录损坏")
	}
	if rec.ClientID != params.Client.ClientID {
		return nil, oauthErr("invalid_grant", "授权码与客户端不匹配")
	}
	if rec.RedirectURI != params.RedirectURI {
		return nil, oauthErr("invalid_grant", "redirect_uri 与授权时不一致")
	}
	if rec.CodeChallenge != "" {
		if params.CodeVerifier == "" {
			return nil, oauthErr("invalid_grant", "缺少 code_verifier")
		}
		if !TimingEqual(PKCEChallenge(params.CodeVerifier), rec.CodeChallenge) {
			return nil, oauthErr("invalid_grant", "PKCE 校验失败")
		}
	} else if !p.registry.IsConfidential(params.Client) && !params.Client.FirstParty {
		return nil, oauthErr("invalid_grant", "公开客户端必须使用 PKCE")
	}
	remember := rec.remember()
	expiresIn := int(rec.SessionExpiresAt - p.now())
	if remember {
		if expiresIn <= 0 {
			expiresIn = p.ttlFor(remember)
		}
	} else if expiresIn <= 0 {
		return nil, oauthErr("invalid_grant", "会话已过期，请重新登录")
	}
	return p.issueTokens(ctx, issueParams{
		Sub: rec.Sub, Client: params.Client, Scope: rec.Scope,
		Nonce: rec.Nonce, AuthTime: rec.AuthTime, SID: rec.SID,
		Remember: remember, ExpiresIn: expiresIn,
		SessionExpiresAt: p.now() + int64(expiresIn),
	})
}

// clientAuth extracts client credentials from the body and/or HTTP Basic auth.
func clientAuth(r *http.Request, body url.Values) (clientID, secret string) {
	clientID = FormStr(body, "client_id")
	secret = FormStr(body, "client_secret")
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(header), "basic ") {
		return clientID, secret
	}
	decoded := ""
	if b, err := decodeBase64(strings.TrimSpace(header[6:])); err == nil {
		decoded = string(b)
	}
	idx := strings.IndexByte(decoded, ':')
	if idx == -1 {
		return clientID, secret
	}
	id := decoded[:idx]
	sec := decoded[idx+1:]
	// RFC 6749 §2.3.1: values are form-urlencoded before base64.
	if unescaped, err := url.QueryUnescape(id); err == nil {
		id = unescaped
	}
	if unescaped, err := url.QueryUnescape(sec); err == nil {
		sec = unescaped
	}
	return id, sec
}

func jsonString(s string) string {
	b, _ := jsonx.Marshal(s)
	return string(b)
}
