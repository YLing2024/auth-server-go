package oidc

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auth-server-go/internal/jsonx"
	"auth-server-go/internal/jwt"
)

// DiscoveryDoc is the /.well-known/openid-configuration document. Field order
// matches the legacy response.
type DiscoveryDoc struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// Discovery returns the discovery document for the configured issuer.
func (p *Provider) Discovery() DiscoveryDoc {
	return DiscoveryDoc{
		Issuer:                            p.issuer,
		AuthorizationEndpoint:             p.issuer + "/authorize",
		TokenEndpoint:                     p.issuer + "/token",
		UserinfoEndpoint:                  p.issuer + "/userinfo",
		JwksURI:                           p.issuer + "/jwks.json",
		EndSessionEndpoint:                p.issuer + "/end_session",
		IntrospectionEndpoint:             p.issuer + "/introspect",
		RevocationEndpoint:                p.issuer + "/revoke",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   []string{"openid", "profile", "email", "offline_access"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		SubjectTypesSupported:             []string{"public"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "jti", "auth_time", "nonce", "preferred_username", "name"},
	}
}

// handleDiscovery serves GET /.well-known/openid-configuration.
func (p *Provider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, p.Discovery())
}

// handleJWKS serves GET /jwks.json.
func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	raw, err := p.keyStore.JWKS()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// body carries a parsed request body, accepting both urlencoded and JSON forms
// because the global JSON parser and the OIDC urlencoded parser both applied in
// the legacy app.
type body struct {
	form url.Values
	json map[string]any
}

func readBody(r *http.Request) body {
	b := body{form: url.Values{}}
	if r.Body == nil {
		return b
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			b.json = m
		}
		return b
	}
	vals, err := url.ParseQuery(string(raw))
	if err == nil {
		b.form = vals
	}
	return b
}

func (b body) str(key string) string {
	if v := FormStr(b.form, key); v != "" {
		return v
	}
	if b.json != nil {
		if s, ok := b.json[key].(string); ok {
			return s
		}
	}
	return ""
}

// errorPage renders the legacy HTML authorization-failure page.
func errorPage(w http.ResponseWriter, status int, code, description string) {
	b := `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>授权失败</title>
<style>
  body { font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         background:#f7f6f3; color:#171512; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
  .card { max-width:420px; border:1px solid rgba(23,21,18,.14); padding:48px 40px; }
  h1 { font-size:16px; margin:0 0 12px; letter-spacing:.02em; }
  p { font-size:13px; line-height:1.7; color:#3d3832; margin:0; }
  code { font-family: ui-monospace, Menlo, Consolas, monospace; font-size:12px; background:#efede7; padding:2px 6px; }
</style></head>
<body><div class="card"><h1>授权失败</h1>
<p><code>` + HTMLEscape(code) + `</code></p><p>` + HTMLEscape(description) + `</p></div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, b)
}

type oauthErrorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func tokenError(w http.ResponseWriter, errCode, description string, status int) {
	if errCode == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, oauthErrorBody{Error: errCode, Description: description})
}

func sendTokens(w http.ResponseWriter, tokens *TokenSet) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokens)
}

// HandleAuthorize serves GET /authorize.
func (p *Provider) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	q := r.URL.Query()
	clientID := QueryStr(q, "client_id")
	redirectURI := QueryStr(q, "redirect_uri")
	responseType := QueryStr(q, "response_type")
	scope := QueryStr(q, "scope")
	state := QueryStr(q, "state")
	nonce := QueryStr(q, "nonce")
	codeChallenge := QueryStr(q, "code_challenge")
	codeChallengeMethod := QueryStr(q, "code_challenge_method")
	prompt := QueryStr(q, "prompt")
	maxAge := QueryStr(q, "max_age")

	client := p.registry.Get(clientID)
	if client == nil {
		errorPage(w, http.StatusBadRequest, "invalid_request", "未知的 client_id")
		return
	}
	if !p.registry.MatchRedirect(client, redirectURI) {
		errorPage(w, http.StatusBadRequest, "invalid_request", "redirect_uri 未注册或与注册值不完全一致")
		return
	}
	if responseType != "code" {
		errorPage(w, http.StatusBadRequest, "unsupported_response_type", "仅支持 response_type=code")
		return
	}
	if !hasScope(scope, "openid") {
		errorPage(w, http.StatusBadRequest, "invalid_scope", "scope 必须包含 openid")
		return
	}
	isPublic := !p.registry.IsConfidential(client)
	if codeChallenge != "" {
		if codeChallengeMethod != "S256" {
			errorPage(w, http.StatusBadRequest, "invalid_request", "code_challenge_method 仅支持 S256")
			return
		}
	} else if isPublic && !client.FirstParty {
		errorPage(w, http.StatusBadRequest, "invalid_request", "公开客户端必须携带 code_challenge (S256)")
		return
	}

	session := p.ResolveSession(r)
	forceLogin := false
	if prompt == "login" && QueryStr(q, "token") == "" {
		forceLogin = true
	}
	if maxAge != "" && session != nil {
		if n, ok := atoiSafe(maxAge); ok && n >= 0 && p.now()-session.AuthTime > int64(n) {
			forceLogin = true
		}
	}
	if forceLogin {
		session = nil
	}

	if session == nil {
		redirectFound(w, "/auth?redirect="+EncodeURIComponent(r.URL.RequestURI()))
		return
	}

	authTime := session.AuthTime
	if authTime == 0 {
		authTime = p.now()
	}
	code := RandomToken(32)
	rec := codeRecord{
		ClientID: client.ClientID, RedirectURI: redirectURI,
		CodeChallenge: codeChallenge,
		Sub:           session.Sub, AuthTime: authTime, Scope: scope, SID: session.SID,
	}
	if codeChallenge != "" {
		rec.CodeChallengeMethod = "S256"
	}
	if nonce != "" {
		rec.Nonce = nonce
	}
	raw, _ := jsonx.Marshal(rec)
	if err := p.rdb().Client().Set(r.Context(), codePrefix+SHA256Hex(code), raw, seconds(CodeTTL)).Err(); err != nil {
		errorPage(w, http.StatusInternalServerError, "server_error", "授权码写入失败")
		return
	}

	if client.FirstParty {
		if _, err := p.exchangeCode(r.Context(), exchangeParams{Code: code, ClientID: client.ClientID, RedirectURI: redirectURI, Client: client}); err != nil {
			p.logger.Error("首方令牌交换失败", "error", err)
			errorPage(w, http.StatusInternalServerError, "server_error", "首方令牌交换失败")
			return
		}
		ssoToken, err := p.EnsureSsoSession(r.Context(), session, client)
		if err != nil {
			errorPage(w, http.StatusInternalServerError, "server_error", "会话写入失败")
			return
		}
		p.setSsoCookie(w, ssoToken, client)
		p.redirectWithQuery(w, r, redirectURI, state, "")
		return
	}

	ssoToken, err := p.EnsureSsoSession(r.Context(), session, client)
	if err != nil {
		errorPage(w, http.StatusInternalServerError, "server_error", "会话写入失败")
		return
	}
	p.setSsoCookie(w, ssoToken, client)
	p.redirectWithQuery(w, r, redirectURI, state, code)
}

// HandleToken serves POST /token.
func (p *Provider) HandleToken(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	if !p.available() {
		tokenError(w, "temporarily_unavailable", "会话存储不可用", http.StatusServiceUnavailable)
		return
	}
	b := readBody(r)
	grantType := b.str("grant_type")
	clientID, secret := clientAuth(r, b.form)
	if s := b.str("client_id"); s != "" {
		clientID = s
	}
	if s := b.str("client_secret"); s != "" {
		secret = s
	}
	client := p.registry.Get(clientID)
	if client == nil {
		tokenError(w, "invalid_client", "未知客户端", http.StatusUnauthorized)
		return
	}
	if !p.registry.CheckSecret(client, secret) {
		tokenError(w, "invalid_client", "客户端密钥错误", http.StatusUnauthorized)
		return
	}
	if !p.registry.AllowsGrant(client, grantType) {
		tokenError(w, "unauthorized_client", "该客户端不允许此 grant_type", http.StatusBadRequest)
		return
	}

	switch grantType {
	case "authorization_code":
		code := b.str("code")
		if code == "" {
			tokenError(w, "invalid_request", "缺少 code", http.StatusBadRequest)
			return
		}
		tokens, err := p.exchangeCode(r.Context(), exchangeParams{
			Code: code, ClientID: client.ClientID, RedirectURI: b.str("redirect_uri"),
			CodeVerifier: b.str("code_verifier"), Client: client,
		})
		if err != nil {
			p.replyExchangeError(w, err)
			return
		}
		sendTokens(w, tokens)
	case "refresh_token":
		p.handleRefresh(w, r, b, client)
	default:
		tokenError(w, "unsupported_grant_type", "不支持的 grant_type", http.StatusBadRequest)
	}
}

func (p *Provider) replyExchangeError(w http.ResponseWriter, err error) {
	var oe *OAuthError
	if asOAuth(err, &oe) {
		tokenError(w, oe.Code, oe.Description, http.StatusBadRequest)
		return
	}
	p.logger.Error("token 交换失败", "error", err)
	tokenError(w, "server_error", "服务器内部错误", http.StatusInternalServerError)
}

func (p *Provider) handleRefresh(w http.ResponseWriter, r *http.Request, b body, client *ClientRecord) {
	refreshToken := b.str("refresh_token")
	if refreshToken == "" {
		tokenError(w, "invalid_request", "缺少 refresh_token", http.StatusBadRequest)
		return
	}
	c := p.rdb().Client()
	h := SHA256Hex(refreshToken)
	key := rtPrefix + h
	raw, err := c.Get(r.Context(), key).Result()
	if err != nil || raw == "" {
		tokenError(w, "invalid_grant", "refresh_token 无效或已过期", http.StatusBadRequest)
		return
	}
	var rec refreshRecord
	if json.Unmarshal([]byte(raw), &rec) != nil {
		tokenError(w, "invalid_grant", "refresh_token 记录损坏", http.StatusBadRequest)
		return
	}
	if rec.ClientID != client.ClientID {
		tokenError(w, "invalid_grant", "refresh_token 与客户端不匹配", http.StatusBadRequest)
		return
	}
	if rec.Used {
		// 重放：整条链作废
		p.revokeChain(r.Context(), rec.Chain)
		tokenError(w, "invalid_grant", "refresh_token 已使用，整条链作废", http.StatusBadRequest)
		return
	}
	ttl, _ := c.TTL(r.Context(), key).Result()
	rec.Used = true
	bodyRaw, _ := jsonx.Marshal(rec)
	ttlSec := int(ttl.Seconds())
	if ttlSec <= 0 {
		ttlSec = p.refreshTTL
	}
	_ = c.Set(r.Context(), key, bodyRaw, seconds(ttlSec)).Err()

	tokens, err := p.issueTokens(r.Context(), issueParams{
		Sub: rec.Sub, Client: client, Scope: rec.Scope, AuthTime: rec.AuthTime, SID: rec.SID, Chain: rec.Chain,
	})
	if err != nil {
		p.logger.Error("refresh 签发失败", "error", err)
		tokenError(w, "server_error", "服务器内部错误", http.StatusInternalServerError)
		return
	}
	sendTokens(w, tokens)
}

// userinfoBody is the /userinfo response body.
type userinfoBody struct {
	Sub               string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	SID               string `json:"sid,omitempty"`
}

// HandleUserinfo serves GET/POST /userinfo.
func (p *Provider) HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	token := BearerFromHeader(r.Header.Get("Authorization"))
	if token == "" && r.Method == http.MethodPost {
		token = readBody(r).str("access_token")
	}
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc"`)
		writeJSON(w, http.StatusUnauthorized, oauthErrorBody{Error: "invalid_token", Description: "缺少 access_token"})
		return
	}
	if !p.available() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	raw, err := p.rdb().Client().Get(r.Context(), atPrefix+SHA256Hex(token)).Result()
	if err != nil || raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, oauthErrorBody{Error: "invalid_token", Description: "access_token 无效或已过期"})
		return
	}
	var rec accessRecord
	if json.Unmarshal([]byte(raw), &rec) != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, oauthErrorBody{Error: "invalid_token", Description: "access_token 无效或已过期"})
		return
	}
	subj := p.normalizeSub(rec.Sub)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, userinfoBody{Sub: subj, PreferredUsername: subj, Name: p.displayName, SID: rec.SID})
}

// introspectBody is the RFC 7662 response. Field order matches the legacy one;
// empty fields are omitted rather than sent as zero values.
type introspectBody struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// HandleIntrospect serves GET/POST /introspect.
func (p *Provider) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	var b body
	if r.Method == http.MethodPost {
		b = readBody(r)
	}
	token := b.str("token")
	if token == "" {
		token = QueryStr(r.URL.Query(), "token")
	}
	if token == "" {
		token = BearerFromHeader(r.Header.Get("Authorization"))
	}
	inactive := func() { writeJSON(w, http.StatusOK, introspectBody{Active: false}) }
	if token == "" {
		inactive()
		return
	}
	if !p.available() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	c := p.rdb().Client()
	h := SHA256Hex(token)
	if raw, err := c.Get(r.Context(), atPrefix+h).Result(); err == nil && raw != "" {
		var a accessRecord
		if json.Unmarshal([]byte(raw), &a) == nil {
			writeJSON(w, http.StatusOK, introspectBody{Active: true, Sub: p.normalizeSub(a.Sub), Scope: a.Scope, ClientID: a.ClientID, Exp: a.Exp, TokenType: "access_token"})
			return
		}
	}
	if raw, err := c.Get(r.Context(), rtPrefix+h).Result(); err == nil && raw != "" {
		var rec refreshRecord
		if json.Unmarshal([]byte(raw), &rec) == nil {
			if rec.Used {
				inactive()
				return
			}
			writeJSON(w, http.StatusOK, introspectBody{Active: true, Sub: p.normalizeSub(rec.Sub), Scope: rec.Scope, ClientID: rec.ClientID, TokenType: "refresh_token"})
			return
		}
	}
	if rec, ok := p.getSSO(r.Context(), token); ok {
		writeJSON(w, http.StatusOK, introspectBody{Active: true, Sub: p.normalizeSub(rec.Sub), Scope: "openid", ClientID: rec.ClientID, TokenType: "sso_session"})
		return
	}
	if user, err := c.Get(r.Context(), token).Result(); err == nil && user != "" {
		writeJSON(w, http.StatusOK, introspectBody{Active: true, Sub: p.normalizeSub(user), Scope: "openid", TokenType: "session"})
		return
	}
	inactive()
}

// HandleRevoke serves POST /revoke (RFC 7009).
func (p *Provider) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	b := readBody(r)
	clientID, secret := clientAuth(r, b.form)
	if s := b.str("client_id"); s != "" {
		clientID = s
	}
	if s := b.str("client_secret"); s != "" {
		secret = s
	}
	client := p.registry.Get(clientID)
	if client == nil {
		tokenError(w, "invalid_client", "未知客户端", http.StatusUnauthorized)
		return
	}
	if !p.registry.CheckSecret(client, secret) {
		tokenError(w, "invalid_client", "客户端密钥错误", http.StatusUnauthorized)
		return
	}
	token := b.str("token")
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	if !p.available() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	c := p.rdb().Client()
	h := SHA256Hex(token)
	_ = c.Del(r.Context(), atPrefix+h).Err()
	if raw, err := c.Get(r.Context(), rtPrefix+h).Result(); err == nil && raw != "" {
		var rec refreshRecord
		if json.Unmarshal([]byte(raw), &rec) == nil {
			p.revokeChain(r.Context(), rec.Chain)
		}
	}
	p.RevokeSsoForToken(r.Context(), token)
	_ = c.Del(r.Context(), token).Err()
	writeJSON(w, http.StatusOK, map[string]any{})
}

// HandleEndSession serves GET/POST /end_session.
func (p *Provider) HandleEndSession(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	var b body
	if r.Method == http.MethodPost {
		b = readBody(r)
	}
	src := func(key string) string {
		if r.Method == http.MethodPost {
			return b.str(key)
		}
		return QueryStr(r.URL.Query(), key)
	}
	cookieToken := ParseCookies(r.Header.Get("Cookie"))[p.cookieName]
	idTokenHint := src("id_token_hint")
	postLogout := src("post_logout_redirect_uri")

	var hintClient *ClientRecord
	hintDomain := ""
	if idTokenHint != "" {
		payload, err := p.keyStore.Verify(idTokenHint, VerifyIssuer(p.issuer))
		if err != nil {
			if postLogout == "" {
				errorPage(w, http.StatusBadRequest, "invalid_request", "id_token_hint 无效: "+err.Error())
				return
			}
		} else if aud, _ := payload["aud"].(string); aud != "" {
			hintClient = p.registry.Get(aud)
			if hintClient != nil {
				hintDomain = hintClient.CookieDomain
			}
		}
	}

	if cookieToken != "" {
		sid, _, ok := p.SidForToken(r.Context(), cookieToken)
		p.RevokeSsoForToken(r.Context(), cookieToken)
		if ok {
			p.RevokeSid(r.Context(), sid)
			go p.NotifyBackchannel(sid, p.subject)
		}
	}
	p.clearSsoCookie(w, hintDomain)

	if postLogout != "" {
		client := hintClient
		if client == nil {
			client = p.registry.Get(src("client_id"))
		}
		if client == nil || !p.registry.MatchPostLogout(client, postLogout) {
			errorPage(w, http.StatusBadRequest, "invalid_request", "post_logout_redirect_uri 未列入白名单")
			return
		}
		redirectFound(w, postLogout)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>已退出</title></head>`+
		`<body style="font-family:sans-serif;text-align:center;padding:80px;color:#171512">已退出登录</body></html>`)
}

// HandleLoginPage serves GET /auth: the login page plus the legacy redirect
// whitelist signalling.
func (p *Provider) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	redirect := QueryStr(r.URL.Query(), "redirect")
	if redirect != "" {
		if !p.isAllowedRedirect(redirect) {
			p.logger.Warn("/auth 拒绝未列入白名单的 redirect")
			w.Header().Set("X-Auth-Deprecated", "redirect-not-allowed")
			p.serveLoginPage(w, r)
			return
		}
		w.Header().Set("Deprecated", "true")
		w.Header().Set("X-Auth-Deprecated", "redirect")
	}
	p.serveLoginPage(w, r)
}

// LoginPageHandler is injected by the http layer (embedded static asset).
func (p *Provider) setLoginPageHandler(h http.Handler) { p.loginPage = h }

func (p *Provider) serveLoginPage(w http.ResponseWriter, r *http.Request) {
	if p.loginPage == nil {
		http.Error(w, "login page not available", http.StatusInternalServerError)
		return
	}
	p.loginPage.ServeHTTP(w, r)
}

func (p *Provider) isAllowedRedirect(raw string) bool {
	if raw == "" {
		return false
	}
	if strings.HasPrefix(raw, "/") {
		return !strings.HasPrefix(raw, "//") && !strings.Contains(raw, "\\")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme+"://"+u.Host == p.issuerOrigin {
		return true
	}
	for _, client := range p.registry.Clients() {
		for _, ru := range client.RedirectURIs {
			if ru == raw {
				return true
			}
		}
	}
	return false
}

/* ---------------- cookie 与重定向 ---------------- */

func (p *Provider) cookieHeader(value string, maxAge int, domain string) string {
	parts := []string{p.cookieName + "=" + value, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=" + itoa(maxAge)}
	if p.secureCookies {
		parts = append(parts, "Secure")
	}
	if domain != "" {
		parts = append(parts, "Domain="+domain)
	}
	return strings.Join(parts, "; ")
}

func (p *Provider) setSsoCookie(w http.ResponseWriter, token string, client *ClientRecord) {
	domain := ""
	if client != nil {
		domain = client.CookieDomain
	}
	w.Header().Add("Set-Cookie", p.cookieHeader(token, p.sessionTTL, domain))
}

func (p *Provider) clearSsoCookie(w http.ResponseWriter, domain string) {
	w.Header().Add("Set-Cookie", p.cookieHeader("", 0, domain))
}

// redirectWithQuery redirects to redirectURI with state (and optionally code)
// added. A non-empty code is appended for the non-first-party flow.
func (p *Provider) redirectWithQuery(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		errorPage(w, http.StatusInternalServerError, "server_error", "回跳地址非法")
		return
	}
	q := u.Query()
	if code != "" {
		q.Set("code", code)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	redirectFound(w, u.String())
}

// SetLoginPage wires the static handler used by /auth.
func (p *Provider) SetLoginPage(h http.Handler) { p.setLoginPageHandler(h) }

// VerifyIssuer builds VerifyOpts requiring the given issuer.
func VerifyIssuer(issuer string) jwt.VerifyOpts { return jwt.VerifyOpts{Issuer: issuer} }

// OIDCPaths lists the paths that share the OIDC CORS middleware.
var OIDCPaths = []string{
	"/.well-known/openid-configuration",
	"/authorize",
	"/token",
	"/userinfo",
	"/jwks.json",
	"/introspect",
	"/end_session",
	"/revoke",
	"/auth",
}

// HandleOIDC dispatches one OIDC path. It returns false when the path is not an
// OIDC endpoint so the caller can continue routing.
func (p *Provider) HandleOIDC(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		p.handleDiscovery(w, r)
	case "/authorize":
		p.HandleAuthorize(w, r)
	case "/token":
		p.HandleToken(w, r)
	case "/userinfo":
		p.HandleUserinfo(w, r)
	case "/jwks.json":
		p.handleJWKS(w, r)
	case "/introspect":
		p.HandleIntrospect(w, r)
	case "/end_session":
		p.HandleEndSession(w, r)
	case "/revoke":
		p.HandleRevoke(w, r)
	case "/auth":
		p.HandleLoginPage(w, r)
	default:
		return false
	}
	return true
}
