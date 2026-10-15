// Route table for the auth centre HTTP surface.
//
// routeTable is the single source of truth for what the mux registers: routes()
// walks it to install handlers, and scripts/check-api-docs.mjs walks the same
// literals to prove docs/API.md still describes every path. Adding a route here
// without documenting it (or the reverse) fails `make check`.
package httpapi

import "net/http"

// routeKind selects the handler for a route. It keeps routeTable free of
// method values so the checker can read it as plain literals.
type routeKind int

const (
	kindConfigJS routeKind = iota
	kindAppTotpReset
	kindAppTotpConfirm
	kindAppLogin
	kindModuleSetup
	kindModuleLogin
	kindModuleReset
	kindVerify
	kindLogout
	kindSessionList
	kindSessionRename
	kindSessionDelete
	kindInternalSessions
	kindInternalRename
	kindInternalDelete
	kindInternalTotpReset
	kindInternalTotpConfirm
	kindOIDC
	kindAsset
	kindRoot
)

// routeSpec is one HTTP route. An empty method means "any verb": the OIDC and
// root handlers enforce their own method whitelist and return 405 otherwise.
type routeSpec struct {
	method string
	path   string
	kind   routeKind
}

// routeTable lists every route the server exposes. Exact patterns must appear
// before their catch-all counterparts to shadow the legacy module routes, the
// same ordering the Express app depended on.
var routeTable = []routeSpec{
	{http.MethodGet, "/config.js", kindConfigJS},

	{http.MethodPost, "/api/totp/reset", kindAppTotpReset},
	{http.MethodPost, "/api/totp/confirm", kindAppTotpConfirm},

	{http.MethodPost, "/api/login", kindAppLogin},

	{http.MethodPost, "/api/totp/setup", kindModuleSetup},
	{http.MethodPost, "/api/totp/login", kindModuleLogin},
	{http.MethodPost, "/api/setup", kindModuleSetup},
	{http.MethodPost, "/api/reset", kindModuleReset},

	{http.MethodGet, "/api/verify", kindVerify},
	{http.MethodPost, "/api/logout", kindLogout},
	{http.MethodGet, "/api/sessions", kindSessionList},
	{http.MethodPut, "/api/sessions/{id}/name", kindSessionRename},
	{http.MethodDelete, "/api/sessions/{id}", kindSessionDelete},

	{http.MethodGet, "/api/internal/sessions", kindInternalSessions},
	{http.MethodPut, "/api/internal/sessions/{id}/name", kindInternalRename},
	{http.MethodDelete, "/api/internal/sessions/{id}", kindInternalDelete},
	{http.MethodPost, "/api/internal/totp/reset", kindInternalTotpReset},
	{http.MethodPost, "/api/internal/totp/confirm", kindInternalTotpConfirm},

	{"", "/.well-known/openid-configuration", kindOIDC},
	{"", "/authorize", kindOIDC},
	{"", "/token", kindOIDC},
	{"", "/userinfo", kindOIDC},
	{"", "/jwks.json", kindOIDC},
	{"", "/introspect", kindOIDC},
	{"", "/end_session", kindOIDC},
	{"", "/revoke", kindOIDC},
	{"", "/auth", kindOIDC},

	{http.MethodGet, "/assets/", kindAsset},
	{"", "/", kindRoot},
}

// handlerFor resolves the handler a route kind maps to.
func (s *Server) handlerFor(k routeKind) http.HandlerFunc {
	switch k {
	case kindConfigJS:
		return s.handleConfigJS
	case kindAppTotpReset:
		return s.handleAppTotpReset
	case kindAppTotpConfirm:
		return s.handleAppTotpConfirm
	case kindAppLogin:
		return s.handleLogin
	case kindModuleSetup:
		return s.handleModuleSetup
	case kindModuleLogin:
		return s.handleModuleLogin
	case kindModuleReset:
		return s.handleModuleReset
	case kindVerify:
		return s.handleVerify
	case kindLogout:
		return s.handleLogout
	case kindSessionList:
		return s.handleSessionList
	case kindSessionRename:
		return s.handleSessionRename
	case kindSessionDelete:
		return s.handleSessionDelete
	case kindInternalSessions:
		return s.handleInternalSessions
	case kindInternalRename:
		return s.handleInternalRename
	case kindInternalDelete:
		return s.handleInternalDelete
	case kindInternalTotpReset:
		return s.handleInternalTotpReset
	case kindInternalTotpConfirm:
		return s.handleInternalTotpConfirm
	case kindOIDC:
		return s.handleRoot
	case kindAsset:
		return s.serveAsset
	case kindRoot:
		return s.handleRoot
	}
	return nil
}
