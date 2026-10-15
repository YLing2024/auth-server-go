// Package httpapi is the auth centre's HTTP surface: the legacy /api/* session
// and TOTP routes, the shared internal endpoints, the runtime /config.js and the
// embedded login page. The OIDC endpoints live in the oidc package and are
// dispatched from the same mux so routing order matches the legacy Express app.
package httpapi

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"auth-server-go/internal/config"
	"auth-server-go/internal/oidc"
	"auth-server-go/internal/redis"
	"auth-server-go/internal/totp"
)

// errEmpty is returned by the strict numeric parsers; callers only care that
// parsing failed, not why.
var errEmpty = errors.New("empty or non-numeric")

// Server wires the configuration, stores and OIDC provider into one mux.
type Server struct {
	cfg     *config.Config
	store   *redis.Store
	oidc    *oidc.Provider
	secrets *totp.SecretStore
	pending *totp.PendingStore
	logger  *slog.Logger

	appLimiter    *totp.RateLimiter
	moduleLimiter *totp.RateLimiter

	geo *geoResolver

	mux     *http.ServeMux
	assets  fs.FS
	index   []byte
	subject string

	legacySubjects map[string]bool
}

// New assembles the server and registers every route. It also injects the
// embedded login page handler into the OIDC provider so /auth stays identical.
func New(cfg *config.Config, store *redis.Store, provider *oidc.Provider, publicFS fs.FS, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		cfg:            cfg,
		store:          store,
		oidc:           provider,
		secrets:        totp.NewSecretStore(filepath.Join(cfg.DataDir, "totp-secret.json")),
		pending:        totp.NewPendingStore(filepath.Join(cfg.DataDir, "totp-pending.json")),
		logger:         logger,
		appLimiter:     totp.NewRateLimiter(5, []int{60, 300, 900}),
		moduleLimiter:  totp.NewRateLimiter(5, []int{60, 300, 900}),
		geo:            newGeoResolver(cfg.GeoIPURL, store),
		subject:        cfg.Subject,
		legacySubjects: map[string]bool{},
	}
	for _, label := range config.LegacySubjects() {
		s.legacySubjects[label] = true
	}
	sub, err := fs.Sub(publicFS, "public")
	if err != nil {
		return nil, err
	}
	s.assets = sub
	if raw, err := fs.ReadFile(sub, "index.html"); err == nil {
		s.index = raw
	}
	provider.SetLoginPage(http.HandlerFunc(s.serveLoginIndex))
	s.mux = s.routes()
	return s, nil
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) log() *slog.Logger { return s.logger }

// routes installs every entry of routeTable into a ServeMux. The table order
// mirrors the legacy registration order; Go 1.22 precedence (more specific
// patterns win) preserves the Express override semantics.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	for _, spec := range routeTable {
		pattern := spec.path
		if spec.method != "" {
			pattern = spec.method + " " + spec.path
		}
		mux.HandleFunc(pattern, s.handlerFor(spec.kind))
	}
	return mux
}

// handleRoot dispatches the OIDC endpoints (with the shared CORS layer) and
// otherwise returns 404, exactly like the legacy router falling through.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if !isOIDCPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.oidc.HandleOIDC(w, r)
}

func isOIDCPath(p string) bool {
	for _, known := range oidc.OIDCPaths {
		if p == known {
			return true
		}
	}
	return false
}

// serveLoginIndex serves the embedded login page for /auth.
func (s *Server) serveLoginIndex(w http.ResponseWriter, r *http.Request) {
	if s.index == nil {
		http.Error(w, "login page not available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=0")
	_, _ = w.Write(s.index)
}

// serveAsset serves the hashed build assets.
func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request) {
	http.FileServer(http.FS(s.assets)).ServeHTTP(w, r)
}

// handleConfigJS injects only the redirect-domain whitelist. It never carries a
// credential or a secret.
func (s *Server) handleConfigJS(w http.ResponseWriter, r *http.Request) {
	roots := s.cfg.AllowedRedirectRoots
	if roots == nil {
		roots = []string{}
	}
	body := "window.__AUTH_CONFIG__ = " + jsonArray(roots) + ";\n"
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body))
}

// jsonArray renders a string slice with the same encoding JSON.stringify used.
func jsonArray(items []string) string {
	var sb strings.Builder
	sb.WriteString(`{"allowedRedirectRoots":[`)
	for i, item := range items {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(jsonString(item))
	}
	sb.WriteString("]}")
	return sb.String()
}
