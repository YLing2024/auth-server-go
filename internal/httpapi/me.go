package httpapi

import (
	"net/http"
	"strings"
)

// meSignedIn is the 200 body of GET /api/me. Field order is the response
// contract; it carries display-safe values only, never the session token.
type meSignedIn struct {
	Authenticated bool   `json:"authenticated"`
	Subject       string `json:"subject"`
	DisplayName   string `json:"displayName"`
	CreatedAt     int64  `json:"createdAt"`
	ExpiresAt     int64  `json:"expiresAt"`
	Remember      bool   `json:"remember"`
}

// meSignedOut is the unauthenticated body. It is also returned with 200 when
// Redis is unavailable, so the landing page can fall back to the login form.
type meSignedOut struct {
	Authenticated bool `json:"authenticated"`
}

// handleMe reports whether the HomeAuth cookie is a live session. It only
// reads: it never creates a session or slides its TTL, and Redis failures
// degrade to authenticated:false instead of a 500.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	session, err := s.oidc.ReadCookieSession(r.Context(), r)
	if err != nil {
		s.log().Warn("api/me: 读取会话失败，按未登录返回", "error", err)
		writeJSON(w, http.StatusOK, meSignedOut{Authenticated: false})
		return
	}
	if session == nil {
		writeJSON(w, http.StatusUnauthorized, meSignedOut{Authenticated: false})
		return
	}
	displayName := strings.TrimSpace(s.cfg.DisplayName)
	if displayName == "" {
		displayName = session.Subject
	}
	writeJSON(w, http.StatusOK, meSignedIn{
		Authenticated: true,
		Subject:       session.Subject,
		DisplayName:   displayName,
		CreatedAt:     session.CreatedAt,
		ExpiresAt:     session.ExpiresAt,
		Remember:      session.Remember,
	})
}
