package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// itoa formats a non-negative integer. Cookie Max-Age values are always >= 0, so
// strconv handles every call site and keeps the header byte layout explicit.
func itoa(n int) string { return strconv.Itoa(n) }

// writeJSON serializes v with the standard library and writes status. A marshal
// failure degrades to a minimal server_error body rather than a partial write.
func writeJSON(w http.ResponseWriter, status int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// allowMethod rejects methods outside the allowed set with 405, mirroring the
// Express router that only registered the listed verbs.
func allowMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	w.WriteHeader(http.StatusMethodNotAllowed)
	return false
}

// hasScope reports whether a space-delimited scope string contains name.
func hasScope(scope, name string) bool {
	for _, part := range strings.Fields(scope) {
		if part == name {
			return true
		}
	}
	return false
}

// atoiSafe parses an optional numeric query parameter. It accepts the same
// integers Number() accepted in the legacy code and rejects everything else.
func atoiSafe(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return n, true
}

// asOAuth unwraps an *OAuthError from an error chain.
func asOAuth(err error, target **OAuthError) bool {
	return errors.As(err, target)
}
