// Express-compatibility layer for the request shapes net/http's ServeMux
// answers differently: automatic route-level OPTIONS, the app-level OPTIONS
// fallback, HEAD-as-GET, and finalhandler's default 404 page.
//
// The legacy service was an Express 4 app, and these behaviours are observable
// HTTP contract, not internals. The measured reference table and per-path
// comparison live in docs/API.md under "方法回退与未匹配路由".
package httpapi

import (
	"net/http"
	"strconv"
	"strings"
)

// expressModuleRoutePaths are the paths the legacy totp-auth module router
// registered, mounted at both /api/totp and /api. Express only emits its
// automatic route-level OPTIONS reply for a route inside a mounted router whose
// stack is exhausted before the OIDC router's CORS middleware runs; every other
// OPTIONS request falls through to that middleware and gets 204. So these six
// paths are the only ones that answer OPTIONS with 200 + Allow + body.
//
// /api/totp/reset is listed even though the new route table treats it as an app
// handler: the legacy app also mounted the module's /reset route there, which is
// what produced the 200. /api/totp/confirm is deliberately absent for the same
// reason — it existed only as an app handler, so the legacy OPTIONS fell through
// to 204.
var expressModuleRoutePaths = map[string]bool{
	"/api/login":      true,
	"/api/setup":      true,
	"/api/reset":      true,
	"/api/totp/setup": true,
	"/api/totp/login": true,
	"/api/totp/reset": true,
}

// oidcLegacyMethods mirrors the verbs the legacy OIDC router registered per
// endpoint. It has to be spelled out here because the new table registers OIDC
// paths as any-verb and lets the OIDC handler enforce the verb: the wrapper
// needs the whitelist up front to turn a wrong verb into the legacy HTML 404
// instead of a 405.
var oidcLegacyMethods = map[string][]string{
	"/.well-known/openid-configuration": {http.MethodGet},
	"/authorize":                        {http.MethodGet},
	"/token":                            {http.MethodPost},
	"/userinfo":                         {http.MethodGet, http.MethodPost},
	"/jwks.json":                        {http.MethodGet},
	"/introspect":                       {http.MethodGet, http.MethodPost},
	"/end_session":                      {http.MethodGet, http.MethodPost},
	"/revoke":                           {http.MethodPost},
	"/auth":                             {http.MethodGet},
}

// legacyCompat wraps the mux with the Express fallbacks. It never mutates the
// original request, so the 404 page still names the path the client sent.
func (s *Server) legacyCompat(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original := r.URL.Path
		path := normalizeTrailingSlash(original)

		if r.Method == http.MethodOptions {
			if expressModuleRoutePaths[path] {
				writeRouteLevelOptions(w)
				return
			}
			writeCORSPreflight(w)
			return
		}

		if methods, ok := oidcLegacyMethods[path]; ok {
			if !methodAllowed(methods, r.Method) {
				writeLegacyNotFound(w, r.Method, expressResourceName(r))
				return
			}
			next.ServeHTTP(w, withNormalizedPath(r, path))
			return
		}

		if allowed, matched := tableMethodAllowed(path, r.Method); matched {
			if !allowed {
				writeLegacyNotFound(w, r.Method, expressResourceName(r))
				return
			}
			next.ServeHTTP(w, withNormalizedPath(r, path))
			return
		}

		if !isKnownPath(path) {
			writeLegacyNotFound(w, r.Method, expressResourceName(r))
			return
		}
		next.ServeHTTP(w, withNormalizedPath(r, path))
	})
}

// normalizeTrailingSlash reproduces Express's default non-strict route matching,
// which accepts one optional trailing slash. Subtree paths are left alone so the
// embedded asset server keeps its own semantics.
func normalizeTrailingSlash(path string) string {
	if len(path) > 1 && path[len(path)-1] == '/' && !strings.HasPrefix(path, "/assets/") {
		return path[:len(path)-1]
	}
	return path
}

// methodAllowed reports whether method is accepted. HEAD follows GET, exactly as
// Express Route._handles_method normalises it.
func methodAllowed(methods []string, method string) bool {
	if method == http.MethodHead {
		return containsMethod(methods, http.MethodGet)
	}
	return containsMethod(methods, method)
}

func containsMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

// tableMethodAllowed resolves a path against the method-restricted entries of
// routeTable. matched reports whether a method-restricted route owns the path;
// allowed reports whether the request verb may reach it. GET entries also accept
// HEAD, and the /assets/ subtree is served for GET/HEAD only.
func tableMethodAllowed(path, method string) (allowed, matched bool) {
	for _, spec := range routeTable {
		if spec.method == "" {
			continue
		}
		if !matchRoutePattern(spec.path, path) {
			continue
		}
		if method == spec.method || (method == http.MethodHead && spec.method == http.MethodGet) {
			return true, true
		}
		return false, true
	}
	if strings.HasPrefix(path, "/assets/") {
		return method == http.MethodGet || method == http.MethodHead, true
	}
	return false, false
}

// isKnownPath reports whether any route (any-verb included) owns the path. An
// unknown path is answered directly so net/http's path cleaning never turns it
// into a 307 redirect, which the legacy server never produced.
func isKnownPath(path string) bool {
	if _, ok := oidcLegacyMethods[path]; ok {
		return true
	}
	for _, spec := range routeTable {
		if matchRoutePattern(spec.path, path) {
			return true
		}
	}
	return strings.HasPrefix(path, "/assets/")
}

// matchRoutePattern implements the subset of net/http patterns routeTable uses:
// literal segments, single-segment {name} wildcards, and the /assets/ subtree.
// The root pattern is an exact match for "/" only, because unknown paths are
// answered separately.
func matchRoutePattern(pattern, path string) bool {
	if pattern == "/" {
		return path == "/"
	}
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(path, pattern)
	}
	if !strings.Contains(pattern, "{") {
		return path == pattern
	}
	ps := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	xs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if strings.HasPrefix(ps[i], "{") && strings.HasSuffix(ps[i], "}") {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if ps[i] != xs[i] {
			return false
		}
	}
	return true
}

// withNormalizedPath returns r unchanged when its path is already canonical, or
// a shallow copy whose URL carries the normalised path otherwise.
func withNormalizedPath(r *http.Request, path string) *http.Request {
	if path == r.URL.Path {
		return r
	}
	clone := new(http.Request)
	*clone = *r
	u := *r.URL
	u.Path = path
	u.RawPath = ""
	clone.URL = &u
	return clone
}

// writeRouteLevelOptions reproduces Express's automatic OPTIONS reply for a
// route: 200, Allow listing the route's verbs, and the verb list as a
// text/html body. Every legacy module route was POST-only.
func writeRouteLevelOptions(w http.ResponseWriter) {
	const body = "POST"
	w.Header().Set("Allow", body)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// writeCORSPreflight reproduces the OIDC router's CORS middleware, which is the
// legacy app-level OPTIONS fallback: 204 with no body and the three CORS
// headers, for every OPTIONS request no route claimed.
func writeCORSPreflight(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.WriteHeader(http.StatusNoContent)
}

// writeLegacyNotFound reproduces finalhandler's default 404 page byte for byte,
// plus the CORS header the OIDC middleware had already set on the way through.
// HEAD keeps the headers and content length but no body, as net/http does for a
// handler write; returning early makes that explicit rather than implicit.
func writeLegacyNotFound(w http.ResponseWriter, method, rawPath string) {
	body := legacyErrorDocument("Cannot " + method + " " + encodeURLPath(rawPath))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusNotFound)
	if method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(body))
}

// legacyErrorDocument builds finalhandler's error document. The newline and
// double-space substitutions mirror createHtmlDocument; they are no-ops for a
// normal request target but keep the shape identical for odd ones.
func legacyErrorDocument(message string) string {
	body := escapeHTML(message)
	body = strings.ReplaceAll(body, "\n", "<br>")
	body = strings.ReplaceAll(body, "  ", " &nbsp;")
	return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n" +
		"<title>Error</title>\n</head>\n<body>\n<pre>" + body + "</pre>\n</body>\n</html>\n"
}

// escapeHTML matches the escape-html package's five entities exactly; note ' and
// " use the legacy numeric/dot forms, unlike html.EscapeString.
func escapeHTML(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("&quot;")
		case '&':
			b.WriteString("&amp;")
		case '\'':
			b.WriteString("&#39;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// expressResourceName returns the path finalhandler would name: the request
// target's path as the client sent it. r.RequestURI holds that raw form, so a
// character Go would escape differently is preserved for encodeURLPath.
func expressResourceName(r *http.Request) string {
	raw := r.RequestURI
	if raw == "" || strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		raw = r.URL.EscapedPath()
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

// encodeURLPath reproduces the encodeurl package: ASCII bytes outside the URI
// path set are percent-encoded, an ill-formed "%" becomes "%25", and multi-byte
// runes are percent-encoded as their UTF-8 bytes.
func encodeURLPath(s string) string {
	const upperHex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			// A well-formed "%XX" is already legal and is copied through; every
			// other "%" is what encodeurl matches and encodeURI turns into "%25".
			if i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
				b.WriteByte('%')
				b.WriteByte(s[i+1])
				b.WriteByte(s[i+2])
				i += 2
				continue
			}
			b.WriteString("%25")
			continue
		}
		if isURLPathByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0xf])
	}
	return b.String()
}

// isURLPathByte reports whether c is left as-is by encodeurl. The set is the
// regexp's allowlist: ! #..; = ?.._ a..z | ~.
func isURLPathByte(c byte) bool {
	switch {
	case c == '!':
		return true
	case c >= '#' && c <= ';':
		return true
	case c == '=':
		return true
	case c >= '?' && c <= '_':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c == '|' || c == '~':
		return true
	}
	return false
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
}
