package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newLegacyHarness serves the compatibility wrapper over a trivial downstream
// handler, so routing decisions can be asserted without a Redis store.
func newLegacyHarness(t *testing.T) *httptest.Server {
	t.Helper()
	var s Server
	h := s.legacyCompat(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("DELEGATED"))
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// doLegacy issues one request. HEAD bodies are empty; the returned headers are
// the real response headers.
func doLegacy(t *testing.T, srv *httptest.Server, method, path string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest(%s %s): %v", method, path, err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	return resp.StatusCode, resp.Header, string(body)
}

// TestLegacyRouteLevelOptions pins the six module paths that answer OPTIONS with
// the Express automatic reply and proves a nearby app-only path does not.
func TestLegacyRouteLevelOptions(t *testing.T) {
	for _, p := range []string{
		"/api/login", "/api/setup", "/api/reset",
		"/api/totp/setup", "/api/totp/login", "/api/totp/reset",
	} {
		if !expressModuleRoutePaths[p] {
			t.Errorf("%s should answer route-level OPTIONS", p)
		}
	}
	for _, p := range []string{"/api/totp/confirm", "/api/verify", "/api/sessions", "/config.js"} {
		if expressModuleRoutePaths[p] {
			t.Errorf("%s must fall through to the 204 OPTIONS fallback", p)
		}
	}
}

// TestLegacyOptionsResponses asserts both OPTIONS shapes over a real server,
// including the trailing-slash tolerance Express has by default.
func TestLegacyOptionsResponses(t *testing.T) {
	srv := newLegacyHarness(t)
	for _, p := range []string{"/api/login", "/api/login/", "/api/totp/reset"} {
		code, h, body := doLegacy(t, srv, http.MethodOptions, p)
		if code != http.StatusOK {
			t.Errorf("OPTIONS %s status = %d, want 200", p, code)
		}
		if got := h.Get("Allow"); got != "POST" {
			t.Errorf("OPTIONS %s Allow = %q, want POST", p, got)
		}
		if got := h.Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("OPTIONS %s Content-Type = %q", p, got)
		}
		if body != "POST" {
			t.Errorf("OPTIONS %s body = %q, want POST", p, body)
		}
		if got := h.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("OPTIONS %s ACAO = %q, want empty", p, got)
		}
	}

	code, h, body := doLegacy(t, srv, http.MethodOptions, "/definitely-nope")
	if code != http.StatusNoContent {
		t.Errorf("OPTIONS /definitely-nope status = %d, want 204", code)
	}
	if body != "" {
		t.Errorf("OPTIONS /definitely-nope body = %q, want empty", body)
	}
	if got := h.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("OPTIONS /definitely-nope ACAO = %q, want *", got)
	}
	if got := h.Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
		t.Errorf("OPTIONS /definitely-nope ACAM = %q", got)
	}
}

// TestLegacyHeadFollowsGet proves HEAD reaches the GET handler through the
// wrapper and that net/http strips the body while keeping the headers.
func TestLegacyHeadFollowsGet(t *testing.T) {
	srv := newLegacyHarness(t)
	code, _, body := doLegacy(t, srv, http.MethodHead, "/api/verify")
	if code != http.StatusOK || body != "" {
		t.Fatalf("HEAD /api/verify = %d %q, want 200 empty", code, body)
	}
	// POST-only paths must not reach the handler on HEAD.
	code, _, _ = doLegacy(t, srv, http.MethodHead, "/api/login")
	if code != http.StatusNotFound {
		t.Fatalf("HEAD /api/login = %d, want 404", code)
	}
}

// TestLegacyNotFoundDocument pins finalhandler's page byte for byte, including
// HTML escaping, percent-encoding and the HEAD body suppression.
func TestLegacyNotFoundDocument(t *testing.T) {
	const want = "<!DOCTYPE html>\n" +
		"<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n" +
		"</head>\n<body>\n<pre>Cannot GET /definitely-nope</pre>\n</body>\n</html>\n"

	srv := newLegacyHarness(t)
	code, h, body := doLegacy(t, srv, http.MethodGet, "/definitely-nope")
	if code != http.StatusNotFound || body != want {
		t.Fatalf("GET /definitely-nope = %d %q, want 404 with legacy page", code, body)
	}
	if got := h.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := h.Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Errorf("Content-Security-Policy = %q", got)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := h.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
	if got := h.Get("Content-Length"); got != "154" {
		t.Errorf("Content-Length = %q, want 154", got)
	}

	// HEAD keeps the length header but sends no body. The message names the
	// verb, so "Cannot HEAD ..." is one byte longer than the GET document.
	code, h, body = doLegacy(t, srv, http.MethodHead, "/definitely-nope")
	if code != http.StatusNotFound || body != "" {
		t.Fatalf("HEAD /definitely-nope = %d %q, want 404 empty", code, body)
	}
	if got := h.Get("Content-Length"); got != "155" {
		t.Errorf("HEAD Content-Length = %q, want 155", got)
	}
}

// TestLegacyNotFoundEscaping checks the escaping and encoding rules that the
// legacy page applies to the request target.
func TestLegacyNotFoundEscaping(t *testing.T) {
	srv := newLegacyHarness(t)
	for _, tc := range []struct{ path, pre string }{
		{"/a&b", "Cannot GET /a&amp;b"},
		{"/a<b>", "Cannot GET /a%3Cb%3E"},
		{"/a%22b", "Cannot GET /a%22b"},
		{"/a%25zz", "Cannot GET /a%25zz"},
		{"/a[b]", "Cannot GET /a[b]"},
	} {
		code, _, body := doLegacy(t, srv, http.MethodGet, tc.path)
		if code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", tc.path, code)
		}
		if !strings.Contains(body, "<pre>"+tc.pre+"</pre>") {
			t.Errorf("GET %s body = %q, want <pre>%s</pre>", tc.path, body, tc.pre)
		}
	}
}

// TestLegacyMethodAllowed pins the verb rules, HEAD following GET included.
func TestLegacyMethodAllowed(t *testing.T) {
	cases := []struct {
		path   string
		method string
		want   bool
	}{
		{"/api/verify", http.MethodGet, true},
		{"/api/verify", http.MethodHead, true},
		{"/api/verify", http.MethodPost, false},
		{"/api/login", http.MethodPost, true},
		{"/api/login", http.MethodHead, false},
		{"/api/login", http.MethodGet, false},
		{"/api/sessions/abc", http.MethodDelete, true},
		{"/api/sessions/abc", http.MethodGet, false},
		{"/api/totp/reset", http.MethodGet, false},
	}
	for _, tc := range cases {
		got, matched := tableMethodAllowed(tc.path, tc.method)
		if !matched {
			t.Errorf("tableMethodAllowed(%s, %s) not matched", tc.path, tc.method)
			continue
		}
		if got != tc.want {
			t.Errorf("tableMethodAllowed(%s, %s) = %v, want %v", tc.path, tc.method, got, tc.want)
		}
	}
	if _, matched := tableMethodAllowed("/totally/unknown", http.MethodGet); matched {
		t.Error("unknown path must not match a method route")
	}
}

// TestLegacyNormalizeTrailingSlash pins the non-strict matching normalisation.
func TestLegacyNormalizeTrailingSlash(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/", "/"},
		{"/api/login/", "/api/login"},
		{"/api/login", "/api/login"},
		{"/assets/", "/assets/"},
		{"/assets/app.js", "/assets/app.js"},
	} {
		if got := normalizeTrailingSlash(tc.in); got != tc.want {
			t.Errorf("normalizeTrailingSlash(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestLegacyMethodAllowedOIDC pins the verb whitelist the wrapper applies to the
// OIDC paths before they reach the handler, so a wrong verb becomes the legacy
// HTML 404 rather than the handler's 405. HEAD follows GET here too.
func TestLegacyMethodAllowedOIDC(t *testing.T) {
	cases := []struct {
		path   string
		method string
		want   bool
	}{
		{"/jwks.json", http.MethodGet, true},
		{"/jwks.json", http.MethodHead, true},
		{"/jwks.json", http.MethodPost, false},
		{"/token", http.MethodPost, true},
		{"/token", http.MethodHead, false},
		{"/token", http.MethodGet, false},
		{"/auth", http.MethodGet, true},
		{"/auth", http.MethodHead, true},
		{"/revoke", http.MethodHead, false},
		{"/userinfo", http.MethodGet, true},
		{"/userinfo", http.MethodPost, true},
	}
	for _, tc := range cases {
		methods := oidcLegacyMethods[tc.path]
		if methods == nil {
			t.Fatalf("oidcLegacyMethods[%s] missing", tc.path)
		}
		if got := methodAllowed(methods, tc.method); got != tc.want {
			t.Errorf("methodAllowed(%s, %s) = %v, want %v", tc.path, tc.method, got, tc.want)
		}
	}
}

// TestEncodeURLPath pins the encodeurl behaviour used by the 404 page.
func TestEncodeURLPath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/definitely-nope", "/definitely-nope"},
		{"/a&b", "/a&b"},
		{"/a'b", "/a'b"},
		{"/a<b>", "/a%3Cb%3E"},
		{"/a%22b", "/a%22b"},
		{"/a%zz", "/a%25zz"},
		{"/a%25zz", "/a%25zz"},
		{"/a[b]", "/a[b]"},
		{"/café", "/caf%C3%A9"},
	} {
		if got := encodeURLPath(tc.in); got != tc.want {
			t.Errorf("encodeURLPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEscapeHTML pins the five entities the legacy package escapes.
func TestEscapeHTML(t *testing.T) {
	if got, want := escapeHTML(`a&b<c>d"e'f`), "a&amp;b&lt;c&gt;d&quot;e&#39;f"; got != want {
		t.Errorf("escapeHTML = %q, want %q", got, want)
	}
}
