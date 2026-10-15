package httpapi

import (
	"net/http"
	"testing"

	"auth-server-go/internal/jsonx"
)

// TestRouteTableWellFormed guards the table that both the mux and the API-doc
// checker read: unique method+path pairs, absolute paths, and a resolvable
// handler for every entry.
func TestRouteTableWellFormed(t *testing.T) {
	var s Server
	seen := map[string]bool{}
	for _, spec := range routeTable {
		if len(spec.path) == 0 || spec.path[0] != '/' {
			t.Errorf("route path %q is not absolute", spec.path)
		}
		key := spec.method + " " + spec.path
		if seen[key] {
			t.Errorf("duplicate route %q", key)
		}
		seen[key] = true
		if s.handlerFor(spec.kind) == nil {
			t.Errorf("route %q has unhandled kind %d", key, spec.kind)
		}
	}
	if len(routeTable) == 0 {
		t.Fatal("routeTable is empty")
	}
}

// TestEveryKindResolvable makes sure a new routeKind cannot be added without a
// matching case in handlerFor.
func TestEveryKindResolvable(t *testing.T) {
	var s Server
	for k := routeKind(0); k <= kindRoot; k++ {
		if s.handlerFor(k) == nil {
			t.Errorf("routeKind %d has no handler", k)
		}
	}
}

// TestOrderedBodies pins the key order of the multi-field success bodies, which
// must equal the legacy JSON.stringify insertion order.
func TestOrderedBodies(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    any
		want string
	}{
		{"okMessage", okMessageBody{OK: true, Message: "Session revoked"}, `{"ok":true,"message":"Session revoked"}`},
		{"okDevice", okDeviceBody{OK: true, DeviceName: "X"}, `{"ok":true,"deviceName":"X"}`},
		{"secret", secretBody{Secret: "S", OtpauthURI: "otpauth://x?a=1&b=2"}, `{"secret":"S","otpauthUri":"otpauth://x?a=1&b=2"}`},
	} {
		out, err := jsonx.Marshal(tc.v)
		if err != nil {
			t.Fatalf("%s: Marshal: %v", tc.name, err)
		}
		if string(out) != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, out, tc.want)
		}
	}
}

// TestRouteTableMethodVerbs sanity-checks a few well-known registrations so a
// future reshuffle cannot silently change the public surface.
func TestRouteTableMethodVerbs(t *testing.T) {
	want := map[string]string{
		"/api/login":                        http.MethodPost,
		"/api/verify":                       http.MethodGet,
		"/api/sessions/{id}":                http.MethodDelete,
		"/.well-known/openid-configuration": "",
	}
	got := map[string]string{}
	for _, spec := range routeTable {
		got[spec.path] = spec.method
	}
	for path, method := range want {
		if got[path] != method {
			t.Errorf("route %q method = %q, want %q", path, got[path], method)
		}
	}
}
