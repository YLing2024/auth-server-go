package jsonx

import "testing"

// TestMarshalNoHTMLEscape proves the value is not HTML-escaped, matching
// JSON.stringify. Go's encoding/json would otherwise emit \u003c / \u0026.
func TestMarshalNoHTMLEscape(t *testing.T) {
	out, err := Marshal(map[string]string{"u": "a&b<c>d"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got, want := string(out), `{"u":"a&b<c>d"}`; got != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
}

// TestMarshalStructFieldOrder proves struct field order is preserved, which the
// ordered response bodies depend on to match the legacy key order.
func TestMarshalStructFieldOrder(t *testing.T) {
	type body struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	out, err := Marshal(body{OK: true, Message: "Session revoked"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got, want := string(out), `{"ok":true,"message":"Session revoked"}`; got != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
}

// TestMarshalIndentShape checks the 2-space on-disk format used by the key files.
func TestMarshalIndentShape(t *testing.T) {
	out, err := MarshalIndent(map[string]string{"secret": "A&B"}, 2)
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	want := "{\n  \"secret\": \"A&B\"\n}"
	if string(out) != want {
		t.Errorf("MarshalIndent = %q, want %q", out, want)
	}
}
