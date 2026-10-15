// Package jsonx wraps encoding/json with the exact escaping behaviour of
// JavaScript's JSON.stringify.
//
// The legacy server is a Node/Express app, so every JSON body it emits, every
// Redis record it persists and every JWT segment it signs is produced by
// JSON.stringify, which does NOT escape `<`, `>` or `&`. Go's encoding/json
// escapes those by default (HTML escaping), which would change stored bytes and
// HTTP response bodies for values such as otpauth URIs and display names. The
// helpers here disable that escaping so the two implementations stay
// byte-compatible, which is a hard requirement of the rewrite.
package jsonx

import (
	"bytes"
	"encoding/json"
)

// Marshal encodes v like JSON.stringify(v): no HTML escaping and no trailing
// newline.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// MarshalIndent encodes v like JSON.stringify(v, null, indent) for the given
// number of spaces: no HTML escaping. It is used for the on-disk key files.
func MarshalIndent(v any, indent int) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", spaces(indent))
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func spaces(n int) string {
	if n < 0 {
		n = 0
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}
