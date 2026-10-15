package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// writeJSON serializes v and writes status. Marshal failure degrades to a
// minimal server_error body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"server_error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// jsonString encodes a single string without HTML escaping, matching
// JavaScript's JSON.stringify output.
func jsonString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				const hexDigits = "0123456789abcdef"
				sb.WriteString(`\u00`)
				sb.WriteByte(hexDigits[(r>>4)&0xf])
				sb.WriteByte(hexDigits[r&0xf])
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// readJSONBody parses a request body as a JSON object. A malformed body is
// treated as empty, matching the lenient global parser in the legacy app; form
// bodies are additionally accepted because some legacy callers used them.
func readJSONBody(r *http.Request) map[string]any {
	if r.Body == nil {
		return map[string]any{}
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}
	}
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		out := map[string]any{}
		values, err := url.ParseQuery(string(raw))
		if err == nil {
			for k, v := range values {
				if len(v) == 1 {
					out[k] = v[0]
				}
			}
		}
		return out
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return map[string]any{}
	}
	return m
}

// bodyString returns a body field only when it is a single string.
func bodyString(body map[string]any, key string) string {
	v, ok := body[key].(string)
	if !ok {
		return ""
	}
	return v
}

// asciiHeaderValue strips non-printable/non-ASCII runes for the X-Auth-User
// header, matching the legacy guard against Node's ERR_INVALID_CHAR.
func asciiHeaderValue(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e {
			sb.WriteRune(r)
		}
	}
	out := strings.TrimSpace(sb.String())
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// truncateRunes keeps at most n runes; used for user-agent slices.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
