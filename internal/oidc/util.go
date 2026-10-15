package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64urlDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// SHA256Hex is the hex SHA-256 used for every Redis key derived from a token.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// PKCEChallenge computes code_challenge = BASE64URL(SHA256(ASCII(verifier))).
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RandomToken returns an opaque token: n random bytes base64url (no padding).
// 32 bytes yields 43 characters, matching the legacy SSO/refresh tokens.
func RandomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not recoverable for security tokens.
		panic("oidc: crypto/rand 不可用: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// TimingEqual is a constant-time string comparison. Different lengths return
// false without padding, matching the legacy helper.
func TimingEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ParseCookies parses a Cookie header. Fragments without '=' are ignored.
func ParseCookies(header string) map[string]string {
	out := map[string]string{}
	if header == "" {
		return out
	}
	for _, part := range strings.Split(header, ";") {
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(part[:idx])
		v := strings.TrimSpace(part[idx+1:])
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// HTMLEscape escapes the five characters that matter for the HTML error pages.
func HTMLEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// EncodeURIComponent mirrors JavaScript's encodeURIComponent so redirect URLs
// round-trip identically through the login page's URLSearchParams parsing. Go's
// url.QueryEscape differs (space becomes '+' and different punctuation is
// escaped), which would corrupt the nested authorize URL.
func EncodeURIComponent(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		const hexDigits = "0123456789ABCDEF"
		sb.WriteByte(hexDigits[c>>4])
		sb.WriteByte(hexDigits[c&0x0f])
	}
	return sb.String()
}

// QueryStr returns a single query parameter value. A repeated parameter is
// treated as absent, matching the legacy `str()` helper that rejected arrays.
func QueryStr(values url.Values, key string) string {
	v := values[key]
	if len(v) != 1 {
		return ""
	}
	return v[0]
}

// FormStr is QueryStr for parsed form bodies (urlencoded).
func FormStr(values url.Values, key string) string {
	return QueryStr(values, key)
}

// Str returns a body value only when it is a single string.
func Str(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
