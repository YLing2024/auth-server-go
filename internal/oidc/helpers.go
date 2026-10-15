package oidc

import (
	"encoding/base64"
	"strings"
	"time"
)

func seconds(n int) time.Duration { return time.Duration(n) * time.Second }

func firstNonZero(a, b int64) int64 {
	if a != 0 {
		return a
	}
	return b
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// BearerFromHeader extracts a Bearer token, returning "" when the scheme is
// absent or the token is empty.
func BearerFromHeader(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < 7 || !strings.EqualFold(header[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

// decodeBase64 accepts standard or URL-safe base64, with or without padding, so
// both RFC 6749 Basic credentials and lenient clients work.
func decodeBase64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
