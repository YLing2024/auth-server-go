package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
)

const (
	// deviceCookieName is the device identity cookie. The __Host- prefix makes
	// browsers require Secure, Path=/ and no Domain, which blocks sibling
	// subdomains from overwriting it.
	deviceCookieName = "__Host-ha_device"
	// deviceCookieMaxAge keeps the identity for one year.
	deviceCookieMaxAge = 31536000
	// deviceIDBytes is the entropy of a freshly issued device id (128 bits).
	deviceIDBytes = 16
)

// DeviceKeyFromRequest returns the rate-limit key for the calling device and
// issues the device cookie when the request does not carry a valid one. The key
// is sha256(cookie + User-Agent + Sec-CH-UA + Accept-Language), so copying the
// cookie to another browser or HTTP client still yields a different device.
//
// The key is only ever an in-memory limiter key: it is never persisted and
// callers may log at most its first eight characters. An empty key means the
// system random source failed; callers then keep the IP dimension only.
func DeviceKeyFromRequest(w http.ResponseWriter, r *http.Request) string {
	id := ""
	if c, err := r.Cookie(deviceCookieName); err == nil && validDeviceID(c.Value) {
		id = c.Value
	}
	if id == "" {
		generated, err := newDeviceID()
		if err != nil {
			return ""
		}
		id = generated
		w.Header().Add("Set-Cookie", deviceCookieHeader(id))
	}
	sum := sha256.Sum256([]byte(id + r.UserAgent() + r.Header.Get("Sec-Ch-Ua") + r.Header.Get("Accept-Language")))
	return hex.EncodeToString(sum[:])
}

// hasValidDeviceCookie reports whether the request already carries a usable
// device id, letting /auth avoid caching a response that sets one.
func hasValidDeviceCookie(r *http.Request) bool {
	c, err := r.Cookie(deviceCookieName)
	return err == nil && validDeviceID(c.Value)
}

// deviceCookieHeader renders the Set-Cookie value. Secure is unconditional
// because a __Host- cookie without it is rejected by browsers.
func deviceCookieHeader(id string) string {
	return deviceCookieName + "=" + id +
		"; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" + strconv.Itoa(deviceCookieMaxAge)
}

// validDeviceID accepts exactly the 32 lowercase hex characters this server
// issues. Rejecting other shapes keeps attacker-supplied cookie values from
// becoming unbounded limiter keys.
func validDeviceID(v string) bool {
	if len(v) != deviceIDBytes*2 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// newDeviceID returns a 128-bit random identifier as 32 lowercase hex chars.
func newDeviceID() (string, error) {
	buf := make([]byte, deviceIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// deviceKeyPrefix is the only device identity material allowed in logs.
func deviceKeyPrefix(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}
