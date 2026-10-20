package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
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

	// deviceFpHeader carries FingerprintJS's visitorId; the confidence header
	// carries confidence.score from the same run.
	deviceFpHeader           = "X-Device-Fp"
	deviceFpConfidenceHeader = "X-Device-Fp-Conf"
	// deviceFpMinConfidence is the documented cutoff: low-confidence values are
	// ignored entirely rather than folded into the device key.
	deviceFpMinConfidence = 0.3
	// deviceFpMaxHeaderLen bounds attacker-supplied header parsing.
	deviceFpMaxHeaderLen = 64

	fpRotationWindow      = 5 * time.Minute
	fpRotationMaxDistinct = 3
	fpRotationLockSeconds = 900
	fpRotationMaxTracked  = 8
	fpRotationMaxEntries  = 4096
	fpRotationSweepEvery  = time.Minute
)

// deviceIdentity is the caller's device material for one request. The key is
// the in-memory limiter key; cookieID anchors fingerprint rotation detection;
// fingerprint is the accepted visitorId (empty when absent or untrusted).
type deviceIdentity struct {
	key         string
	cookieID    string
	fingerprint string
}

// DeviceIdentityFromRequest resolves the calling device and issues the device
// cookie when the request does not carry a valid one.
//
// The limiter key is sha256(cookie + User-Agent + Sec-CH-UA + Accept-Language
// + fingerprint). The fingerprint is only appended when it is 32 lowercase hex
// characters and its confidence score is at least 0.3; otherwise the key falls
// back to the legacy four-field hash.
//
// The key is only ever an in-memory limiter key: it is never persisted and
// callers may log at most its first eight characters. An empty key means the
// system random source failed; callers then keep the IP dimension only.
func DeviceIdentityFromRequest(w http.ResponseWriter, r *http.Request) deviceIdentity {
	id := ""
	if c, err := r.Cookie(deviceCookieName); err == nil && validDeviceID(c.Value) {
		id = c.Value
	}
	if id == "" {
		generated, err := newDeviceID()
		if err != nil {
			return deviceIdentity{}
		}
		id = generated
		w.Header().Add("Set-Cookie", deviceCookieHeader(id))
	}
	fp := fingerprintFromRequest(r)
	sum := sha256.Sum256([]byte(id + r.UserAgent() + r.Header.Get("Sec-Ch-Ua") + r.Header.Get("Accept-Language") + fp))
	return deviceIdentity{key: hex.EncodeToString(sum[:]), cookieID: id, fingerprint: fp}
}

// DeviceKeyFromRequest is the key-only view of DeviceIdentityFromRequest,
// retained for callers that do not need rotation detection.
func DeviceKeyFromRequest(w http.ResponseWriter, r *http.Request) string {
	return DeviceIdentityFromRequest(w, r).key
}

// fingerprintFromRequest returns the visitorId only when it is well formed and
// its confidence score clears the threshold. Anything else is ignored as a
// whole, so a missing or malformed confidence header cannot influence the key.
func fingerprintFromRequest(r *http.Request) string {
	raw := r.Header.Get(deviceFpHeader)
	if raw == "" || len(raw) > deviceFpMaxHeaderLen || !validDeviceID(raw) {
		return ""
	}
	conf, err := strconv.ParseFloat(strings.TrimSpace(r.Header.Get(deviceFpConfidenceHeader)), 64)
	if err != nil || math.IsNaN(conf) || conf < deviceFpMinConfidence || conf > 1 {
		return ""
	}
	return raw
}

// fingerprintRotator tracks how many distinct visitorIds one device cookie
// presents inside a sliding window. More than three distinct values in five
// minutes locks that cookie for fifteen minutes; the state is process-local,
// like the other limiters.
type fingerprintRotator struct {
	mu        sync.Mutex
	entries   map[string]*fpRotationEntry
	now       func() int64 // unix milliseconds
	lastSweep int64
}

type fpRotationEntry struct {
	seen        map[string]int64 // visitorId -> first seen (unix ms)
	lockedUntil int64            // unix ms
}

func newFingerprintRotator() *fingerprintRotator {
	return &fingerprintRotator{entries: make(map[string]*fpRotationEntry), now: func() int64 { return time.Now().UnixMilli() }}
}

// Status reports whether a cookie is currently locked by fingerprint rotation.
func (f *fingerprintRotator) Status(cookieID string) (bool, int) {
	if cookieID == "" {
		return false, 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	f.sweepLocked(now)
	e := f.entries[cookieID]
	if e == nil {
		return false, 0
	}
	f.pruneLocked(e, now)
	if e.lockedUntil > now {
		return true, retrySeconds(e.lockedUntil, now)
	}
	return false, 0
}

// Record adds a visitorId to the cookie's window and locks the cookie once it
// has seen more than three distinct values. Callers only invoke this on a
// failed login, so a correct code never poisons the set.
func (f *fingerprintRotator) Record(cookieID, visitorID string) (bool, int) {
	if cookieID == "" || visitorID == "" {
		return false, 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	f.sweepLocked(now)

	e := f.entries[cookieID]
	if e == nil {
		// Fail open under memory pressure: tracking is best-effort, the IP and
		// device dimensions still apply. This keeps hostile random cookies from
		// growing the map without bound.
		if len(f.entries) >= fpRotationMaxEntries {
			return false, 0
		}
		e = &fpRotationEntry{seen: make(map[string]int64)}
		f.entries[cookieID] = e
	}
	f.pruneLocked(e, now)
	if e.lockedUntil > now {
		return true, retrySeconds(e.lockedUntil, now)
	}
	if _, ok := e.seen[visitorID]; !ok && len(e.seen) < fpRotationMaxTracked {
		e.seen[visitorID] = now
	}
	if len(e.seen) > fpRotationMaxDistinct {
		e.lockedUntil = now + int64(fpRotationLockSeconds)*1000
		return true, fpRotationLockSeconds
	}
	return false, 0
}

// pruneLocked drops observations older than the window; lockedUntil is kept
// until the lock itself expires.
func (f *fingerprintRotator) pruneLocked(e *fpRotationEntry, now int64) {
	cutoff := now - fpRotationWindow.Milliseconds()
	for id, seen := range e.seen {
		if seen <= cutoff {
			delete(e.seen, id)
		}
	}
}

// sweepLocked reclaims entries that hold neither recent observations nor an
// active lock. It runs at most once per interval so the common path stays O(1).
func (f *fingerprintRotator) sweepLocked(now int64) {
	if now-f.lastSweep < fpRotationSweepEvery.Milliseconds() {
		return
	}
	f.lastSweep = now
	for key, e := range f.entries {
		f.pruneLocked(e, now)
		if len(e.seen) == 0 && e.lockedUntil <= now {
			delete(f.entries, key)
		}
	}
}

// retrySeconds rounds a remaining lock up to whole seconds.
func retrySeconds(until, now int64) int {
	return int((until - now + 999) / 1000)
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
// becoming unbounded limiter keys. The same shape is required of fingerprint
// headers, which FingerprintJS also renders as 32 lowercase hex characters.
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
