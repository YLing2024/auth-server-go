package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auth-server-go/internal/totp"
)

// loginTestServer is a Server wired with real limiters and a throwaway TOTP
// secret, so login handlers can be exercised without Redis.
type loginTestServer struct {
	*Server
	logs *bytes.Buffer
}

func newLoginTestServer(t *testing.T) *loginTestServer {
	t.Helper()
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	store := totp.NewSecretStore(filepath.Join(t.TempDir(), "totp-secret.json"))
	if err := store.Save(secret); err != nil {
		t.Fatalf("save secret: %v", err)
	}
	var logs bytes.Buffer
	s := &Server{
		secrets:       store,
		logger:        slog.New(slog.NewTextHandler(&logs, nil)),
		appLimiter:    totp.NewRateLimiter(5, []int{60, 300, 900}),
		moduleLimiter: totp.NewRateLimiter(5, []int{60, 300, 900}),
		deviceLimiter: totp.NewRateLimiter(10, []int{300, 900, 3600}),
		globalLimiter: totp.NewGlobalCounter(60, 5*time.Minute),
	}
	return &loginTestServer{Server: s, logs: &logs}
}

// postLogin sends a wrong TOTP code with the given client IP and optional
// device cookie.
func (h *loginTestServer) postLogin(t *testing.T, ip, deviceID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"code":"000000"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "test-agent/1.0")
	if deviceID != "" {
		req.AddCookie(&http.Cookie{Name: deviceCookieName, Value: deviceID})
	}
	rec := httptest.NewRecorder()
	h.handleLogin(rec, req)
	return rec
}

// issuedDeviceID extracts the device cookie from a response.
func issuedDeviceID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == deviceCookieName {
			return c.Value
		}
	}
	t.Fatalf("response did not set %s", deviceCookieName)
	return ""
}

// decodeRateLimit parses the shared 429 payload.
func decodeRateLimit(t *testing.T, rec *httptest.ResponseRecorder) rateLimitBody {
	t.Helper()
	var body rateLimitBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("429 body %q: %v", rec.Body.String(), err)
	}
	return body
}

// TestDeviceKeyFromRequestIssuesCookie pins the __Host- cookie attributes and
// the documented hash formula.
func TestDeviceKeyFromRequestIssuesCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.Header.Set("Sec-CH-UA", `"Chromium";v="130"`)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	rec := httptest.NewRecorder()

	key := DeviceKeyFromRequest(rec, req)
	raw := rec.Header().Get("Set-Cookie")
	for _, attr := range []string{
		deviceCookieName + "=", "HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age=31536000",
	} {
		if !strings.Contains(raw, attr) {
			t.Errorf("Set-Cookie %q missing %q", raw, attr)
		}
	}
	if strings.Contains(raw, "Domain=") {
		t.Errorf("Set-Cookie must not carry Domain: %q", raw)
	}

	id := issuedDeviceID(t, rec)
	if !validDeviceID(id) {
		t.Fatalf("issued device id %q is not 128-bit lowercase hex", id)
	}
	want := sha256.Sum256([]byte(id + "test-agent/1.0" + `"Chromium";v="130"` + "zh-CN,zh;q=0.9"))
	if key != hex.EncodeToString(want[:]) {
		t.Fatalf("key = %q, want hash of cookie+UA+sec-ch-ua+Accept-Language", key)
	}

	// A request carrying the issued cookie reuses the same key and must not
	// receive another Set-Cookie.
	req2 := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req2.Header = req.Header.Clone()
	req2.AddCookie(&http.Cookie{Name: deviceCookieName, Value: id})
	rec2 := httptest.NewRecorder()
	if got := DeviceKeyFromRequest(rec2, req2); got != key {
		t.Fatalf("second key = %q, want %q", got, key)
	}
	if got := rec2.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("unexpected re-issue: %q", got)
	}
}

// TestDeviceKeyFromRequestVariesWithHeaders proves copying a cookie to another
// browser or locale does not keep the same device identity.
func TestDeviceKeyFromRequestVariesWithHeaders(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	base := map[string]string{
		"User-Agent":      "agent-a",
		"Sec-CH-UA":       `"Chromium";v="130"`,
		"Accept-Language": "zh-CN",
	}
	keyFor := func(headers map[string]string) string {
		req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.AddCookie(&http.Cookie{Name: deviceCookieName, Value: id})
		return DeviceKeyFromRequest(httptest.NewRecorder(), req)
	}

	baseKey := keyFor(base)
	for _, tc := range []struct {
		name   string
		header string
		value  string
	}{
		{"user-agent", "User-Agent", "agent-b"},
		{"sec-ch-ua", "Sec-CH-UA", `"Chromium";v="131"`},
		{"accept-language", "Accept-Language", "en-US"},
	} {
		changed := map[string]string{}
		for k, v := range base {
			changed[k] = v
		}
		changed[tc.header] = tc.value
		if got := keyFor(changed); got == baseKey {
			t.Errorf("%s change did not alter the device key", tc.name)
		}
	}
	if keyFor(map[string]string{"User-Agent": "agent-a"}) == baseKey {
		t.Error("missing headers must not hash the same as present headers")
	}
}

// TestDeviceKeyFromRequestReplacesInvalidCookie keeps attacker-shaped cookie
// values out of the limiter map.
func TestDeviceKeyFromRequestReplacesInvalidCookie(t *testing.T) {
	for _, bad := range []string{"", "not-hex", strings.Repeat("A", 32), strings.Repeat("a", 31)} {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.AddCookie(&http.Cookie{Name: deviceCookieName, Value: bad})
		rec := httptest.NewRecorder()
		DeviceKeyFromRequest(rec, req)
		id := issuedDeviceID(t, rec)
		if !validDeviceID(id) || id == bad {
			t.Errorf("cookie %q was not replaced with a valid id (got %q)", bad, id)
		}
	}
}

// TestServeLoginIndexIssuesDeviceCookie ensures /auth itself creates the cookie
// before a login attempt can fail, and marks that response uncacheable.
func TestServeLoginIndexIssuesDeviceCookie(t *testing.T) {
	s := &Server{index: []byte("<html>login</html>")}
	rec := httptest.NewRecorder()
	s.serveLoginIndex(rec, httptest.NewRequest(http.MethodGet, "/auth", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store when issuing a cookie", got)
	}
	_ = issuedDeviceID(t, rec)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.AddCookie(&http.Cookie{Name: deviceCookieName, Value: "0123456789abcdef0123456789abcdef"})
	rec = httptest.NewRecorder()
	s.serveLoginIndex(rec, req)
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=0" {
		t.Errorf("Cache-Control = %q, want the legacy value when the cookie exists", got)
	}
	if got := rec.Header().Get("Set-Cookie"); got != "" {
		t.Errorf("unexpected Set-Cookie: %q", got)
	}
}

// TestLoginIPDimensionLocksAcrossDevices keeps the legacy behaviour: five
// failures for one IP lock it even when every request uses a fresh cookie.
func TestLoginIPDimensionLocksAcrossDevices(t *testing.T) {
	h := newLoginTestServer(t)
	const ip = "203.0.113.5"
	for i := 0; i < 5; i++ {
		if rec := h.postLogin(t, ip, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, rec.Code)
		}
	}
	rec := h.postLogin(t, ip, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("sixth attempt status = %d, want 429", rec.Code)
	}
	body := decodeRateLimit(t, rec)
	if body.Code != "rate_limited" || body.Message != "Too many attempts" || body.RetryAfter <= 0 {
		t.Fatalf("429 body = %+v", body)
	}
}

// TestLoginDeviceDimensionLocksAcrossIPs is the IP-pool case: the device keeps
// failing from fresh addresses and is locked once its own threshold is hit.
func TestLoginDeviceDimensionLocksAcrossIPs(t *testing.T) {
	h := newLoginTestServer(t)
	first := h.postLogin(t, "198.51.100.1", "")
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first attempt status = %d", first.Code)
	}
	deviceID := issuedDeviceID(t, first)

	for i := 2; i <= 10; i++ {
		ip := "198.51.100." + itoaTest(i)
		if rec := h.postLogin(t, ip, deviceID); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i, rec.Code)
		}
	}
	rec := h.postLogin(t, "198.51.100.11", deviceID)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("eleventh attempt status = %d, want 429", rec.Code)
	}
	body := decodeRateLimit(t, rec)
	if body.RetryAfter < 299 || body.RetryAfter > 300 {
		t.Fatalf("device lock retryAfter = %d, want 300", body.RetryAfter)
	}
	// The payload must not name the dimension that fired.
	if strings.Contains(strings.ToLower(rec.Body.String()), "device") ||
		strings.Contains(strings.ToLower(rec.Body.String()), "ip") {
		t.Fatalf("429 body leaks the dimension: %s", rec.Body.String())
	}
}

// TestLoginRetryAfterUsesLongerLock proves the 429 wait is the maximum of the
// two dimensions when both are locked.
func TestLoginRetryAfterUsesLongerLock(t *testing.T) {
	h := newLoginTestServer(t)
	const lockedIP = "203.0.113.20"
	first := h.postLogin(t, lockedIP, "")
	deviceID := issuedDeviceID(t, first)
	for i := 0; i < 4; i++ {
		h.postLogin(t, lockedIP, deviceID)
	}
	// lockedIP now has 60s left; feed the device from fresh IPs until it locks.
	for i := 0; i < 5; i++ {
		h.postLogin(t, "10.0.0."+itoaTest(i+1), deviceID)
	}
	rec := h.postLogin(t, lockedIP, deviceID)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	body := decodeRateLimit(t, rec)
	if body.RetryAfter < 299 {
		t.Fatalf("retryAfter = %d, want the device lock (300) not the IP lock", body.RetryAfter)
	}
}

// TestLoginSuccessClearsBothDimensions checks a good login resets both failure
// counters, so the next mistake does not lock immediately.
func TestLoginSuccessClearsBothDimensions(t *testing.T) {
	h := newLoginTestServer(t)
	const ip = "203.0.113.30"
	const device = "device-key-for-clear"
	for i := 0; i < 4; i++ {
		h.recordLoginFailure(h.appLimiter, ip, device)
	}
	h.clearLoginFailures(h.appLimiter, ip, device)
	for name, st := range map[string]totp.Status{
		"ip":     h.appLimiter.Status(ip),
		"device": h.deviceLimiter.Status(device),
	} {
		if st.Locked || st.Failures != 0 || st.Tier != 0 {
			t.Errorf("%s after success = %+v, want clean", name, st)
		}
	}
	if locked, _ := h.loginLockStatus(h.appLimiter, ip, device); locked {
		t.Fatal("locked immediately after success")
	}
}

// TestCombineLockStatus covers the maximum-retry merge without relying on
// wall-clock ladders.
func TestCombineLockStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ip     totp.Status
		device totp.Status
		hasDev bool
		locked bool
		retry  int
	}{
		{"neither", totp.Status{}, totp.Status{}, true, false, 0},
		{"ip only", totp.Status{Locked: true, RetryAfter: 60}, totp.Status{}, true, true, 60},
		{"device only", totp.Status{}, totp.Status{Locked: true, RetryAfter: 300}, true, true, 300},
		{"ip longer", totp.Status{Locked: true, RetryAfter: 900}, totp.Status{Locked: true, RetryAfter: 300}, true, true, 900},
		{"device longer", totp.Status{Locked: true, RetryAfter: 60}, totp.Status{Locked: true, RetryAfter: 300}, true, true, 300},
		{"device ignored when absent", totp.Status{}, totp.Status{Locked: true, RetryAfter: 300}, false, false, 0},
	} {
		locked, retry := combineLockStatus(tc.ip, tc.device, tc.hasDev)
		if locked != tc.locked || retry != tc.retry {
			t.Errorf("%s = (%v, %d), want (%v, %d)", tc.name, locked, retry, tc.locked, tc.retry)
		}
	}
}

// TestGlobalAlertDoesNotBlock checks the global counter logs once and never
// feeds into the lock decision.
func TestGlobalAlertDoesNotBlock(t *testing.T) {
	h := newLoginTestServer(t)
	for i := 0; i < 60; i++ {
		h.recordLoginFailure(h.appLimiter, "192.0.2."+itoaTest(i), "device-"+itoaTest(i))
	}
	if got := strings.Count(h.logs.String(), "全局失败计数达到阈值"); got != 1 {
		t.Fatalf("global alert lines = %d, want 1\n%s", got, h.logs.String())
	}
	status := h.globalLimiter.Status()
	if status.WindowFailures != 60 || !status.Alerted || status.TotalFailures != 60 {
		t.Fatalf("global status = %+v", status)
	}
	if locked, _ := h.loginLockStatus(h.appLimiter, "192.0.2.200", "fresh-device"); locked {
		t.Fatal("global counter must not reject a fresh IP/device")
	}
}

// TestDeviceKeyLogsOnlyPrefix enforces the privacy rule: at most eight
// characters of a device key may appear in logs.
func TestDeviceKeyLogsOnlyPrefix(t *testing.T) {
	h := newLoginTestServer(t)
	deviceKey := strings.Repeat("ab", 32)
	for i := 0; i < 10; i++ {
		h.recordLoginFailure(h.appLimiter, "198.51.100."+itoaTest(i+1), deviceKey)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "device="+deviceKeyPrefix(deviceKey)) {
		t.Fatalf("device lock was not logged with its prefix:\n%s", logs)
	}
	if strings.Contains(logs, deviceKey) {
		t.Fatalf("full device key leaked into logs:\n%s", logs)
	}
}

// itoaTest avoids pulling strconv into test assertions.
func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
