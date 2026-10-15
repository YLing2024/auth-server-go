package totp

import (
	"testing"
	"time"
)

// TestBase32RoundTrip checks the RFC 4648 codec the key files rely on.
func TestBase32RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		raw string
		enc string
	}{
		{"12345678901234567890", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
		{"f", "MY"},
		{"fo", "MZXQ"},
		{"foo", "MZXW6"},
		{"foob", "MZXW6YQ"},
		{"fooba", "MZXW6YTB"},
		{"foobar", "MZXW6YTBOI"},
	} {
		if got := Base32Encode([]byte(tc.raw)); got != tc.enc {
			t.Errorf("Base32Encode(%q) = %q, want %q", tc.raw, got, tc.enc)
		}
		back, err := Base32Decode(tc.enc)
		if err != nil {
			t.Errorf("Base32Decode(%q) error: %v", tc.enc, err)
			continue
		}
		if string(back) != tc.raw {
			t.Errorf("Base32Decode(%q) = %q, want %q", tc.enc, back, tc.raw)
		}
	}
}

// TestTOTPVectors pins the numeric output for the RFC 6238 test seed
// (HMAC-SHA1, 20-byte seed "12345678901234567890") at the RFC timestamps. The
// expected six-digit codes are the golden values produced by the legacy
// lib/totp-auth module for the same times, so this is a cross-implementation
// check, not a re-derivation of the algorithm under test.
func TestTOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		if got := generateWithKey(key, tc.unix); got != tc.want {
			t.Errorf("generateWithKey(%d) = %q, want %q", tc.unix, got, tc.want)
		}
	}
}

// TestVerifyWindow checks the ±1 step tolerance used on login.
func TestVerifyWindow(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Now().Unix()

	valid, err := Generate(secret, now)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !Verify(secret, valid, DefaultWindow) {
		t.Errorf("Verify(now code) = false, want true")
	}
	prev, _ := Generate(secret, now-Step)
	if !Verify(secret, prev, DefaultWindow) {
		t.Errorf("Verify(prev step) = false, want true")
	}
	next, _ := Generate(secret, now+Step)
	if !Verify(secret, next, DefaultWindow) {
		t.Errorf("Verify(next step) = false, want true")
	}
	// Two steps away is outside the window.
	far, _ := Generate(secret, now+2*Step)
	if Verify(secret, far, DefaultWindow) {
		t.Errorf("Verify(now+2 steps) = true, want false")
	}
	// Garbage input never verifies.
	if Verify(secret, "", DefaultWindow) || Verify(secret, "abcdef", DefaultWindow) {
		t.Errorf("Verify accepted an invalid candidate")
	}
}

// TestGenerateSecretShape checks the 160-bit / 32-char secret contract.
func TestGenerateSecretShape(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if len(s) != 32 {
		t.Errorf("secret length = %d, want 32", len(s))
	}
	if _, err := Base32Decode(s); err != nil {
		t.Errorf("generated secret is not valid base32: %v", err)
	}
}
