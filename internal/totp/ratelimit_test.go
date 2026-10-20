package totp

import "testing"

// TestRateLimiterTierLadder walks the 60/300/900 ladder with a controllable
// clock and checks that each expire only resets the failure count, not the tier.
func TestRateLimiterTierLadder(t *testing.T) {
	now := int64(1_000_000_000_000)
	l := NewRateLimiter(5, nil)
	l.now = func() int64 { return now }

	const ip = "203.0.113.9"
	const other = "203.0.113.10"

	// Four failures are not enough to lock.
	for i := 0; i < 4; i++ {
		l.RecordFailure(ip)
	}
	if st := l.Status(ip); st.Locked {
		t.Fatalf("locked after 4 failures: %+v", st)
	}

	// Fifth failure locks for the first tier (60s).
	st := l.RecordFailure(ip)
	if !st.Locked || st.RetryAfter != 60 || st.Tier != 1 {
		t.Fatalf("first lock = %+v, want locked 60s tier 1", st)
	}

	// A different IP is untouched.
	if st := l.Status(other); st.Locked || st.Failures != 0 {
		t.Fatalf("isolation broken: other IP state = %+v", st)
	}

	// After the lock window passes, failures reset but the tier escalates.
	now += 60_000
	if st := l.Status(ip); st.Locked || st.Failures != 0 {
		t.Fatalf("after 60s = %+v, want unlocked", st)
	}
	for i := 0; i < 5; i++ {
		st = l.RecordFailure(ip)
	}
	if !st.Locked || st.RetryAfter != 300 || st.Tier != 2 {
		t.Fatalf("second lock = %+v, want 300s tier 2", st)
	}

	now += 300_000
	for i := 0; i < 5; i++ {
		st = l.RecordFailure(ip)
	}
	if !st.Locked || st.RetryAfter != 900 || st.Tier != 3 {
		t.Fatalf("third lock = %+v, want 900s tier 3", st)
	}

	// The ladder is capped at 900s.
	now += 900_000
	for i := 0; i < 5; i++ {
		st = l.RecordFailure(ip)
	}
	if !st.Locked || st.RetryAfter != 900 {
		t.Fatalf("capped lock = %+v, want 900s", st)
	}
}

// TestRateLimiterKeyedIsolation proves the limiter treats keys as opaque
// strings, which is what lets the same algorithm serve device keys.
func TestRateLimiterKeyedIsolation(t *testing.T) {
	now := int64(1_000_000_000_000)
	l := NewRateLimiter(10, []int{300, 900, 3600})
	l.now = func() int64 { return now }

	keyA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	keyB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for i := 0; i < 4; i++ {
		l.RecordFailure(keyA)
	}
	if st := l.Status(keyB); st.Failures != 0 || st.Locked || st.Tier != 0 {
		t.Fatalf("key isolation broken: B = %+v", st)
	}
	if st := l.Status(keyA); st.Failures != 4 {
		t.Fatalf("key A failures = %d, want 4", st.Failures)
	}
}

// TestRateLimiterDeviceLadder pins the device dimension's 300/900/3600 ladder.
func TestRateLimiterDeviceLadder(t *testing.T) {
	now := int64(1_000_000_000_000)
	l := NewRateLimiter(10, []int{300, 900, 3600})
	l.now = func() int64 { return now }

	const device = "device-key"
	for i := 0; i < 9; i++ {
		l.RecordFailure(device)
	}
	if st := l.Status(device); st.Locked {
		t.Fatalf("locked before 10 failures: %+v", st)
	}

	st := l.RecordFailure(device)
	if !st.Locked || st.RetryAfter != 300 || st.Tier != 1 {
		t.Fatalf("first device lock = %+v, want 300s tier 1", st)
	}

	now += 300_000
	for i := 0; i < 10; i++ {
		st = l.RecordFailure(device)
	}
	if !st.Locked || st.RetryAfter != 900 || st.Tier != 2 {
		t.Fatalf("second device lock = %+v, want 900s tier 2", st)
	}

	now += 900_000
	for i := 0; i < 10; i++ {
		st = l.RecordFailure(device)
	}
	if !st.Locked || st.RetryAfter != 3600 || st.Tier != 3 {
		t.Fatalf("third device lock = %+v, want 3600s tier 3", st)
	}

	// The ladder is capped at one hour.
	now += 3600_000
	for i := 0; i < 10; i++ {
		st = l.RecordFailure(device)
	}
	if !st.Locked || st.RetryAfter != 3600 {
		t.Fatalf("capped device lock = %+v, want 3600s", st)
	}
}

// TestRateLimiterSuccessClears checks that a good login wipes the record.
func TestRateLimiterSuccessClears(t *testing.T) {
	now := int64(1_000_000_000_000)
	l := NewRateLimiter(0, nil) // default 5 / 60-300-900
	l.now = func() int64 { return now }

	for i := 0; i < 5; i++ {
		l.RecordFailure("198.51.100.7")
	}
	if st := l.Status("198.51.100.7"); !st.Locked {
		t.Fatalf("expected lock, got %+v", st)
	}
	l.RecordSuccess("198.51.100.7")
	if st := l.Status("198.51.100.7"); st.Locked || st.Failures != 0 || st.Tier != 0 {
		t.Fatalf("after success = %+v, want clean", st)
	}
}
