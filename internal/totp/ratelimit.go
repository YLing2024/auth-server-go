package totp

import "sync"

// RateLimiter is an in-memory, per-key tiered lockout limiter. Keys are opaque
// strings, so the same algorithm serves both the client-IP dimension and the
// device dimension. Each round of MaxFailures consecutive failures raises the
// lockout tier. A successful login clears the record. Tiers default to
// 60/300/900 seconds.
type RateLimiter struct {
	mu          sync.Mutex
	maxFailures int
	lockout     []int
	entries     map[string]*entry
	now         func() int64
}

type entry struct {
	failures  int
	tier      int
	lockUntil int64 // unix milliseconds
}

// NewRateLimiter builds a limiter. A nil or empty lockout falls back to the
// legacy 60/300/900 ladder; maxFailures <= 0 becomes 5.
func NewRateLimiter(maxFailures int, lockout []int) *RateLimiter {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if len(lockout) == 0 {
		lockout = []int{60, 300, 900}
	}
	return &RateLimiter{
		maxFailures: maxFailures,
		lockout:     append([]int(nil), lockout...),
		entries:     make(map[string]*entry),
		now:         defaultNowMillis,
	}
}

// Status reports the current lock state for a key.
type Status struct {
	Locked     bool
	RetryAfter int
	Failures   int
	Tier       int
}

func (l *RateLimiter) get(key string) *entry {
	e := l.entries[key]
	if e == nil {
		e = &entry{}
		l.entries[key] = e
	}
	if e.lockUntil != 0 && e.lockUntil <= l.now() {
		e.lockUntil = 0
		e.failures = 0
	}
	return e
}

// Status returns the lock state without mutating counters beyond expiry reset.
func (l *RateLimiter) Status(key string) Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.get(key)
	locked := e.lockUntil > l.now()
	retry := 0
	if locked {
		retry = int((e.lockUntil - l.now() + 999) / 1000)
		if retry < 0 {
			retry = 0
		}
	}
	return Status{Locked: locked, RetryAfter: retry, Failures: e.failures, Tier: e.tier}
}

// RecordFailure increments the failure count for key, escalating the tier when
// the threshold is crossed.
func (l *RateLimiter) RecordFailure(key string) Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.get(key)
	e.failures++
	if e.failures >= l.maxFailures {
		tier := e.tier
		if tier > len(l.lockout)-1 {
			tier = len(l.lockout) - 1
		}
		if tier < 0 {
			tier = 0
		}
		e.lockUntil = l.now() + int64(l.lockout[tier])*1000
		e.failures = 0
		if e.tier < len(l.lockout) {
			e.tier++
		}
	}
	locked := e.lockUntil > l.now()
	retry := 0
	if locked {
		retry = int((e.lockUntil - l.now() + 999) / 1000)
	}
	return Status{Locked: locked, RetryAfter: retry, Failures: e.failures, Tier: e.tier}
}

// RecordSuccess clears the record for a key.
func (l *RateLimiter) RecordSuccess(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}
