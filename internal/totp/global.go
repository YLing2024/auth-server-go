package totp

import (
	"sync"
	"time"
)

// defaultGlobalWindow is the observation window for the global failure counter.
const defaultGlobalWindow = 5 * time.Minute

// GlobalCounter counts failed logins across every client inside a fixed
// window and raises at most one alert per window. It is intentionally not a
// RateLimiter: a wide-net attack must never be able to lock legitimate users
// out, so callers only log the alert and keep serving requests.
type GlobalCounter struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	start     time.Time
	failures  int
	total     uint64
	alerted   bool
	now       func() time.Time
}

// GlobalStatus is a snapshot of the counter, suitable for diagnostics.
type GlobalStatus struct {
	WindowFailures int
	TotalFailures  uint64
	Threshold      int
	Alerted        bool
}

// GlobalAlert describes the moment a window first crosses its threshold.
type GlobalAlert struct {
	WindowFailures int
	Threshold      int
	TotalFailures  uint64
}

// NewGlobalCounter builds a counter. A non-positive threshold falls back to 60;
// a non-positive window falls back to five minutes.
func NewGlobalCounter(threshold int, window time.Duration) *GlobalCounter {
	if threshold <= 0 {
		threshold = 60
	}
	if window <= 0 {
		window = defaultGlobalWindow
	}
	return &GlobalCounter{
		threshold: threshold,
		window:    window,
		now:       time.Now,
	}
}

// rollLocked starts a fresh window when the current one has elapsed. The
// caller must hold g.mu.
func (g *GlobalCounter) rollLocked(now time.Time) {
	if g.start.IsZero() || now.Sub(g.start) >= g.window {
		g.start = now
		g.failures = 0
		g.alerted = false
	}
}

// RecordFailure counts one failed login and reports whether this call crossed
// the window threshold. The alert is emitted once per window, so a sustained
// flood produces one log line rather than one per request.
func (g *GlobalCounter) RecordFailure() (GlobalAlert, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rollLocked(g.now())
	g.failures++
	g.total++
	if g.alerted || g.failures < g.threshold {
		return GlobalAlert{}, false
	}
	g.alerted = true
	return GlobalAlert{
		WindowFailures: g.failures,
		Threshold:      g.threshold,
		TotalFailures:  g.total,
	}, true
}

// Status returns the current window and lifetime counts without changing them.
func (g *GlobalCounter) Status() GlobalStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rollLocked(g.now())
	return GlobalStatus{
		WindowFailures: g.failures,
		TotalFailures:  g.total,
		Threshold:      g.threshold,
		Alerted:        g.alerted,
	}
}
