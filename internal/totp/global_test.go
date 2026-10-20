package totp

import "testing"

// TestGlobalCounterAlertsOncePerWindow checks the global counter is an alerting
// device only: it crosses once per five-minute window and keeps a lifetime
// total for diagnostics.
func TestGlobalCounterAlertsOncePerWindow(t *testing.T) {
	now := int64(1_000_000_000_000)
	g := NewGlobalCounter(60, defaultGlobalWindow)
	g.now = func() int64 { return now }

	for i := 0; i < 59; i++ {
		if _, alerted := g.RecordFailure(); alerted {
			t.Fatalf("alerted early at failure %d", i+1)
		}
	}
	if st := g.Status(); st.WindowFailures != 59 || st.Alerted {
		t.Fatalf("status before threshold = %+v", st)
	}

	alert, ok := g.RecordFailure()
	if !ok {
		t.Fatal("no alert at threshold")
	}
	if alert.WindowFailures != 60 || alert.Threshold != 60 || alert.TotalFailures != 60 {
		t.Fatalf("alert = %+v", alert)
	}
	// Further failures in the same window must not repeat the alert.
	for i := 0; i < 10; i++ {
		if _, alerted := g.RecordFailure(); alerted {
			t.Fatalf("alert repeated at extra failure %d", i+1)
		}
	}
	if st := g.Status(); st.WindowFailures != 70 || st.TotalFailures != 70 || !st.Alerted {
		t.Fatalf("status after extra failures = %+v", st)
	}

	// A new window starts clean but the lifetime total keeps growing.
	now += defaultGlobalWindow
	if st := g.Status(); st.WindowFailures != 0 || st.Alerted || st.TotalFailures != 70 {
		t.Fatalf("new window status = %+v", st)
	}
	for i := 0; i < 60; i++ {
		_, _ = g.RecordFailure()
	}
	if st := g.Status(); !st.Alerted || st.TotalFailures != 130 {
		t.Fatalf("second window status = %+v", st)
	}
}

// TestGlobalCounterDefaults makes sure a zero configuration still yields the
// documented 60-per-five-minutes behaviour.
func TestGlobalCounterDefaults(t *testing.T) {
	g := NewGlobalCounter(0, 0)
	if g.threshold != 60 || g.window != defaultGlobalWindow {
		t.Fatalf("defaults = threshold %d window %d", g.threshold, g.window)
	}
}
