package fuzzutil

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func withGuardTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := GuardTimeout
	GuardTimeout = d
	t.Cleanup(func() { GuardTimeout = prev })
}

func TestGuard_ReturnsWhenFnFinishes(t *testing.T) {
	withGuardTimeout(t, 5*time.Second)
	ran := 0
	for range 1000 {
		Guard(t.Fatalf, "fast", func() { ran++ })
	}
	if ran != 1000 {
		t.Fatalf("fn ran %d times, want 1000", ran)
	}
}

// A hang must still be reported, on the caller's goroutine, with the label, and
// a later call must still work (the hung runner is abandoned, not reused).
func TestGuard_ReportsHang(t *testing.T) {
	withGuardTimeout(t, 50*time.Millisecond)
	release := make(chan struct{})
	var got string
	start := time.Now()
	Guard(func(format string, args ...any) { got = fmt.Sprintf(format, args...) }, "hanger", func() { <-release })
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Guard took %s to report a 50ms hang", elapsed)
	}
	if !strings.Contains(got, "hanger") || !strings.Contains(got, "exceeded") {
		t.Fatalf("hang not reported, got %q", got)
	}
	close(release)

	ran := false
	Guard(t.Fatalf, "after-hang", func() { ran = true })
	if !ran {
		t.Fatal("Guard did not run fn after an earlier hang")
	}
}

// A runner whose fn finishes just inside the deadline must not leak a stale
// timer fire or done signal into the next call.
func TestGuard_ReuseAfterSlowButInTimeCall(t *testing.T) {
	withGuardTimeout(t, 2*time.Second)
	Guard(t.Fatalf, "slowish", func() { time.Sleep(20 * time.Millisecond) })
	calls := 0
	for range 100 {
		Guard(t.Fatalf, "next", func() { calls++ })
	}
	if calls != 100 {
		t.Fatalf("calls = %d, want 100", calls)
	}
}
