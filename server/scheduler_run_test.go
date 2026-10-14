package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// TestRunScheduler_TickPanicIsRecovered pins #314's defense-in-depth half: a
// panic inside a scheduler job's tick function must never crash the process.
// Before this fix, runScheduler's goroutine had no recover() at all, so ANY
// panic (the now-fixed nil *APIError dereference, or any future bug) would
// take down the whole server — and would crash again on the next tick after
// restart if the underlying condition persisted, a repeated-crash DoS from
// ordinary operational noise.
func TestRunScheduler_TickPanicIsRecovered(t *testing.T) {
	var ticks atomic.Int32
	ctx := t.Context()

	runScheduler(ctx, "test-panicking-job", 10*time.Millisecond, func() middleware.SchedulerOutcome {
		n := ticks.Add(1)
		if n == 1 {
			panic("simulated tick panic")
		}
		return middleware.SchedulerSuccess
	})

	// The first tick (immediate, on startup) panics. If unrecovered, the whole
	// test binary would crash here rather than reaching this assertion. Wait for
	// a second tick (from the ticker) to prove the goroutine survived the panic
	// and kept running on schedule.
	deadline := time.Now().Add(2 * time.Second)
	for ticks.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ticks.Load() < 2 {
		t.Fatalf("scheduler goroutine did not survive the panic — got %d ticks, want >= 2", ticks.Load())
	}
}

// TestRunSchedulerAfter_DefersFirstTick: with a non-zero firstDelay nothing runs
// until the delay elapses (the anomaly sweep no longer fires at process start),
// and cancelling during the delay exits without ever ticking.
func TestRunSchedulerAfter_DefersFirstTick(t *testing.T) {
	t.Run("first tick waits for the delay", func(t *testing.T) {
		var ticks atomic.Int32
		ctx := t.Context()
		start := time.Now()
		var first atomic.Int64
		runSchedulerAfter(ctx, "test-delayed-first-tick", time.Hour, 150*time.Millisecond, func() middleware.SchedulerOutcome {
			if ticks.Add(1) == 1 {
				first.Store(int64(time.Since(start)))
			}
			return middleware.SchedulerSuccess
		})
		time.Sleep(50 * time.Millisecond)
		if n := ticks.Load(); n != 0 {
			t.Fatalf("tick ran %d time(s) before firstDelay elapsed", n)
		}
		deadline := time.Now().Add(5 * time.Second)
		for ticks.Load() < 1 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if ticks.Load() != 1 {
			t.Fatalf("want exactly one tick after the delay (interval is 1h), got %d", ticks.Load())
		}
		if got := time.Duration(first.Load()); got < 150*time.Millisecond {
			t.Fatalf("first tick after %s, want >= 150ms", got)
		}
	})
	t.Run("cancel during the delay never ticks", func(t *testing.T) {
		var ticks atomic.Int32
		ctx, cancel := context.WithCancel(context.Background())
		runSchedulerAfter(ctx, "test-delayed-cancel", 10*time.Millisecond, 100*time.Millisecond, func() middleware.SchedulerOutcome {
			ticks.Add(1)
			return middleware.SchedulerSuccess
		})
		cancel()
		time.Sleep(250 * time.Millisecond)
		if n := ticks.Load(); n != 0 {
			t.Fatalf("scheduler ticked %d time(s) after being cancelled during its first delay", n)
		}
	})
}

func TestAnomalyFirstPassDelay_Bounds(t *testing.T) {
	maxRand := func(n time.Duration) time.Duration { return n - 1 }
	zeroRand := func(time.Duration) time.Duration { return 0 }
	cases := []struct {
		interval time.Duration
		randN    func(time.Duration) time.Duration
		want     time.Duration
	}{
		{time.Hour, zeroRand, anomalyFirstPassBaseDelay},
		{time.Hour, maxRand, anomalyFirstPassBaseDelay + anomalyFirstPassMaxJitter - 1},
		{time.Minute, maxRand, anomalyFirstPassBaseDelay + time.Minute - 1}, // jitter clamped below the interval
		{0, maxRand, anomalyFirstPassBaseDelay},
	}
	for _, c := range cases {
		if got := anomalyFirstPassDelay(c.interval, c.randN); got != c.want {
			t.Errorf("anomalyFirstPassDelay(%s) = %s, want %s", c.interval, got, c.want)
		}
	}
	for range 1000 {
		d := anomalyFirstPassDelay(time.Hour, defaultRandN)
		if d < anomalyFirstPassBaseDelay || d >= anomalyFirstPassBaseDelay+anomalyFirstPassMaxJitter {
			t.Fatalf("delay %s outside [base, base+jitter)", d)
		}
	}
}
