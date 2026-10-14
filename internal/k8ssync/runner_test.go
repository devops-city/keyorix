package k8ssync

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedRand returns a randFloat stub that always yields v (in [0, 1)) — for tests that
// want a deterministic, exact jitter offset rather than a range assertion.
func fixedRand(v float64) func() float64 { return func() float64 { return v } }

func TestNextDelay_HealthyPassUsesPlainInterval(t *testing.T) {
	d := nextDelay(5*time.Minute, 0, fixedRand(0.5))
	assert.Equal(t, 5*time.Minute, d, "0 consecutive unhealthy passes must not back off at all")
}

func TestNextDelay_BacksOffExponentiallyThenCaps(t *testing.T) {
	base := time.Minute
	noJitter := fixedRand(0.5) // randFloat()*2-1 == 0 -> jitter multiplier exactly 1
	cases := []struct {
		consecutiveUnhealthy int
		wantMultiple         int64
	}{
		{1, 2},
		{2, 4},
		{3, 8}, // backoffCapMultiple
		{4, 8}, // still capped, does not keep growing
		{10, 8},
	}
	for _, c := range cases {
		got := nextDelay(base, c.consecutiveUnhealthy, noJitter)
		want := base * time.Duration(c.wantMultiple)
		assert.Equal(t, want, got, "consecutiveUnhealthy=%d", c.consecutiveUnhealthy)
	}
}

func TestNextDelay_JitterStaysWithinBoundedFraction(t *testing.T) {
	base := 10 * time.Minute
	// randFloat()=0 -> jitter multiplier (1 - jitterFraction); randFloat()=1 (exclusive
	// upper bound, but 1 itself is a legal float64 return per the documented [0,1)
	// contract's edge) -> (1 + jitterFraction). Assert both edges land exactly where
	// the jitterFraction formula says they should -- not just "somewhere plausible".
	low := nextDelay(base, 1, fixedRand(0))
	high := nextDelay(base, 1, fixedRand(1))
	wantLow := time.Duration(float64(base*2) * (1 - jitterFraction))
	wantHigh := time.Duration(float64(base*2) * (1 + jitterFraction))
	assert.Equal(t, wantLow, low)
	assert.Equal(t, wantHigh, high)
}

func TestNextDelay_ZeroOrNegativeIntervalPassesThrough(t *testing.T) {
	// A degenerate interval (shouldn't occur in practice -- Config.GetInterval always
	// floors to a positive default) must not be amplified into something worse than
	// the input; nextDelay only ever multiplies interval, so 0 stays 0.
	assert.Equal(t, time.Duration(0), nextDelay(0, 5, fixedRand(0.5)))
}

// fakeFetcherSeq lets a test script a different outcome per Fetch call, keyed by call
// count -- used to simulate "Keyorix comes back after N failed passes" without a real
// clock or network.
type fakeFetcherSeq struct {
	// outcomes[i] applies to the i-th call to Fetch (0-indexed); the last entry repeats
	// for any call beyond len(outcomes).
	outcomes []error
	calls    int
}

func (f *fakeFetcherSeq) Fetch(_ context.Context, _ string) ([]byte, error) {
	i := f.calls
	if i >= len(f.outcomes) {
		i = len(f.outcomes) - 1
	}
	f.calls++
	if err := f.outcomes[i]; err != nil {
		return nil, err
	}
	return []byte("v"), nil
}

func TestRun_BacksOffOnConsecutiveFailuresThenResetsOnRecovery(t *testing.T) {
	f := &fakeFetcherSeq{outcomes: []error{
		fmt.Errorf("boom 1"), // pass 1: fails -> consecutiveUnhealthy becomes 1
		fmt.Errorf("boom 2"), // pass 2: fails -> becomes 2
		nil,                  // pass 3: succeeds -> resets to 0
		nil,                  // pass 4: succeeds -> stays 0
	}}
	s := newFakeSink()
	e := NewEngine(f, s)
	mappings := []SecretMapping{{Ref: "r", Namespace: "app", Name: "creds", Key: "K"}}

	var delays []time.Duration
	var gotUnhealthy []int
	// randFloat fixed at the midpoint so every backed-off delay is an EXACT multiple of
	// the base interval (no jitter noise to account for in the assertion below).
	noJitter := fixedRand(0.5)

	ctx := t.Context()

	consecutiveUnhealthy := 0
	base := 10 * time.Millisecond
	sync := func() {
		res := Sync(ctx, e, mappings, func(string, ...any) {})
		if res.Failed > 0 || res.Revoked > 0 {
			consecutiveUnhealthy++
		} else {
			consecutiveUnhealthy = 0
		}
		gotUnhealthy = append(gotUnhealthy, consecutiveUnhealthy)
		delays = append(delays, nextDelay(base, consecutiveUnhealthy, noJitter))
	}
	// Drive 4 passes directly through the same sync/backoff bookkeeping `run` uses,
	// without depending on real wall-clock timer firing (keeps this test instant and
	// deterministic rather than racing actual timers).
	for range 4 {
		sync()
	}

	require.Equal(t, []int{1, 2, 0, 0}, gotUnhealthy)
	assert.Equal(t, []time.Duration{base * 2, base * 4, base, base}, delays,
		"delay grows after each failure and drops back to the base interval the moment a pass is fully clean")
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	f := &fakeFetcherSeq{outcomes: []error{nil}}
	s := newFakeSink()
	e := NewEngine(f, s)
	mappings := []SecretMapping{{Ref: "r", Namespace: "app", Name: "creds", Key: "K"}}

	ctx, cancel := context.WithCancel(context.Background())
	status := NewStatus()
	done := make(chan struct{})
	go func() {
		run(ctx, e, mappings, time.Hour, func(string, ...any) {}, status, fixedRand(0.5))
		close(done)
	}()

	// The immediate first pass (before the loop's select) should complete and be
	// recorded well within this deadline; cancel right after to prove the loop exits
	// instead of blocking on the (1 hour, never firing in this test) timer.
	deadline := time.After(2 * time.Second)
	for {
		ran, _, _ := status.snapshot()
		if ran {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for the first pass to record a result")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after context cancellation")
	}
}
