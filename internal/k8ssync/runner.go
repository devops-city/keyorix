package k8ssync

import (
	"context"
	"math/rand" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- non-crypto jitter for retry backoff (see nextDelay), not a security context
	"time"
)

// Logf is a minimal logging sink (satisfied by log.Printf). The agent never logs
// secret values — only counts, target identities, and error reasons.
type Logf func(format string, args ...any)

// Sync runs one reconcile pass and logs a one-line summary plus any per-target
// errors. Returns the Result for callers/tests.
func Sync(ctx context.Context, e *Engine, mappings []SecretMapping, logf Logf) Result {
	res, err := e.Reconcile(ctx, mappings)
	if err != nil {
		logf("k8s-sync: reconcile error: %v", err)
		return res
	}
	logf("k8s-sync: created=%d updated=%d unchanged=%d deleted=%d revoked=%d suspected=%d source_suspended=%d source_expired=%d source_expiring=%d auth_failed=%d keyorix_unreachable=%d failed=%d",
		res.Created, res.Updated, res.Unchanged, res.Deleted, res.Revoked, res.Suspected,
		res.SourceSuspended, res.SourceExpired, res.SourceExpiring, res.AuthFailed, res.KeyorixUnreachable, res.Failed)
	for _, n := range res.Notes {
		logf("k8s-sync: %s", n)
	}
	for _, e := range res.Errors {
		logf("k8s-sync: %s", e)
	}
	return res
}

// backoffCapMultiple bounds exponential growth after repeated unhealthy passes (K8S
// track backlog item 3b: "no retry storm — bounded backoff with jitter") at 8x the
// configured interval — e.g. a persistently revoked token still gets retried at a
// predictable, bounded cadence (40 minutes on the 5m default) rather than either
// hammering Keyorix at the healthy-state interval forever or backing off unboundedly
// until a human notices via /status or the revoked metric.
const backoffCapMultiple = 8

// jitterFraction randomizes the computed delay by up to +/-20%, so multiple replicas
// of this agent (or multiple agents pointed at the same Keyorix server) that all
// started failing around the same time — a shared Keyorix outage or a bulk credential
// rotation — don't all retry in lockstep once conditions clear.
const jitterFraction = 0.2

// nextDelay computes the delay before the next reconcile pass. consecutiveUnhealthy is
// the number of consecutive PRIOR passes that had any Failed or Revoked target (see
// Run) — 0 means the last pass was fully clean, so the next delay is just the
// configured interval, unchanged from today's fixed-ticker behavior. randFloat must
// return a value in [0, 1); production callers use math/rand, tests inject a
// deterministic stub.
func nextDelay(interval time.Duration, consecutiveUnhealthy int, randFloat func() float64) time.Duration {
	if consecutiveUnhealthy <= 0 || interval <= 0 {
		return interval
	}
	// 2, 4, 8, 16, ... (consecutiveUnhealthy=1 already doubles)
	multiple := min(int64(1)<<consecutiveUnhealthy, backoffCapMultiple)
	base := interval * time.Duration(multiple)
	// jitter in [1-jitterFraction, 1+jitterFraction]
	jitter := 1 + (randFloat()*2-1)*jitterFraction
	return time.Duration(float64(base) * jitter)
}

// Run reconciles once immediately, then repeatedly until ctx is cancelled. When status
// is non-nil, each pass's result is recorded for the health/readiness probes. The
// delay between passes is normally the configured interval; after a pass with any
// Failed or Revoked target it backs off exponentially (bounded, jittered — see
// nextDelay) and resets to the plain interval the moment a pass is fully clean again.
func Run(ctx context.Context, e *Engine, mappings []SecretMapping, interval time.Duration, logf Logf, status *Status) {
	run(ctx, e, mappings, interval, logf, status, rand.Float64)
}

// run is Run's testable core: randFloat is injected so backoff+jitter timing is
// deterministic in tests instead of depending on the real math/rand global source.
func run(ctx context.Context, e *Engine, mappings []SecretMapping, interval time.Duration, logf Logf, status *Status, randFloat func() float64) {
	consecutiveUnhealthy := 0
	sync := func() {
		res := Sync(ctx, e, mappings, logf)
		if status != nil {
			status.Record(res)
		}
		if res.Failed > 0 || res.Revoked > 0 || res.Suspected > 0 {
			consecutiveUnhealthy++
		} else {
			consecutiveUnhealthy = 0
		}
	}
	sync()
	for {
		delay := nextDelay(interval, consecutiveUnhealthy, randFloat)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
			sync()
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}
