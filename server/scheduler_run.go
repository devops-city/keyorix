// scheduler_run.go — shared driver for the background schedulers.
//
// Every periodic job in startHTTPServer has the same skeleton: run once on startup,
// then on a ticker until the context is cancelled, with the work guarded by the
// single-writer advisory lock (ADR-039). runScheduler owns that skeleton and times
// each tick into Prometheus (see server/middleware/scheduler_metrics.go); lockedRun
// runs the work under the lock and maps the result to a metric outcome. The per-job
// closures keep only their own logic — guards, lock key, and log lines unchanged.
package main

import (
	"context"
	"crypto/rand"
	"log"
	"math/big"
	"sync"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedulerTrackingKey carries the *sync.WaitGroup that startSchedulers waits on.
type schedulerTrackingKey struct{}

// withSchedulerTracking returns ctx carrying wg: every scheduler goroutine that
// runSchedulerAfter starts under the returned context is counted in wg until it
// exits.
func withSchedulerTracking(ctx context.Context, wg *sync.WaitGroup) context.Context {
	return context.WithValue(ctx, schedulerTrackingKey{}, wg)
}

// runScheduler starts a named scheduler goroutine: it runs tick once immediately, then
// every interval until ctx is cancelled. Each tick's outcome and (when it actually
// ran) its duration are recorded to Prometheus under name.
func runScheduler(ctx context.Context, name string, interval time.Duration, tick func() middleware.SchedulerOutcome) {
	runSchedulerAfter(ctx, name, interval, 0, tick)
}

// runSchedulerAfter is runScheduler with the first tick deferred by firstDelay (0 =
// immediately, runScheduler's behaviour); later ticks follow every interval after
// that first one. Cancelling ctx during the delay exits without ever ticking.
func runSchedulerAfter(ctx context.Context, name string, interval, firstDelay time.Duration, tick func() middleware.SchedulerOutcome) {
	middleware.RegisterScheduler(name)
	tracked, _ := ctx.Value(schedulerTrackingKey{}).(*sync.WaitGroup)
	if tracked != nil {
		tracked.Add(1)
	}
	go func() {
		if tracked != nil {
			defer tracked.Done()
		}
		if firstDelay > 0 {
			timer := time.NewTimer(firstDelay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return
			}
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		run := func() {
			start := time.Now()
			// #314: a scheduler job must never be able to take down the whole
			// process. This goroutine previously had no recover() at all — any
			// panic inside tick() (e.g. the remote-storage client's now-fixed nil
			// *APIError dereference, or a future bug) would crash the entire
			// server, and would crash again on the next tick after restart if the
			// underlying condition (a degraded upstream, ordinary operational
			// noise like an LB/WAF/CDN interstitial) persisted — a repeated-crash
			// DoS from conditions far short of a deliberate attack. Every other
			// job on this same ticker keeps running regardless of one job's panic.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("scheduler %q: recovered from panic: %v", name, r)
					middleware.RecordSchedulerRun(name, middleware.SchedulerFailure, time.Since(start))
				}
			}()
			outcome := tick()
			middleware.RecordSchedulerRun(name, outcome, time.Since(start))
		}
		run() // run once on startup (after firstDelay, if any)
		for {
			select {
			case <-ticker.C:
				run()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// lockedRun executes fn under scheduler advisory lock key and maps the result to a
// metric outcome: skipped when another replica holds the lock (a follower, by design),
// failure when fn errors or the lock cannot be acquired (logged via errLabel), success
// otherwise. The error log line mirrors the pre-refactor per-job wording.
func lockedRun(ctx context.Context, storage corestorage.Storage, key int64, errLabel string, fn func() error) middleware.SchedulerOutcome {
	ran, err := storage.WithSchedulerLock(ctx, key, fn)
	if err != nil {
		log.Printf("%s scheduler error: %v", errLabel, err)
		return middleware.SchedulerFailure
	}
	if !ran {
		return middleware.SchedulerSkipped
	}
	return middleware.SchedulerSuccess
}

// anomalyFirstPassBaseDelay and anomalyFirstPassMaxJitter bound when the first
// anomaly-detection pass runs after process start (C-PERF-FIXES, Detected-by: PERF-2):
// base + uniform[0, jitter), with the jitter clamped below the pass interval. The pass
// used to run the instant the process started — a full sweep competing with startup
// and first traffic, and, with every replica of a rolling restart doing the same,
// repeated back to back. Deferring it drops no detection: the pass's scan window
// extends back to the persisted high-water mark of the last successful pass
// (core.AnomalyDetector.RunDetection), so the delay leaves no unexamined gap.
const (
	anomalyFirstPassBaseDelay = time.Minute
	anomalyFirstPassMaxJitter = 4 * time.Minute
)

// anomalyFirstPassDelay returns the jittered delay before the first anomaly pass.
// randN is rand.N in production; tests pass a deterministic stand-in.
func anomalyFirstPassDelay(interval time.Duration, randN func(time.Duration) time.Duration) time.Duration {
	jitter := min(interval, anomalyFirstPassMaxJitter)
	if jitter <= 0 {
		return anomalyFirstPassBaseDelay
	}
	return anomalyFirstPassBaseDelay + randN(jitter)
}

// defaultRandN is the production randN for anomalyFirstPassDelay. Scheduling jitter,
// not a security value (crypto/rand keeps scanners quiet).
func defaultRandN(n time.Duration) time.Duration {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return time.Duration(v.Int64())
}
