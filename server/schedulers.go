package main

import (
	"context"
	"log"
	"sync"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// startSchedulers starts every opt-in/default background scheduler exactly
// once for the process (#G12). Previously this whole block lived inside
// startHTTPServer, so a gRPC-only deployment (HTTP disabled) never ran ANY of
// these — most visibly, SetDynamicSweepEnabled(cfg.DynamicSecrets.SweepEnabled)
// (set unconditionally from static config in initializeCoreService) told the
// dynamic-secrets engine a sweeper was active when, for that deployment shape,
// no process actually ran one. Each job is already single-replica-gated via a
// Postgres advisory lock (ADR-039), so starting the loop in every process
// (regardless of which transport it serves) is the existing, intended
// coordination model — not a new behavior.
//
// The returned wait blocks until every scheduler goroutine started here has
// exited, which happens once ctx is cancelled and any in-flight tick returns.
// The server process never needs it (it exits); tests do, so a tick cannot
// outlive the test that started it and run against the next test's process
// state (log output, i18n, config) -- see startSchedulersForTest.
func startSchedulers(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) (wait func()) {
	var schedulers sync.WaitGroup
	ctx = withSchedulerTracking(ctx, &schedulers)

	for _, start := range schedulerStarts {
		start(ctx, cfg, coreService)
	}
	return schedulers.Wait
}

// schedulerStart starts one background job (see schedulerStarts in main.go).
type schedulerStart func(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore)

// legalHoldBlocks reports whether a deployment-wide legal hold (ISO A.5.34)
// should block a hard-delete purge job this tick. Fails SAFE: if the hold status
// can't be read it returns true (skip the purge), so records that may be under
// hold are never destroyed on a transient lookup error.
func legalHoldBlocks(ctx context.Context, coreService *core.KeyorixCore, job string) bool {
	active, err := coreService.IsLegalHoldActive(ctx)
	if err != nil {
		log.Printf("%s skipped: could not check legal-hold status: %v", job, err)
		return true
	}
	if active {
		log.Printf("%s skipped: a legal hold is active", job)
		return true
	}
	return false
}
