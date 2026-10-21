package main

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockDynamicSweep is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockDynamicSweep int64 = 0x4B455953_44594E53 // "KEYSDYNS"

// startDynamicSecretSweepScheduler starts the "dynamic_secret_sweep" background job.
//
// Start the dynamic-secrets auto-revoke sweeper (ADR-035) — opt-in. Revokes
// every active lease past its expiry so credentials don't outlive their TTL.
func startDynamicSecretSweepScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.DynamicSecrets.SweepEnabled {
		interval := cfg.DynamicSecrets.GetSweepInterval()
		log.Printf("Dynamic-secrets auto-revoke sweeper enabled: every %s", interval)
		runScheduler(ctx, "dynamic_secret_sweep", interval, func() middleware.SchedulerOutcome {
			// Single-replica-gated (ADR-039): one replica revokes per tick, so
			// replicas don't storm the target DBs revoking the same leases.
			return lockedRun(ctx, coreService.Storage(), schedLockDynamicSweep, "Dynamic-secrets sweep", func(ctx context.Context) error {
				// EffectiveNow, not a bare time.Now(): sources this sweep's cutoff from
				// this process's injected/testable clock (#1983 investigation finding).
				n, rerr := coreService.RevokeExpiredLeases(ctx, coreService.EffectiveNow())
				if rerr != nil {
					log.Printf("Dynamic-secrets sweep error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Dynamic-secrets sweep revoked %d expired lease(s)", n)
				}
				return nil
			})
		})
	}
}
