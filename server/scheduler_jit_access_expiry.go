package main

import (
	"context"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockJITExpiry is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockJITExpiry int64 = 0x4B455953_4A495445 // "KEYSJITE"

// startJITAccessExpiryScheduler starts the "jit_access_expiry" background job.
//
// Start the JIT access-expiry sweeper — opt-in. Removes time-bound role grants
// whose expiry has passed (auditing each as role.expired) and reclaims the rows.
// Expired grants already stop authorizing immediately (the auth queries filter
// on expiry); this just keeps the tables clean and writes the expiry audit trail.
func startJITAccessExpiryScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.JITAccessExpiry.Enabled {
		interval := cfg.JITAccessExpiry.GetInterval()
		log.Printf("JIT access-expiry sweeper enabled: every %s", interval)
		runScheduler(ctx, "jit_access_expiry", interval, func() middleware.SchedulerOutcome {
			// A legal hold preserves the grant rows (the auth queries still deny
			// expired grants immediately, so blocking the sweep loses no security).
			if legalHoldBlocks(ctx, coreService, "JIT access-expiry sweep") {
				return middleware.SchedulerSkipped
			}
			// Single-replica-gated (ADR-039): one replica sweeps per tick.
			return lockedRun(ctx, coreService.Storage(), schedLockJITExpiry, "JIT access-expiry", func(ctx context.Context) error {
				now := time.Now()
				n, rerr := coreService.RemoveExpiredRoleGrants(ctx, now)
				if rerr != nil {
					log.Printf("JIT access-expiry sweep error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("JIT access-expiry sweep removed %d expired grant(s)", n)
				}
				// The same sweep reclaims expired time-bound secret shares (both already
				// stop authorizing immediately; this keeps the tables clean + audited).
				// ShareEffectiveNow, not the bare `now` above: sources this sweep's cutoff
				// from the SAME watermarked clock every other share-active check in this
				// process already uses, instead of an independent real-wall-clock read
				// (#1983 investigation finding).
				sn, serr := coreService.RemoveExpiredShares(ctx, coreService.ShareEffectiveNow())
				if serr != nil {
					log.Printf("JIT access-expiry share-sweep error: %v", serr)
					return serr
				}
				if sn > 0 {
					log.Printf("JIT access-expiry sweep removed %d expired share(s)", sn)
				}
				return nil
			})
		})
	}
}
