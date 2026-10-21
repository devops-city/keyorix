package main

import (
	"context"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockPurge is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockPurge int64 = 0x4B455953_50555247 // "KEYSPURG"

// startRetentionPurgeScheduler starts the "retention_purge" background job.
//
// Start the retention purge scheduler (ADR-032) — opt-in. Hard-deletes
// soft-deleted users/projects/environments older than the retention window.
func startRetentionPurgeScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.Purge.Enabled {
		retentionDays := cfg.SoftDelete.GetRetentionDays()
		interval := cfg.Purge.GetInterval()
		log.Printf("Retention purge scheduler enabled: every %s, %d-day retention", interval, retentionDays)
		runScheduler(ctx, "retention_purge", interval, func() middleware.SchedulerOutcome {
			if legalHoldBlocks(ctx, coreService, "Retention purge") {
				return middleware.SchedulerSkipped
			}
			// Single-replica-gated (ADR-039): only one replica runs the purge.
			return lockedRun(ctx, coreService.Storage(), schedLockPurge, "Retention purge", func(ctx context.Context) error {
				// UTC so the cutoff is exactly the inverse of models.PurgeAtFor
				// (deleted_at + N days in UTC): a local zone with DST would let a
				// legacy (un-stamped) secret go an hour before its displayed purge date.
				cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
				res, err := coreService.PurgeExpiredSoftDeletes(ctx, cutoff)
				if err != nil {
					log.Printf("Retention purge error: %v", err)
					return err
				}
				if res.Total() > 0 {
					log.Printf("Retention purge removed %d soft-deleted records (users=%d, projects=%d, environments=%d, secrets=%d)",
						res.Total(), res.Users, res.Projects, res.Environments, res.Secrets)
				}
				return nil
			})
		})
	}
}
