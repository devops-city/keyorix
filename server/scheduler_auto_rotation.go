package main

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockAutoRotate is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockAutoRotate int64 = 0x4B455953_4155544F // "KEYSAUTO"

// startAutoRotationScheduler starts the "auto_rotation" background job.
//
// Start the automated-rotation scheduler — opt-in (ADR-046). Rotates auto-rotate-
// enabled secrets that are overdue under an active policy, regenerating their value.
// Single-replica-gated (ADR-039) so a secret rotates once per tick in an HA
// deployment.
func startAutoRotationScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.AutoRotation.Enabled {
		interval := cfg.AutoRotation.GetInterval()
		log.Printf("Auto-rotation scheduler enabled: every %s", interval)
		runScheduler(ctx, "auto_rotation", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockAutoRotate, "Auto-rotation", func(ctx context.Context) error {
				n, rerr := coreService.RunAutoRotation(ctx)
				if rerr != nil {
					log.Printf("Auto-rotation error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Auto-rotation: rotated %d secret(s)", n)
				}
				return nil
			})
		})
	}
}
