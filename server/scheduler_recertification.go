package main

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockRecertify is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockRecertify int64 = 0x4B455953_52454354 // "KEYSRECT"

// startRecertificationScheduler starts the "recertification" background job.
//
// Start the scheduled access-recertification scheduler (ISO 27001 A.5.18) —
// opt-in. Finds projects overdue for review and either auto-opens a recert
// campaign (when auto_open) or reminds the project's admins to; also nudges
// admins of in-flight campaigns with pending items. A create/notify, not a
// delete, so NOT legal-hold-gated. Single-replica-gated (ADR-039) so a campaign
// is opened once per project per tick in HA.
func startRecertificationScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.Recertification.Enabled {
		interval := cfg.Recertification.GetInterval()
		cadence := cfg.Recertification.CadenceDays
		autoOpen := cfg.Recertification.AutoOpen
		log.Printf("Recertification scheduler enabled: every %s (cadence %dd, auto_open=%t)", interval, cadence, autoOpen)
		runScheduler(ctx, "recertification", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockRecertify, "Recertification", func(ctx context.Context) error {
				res, rerr := coreService.RunScheduledRecertification(ctx, cadence, autoOpen)
				if rerr != nil {
					log.Printf("Recertification error: %v", rerr)
					return rerr
				}
				if res.Opened > 0 || res.Reminded > 0 {
					log.Printf("Recertification: opened %d campaign(s), sent %d reminder(s)", res.Opened, res.Reminded)
				}
				return nil
			})
		})
	}
}
