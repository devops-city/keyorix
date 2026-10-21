package main

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockRotationRmdr is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockRotationRmdr int64 = 0x4B455953_524F5452 // "KEYSROTR"

// startRotationReminderScheduler starts the "rotation_reminder" background job.
//
// Start the rotation-reminder scheduler — opt-in. Notifies project admins of
// secrets overdue/approaching their rotation deadline (proactive rotation
// hygiene; a NIS2/ISO control). Single-replica-gated (ADR-039) so admins aren't
// notified N times in an HA deployment.
func startRotationReminderScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.RotationReminders.Enabled {
		interval := cfg.RotationReminders.GetInterval()
		log.Printf("Rotation-reminder scheduler enabled: every %s", interval)
		runScheduler(ctx, "rotation_reminder", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockRotationRmdr, "Rotation-reminder", func(ctx context.Context) error {
				n, rerr := coreService.SendRotationReminders(ctx)
				if rerr != nil {
					log.Printf("Rotation-reminder error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Rotation reminders: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}
}
