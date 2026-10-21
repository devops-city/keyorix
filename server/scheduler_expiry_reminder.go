package main

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockExpiryRmdr is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockExpiryRmdr int64 = 0x4B455953_45585052 // "KEYSEXPR"

// startExpiryReminderScheduler starts the "expiry_reminder" background job.
//
// Start the secret-expiry reminder scheduler — opt-in. Notifies project admins of
// secrets that have expired or are approaching expiration, so a secret never silently
// lapses. Single-replica-gated (ADR-039) so admins aren't notified N times in HA.
func startExpiryReminderScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.ExpiryReminders.Enabled {
		interval := cfg.ExpiryReminders.GetInterval()
		leadDays := cfg.ExpiryReminders.LeadDays
		log.Printf("Expiry-reminder scheduler enabled: every %s (lead %dd)", interval, leadDays)
		runScheduler(ctx, "expiry_reminder", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockExpiryRmdr, "Expiry-reminder", func(ctx context.Context) error {
				n, rerr := coreService.SendExpiryReminders(ctx, leadDays)
				if rerr != nil {
					log.Printf("Expiry-reminder error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Expiry reminders: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}
}
