package main

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockReadQuota is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockReadQuota int64 = 0x4B455953_52445154 // "KEYSRDQT"

// startReadQuotaAlertsScheduler starts the "read_quota_alerts" background job.
//
// Start the read-quota alert scheduler — opt-in. Scans all secrets with MaxReads > 0
// and sends in-app notifications to their owners when usage reaches 80 % (Warning)
// or 95 % / 100 % (Critical / Exhausted). Single-replica-gated (ADR-039).
func startReadQuotaAlertsScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.ReadQuotaAlerts.Enabled {
		interval := cfg.ReadQuotaAlerts.GetInterval()
		log.Printf("Read-quota alert scheduler enabled: every %s", interval)
		runScheduler(ctx, "read_quota_alerts", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockReadQuota, "Read-quota alerts", func(ctx context.Context) error {
				result, rerr := coreService.CheckReadQuotas(ctx)
				if rerr != nil {
					log.Printf("Read-quota alert scan error: %v", rerr)
					return rerr
				}
				if result.Warnings+result.Criticals > 0 {
					log.Printf("Read-quota alert scan: %d warning(s), %d critical(s), %d exhausted",
						result.Warnings, result.Criticals, result.Exhausted)
				}
				return nil
			})
		})
	}
}
