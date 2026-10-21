package main

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockDigest is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockDigest int64 = 0x4B455953_44494753 // "KEYSDIGS"

// startComplianceDigestScheduler starts the "compliance_digest" background job.
//
// Start the compliance-digest scheduler — opt-in. Periodically broadcasts a
// posture + control-matrix summary to the configured notification channels
// (Slack/Teams/webhook). Single-replica-gated (ADR-039) so the channel gets one
// digest per tick. A no-op (logged) when no notification channel is configured.
func startComplianceDigestScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.ComplianceDigest.Enabled {
		interval := cfg.ComplianceDigest.GetInterval()
		log.Printf("Compliance-digest scheduler enabled: every %s", interval)
		runScheduler(ctx, "compliance_digest", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockDigest, "Compliance-digest", func(ctx context.Context) error {
				sent, derr := coreService.SendComplianceDigest(ctx, 0)
				if derr != nil {
					log.Printf("Compliance-digest error: %v", derr)
					return derr
				}
				if !sent {
					log.Printf("Compliance digest: no notification channel configured; nothing sent")
				}
				return nil
			})
		})
	}
}
