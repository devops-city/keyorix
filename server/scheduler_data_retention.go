package main

import (
	"context"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockRetention is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockRetention int64 = 0x4B455953_52455445 // "KEYSRETE"

// startDataRetentionScheduler starts the "data_retention" background job.
//
// Start the data-retention scheduler (ISO A.5.33 / GDPR / DORA) — opt-in.
// Hard-deletes compliance records (anomaly alerts, closed campaigns, the
// break-glass register, resolved access requests) past their per-type window.
// Legal-hold-gated and single-replica-gated (ADR-039); audit events are never
// touched (append-only). Runs only when at least one window is configured.
func startDataRetentionScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.DataRetention.Enabled {
		policy := core.RetentionPolicy{
			AnomalyAlertsDays:               cfg.DataRetention.AnomalyAlertsDays,
			AnomalyAlertsUnackedCeilingDays: cfg.DataRetention.AnomalyAlertsUnackedCeilingDays,
			ClosedAccessReviewsDays:         cfg.DataRetention.ClosedAccessReviewsDays,
			BreakGlassDays:                  cfg.DataRetention.BreakGlassDays,
			ResolvedAccessRequestsDays:      cfg.DataRetention.ResolvedAccessRequestsDays,
		}
		if !policy.Configured() {
			log.Printf("Data-retention scheduler enabled but no retention windows are set; nothing to purge")
		} else {
			interval := cfg.DataRetention.GetInterval()
			log.Printf("Data-retention scheduler enabled: every %s (anomaly_alerts=%dd, anomaly_alerts_unacked_ceiling=%dd, closed_reviews=%dd, break_glass=%dd, access_requests=%dd; 0=keep)",
				interval, policy.AnomalyAlertsDays, policy.AnomalyAlertsUnackedCeilingDays, policy.ClosedAccessReviewsDays, policy.BreakGlassDays, policy.ResolvedAccessRequestsDays)
			runScheduler(ctx, "data_retention", interval, func() middleware.SchedulerOutcome {
				if legalHoldBlocks(ctx, coreService, "Data-retention purge") {
					return middleware.SchedulerSkipped
				}
				return lockedRun(ctx, coreService.Storage(), schedLockRetention, "Data-retention", func(ctx context.Context) error {
					res, err := coreService.PurgeExpiredComplianceRecords(ctx, time.Now(), policy)
					if err != nil {
						log.Printf("Data-retention purge error: %v", err)
						return err
					}
					if res.Total() > 0 {
						log.Printf("Data-retention purge removed %d records (anomaly_alerts=%d, closed_campaigns=%d, review_items=%d, break_glass=%d, access_requests=%d, approvals=%d)",
							res.Total(), res.AnomalyAlerts, res.ClosedAccessReviews, res.AccessReviewItems,
							res.BreakGlass, res.ResolvedAccessRequests, res.AccessRequestApprovals)
					}
					return nil
				})
			})
		}
	}
}
