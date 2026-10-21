package main

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockOwedAudit is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockOwedAudit int64 = 0x4B455953_4F574544 // "KEYSOWED"

// startAuditOwedBackfillScheduler starts the "audit_owed_backfill" background job.
//
// Owed audit rows (core audit_owed.go): a plain secret suspend never waits for
// the audit log, so a secret.suspended row the audit log refused is kept in
// pending_audit_events and written here once the audit log accepts writes
// again. A degraded break-glass activation (BREAKGLASS-OWED-1) owes its rows
// here too; they keep their original time and settle the activation. Every
// minute; single-replica-gated, and exactly-once anyway (the claim and the
// append share a transaction).
func startAuditOwedBackfillScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	coreService.PublishOwedAuditMetric() // keyorix_audit_owed_pending, authenticated scheduler-metrics only
	runScheduler(ctx, "audit_owed_backfill", time.Minute, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockOwedAudit, "Owed audit backfill", func(ctx context.Context) error {
			_, berr := coreService.BackfillPendingAuditEvents(ctx)
			return berr
		})
	})
}
