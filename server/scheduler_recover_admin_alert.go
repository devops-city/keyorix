package main

import (
	"context"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockRecoverAdminAlert is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockRecoverAdminAlert int64 = 0x4B455953_52435652 // "KEYSRCVR"

// startRecoverAdminAlertScheduler starts the "recover_admin_alert" background job.
//
// Alert on recover-admin use (F7, Akeyless-style) — ALWAYS runs, not
// opt-in: `recover-admin` bypasses RBAC by design (host access + the
// recovery key alone), so an install must not be able to silently turn
// off being notified when it's used. Runs once immediately on startup
// (the primary trigger — recover-admin is an offline CLI command, so
// the next server start after it ran is normally the first chance to
// alert) and every 10 minutes thereafter as a safety net (e.g. an HA
// replica whose own process never restarted). Single-replica-gated
// (ADR-039) so admins aren't notified N times in an HA deployment.
func startRecoverAdminAlertScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	runScheduler(ctx, "recover_admin_alert", 10*time.Minute, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockRecoverAdminAlert, "Recover-admin alert", func(ctx context.Context) error {
			n, aerr := coreService.RunRecoverAdminAlerting(ctx)
			if aerr != nil {
				return aerr
			}
			if n > 0 {
				log.Printf("Recover-admin alert: notified %d recover-admin use(s)", n)
			}
			return nil
		})
	})
}
