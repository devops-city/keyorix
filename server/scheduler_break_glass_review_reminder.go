package main

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockBreakGlassReview is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockBreakGlassReview int64 = 0x4B455953_42475256 // "KEYSBGRV"

// startBreakGlassReviewReminderScheduler starts the "break_glass_review_reminder" background job.
//
// Warn about break-glass activations that have gone unreviewed past the
// configured review window (ADR-112 §3, item 4/5; #2461) — ALWAYS runs,
// deliberately not gated on cfg.BreakGlass.Enabled, for the same reason the
// recover-admin alert above isn't opt-in: an install that has since turned
// break-glass OFF can still be holding unreviewed activations from when it
// was on, and those are precisely the ones that must not quietly drop off
// the report. Runs once immediately on startup (the "startup warning" half)
// and every 6h thereafter. Single-replica-gated (ADR-039) so an HA
// deployment logs and audits this once per pass, not once per replica.
//
// Visibility only — see RunBreakGlassReviewReminder's own doc comment for
// why ADR-112's "enforced" is a posture deviation plus this warning, and
// explicitly NOT a lockout.
func startBreakGlassReviewReminderScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	runScheduler(ctx, "break_glass_review_reminder", 6*time.Hour, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockBreakGlassReview, "Break-glass review reminder", func(ctx context.Context) error {
			_, rerr := coreService.RunBreakGlassReviewReminder(ctx)
			return rerr
		})
	})
}
