package main

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockMFAGrantPrune is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockMFAGrantPrune int64 = 0x4B455953_4D464147 // "KEYSMFAG"

// startMFAStepUpGrantPruneScheduler starts the "mfa_stepup_grant_prune" background job.
//
// Prune expired MFA step-up grant rows every 6 hours (store-mfa-002). Each
// successful VerifyMFAStepUp creates a new MFAStepUpGrant row, kept briefly
// past its own expiry for audit purposes (internal/storage/store/
// local_mfa_stepup_grant.go) — with no sweep, every legitimate
// re-verification left a permanent row. This scheduler calls
// PruneMFAStepUpGrants below, not DeleteMFAStepUpGrantsFor -- that older
// method was originally only reachable via the now-deleted RemoteStorage
// proxy and has zero callers of any kind today (interface.go's declaration
// and the generated fault-injection wrapper aside); another follow-up
// cleanup candidate, not removed here. Like login_attempt_prune above, this
// ALWAYS runs — not
// legal-hold-gated: a grant row's CREATION is already permanently,
// independently audited (mfa.stepup_verified, never purged — ADR-029), so
// pruning the row itself never destroys evidence, only a redundant
// operational copy, and letting a long-running legal hold block this would
// just grow the table unbounded for no compliance benefit. Retention
// defaults to 30 days (config classification.mfa_stepup_grant_retention_days,
// mirroring SoftDeleteConfig's default) — much looser than the 15-minute
// cadence/window ratio login_attempt_prune uses, since grant rows are
// created far less often (once per MFA step-up verification, not once per
// rate-limit check).
func startMFAStepUpGrantPruneScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	mfaGrantRetention := time.Duration(cfg.Classification.GetMFAStepUpGrantRetentionDays()) * 24 * time.Hour
	runScheduler(ctx, "mfa_stepup_grant_prune", 6*time.Hour, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockMFAGrantPrune, "MFA step-up grant prune", func(ctx context.Context) error {
			_, perr := coreService.PruneMFAStepUpGrants(ctx, mfaGrantRetention, time.Time{})
			return perr
		})
	})
}
