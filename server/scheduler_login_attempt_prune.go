package main

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockLoginPrune is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockLoginPrune int64 = 0x4B455953_4C474E50 // "KEYSLGNP"

// startLoginAttemptPruneScheduler starts the "login_attempt_prune" background job.
//
// Prune expired login-attempt records every 15 minutes (ADR-040). Single-replica-
// gated and ALWAYS run — login_attempts are ephemeral rate-limit data (never legal
// evidence), so this is deliberately NOT subject to legalHoldBlocks: a long-running
// legal hold must not stop the prune, or the table grows unbounded (an attacker
// failing logins from rotating IPs would exhaust disk). The rate-limit window is
// 15 minutes, so a 15-minute cadence keeps the table at roughly one window of rows.
func startLoginAttemptPruneScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	runScheduler(ctx, "login_attempt_prune", 15*time.Minute, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockLoginPrune, "Login-attempt prune", func(ctx context.Context) error {
			// Zero `before` and a zero actorID: PruneLoginAttempts resolves the
			// cutoff itself (now - LoginWindow) and attributes the event to no
			// human/machine principal. System-actored via WithActorType so the
			// resulting data.login_attempts_pruned audit event (when anything is
			// removed) reads as "system", not the default "user".
			sysCtx := core.WithActorType(ctx, core.ActorTypeSystem)
			_, perr := coreService.PruneLoginAttempts(sysCtx, time.Time{}, 0)
			return perr
		})
	})
}
