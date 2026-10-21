package main

import (
	"context"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockAuditCkpt is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockAuditCkpt int64 = 0x4B455953_41434B50 // "KEYSACKP"

// startAuditCheckpointScheduler starts the "audit_checkpoint" background job.
//
// Start the audit-checkpoint scheduler (ADR-029). Periodically signs the verified
// audit-chain head so tampering, tail-truncation, and genesis re-seed are
// detectable. This is the trail's FORGERY-RESISTANCE layer: the per-row hash chain
// is unkeyed, so a database-write attacker could otherwise edit/delete/reorder rows
// and recompute a self-consistent chain undetected. It is therefore enabled BY
// DEFAULT whenever a signing key is available (the key is DEK-derived → encryption
// must be configured). HA-gated so one replica writes per tick.
func startAuditCheckpointScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	switch {
	case cfg.AuditCheckpoints.Disabled:
		log.Printf("WARNING: audit-checkpoint forgery-resistance is explicitly DISABLED; the audit trail is tamper-evident but a database-write attacker can recompute the hash chain undetected")
	case !coreService.AuditCheckpointsAvailable():
		log.Printf("WARNING: audit checkpointing is UNAVAILABLE (encryption/signing key not configured) — the audit trail is tamper-EVIDENT only, NOT forgery-resistant: a database-write attacker can edit/delete/reorder audit rows and recompute the chain. Enable encryption to activate forgery resistance.")
	default:
		interval := cfg.AuditCheckpoints.GetInterval()
		segments := core.DefaultAuditFullVerificationSegments
		// Incremental verification (docs/specs/audit-incremental-verification.md):
		// each tick checks only the tail since the latest checkpoint and re-walks
		// 1/segments of the chain, so the whole chain is re-hashed every
		// interval × segments; requests and posture read the persisted result.
		coreService.SetAuditIncrementalVerification(interval, segments)
		// Publish the persisted verification state now, not at the first tick: a
		// restart must not read as "no audit-chain break recorded" until then.
		if perr := coreService.PublishAuditVerifyState(ctx); perr != nil {
			log.Printf("WARNING: could not read the audit verification state at startup: %v (the audit-verify failure gauges stay unknown until the first checkpoint tick)", perr)
		}
		// A fresh checkpoint defers the first tick (spec §6): a restart does not
		// re-verify what the last tick already covered.
		firstDelay := coreService.AuditCheckpointFirstTickDelay(ctx, interval)
		log.Printf("Audit-checkpoint scheduler enabled (forgery resistance active): every %s, full re-walk every %s, first tick in %s",
			interval, interval*time.Duration(segments), firstDelay.Round(time.Second))
		runSchedulerAfter(ctx, "audit_checkpoint", interval, firstDelay, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockAuditCkpt, "Audit-checkpoint", func(ctx context.Context) error {
				res, werr := coreService.RunAuditVerificationTick(ctx)
				if res != nil && res.Written {
					log.Printf("Audit checkpoint written: #%d head=%d events=%d", res.Checkpoint.ID, res.Checkpoint.HeadID, res.Checkpoint.ChainedEvents)
				}
				if res != nil && res.SegmentWalked {
					log.Printf("Audit rolling verification: verified through #%d of #%d (cycle complete: %t)", res.VerifiedThrough, res.CycleTarget, res.CycleCompleted)
				}
				if werr != nil {
					log.Printf("Audit-checkpoint error: %v", werr)
					return werr
				}
				return nil
			})
		})
	}
}
