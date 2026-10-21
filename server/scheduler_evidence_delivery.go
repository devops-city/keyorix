package main

import (
	"context"
	"log"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockEvidence is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockEvidence int64 = 0x4B455953_45564944 // "KEYSEVID"

// startEvidenceDeliveryScheduler starts the "evidence_delivery" background job.
//
// Start the scheduled compliance-evidence delivery (ISO 27001 / SOC 2) — opt-in.
// Periodically generates the auditor evidence pack and delivers it to the
// configured targets (a local directory and/or a webhook); each export emits an
// audit event (forwarded to a SIEM if configured). Single-replica-gated (ADR-039)
// so one pack is delivered per tick. Not legal-hold-gated (it only reads).
func startEvidenceDeliveryScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.EvidenceDelivery.Enabled {
		if !cfg.EvidenceDelivery.HasTarget() {
			log.Printf("Evidence-delivery scheduler enabled but no target (output_dir or webhook) is configured; skipping")
		} else {
			outputDir := cfg.EvidenceDelivery.OutputDir
			interval := cfg.EvidenceDelivery.GetInterval()
			log.Printf("Evidence-delivery scheduler enabled: every %s (dir=%q, webhook=%t)", interval, outputDir, cfg.EvidenceDelivery.Webhook.Enabled)
			runScheduler(ctx, "evidence_delivery", interval, func() middleware.SchedulerOutcome {
				return lockedRun(ctx, coreService.Storage(), schedLockEvidence, "Evidence-delivery", func(ctx context.Context) error {
					res, err := coreService.ExportComplianceEvidence(ctx, outputDir)
					if err != nil {
						log.Printf("Evidence-delivery error: %v", err)
						return err
					}
					if res.Degraded {
						// #136: a degraded pack must be loud in the operator-facing log, not
						// just embedded in the archived JSON — a collection failure means
						// this export is incomplete, not a clean point-in-time snapshot.
						log.Printf("Evidence pack exported DEGRADED (%d collection failure(s)): %d bytes -> %v; reasons: %s",
							len(res.DegradedReasons), res.Bytes, res.Targets, strings.Join(res.DegradedReasons, "; "))
					} else {
						log.Printf("Evidence pack exported: %d bytes -> %v", res.Bytes, res.Targets)
					}
					return nil
				})
			})
		}
	}
}
