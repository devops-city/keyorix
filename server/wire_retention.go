package main

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core"
)

// wireSoftDeleteRetention is a core wiring step (coreWiringSteps in main.go).
func wireSoftDeleteRetention(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// The configured soft-delete window, wired where the service is built (not in an
	// unrelated wireX helper) so every transport and job that shows or applies a
	// purge date (core.SecretPurgeAt) sees soft_delete.retention_days, never core's
	// 30-day library default.
	coreService.SetSoftDeleteRetentionDays(cfg.SoftDelete.GetRetentionDays())
	return nil
}

// wireRetentionPolicy is a core wiring step (coreWiringSteps in main.go).
func wireRetentionPolicy(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire the configured data-retention windows (A.5.33) so the compliance posture
	// reports them; the scheduler below drives the actual purge. Audited (#160) so a
	// shortened window is on the record, not just its eventual purge counts.
	coreService.SetRetentionPolicy(context.Background(), core.RetentionPolicy{
		AnomalyAlertsDays:               cfg.DataRetention.AnomalyAlertsDays,
		AnomalyAlertsUnackedCeilingDays: cfg.DataRetention.AnomalyAlertsUnackedCeilingDays,
		ClosedAccessReviewsDays:         cfg.DataRetention.ClosedAccessReviewsDays,
		BreakGlassDays:                  cfg.DataRetention.BreakGlassDays,
		ResolvedAccessRequestsDays:      cfg.DataRetention.ResolvedAccessRequestsDays,
	})
	return nil
}

// wireRecertificationCadence is a core wiring step (coreWiringSteps in main.go).
func wireRecertificationCadence(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire the access-recertification cadence (A.5.18) so the posture flags overdue
	// projects; the scheduler below acts on it when enabled.
	coreService.SetRecertificationCadence(cfg.Recertification.CadenceDays)
	return nil
}
