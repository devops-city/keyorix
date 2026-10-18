package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Anomaly config knob ceilings (#G44) — without an upper bound, a caller-supplied
// value drives real per-scan work: LookbackDays widens the audit_events window
// scanned every detection tick, and MLNumTrees/MLSampleSize scale the isolation-
// forest training cost directly, so an unbounded value is a resource-exhaustion
// vector each time the detector runs.
const (
	maxAnomalyLookbackDays  = 365
	maxAnomalyQuarantineHrs = 24 * 90 // 90 days
	maxAnomalyMLNumTrees    = 1000
	maxAnomalyMLSampleSize  = 100000
)

// EventAnomalyConfigUpdated is the audit event type emitted when the
// persisted anomaly detection config is replaced -- see config_change_audit.go
// for the shared writer. Distinct from EventAnomalyBusinessHoursConfigured
// (anomaly.go), which audits only the off-hours band as actually applied to
// the live detector (change-deduped across scheduler ticks); this event
// audits the raw admin PUT itself, including knobs (ML enable, lookback,
// quarantine) that ApplyAnomalyConfig's dedup never covers.
const EventAnomalyConfigUpdated = "anomaly_config.updated" // #nosec G101 -- audit event type, not a credential

// validateAnomalyConfig bounds the knobs that drive per-scan detector cost.
func validateAnomalyConfig(cfg *models.AnomalyConfigRecord) error {
	if cfg.LookbackDays > maxAnomalyLookbackDays {
		return fmt.Errorf("lookback_days exceeds the maximum of %d", maxAnomalyLookbackDays)
	}
	if cfg.QuarantineHours > maxAnomalyQuarantineHrs {
		return fmt.Errorf("quarantine_hours exceeds the maximum of %d", maxAnomalyQuarantineHrs)
	}
	if cfg.MLNumTrees > maxAnomalyMLNumTrees {
		return fmt.Errorf("ml_num_trees exceeds the maximum of %d", maxAnomalyMLNumTrees)
	}
	if cfg.MLSampleSize > maxAnomalyMLSampleSize {
		return fmt.Errorf("ml_sample_size exceeds the maximum of %d", maxAnomalyMLSampleSize)
	}
	return nil
}

// ApplyAnomalyConfig loads the persisted anomaly config and applies it to the
// given detector. Call at startup and before each detection scan so runtime
// changes take effect without a restart.
func (c *KeyorixCore) ApplyAnomalyConfig(ctx context.Context, detector *AnomalyDetector) error {
	cfg, err := c.storage.GetAnomalyConfig(ctx)
	if err != nil {
		return err
	}

	// Lookback
	if cfg.LookbackDays > 0 {
		detector.SetLookback(time.Duration(cfg.LookbackDays) * 24 * time.Hour)
	}
	// Quarantine
	if cfg.QuarantineHours > 0 {
		detector.SetBaselineQuarantine(time.Duration(cfg.QuarantineHours) * time.Hour)
	}
	// Off-hours (only applied when enabled; the detector keeps its own default when
	// disabled). A rejected band (invalid hour, or a degenerate start==end collision —
	// see SetBusinessHours) must not be silently swallowed: the detector keeps its
	// prior policy, but the caller needs to know the persisted config didn't take
	// effect, so this deferred until after the remaining, independent knobs below are
	// applied rather than aborting the whole config apply.
	var offHoursErr error
	if cfg.OffHoursEnabled {
		if err := detector.SetBusinessHours(ctx, cfg.OffHoursTimezone, cfg.OffHoursStart, cfg.OffHoursEnd); err != nil {
			offHoursErr = fmt.Errorf("anomaly business_hours config rejected: %w", err)
		}
	}
	// ML
	detector.SetMLConfig(MLConfig{
		Enabled:    cfg.MLEnabled,
		Threshold:  cfg.MLThreshold,
		NumTrees:   cfg.MLNumTrees,
		SampleSize: cfg.MLSampleSize,
	})
	// Volume spike floor and cumulative rate rule (ANOMALY-06).
	if cfg.VolumeMinCount > 0 {
		detector.SetVolumeMinCount(cfg.VolumeMinCount)
	}
	if cfg.CumulativeRateFloor > 0 {
		detector.SetCumulativeRateFloor(cfg.CumulativeRateFloor)
	}
	if cfg.CumulativeRateMax > 0 {
		detector.SetCumulativeRateMax(cfg.CumulativeRateMax)
	}
	return offHoursErr
}

// GetAnomalyConfig returns the current persisted anomaly detection config (or
// sensible defaults if none has been saved yet).
func (c *KeyorixCore) GetAnomalyConfig(ctx context.Context) (*models.AnomalyConfigRecord, error) {
	return c.storage.GetAnomalyConfig(ctx)
}

// UpdateAnomalyConfig persists a new anomaly detection config.  updatedBy is
// the username of the operator making the change (stored on the row for audit
// purposes); actorID is their numeric ID for audit-event attribution (0 when
// unknown, e.g. a local CLI invocation); the caller is responsible for
// applying the new config to the live detector via ApplyAnomalyConfig if one
// is running.
//
// This is a full-replace write (cfg goes straight into storage.SaveAnomalyConfig's
// unconditional Save), not the unfetched-struct-into-full-row-overwrite bug class
// fixed elsewhere (UpdateWebAuthnCredentialProxy, UpdateUserIfActiveStateMatchesProxy).
// Confirmed during that fix's repo-wide sweep as a deliberate, accepted tradeoff:
// anomaly config is a small operator knob set with no partial-patch use case, and a
// PUT is expected to carry the complete config, not a diff.
//
// Every write is audited (EventAnomalyConfigUpdated) with the before/after config
// as the diff -- an admin who disables ML/off-hours detection deployment-wide,
// acts, then restores the defaults must leave a permanent record of the
// intervening window, not just the final restored row (#G-audit-notif-anomaly).
// The before-state fetch is best-effort: a failure to read the PRIOR config must
// not block persisting and auditing the new one (the write itself, and its audit
// record, are the security-relevant guarantee here; a missing "before" snapshot
// degrades the diff's usefulness but must never suppress the write's own record).
func (c *KeyorixCore) UpdateAnomalyConfig(ctx context.Context, cfg *models.AnomalyConfigRecord, updatedBy string, actorID uint) error {
	if err := validateAnomalyConfig(cfg); err != nil {
		return err
	}
	var before any
	if prior, err := c.storage.GetAnomalyConfig(ctx); err == nil {
		before = prior
	}
	cfg.UpdatedBy = updatedBy
	cfg.UpdatedAt = time.Now()
	// AUDIT-TX-3: the save and its audit row commit together (fail closed): anomaly
	// detection is never switched off or retuned unrecorded.
	return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.SaveAnomalyConfig(ctx, cfg); err != nil {
			return err
		}
		c.writeConfigChangeAuditEventOn(ctx, tgt, EventAnomalyConfigUpdated, actorID,
			fmt.Sprintf("anomaly detection config updated by %s (ml_enabled=%t off_hours_enabled=%t)", updatedBy, cfg.MLEnabled, cfg.OffHoursEnabled),
			before, cfg)
		return nil
	})
}
