package config

import (
	"time"
)

type SoftDeleteConfig struct {
	Enabled       bool `yaml:"enabled"`
	RetentionDays int  `yaml:"retention_days"`
}

// GetRetentionDays returns the soft-delete grace period in days, defaulting to
// 30 when unset (ADR-032).
func (c SoftDeleteConfig) GetRetentionDays() int {
	if c.RetentionDays <= 0 {
		return 30
	}
	return c.RetentionDays
}

type PurgeConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// DataRetentionConfig configures the data-retention scheduler (ISO 27001 A.5.33 /
// GDPR storage-limitation / DORA): a background job that hard-deletes compliance
// records past their per-record-type retention window. Each *_days window is a
// number of days; 0 (the zero value) disables retention for that type — those
// records are kept indefinitely. Opt-in (Enabled, default off). Respects legal
// hold: while a hold is active nothing is purged. Audit events are NEVER purged
// (append-only tamper-evidence, ADR-029) and soft-deleted rows are handled by the
// separate ADR-032 purge — this scheduler covers the compliance records that would
// otherwise accumulate forever.
type DataRetentionConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	// AnomalyAlertsDays ages out resolved/old access-anomaly alerts on detected_at.
	// Only ACKNOWLEDGED alerts are eligible (#415) — a never-acknowledged alert is
	// still a live, unreviewed signal and survives this window regardless of age.
	AnomalyAlertsDays int `yaml:"anomaly_alerts_days"`
	// AnomalyAlertsUnackedCeilingDays is a separate, much more generous absolute-age
	// safety net (#489) for alerts that are NEVER acknowledged: without it, an
	// environment (or an actor deliberately triggering distinct anomalies to defeat
	// the creation-time dedup window) accumulates unacknowledged alert rows forever,
	// with no cap — a disk-exhaustion surface and an ever-slower ListAnomalyAlerts
	// scan. This window is independent of, and does not weaken, AnomalyAlertsDays:
	// it only catches alerts old enough that they are almost certainly abandoned, not
	// a reasonable operational review backlog. 0 disables it (kept forever, the
	// pre-#489 behavior).
	AnomalyAlertsUnackedCeilingDays int `yaml:"anomaly_alerts_unacked_ceiling_days"`
	// ClosedAccessReviewsDays ages out closed recertification campaigns (and their
	// snapshot items) on closed_at. Open campaigns are never purged.
	ClosedAccessReviewsDays int `yaml:"closed_access_reviews_days"`
	// BreakGlassDays ages out non-active emergency-access activations on created_at.
	// Active activations are never purged.
	BreakGlassDays int `yaml:"break_glass_days"`
	// ResolvedAccessRequestsDays ages out terminal-state access requests (and their
	// approval records) on resolved_at. Pending requests are never purged.
	ResolvedAccessRequestsDays int `yaml:"resolved_access_requests_days"`
}

// GetInterval returns the data-retention run interval, parsing Schedule as a Go
// duration (e.g. "24h", "6h"); defaults to 24h when unset or unparseable.
func (c DataRetentionConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// GetInterval returns the purge run interval, parsing Schedule as a Go duration
// (e.g. "24h", "6h"); defaults to 24h when unset or unparseable (ADR-032).
func (c PurgeConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}
