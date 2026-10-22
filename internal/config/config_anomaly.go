package config

import (
	"time"
)

// AnomalyAlertsConfig configures proactive alerting for detected access anomalies
// (NIS2 detection & response). The hourly detection scan always runs; when this is
// enabled, each newly detected anomaly is also pushed to the project's admins
// (in-app) and the audit trail / SIEM. Opt-in (default off).
type AnomalyAlertsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	// ML configures the optional Isolation Forest detection pass (ADR-050). It is
	// independent of Enabled (which gates alert *push*): ML.Enabled gates whether the
	// detection scan additionally scores accesses for multivariate outliers.
	ML AnomalyMLConfig `yaml:"ml"`
	// BusinessHours configures the timezone and band the off_hours rule uses. Unset =
	// the legacy UTC 22:00–06:00 default.
	BusinessHours AnomalyBusinessHoursConfig `yaml:"business_hours"`
	// BaselineQuarantine is how long an IP/user must be observed before the live scan
	// window before it is trusted as "known" baseline (#101) — see
	// AnomalyDetector.SetBaselineQuarantine. Go duration string (e.g. "24h"); unset
	// keeps the 24h default. An explicit "0" or "0s" disables quarantine.
	BaselineQuarantine string `yaml:"baseline_quarantine"`
}

// GetBaselineQuarantine returns the parsed BaselineQuarantine duration; defaults to 24h.
// A configured zero duration ("0", "0s") is honored as an explicit opt-out rather than
// falling back to the default, since Go's ParseDuration("0") succeeds with d == 0.
func (c AnomalyAlertsConfig) GetBaselineQuarantine() time.Duration {
	if c.BaselineQuarantine == "" {
		return 24 * time.Hour
	}
	if d, err := time.ParseDuration(c.BaselineQuarantine); err == nil && d >= 0 {
		return d
	}
	return 24 * time.Hour
}

// AnomalyBusinessHoursConfig defines when secret access counts as "off hours" for the
// off_hours detection rule. The hours are evaluated in Timezone, and the off-hours band
// is [OffHoursStart, OffHoursEnd) wrapping midnight (e.g. 22→6). All fields are optional
// and default to the legacy behaviour: UTC, 22:00–06:00. Setting Timezone alone is the
// common case — it stops flagging local business-hours access as off-hours on non-UTC
// deployments (and vice versa).
type AnomalyBusinessHoursConfig struct {
	Timezone      string `yaml:"timezone"`        // IANA name (e.g. "America/New_York"); "" = UTC
	OffHoursStart int    `yaml:"off_hours_start"` // off-hours band start hour [0,23]; default 22
	OffHoursEnd   int    `yaml:"off_hours_end"`   // off-hours band end hour [0,23]; default 6
}

// AnomalyMLConfig configures the Isolation Forest anomaly-detection pass (ADR-050).
// Opt-in (default off). When enabled, each detection scan trains a per-secret forest
// on the secret's 30-day access baseline and flags recent accesses whose joint
// feature vector (hour, IP novelty, user novelty) is a multivariate outlier — the
// single-signal statistical rules miss these. Metadata only; no secret values.
type AnomalyMLConfig struct {
	Enabled    bool    `yaml:"enabled"`
	Threshold  float64 `yaml:"threshold"`   // anomaly-score cutoff (0.5,1.0); default 0.60
	NumTrees   int     `yaml:"num_trees"`   // ensemble size; default 100
	SampleSize int     `yaml:"sample_size"` // per-tree subsample (psi); default 256
	// Seed, if set, pins the Isolation Forest's RNG for reproducible scoring (e.g. to
	// diff forest behavior across a config change). Unset (0) draws a fresh
	// crypto/rand-sourced seed per process instead of a fixed constant, so the forest
	// structure isn't predictable from source (#101).
	Seed int64 `yaml:"seed"`
}

// GetInterval returns the anomaly scan/alert interval (Go duration); defaults to 1h.
func (c AnomalyAlertsConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}
