package config

import (
	"time"
)

// RecertificationConfig configures scheduled access recertification (ISO 27001
// A.5.18, "review access rights at planned intervals"). When Enabled, a background
// job finds projects whose access is due for review — never reviewed, or last
// reviewed more than CadenceDays ago — and, if AutoOpen, opens a recert campaign for
// each (system-actored); otherwise it reminds the project's admins to. It also nudges
// admins of in-flight campaigns that still have pending items. Opt-in (default off).
type RecertificationConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	// CadenceDays is the review interval; a project becomes due this many days after
	// its last campaign closed. 0 = the default (90 days).
	CadenceDays int `yaml:"cadence_days"`
	// AutoOpen, when true, opens a campaign automatically for an overdue project;
	// when false the scheduler only reminds admins to open one themselves.
	AutoOpen bool `yaml:"auto_open"`
}

// GetInterval returns the recertification run interval, parsing Schedule as a Go
// duration (e.g. "24h"); defaults to 24h when unset or unparseable.
func (c RecertificationConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}
