package config

import (
	"time"
)

// AutoRotationConfig configures the opt-in automated-rotation scheduler (ADR-046) and
// the backend rotation executors it can drive (ADR-047).
type AutoRotationConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	// Backends are the upstream rotation executors (ADR-047) — e.g. a PostgreSQL admin
	// connection that can ALTER ROLE. Each backend's admin DSN is read from its named
	// environment variable, never from this file.
	Backends []RotationBackendConfig `yaml:"backends"`
}

// RotationBackendConfig describes one upstream rotation executor (ADR-047). Name is the
// registry key; Type selects the backend ("postgresql"); DSNEnv names the environment
// variable holding the admin connection string. AllowedRefs optionally restricts which
// references (e.g. role names) the backend may rotate, by prefix.
type RotationBackendConfig struct {
	Name        string   `yaml:"name"`
	Type        string   `yaml:"type"`
	DSNEnv      string   `yaml:"dsn_env"`
	Region      string   `yaml:"region"` // for cloud backends (e.g. aws-iam); creds from the ambient chain
	AllowedRefs []string `yaml:"allowed_refs"`
}

// GetDSN returns the backend admin DSN from its configured environment variable
// (empty when DSNEnv is unset or the variable is empty — the credential never lives in
// the config file).
func (c RotationBackendConfig) GetDSN() string {
	if c.DSNEnv == "" {
		return ""
	}
	return resolveSecret(c.DSNEnv, "") // also honours <DSNEnv>_FILE
}

// GetInterval returns the auto-rotation run interval (Go duration, e.g. "1h");
// defaults to 1h when unset or unparseable.
func (c AutoRotationConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}
