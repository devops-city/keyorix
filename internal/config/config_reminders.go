package config

import (
	"time"
)

// RotationRemindersConfig configures the rotation-reminder scheduler: a background
// job that notifies project admins of secrets overdue/approaching their rotation
// deadline under an active rotation policy. Opt-in (default off).
type RotationRemindersConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// ExpiryRemindersConfig configures the opt-in secret-expiry reminder scheduler.
type ExpiryRemindersConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	LeadDays int    `yaml:"lead_days"` // notify this many days before expiry (0 = default 14)
}

// CertificateExpiryConfig configures the opt-in certificate-expiry monitoring scan
// (ADR-055). It parses certificate-typed secrets and notifies project admins of certs
// expired or expiring within LeadDays (using the certificate's real notAfter).
type CertificateExpiryConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	LeadDays int    `yaml:"lead_days"` // notify this many days before notAfter (0 = default 30)
}

// GetInterval returns the certificate-expiry scan interval (Go duration, e.g. "24h");
// defaults to 24h when unset or unparseable.
func (c CertificateExpiryConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// LicenseExpiryConfig configures the opt-in background reminder that notifies install-wide
// admins when the offline commercial license (ADR-065) is within LeadDays of expiry or has
// expired. Disabled (zero value) = no reminder; the fail-safe gate and status endpoint are
// unaffected.
type LicenseExpiryConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	LeadDays int    `yaml:"lead_days"` // notify this many days before expiry (0 = default 30)
}

// GetInterval returns the license-expiry reminder interval (Go duration, e.g. "24h");
// defaults to 24h when unset or unparseable.
func (c LicenseExpiryConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// GetInterval returns the expiry-reminder run interval (Go duration, e.g. "24h");
// defaults to 24h when unset or unparseable.
func (c ExpiryRemindersConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// GetInterval returns the rotation-reminder run interval (Go duration, e.g. "24h");
// defaults to 24h when unset or unparseable.
func (c RotationRemindersConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// ReadQuotaAlertsConfig configures the opt-in background scheduler that scans all
// secrets with MaxReads set and notifies their owners when the read count approaches
// or reaches the limit (80 % → Warning, 95 % → Critical).
type ReadQuotaAlertsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"` // Go duration (e.g. "24h"); defaults to 24h
}

// GetInterval returns the read-quota alert scan interval; defaults to 24h.
func (c ReadQuotaAlertsConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}
