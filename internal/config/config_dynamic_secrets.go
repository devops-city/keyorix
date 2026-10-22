package config

import (
	"time"
)

// DynamicSecretsConfig configures the dynamic-secrets auto-revoke sweep (ADR-035).
type DynamicSecretsConfig struct {
	// SweepEnabled turns on the background sweeper that revokes leases past expiry.
	SweepEnabled bool `yaml:"sweep_enabled"`
	// SweepInterval is the sweep cadence as a Go duration (e.g. "1m", "5m").
	SweepInterval string `yaml:"sweep_interval"`
	// MaxLeaseTTL is a hard, install-wide ceiling on any dynamic-secret lease's TTL —
	// independent of (and always enforced alongside) each DynamicSecretConfig's own
	// per-config MaxTTLSeconds, which has no ceiling of its own and defaults to
	// "unset = unbounded" (#97: without this, an operator could set/leave a config's
	// max_ttl_seconds unbounded and mint a credential valid for, say, 100 years). Go
	// duration string (e.g. "720h"); defaults to 90 days when unset or unparseable.
	MaxLeaseTTL string `yaml:"max_lease_ttl"`
	// AllowPrivateNetworkTargets, when true, disables the SSRF guard on admin_dsn so
	// dynamic-secret backends at RFC-1918, loopback, or link-local addresses can be
	// registered. False by default: Keyorix otherwise rejects DSNs whose resolved host
	// is a private address, preventing an internal operator from using the service as
	// an SSRF proxy against other internal hosts (including cloud IMDS at
	// 169.254.169.254). Set this only when the dynamic-secret backend legitimately
	// lives on a private network segment that Keyorix must reach.
	AllowPrivateNetworkTargets bool `yaml:"insecure_allow_private_network_dynamic_secret_targets"`
	// AllowInsecureTransport, when true, disables the TLS-required-by-default
	// guard on the mongodb/redis backends (the two backends here whose wire
	// protocol has no bolted-on-elsewhere TLS enforcement of its own -- see
	// internal/netutil.Guard.RequireTLS). False by default: a mongodb:// (no
	// tls=true) or redis:// (non-rediss://) admin_dsn is rejected. Every
	// connection actually made under this opt-out is logged (2d) -- set this
	// only when the backend legitimately cannot use TLS (e.g. a legacy/
	// internal deployment).
	AllowInsecureTransport bool `yaml:"insecure_allow_plaintext_dynamic_secret_transport"`
}

// GetSweepInterval returns the auto-revoke sweep cadence, parsing SweepInterval
// as a Go duration; defaults to 1m when unset or unparseable (ADR-035).
func (c DynamicSecretsConfig) GetSweepInterval() time.Duration {
	if c.SweepInterval != "" {
		if d, err := time.ParseDuration(c.SweepInterval); err == nil && d > 0 {
			return d
		}
	}
	return 1 * time.Minute
}

// GetMaxLeaseTTL returns the install-wide dynamic-secret lease TTL ceiling; defaults to
// 90 days when unset or unparseable (#97).
func (c DynamicSecretsConfig) GetMaxLeaseTTL() time.Duration {
	if c.MaxLeaseTTL != "" {
		if d, err := time.ParseDuration(c.MaxLeaseTTL); err == nil && d > 0 {
			return d
		}
	}
	return 90 * 24 * time.Hour
}
