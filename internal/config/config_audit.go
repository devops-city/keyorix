package config

import (
	"time"
)

// AuditConfig groups audit-log delivery integrations.
type AuditConfig struct {
	SIEM SIEMConfig `yaml:"siem"`
	// CheckpointNotary anchors each written audit checkpoint to an external RFC 3161
	// timestamp authority for a forge-proof proof-of-existence (ADR-029). Opt-in.
	CheckpointNotary CheckpointNotaryConfig `yaml:"checkpoint_notary"`
	// OfflineAnchorPath is the offline anchor source for `keyorix-server admin
	// verify-audit` (ADR-108 §B4, design-b4-offline-audit-verify.md §10 Q5): the
	// path to a signed checkpoint export (`admin audit export-checkpoint`'s
	// output) held on write-once media (USB, WORM, an air-gapped transfer),
	// read as the default `--anchor` bundle when the flag is not passed
	// explicitly. verify-audit's own `--anchor <path>` always takes precedence
	// over this when both are set. Lets an operator configure the anchor
	// location once instead of remembering the flag on every offline
	// verification run.
	OfflineAnchorPath string `yaml:"offline_anchor_path"`
}

// CheckpointNotaryConfig configures external-notary anchoring of audit checkpoints.
// type is currently always "rfc3161" (the default when enabled). URL is the TSA's
// timestamp-query endpoint; Timeout is a Go duration (default 15s).
type CheckpointNotaryConfig struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"` // "rfc3161" (default)
	URL     string `yaml:"url"`  // TSA query endpoint, e.g. https://freetsa.org/tsr
	Timeout string `yaml:"timeout"`
	// CACertPath is a PEM bundle of the TSA's trusted root/CA cert(s). REQUIRED to
	// verify a stored anchor's issuer — without it anchoring still records tokens,
	// but verification fails closed (an untrusted/self-signed issuer must not be
	// trusted, since the checkpoint-row writer is the actor the anchor defends
	// against).
	CACertPath string `yaml:"ca_cert_path"`
}

// GetTimeout returns the TSA round-trip timeout (default 15s when unset/unparseable).
func (c CheckpointNotaryConfig) GetTimeout() time.Duration {
	return parseDurationDefault(c.Timeout, 15*time.Second)
}

// SIEMConfig configures native push of audit events to an external SIEM.
// The token is resolved from KEYORIX_SIEM_TOKEN when that env var is set, so it
// need not be written into the config file.
type SIEMConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Provider           string `yaml:"provider"` // splunk | datadog | webhook
	Endpoint           string `yaml:"endpoint"`
	Token              string `yaml:"token"` // use KEYORIX_SIEM_TOKEN env var instead
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	// SpoolDir enables a durable on-disk backlog: events that can't be delivered
	// (full queue / retries exhausted) are persisted here and replayed until the SIEM
	// accepts them, so a sustained outage doesn't silently lose the off-box copy.
	// Empty = best-effort only.
	SpoolDir string `yaml:"spool_dir"`
	// AllowPrivateNetworkTarget opts Endpoint out of the SSRF guard -- a
	// SEPARATE decision from InsecureSkipVerify (#130): an operator forwarding
	// audit events to a self-signed on-prem SIEM collector should not also
	// have to disable the private-network/SSRF check, and vice versa. False
	// by default: Endpoint's resolved host must not be private/link-local/
	// IMDS (loopback is exempt -- see notifychan/evidencesink's identical
	// convention for this class of operator-configured external receiver).
	AllowPrivateNetworkTarget bool `yaml:"insecure_allow_private_network_siem_target"`
	// AllowInsecureTransport permits a plaintext (http://) Endpoint. False by
	// default: Endpoint must be https unless it targets loopback. Every use
	// of this opt-out is logged (2d) -- see internal/netutil.Guard.RequireTLS.
	AllowInsecureTransport bool `yaml:"insecure_allow_plaintext_siem_transport"`
}

// GetToken returns the resolved SIEM token, preferring the environment variable.
func (s *SIEMConfig) GetToken() string {
	return resolveSecret("KEYORIX_SIEM_TOKEN", s.Token)
}

// AuditCheckpointsConfig configures the audit-checkpoint scheduler: a background
// job that signs the audit hash-chain head (ADR-029) so tampering, tail-truncation,
// and genesis re-seed are detectable. This is the audit trail's forgery-resistance
// layer — the per-row hash chain alone is unkeyed and a database-write attacker can
// recompute it, so without signed checkpoints the trail is only tamper-EVIDENT, not
// forgery-resistant. It is therefore enabled BY DEFAULT whenever a signing key is
// available (encryption configured). Set Disabled to opt out (a loud warning is
// logged). Enabled is retained for backward compatibility and is now redundant with
// the default-on behavior.
type AuditCheckpointsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Disabled bool   `yaml:"insecure_disable_audit_checkpoints"`
	Schedule string `yaml:"schedule"`
}

// GetInterval returns the checkpoint write interval (Go duration, e.g. "12h");
// defaults to 24h when unset or unparseable.
func (c AuditCheckpointsConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}
