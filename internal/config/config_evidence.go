package config

import (
	"time"
)

// EvidenceDeliveryConfig configures the scheduled compliance-evidence export
// (ISO 27001 / SOC 2 continuous evidence): a background job that periodically
// generates the auditor evidence pack (the posture plus the records that
// substantiate it) and delivers it to the configured targets — a timestamped JSON
// file under OutputDir, and/or a Webhook that POSTs the pack off-box (so evidence
// survives the node without a mounted volume). Each run also emits a
// compliance.evidence_exported audit event, so an installed SIEM forwarder receives
// the delivery signal too. Opt-in (Enabled, default off); at least one target
// (OutputDir or Webhook) must be configured.
type EvidenceDeliveryConfig struct {
	Enabled     bool                      `yaml:"enabled"`
	Schedule    string                    `yaml:"schedule"`
	OutputDir   string                    `yaml:"output_dir"`
	Webhook     EvidenceWebhookConfig     `yaml:"webhook"`
	ObjectStore EvidenceObjectStoreConfig `yaml:"object_store"`
}

// EvidenceObjectStoreConfig configures the off-box S3-compatible object-storage
// target: each run uploads the pack (and detached signature) to a bucket. Works with
// AWS S3 and S3-compatible stores (MinIO, Cloudflare R2, Backblaze B2, GCS interop)
// via a custom endpoint. Credentials resolve via the standard AWS credential chain
// (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars, shared config, or
// instance/workload identity) — never from Keyorix config.
type EvidenceObjectStoreConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Bucket       string `yaml:"bucket"`         // required when enabled
	Prefix       string `yaml:"prefix"`         // optional key prefix, e.g. "keyorix/evidence/"
	Region       string `yaml:"region"`         // bucket region
	Endpoint     string `yaml:"endpoint"`       // optional custom endpoint for S3-compatible stores
	UsePathStyle bool   `yaml:"use_path_style"` // path-style addressing (MinIO and some gateways)
	// LockMode opts into S3 Object Lock (WORM) on each uploaded object: "" (off),
	// "governance", or "compliance". The bucket must have Object Lock enabled.
	LockMode string `yaml:"lock_mode"`
	// LockRetainDays is the retention window in days; required (> 0) when LockMode set.
	LockRetainDays int `yaml:"lock_retain_days"`
	// LegalHold places an indefinite S3 Object Lock legal hold on each uploaded
	// object (no expiry; cleared only out-of-band). Independent of LockMode; the
	// bucket must have Object Lock enabled.
	LegalHold bool `yaml:"legal_hold"`
}

// EvidenceWebhookConfig configures the off-box webhook target: each run POSTs the
// evidence pack JSON to Endpoint, optionally bearer-authenticated.
type EvidenceWebhookConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Endpoint           string `yaml:"endpoint"`
	Token              string `yaml:"token"` // use KEYORIX_EVIDENCE_WEBHOOK_TOKEN env var instead
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	// AllowPrivateNetworkTarget opts the endpoint out of the SSRF guard — a
	// SEPARATE decision from InsecureSkipVerify; see evidencesink.WebhookConfig.
	AllowPrivateNetworkTarget bool `yaml:"insecure_allow_private_network_evidence_target"`
	// AllowInsecureTransport permits a plaintext (http://) endpoint to a
	// non-loopback host. False by default: Endpoint must be https unless it
	// targets loopback. A SEPARATE decision from AllowPrivateNetworkTarget
	// (previously conflated: enabling AllowPrivateNetworkTarget alone used to
	// ALSO silently unlock cleartext HTTP to any public host, not just a
	// private one — an operator opting in to reach a legitimate internal
	// receiver got a second, unrelated, broader exception for free). Every
	// use of this opt-out is logged; see evidencesink.WebhookConfig.
	AllowInsecureTransport bool `yaml:"insecure_allow_plaintext_evidence_transport"`
}

// GetToken returns the resolved webhook token, preferring the environment variable.
func (c *EvidenceWebhookConfig) GetToken() string {
	return resolveSecret("KEYORIX_EVIDENCE_WEBHOOK_TOKEN", c.Token)
}

// HasTarget reports whether at least one delivery target is configured.
func (c EvidenceDeliveryConfig) HasTarget() bool {
	return c.OutputDir != "" || c.Webhook.Enabled || c.ObjectStore.Enabled
}

// GetInterval returns the evidence-export run interval, parsing Schedule as a Go
// duration (e.g. "24h"); defaults to 24h when unset or unparseable.
func (c EvidenceDeliveryConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}
