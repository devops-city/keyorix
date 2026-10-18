package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/connect/connecttypes"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Environment string           `yaml:"environment"` // label: production (admin init), local (admin init --dev), staging; "development" also enables the localhost CORS origins
	Locale      LocaleConfig     `yaml:"locale"`
	Server      ServerConfig     `yaml:"server"`
	Storage     StorageConfig    `yaml:"storage"`
	Client      *ClientConfig    `yaml:"client,omitempty"`
	Secrets     SecretsConfig    `yaml:"secrets"`
	Security    SecurityConfig   `yaml:"security"`
	SoftDelete  SoftDeleteConfig `yaml:"soft_delete"`
	Purge       PurgeConfig      `yaml:"purge"`
	// MinimumCLIVersion is the lowest CLI semantic version (e.g. "1.2.0") this server
	// accepts, per the tiered version-skew rule (ADR-108 §Decision 3): a CLI build older
	// than this is refused outright, not just warned. Set this after shipping a CLI-side
	// security fix, to force operators onto it. Empty (the default) means no floor beyond
	// the same-major-version rule the CLI applies on its own. Read by
	// GET /api/v1/version (server/http/handlers/version.go) -- unauthenticated, so a CLI
	// can check compatibility before it has credentials.
	MinimumCLIVersion string `yaml:"minimum_cli_version,omitempty"`
	// RotationReminders configures the opt-in background scheduler that notifies
	// project admins of secrets overdue / approaching their rotation deadline.
	RotationReminders RotationRemindersConfig `yaml:"rotation_reminders"`
	// ExpiryReminders configures the opt-in background scheduler that notifies project
	// admins of secrets that have expired or are approaching their expiration.
	ExpiryReminders ExpiryRemindersConfig `yaml:"expiry_reminders"`
	// CertificateExpiry configures the opt-in background scan (ADR-055) that parses
	// certificate-typed secrets and notifies project admins of certificates expired or
	// expiring within the lead window (using the real cert notAfter).
	CertificateExpiry CertificateExpiryConfig `yaml:"certificate_expiry"`
	// AutoRotation configures the opt-in background scheduler that actually rotates
	// auto-rotate-enabled secrets overdue under a policy (ADR-046), regenerating their
	// value. Distinct from rotation_reminders, which only notifies.
	AutoRotation AutoRotationConfig `yaml:"auto_rotation"`
	// AuditCheckpoints configures the opt-in background scheduler that writes
	// signed checkpoints of the audit hash chain (ADR-029) for on-box truncation
	// detection. Requires encryption enabled (the signing key is DEK-derived).
	AuditCheckpoints AuditCheckpointsConfig `yaml:"audit_checkpoints"`
	// JITAccessExpiry configures the opt-in background sweeper that removes
	// time-bound role grants whose expiry has passed (just-in-time access).
	JITAccessExpiry JITAccessExpiryConfig `yaml:"jit_access_expiry"`
	// BreakGlass configures opt-in self-service emergency access (incident response).
	BreakGlass BreakGlassConfig `yaml:"break_glass"`
	// DualControl configures N-of-M approval for access-request grants (A.5.3).
	DualControl DualControlConfig `yaml:"dual_control"`
	// Classification configures whether the "restricted" data-classification label
	// (the highest tier, see internal/core/classification.go) changes read-time
	// behaviour. Disabled (zero value) = the label stays purely informational,
	// exactly like every deployment today — required so enabling this feature is
	// never a surprise breaking change for an install that already uses
	// "restricted" as a label with no enforcement behind it.
	Classification ClassificationConfig `yaml:"classification"`
	// AnomalyAlerts configures proactive alerting for detected access anomalies.
	AnomalyAlerts AnomalyAlertsConfig `yaml:"anomaly_alerts"`
	// DataRetention configures the opt-in scheduler that hard-deletes compliance
	// records past their per-record-type retention window (ISO 27001 A.5.33 /
	// GDPR storage-limitation / DORA). Respects legal hold; audit events are never
	// purged (append-only, ADR-029).
	DataRetention DataRetentionConfig `yaml:"data_retention"`
	// EvidenceDelivery configures the opt-in scheduler that periodically generates
	// the auditor evidence pack and writes it to an output directory for off-box
	// archival (ISO 27001 / SOC 2 continuous evidence).
	EvidenceDelivery EvidenceDeliveryConfig `yaml:"evidence_delivery"`
	// Recertification configures the opt-in scheduler that enforces an access-review
	// cadence (ISO 27001 A.5.18): reminding admins of (or auto-opening) recert
	// campaigns for projects overdue for review.
	Recertification RecertificationConfig `yaml:"recertification"`
	// Notifications configures external delivery (email/webhook) of the in-app
	// notifications Keyorix creates (approvals, anomalies, reminders, break-glass).
	Notifications NotificationsConfig `yaml:"notifications"`
	// ComplianceDigest configures the opt-in scheduler that periodically broadcasts a
	// posture + control-matrix summary to the configured notification channels.
	ComplianceDigest ComplianceDigestConfig `yaml:"compliance_digest"`
	// SCIM configures the SCIM 2.0 provisioning endpoints (RFC 7644) used by an IdP
	// to provision/deprovision users. Disabled (zero value) = /scim/v2 is not served.
	SCIM SCIMConfig `yaml:"scim"`
	// SSO configures human single-sign-on login via OIDC (authorization-code flow):
	// users sign in through their IdP and Keyorix mints a session. Disabled (zero
	// value) = the /auth/sso endpoints are not served.
	SSO SSOConfig `yaml:"sso"`
	// DynamicSecrets configures the on-demand database-credentials engine and its
	// auto-revoke sweep (ADR-035). Disabled (zero value) = the API is still served
	// but no background sweeper runs; enable to auto-revoke leases at expiry.
	DynamicSecrets DynamicSecretsConfig `yaml:"dynamic_secrets"`
	// WebAuthn configures passkey / FIDO2 second-factor auth (ADR-036). Disabled
	// (zero value) = passkey endpoints return "not enabled"; enable + set the RP ID
	// and origins to allow registration and assertion.
	WebAuthn WebAuthnConfig `yaml:"webauthn"`
	// OIDC configures machine-identity federation (ADR-031): trusted issuers
	// whose JWTs (e.g. Kubernetes projected service-account tokens) Keyorix
	// verifies and maps to a machine identity. Empty/disabled = OIDC auth off.
	OIDC       OIDCConfig       `yaml:"oidc"`
	Audit      AuditConfig      `yaml:"audit"`
	Membership MembershipConfig `yaml:"membership"`
	Session    SessionConfig    `yaml:"session"`

	// CredentialDelivery configures how a new principal receives their first-credential
	// setup link (ADR-028). Absent (zero value) = auto mode, out-of-band when no SMTP.
	CredentialDelivery CredentialDeliveryConfig `yaml:"credential_delivery"`

	// SecretValuePolicy is an optional quality gate on secret VALUES (reject weak/
	// placeholder values at create/rotate). Disabled (zero value) by default.
	SecretValuePolicy SecretValuePolicyConfig `yaml:"secret_value_policy"`

	// SecretNamePolicy is an optional naming convention on secret NAMES (regex /
	// max-length, enforced at create). Disabled (zero value) by default.
	SecretNamePolicy SecretNamePolicyConfig `yaml:"secret_name_policy"`

	// PasswordPolicy is optional. When the block is absent (zero value), the
	// server keeps its conservative built-in defaults (see core.DefaultPasswordPolicy);
	// when present, the install's values fully replace them.
	PasswordPolicy PasswordPolicyConfig `yaml:"password_policy"`

	// Connect configures Keyorix Connect (ADR-043): read-through federation to
	// external secret stores. Disabled (zero value) = the /connect endpoints are not
	// served.
	Connect ConnectConfig `yaml:"connect"`

	// License configures offline commercial-license validation (ADR-065). Absent (zero
	// value) = no license installed → the community baseline (no commercial features).
	// Enforcement is fail-safe: a missing/expired/invalid license never denies access or
	// stops the server; it degrades to the baseline with an admin warning + audit event.
	License LicenseConfig `yaml:"license"`

	// LicenseExpiry configures the opt-in background reminder that notifies install-wide
	// admins when the offline license is approaching or past expiry (ADR-065 Phase 2c).
	LicenseExpiry LicenseExpiryConfig `yaml:"license_expiry"`

	// ReadQuotaAlerts configures the opt-in background scheduler that scans all
	// secrets with MaxReads > 0 and sends in-app notifications to their owners
	// when the read count approaches or reaches the limit.
	ReadQuotaAlerts ReadQuotaAlertsConfig `yaml:"read_quota_alerts"`

	// DeprecatedSettingWarnings lists every ADR-112 deprecated-alias key Load()
	// found in this config file (old name -> current insecure_ name), one
	// human-readable line per key. Computed by Load() from the raw YAML before
	// the deprecated keys are translated away; never itself read from YAML. The
	// caller (server/main.go) logs each line as a start-up warning.
	DeprecatedSettingWarnings []string `yaml:"-"`
}

// LicenseConfig points at an installed offline license token and tunes its evaluation
// (ADR-065). All fields are optional; an empty Path means no license is installed.
type LicenseConfig struct {
	// Path is the file holding the license token (as written by `keyorix license install`).
	Path string `yaml:"path"`
	// DeploymentID, when set, is checked against a license bound to a deployment; a
	// mismatch degrades to the baseline (it never shuts the server down).
	DeploymentID string `yaml:"deployment_id"`
	// GraceHours is the post-expiry tolerance window during which features are retained
	// (with a loud warning) so a lapse doesn't instantly drop entitlement. Default 336 (14d).
	GraceHours int `yaml:"grace_hours"`
}

// LicenseGrace returns the configured post-expiry grace window, defaulting to 14 days.
func (c *Config) LicenseGrace() time.Duration {
	if c.License.GraceHours <= 0 {
		return 14 * 24 * time.Hour
	}
	return time.Duration(c.License.GraceHours) * time.Hour
}

// ConnectConfig configures read-through federation to external secret stores
// (ADR-043). Opt-in: with no connectors (or Enabled false) the /connect API is off.
type ConnectConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Connectors []ConnectorConfig `yaml:"connectors"`
}

// ConnectorConfig describes one external-store connector. Name is the API path key
// (unique); Type selects the backend ("aws-secrets-manager"); Region is the backend
// region where applicable. Credentials come from the backend's ambient identity
// chain, never from here.
type ConnectorConfig struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Region string `yaml:"region"`
	// Address is the backend base URL: the Vault server for type "vault"
	// (e.g. https://vault:8200), or the Key Vault URL for type "azure-key-vault"
	// (e.g. https://myvault.vault.azure.net/).
	Address string `yaml:"address"`
	// ProjectID pins a "gcp-secret-manager" connector to a single GCP project (#431):
	// every ref must embed this exact project ID
	// (projects/PROJECT/secrets/NAME/versions/VERSION), or the read is rejected before
	// reaching the backend. Unlike Address for "vault"/"azure-key-vault", a GCP ref
	// carries its own project ID, so leaving this unset would let a single connector
	// (and the ambient ADC identity it runs under) address secrets in ANY project
	// that identity can reach, regardless of this connector's Keyorix-side tenant
	// scope (a confused-deputy gap). Required, unconditionally, for every
	// "gcp-secret-manager" connector — validateConnectGCPProjectID (below) fails
	// boot on an unset value, with no deployment-wide escape hatch, mirroring how
	// Scope has none. An existing deployment upgrading past this change must add
	// project_id to every gcp-secret-manager connector first (see CHANGELOG.md).
	// Unrelated to Project below — this is a GCP-side identifier, Project is Keyorix's.
	ProjectID string `yaml:"project_id"`
	// AccountID optionally pins an "aws-secrets-manager" connector to a single AWS
	// account: an ARN-shaped ref naming a DIFFERENT account is rejected before the
	// backend call. Unlike ProjectID above, this is NOT required: a bare secret-name
	// ref (the common shape) is always resolved within the ambient credential's own
	// AWS account by the Secrets Manager API itself, so it never carries a competing
	// account to check, and a full-ARN ref naming another account additionally
	// requires that target account's own resource policy to have separately granted
	// cross-account access (a double opt-in, unlike GCP's single-opt-in
	// ambient-reach gap — see internal/connect/awssm.go's doc comment). When set,
	// validateConnectAWSAccountID (below) fails boot if it is not exactly 12 digits
	// (the AWS account ID format); when unset, server/main.go logs a startup
	// recommendation but boots — a deliberate phase-in, not a bug: making this
	// mandatory would force every connector that only ever reads bare-name refs
	// (which cannot cross accounts regardless) to configure a field with zero
	// enforcement value for them.
	AccountID string `yaml:"account_id"`
	// TokenEnv names the environment variable holding the backend token for type
	// "vault" (default "VAULT_TOKEN"). The token is read from the environment, never
	// from this file.
	TokenEnv string `yaml:"token_env"`
	// AllowedRefs, when non-empty, restricts which secret references this connector
	// may read: a requested ref must have one of these prefixes (a defense-in-depth
	// guardrail in Keyorix's layer, on top of the backend identity's IAM policy). An
	// empty list places no restriction here — the backend IAM scope is then the only
	// bound, so prefer setting both.
	AllowedRefs []string `yaml:"allowed_refs"`
	// Scope declares this connector's tenant boundary (ADR-082): "project" (owned by
	// exactly one Keyorix project — requires Project) or "platform" (org-wide; requires
	// the connect.platform.use permission at authorization time, must NOT set Project).
	// Required, unconditionally: a missing or unrecognized value (anything other than
	// "project"/"platform") always fails boot. There is no escape hatch — an operator
	// migrating an existing config adds scope: to every connector before upgrading; see
	// ADR-082 §C for why that boot-fail-loud requirement has no deployment-wide bypass.
	Scope string `yaml:"scope"`
	// Project names the Keyorix project that owns this connector, by NAME — not a
	// numeric ID. A numeric project ID differs per deployment (the same logical project
	// has a different row ID in every install's database), which would break config
	// portability across environments and air-gap bundles; a name travels with the
	// config unchanged. Required when Scope is "project"; must be empty when Scope is
	// "platform" (a platform connector is not owned by any single project — setting
	// both is a contradiction, and fails boot). This branch only checks presence — the
	// name is resolved to a real project ID at boot in a later branch (ADR-082 §A/§D);
	// an unresolvable name fails boot at that point, not here.
	Project string `yaml:"project"`
	// Environment optionally further scopes a "project"-scoped connector to one
	// environment within Project, by name. Reserved (ADR-082 §G): accepted and stored,
	// but NOT enforced — every environment within Project is currently treated
	// identically for authorization purposes regardless of this field. Enforcement
	// semantics are a real design question deferred to a follow-up ADR, not decided
	// here.
	Environment string `yaml:"environment"`
}

// PasswordPolicyConfig mirrors the password rules from ADR-025: synchronous
// complexity rules plus the stateful rules (reject_common_passwords,
// history_count, max_age_days) backed by the password-history table.
//
// #G37: MinLength/RequireUppercase/RequireLowercase/RequireDigit/RequireSpecial/
// RejectPersonalInfo/RejectCommonPasswords/HistoryCount are pointers so "unset"
// is distinguishable from an explicit false/0 — a PARTIAL password_policy block
// (e.g. only reject_common_passwords set) must not silently zero out every
// other rule it didn't mention. Resolve merges unset fields onto a caller-
// supplied default (core.DefaultPasswordPolicy()) instead. MaxAgeDays stays a
// plain int: its safe default (0 = never expires, ADR-025) equals the Go zero
// value, so there is no unset/explicit-off ambiguity to resolve.
type PasswordPolicyConfig struct {
	MinLength          *int  `yaml:"min_length"`
	RequireUppercase   *bool `yaml:"require_uppercase"`
	RequireLowercase   *bool `yaml:"require_lowercase"`
	RequireDigit       *bool `yaml:"require_digit"`
	RequireSpecial     *bool `yaml:"require_special"`
	RejectPersonalInfo *bool `yaml:"reject_personal_info"`
	// RejectCommonPasswords rejects passwords on the curated common-password list.
	RejectCommonPasswords *bool `yaml:"reject_common_passwords"`
	// HistoryCount forbids reusing the last N passwords (0 = no history check).
	HistoryCount *int `yaml:"history_count"`
	// MaxAgeDays expires a password after N days (0 = never expires).
	MaxAgeDays int `yaml:"max_age_days"`
}

// PasswordPolicyValues is the fully-resolved (no-longer-optional) form of
// PasswordPolicyConfig — field-for-field identical to core.PasswordPolicy, but
// defined here (rather than importing internal/core, which would cycle back
// through internal/encryption) so config.Resolve can stay in this package.
type PasswordPolicyValues struct {
	MinLength             int
	RequireUppercase      bool
	RequireLowercase      bool
	RequireDigit          bool
	RequireSpecial        bool
	RejectPersonalInfo    bool
	RejectCommonPasswords bool
	HistoryCount          int
	MaxAgeDays            int
}

// Resolve merges p's explicitly-set fields onto defaults (the caller's
// core.DefaultPasswordPolicy(), converted to PasswordPolicyValues), so a partial
// password_policy block overrides only the rules it actually names — see the
// #G37 note on PasswordPolicyConfig above.
func (p PasswordPolicyConfig) Resolve(defaults PasswordPolicyValues) PasswordPolicyValues {
	resolved := defaults
	if p.MinLength != nil {
		resolved.MinLength = *p.MinLength
	}
	if p.RequireUppercase != nil {
		resolved.RequireUppercase = *p.RequireUppercase
	}
	if p.RequireLowercase != nil {
		resolved.RequireLowercase = *p.RequireLowercase
	}
	if p.RequireDigit != nil {
		resolved.RequireDigit = *p.RequireDigit
	}
	if p.RequireSpecial != nil {
		resolved.RequireSpecial = *p.RequireSpecial
	}
	if p.RejectPersonalInfo != nil {
		resolved.RejectPersonalInfo = *p.RejectPersonalInfo
	}
	if p.RejectCommonPasswords != nil {
		resolved.RejectCommonPasswords = *p.RejectCommonPasswords
	}
	if p.HistoryCount != nil {
		resolved.HistoryCount = *p.HistoryCount
	}
	resolved.MaxAgeDays = p.MaxAgeDays
	return resolved
}

type LocaleConfig struct {
	Language         string `yaml:"language"`
	FallbackLanguage string `yaml:"fallback_language"`
}

// LocaleSettings returns the configured language and fallback language. It
// satisfies i18n.LocaleSource, so i18n.Initialize(cfg) works without the i18n
// package importing this one.
func (c *Config) LocaleSettings() (language, fallbackLanguage string) {
	return c.Locale.Language, c.Locale.FallbackLanguage
}

type ServerConfig struct {
	HTTP      ServerInstanceConfig `yaml:"http"`
	GRPC      ServerInstanceConfig `yaml:"grpc"`
	AccessLog AccessLogConfig      `yaml:"access_log,omitempty"`
	Log       LogConfig            `yaml:"log,omitempty"`
}

// Values of server.log.format.
const (
	LogFormatText = "text"
	LogFormatJSON = "json"
)

// LogConfig configures the server's log output format (not the audit trail).
type LogConfig struct {
	// Format is "" or "text" (default: the existing human-readable lines) or "json"
	// (one JSON object per line with ts, level, msg and, where known, request_id,
	// principal_type and route; see docs/operations/logging.md). Any other value is
	// rejected by Validate.
	Format string `yaml:"format,omitempty"`
}

// EffectiveFormat returns the format in effect: "text" when unset.
func (l LogConfig) EffectiveFormat() string {
	if l.Format == "" {
		return LogFormatText
	}
	return l.Format
}

func validateLogFormat(v string) error {
	switch v {
	case "", LogFormatText, LogFormatJSON:
		return nil
	}
	return fmt.Errorf("server.log.format: unknown value %q (want %q or %q)", v, LogFormatText, LogFormatJSON)
}

// Values of server.access_log.on_sink_stall.
const (
	// AccessLogOnSinkStallBlock (the default) makes a request wait when the
	// access-log queue is full because the log sink has stalled: no line is ever
	// lost, but every request stalls with the sink.
	AccessLogOnSinkStallBlock = "block"
	// AccessLogOnSinkStallDrop keeps serving when the sink stalls; lines past the
	// 1 MiB queue are dropped, counted, and reported.
	AccessLogOnSinkStallDrop = "drop"
)

// AccessLogConfig configures the HTTP access log (not the audit trail).
type AccessLogConfig struct {
	// OnSinkStall is what a request does when the access-log sink (stdout, a
	// pipe to a log collector) has stalled and the 1 MiB in-memory queue is full.
	//
	//   - "" or "block" (default): wait for the sink. No access-log line is ever
	//     lost; requests stall while the sink does.
	//   - "drop": keep serving secrets. Lines past the queue are dropped, counted
	//     (GET /api/v1/system/info security.access_log_dropped), and reported by a
	//     rate-limited warning plus a recovery line. The audit trail is unaffected:
	//     it is written separately and never dropped.
	//
	// Config file only, like the fast audit mode, since "drop" trades log
	// completeness for availability. Any other value is rejected by Validate.
	OnSinkStall string `yaml:"on_sink_stall,omitempty"`
}

// EffectiveOnSinkStall returns the mode in effect: "block" when unset.
func (a AccessLogConfig) EffectiveOnSinkStall() string {
	if a.OnSinkStall == "" {
		return AccessLogOnSinkStallBlock
	}
	return a.OnSinkStall
}

func validateAccessLogOnSinkStall(v string) error {
	switch v {
	case "", AccessLogOnSinkStallBlock, AccessLogOnSinkStallDrop:
		return nil
	}
	return fmt.Errorf("server.access_log.on_sink_stall: unknown value %q (want %q or %q)",
		v, AccessLogOnSinkStallBlock, AccessLogOnSinkStallDrop)
}

// DefaultBindHost is the listen address used when server.http.host /
// server.grpc.host is unset: loopback only. Reaching the server from another
// machine (a container, a Kubernetes pod, a LAN demo) is an explicit opt-in,
// e.g. host: "0.0.0.0". (#2939: the listeners used to bind all interfaces
// while the startup log claimed 127.0.0.1.)
const DefaultBindHost = "127.0.0.1"

type ServerInstanceConfig struct {
	Enabled bool `yaml:"enabled"`
	// Host is the address the listener binds to. Empty means DefaultBindHost
	// (loopback only). Use "0.0.0.0" or "::" to listen on all interfaces.
	Host             string    `yaml:"host"`
	Port             string    `yaml:"port"`
	ProtocolVersions []string  `yaml:"protocol_versions"`
	TLS              TLSConfig `yaml:"tls"`
	// TLSMode switches the TLS posture from the default (TLS 1.2 floor,
	// restricted to the forward-secret AEAD suites in hardenedCipherSuites /
	// tls.allowed_ciphers) to "strict": TLS 1.3 only, nothing below it ever
	// accepted. ADR-112 §3 (decided 2026-10-02): TLS 1.2 with modern ciphers
	// stays compliant, not an insecure_ opt-out — NIST SP 800-52 Rev. 2
	// requires servers to support both 1.2 and 1.3, BSI TR-02102-2 prefers
	// 1.3 while planning 1.2's phase-out, and OT/legacy clients still need
	// 1.2 — so "strict" is an explicit UPGRADE an operator opts INTO, not a
	// downgrade to warn about. Empty ("") = the default (1.2 floor); any
	// other value is rejected at Validate() time. See applyTLSHardening
	// (server/main.go, server/grpc/server.go) for where this is wired in.
	TLSMode           string          `yaml:"tls_mode,omitempty"`
	RateLimit         RateLimitConfig `yaml:"ratelimit"`
	SwaggerEnabled    bool            `yaml:"swagger_enabled,omitempty"`
	ReflectionEnabled bool            `yaml:"reflection_enabled,omitempty"`
	// MaxRequestBodyBytes caps each request body to mitigate memory-exhaustion DoS from
	// an oversized payload. 0 uses a generous default (10 MiB — well above any normal
	// JSON request); a negative value disables the cap (for endpoints that legitimately
	// accept very large bodies).
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes,omitempty"`
	// TrustedProxies is the set of reverse-proxy/load-balancer source addresses (CIDRs
	// or bare IPs) whose X-Forwarded-For / X-Real-IP header is honored when deriving the
	// client IP. When empty, those headers are IGNORED and the real TCP peer is used —
	// so a client cannot spoof its source IP (which would otherwise defeat the per-IP
	// login/MFA rate limiter) unless it actually connects from a trusted proxy. Set this
	// to your ingress/LB CIDR(s) when running behind a proxy. (HTTP only.)
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
	// HSTSPreload adds the "preload" directive to the Strict-Transport-Security header
	// (sent when this listener serves TLS, or a trusted proxy reports
	// X-Forwarded-Proto: https). Off by default: submitting a domain to the browser
	// preload lists covers every subdomain and is slow to undo, so only the domain's
	// owner opts in. (HTTP only.)
	HSTSPreload bool `yaml:"hsts_preload,omitempty"`
	// Web dashboard specific settings (HTTP only)
	WebAssetsPath  string   `yaml:"web_assets_path,omitempty"`
	AllowedOrigins []string `yaml:"allowed_origins,omitempty"`
	Domain         string   `yaml:"domain,omitempty"`
	// MetricsToken, when non-empty, requires callers to present a matching
	// "Authorization: Bearer <token>" header to reach GET /metrics. When empty
	// (the default) /metrics is unauthenticated — restrict network access at the
	// perimeter. Set this to a long random token for any internet-facing deployment.
	MetricsToken string `yaml:"metrics_token,omitempty"`
	// MetricsTokenFile names a file holding the metrics token instead (same rules
	// as a KEYORIX_*_FILE secret file: regular file, one trailing newline
	// stripped, must not be empty, owner/group-readable only). `keyorix-server
	// admin init` generates one at 0600 and points both listeners at it. Setting
	// both metrics_token and metrics_token_file refuses to start.
	MetricsTokenFile string `yaml:"metrics_token_file,omitempty"`
	// Keepalive tunes server-side connection keepalive/idle-reclaim (#222/#435). GRPC
	// only — an authenticated credential holder can otherwise open many long-lived,
	// mostly-idle connections that the server has no way to detect and reclaim, a
	// slow-drip goroutine/fd exhaustion surface distinct from the per-principal
	// concurrency cap already applied to StreamAuditLogs.
	Keepalive GRPCKeepaliveConfig `yaml:"keepalive,omitempty"`
}

// GRPCKeepaliveConfig tunes the gRPC server's keepalive ping and enforcement policy
// (#222/#435). Every field is a Go duration string (e.g. "5m", "20s"); empty/unparseable
// values fall back to the documented default via the Get* accessors below.
type GRPCKeepaliveConfig struct {
	// Time is how long the server waits on an idle connection before sending a
	// keepalive ping to check it's still alive. Default 5m when unset/unparseable.
	Time string `yaml:"time,omitempty"`
	// Timeout is how long the server waits for a ping ack before closing the
	// connection as dead. Default 20s when unset/unparseable.
	Timeout string `yaml:"timeout,omitempty"`
	// MinTime is the minimum interval a client is allowed to send keepalive pings on;
	// a client pinging more often than this is judged abusive and sent GOAWAY
	// ENHANCE_YOUR_CALM. Default 5m when unset/unparseable.
	MinTime string `yaml:"min_time,omitempty"`
	// PermitWithoutStream, if true, lets a client send keepalive pings even with no
	// active RPC/stream open. No client in this codebase pings without an active
	// call (StreamAuditLogs keeps its stream open for the duration it needs pings),
	// so this defaults to false — rejecting streamless pings closes off a cheap
	// ping-flood vector from a valid credential holder that never opens an RPC.
	PermitWithoutStream bool `yaml:"permit_without_stream,omitempty"`
	// MaxConnectionAge is the maximum duration a connection may be kept open before
	// the server sends a GOAWAY and begins graceful shutdown of that connection.
	// Forces periodic reconnection so stream-slot-holding attacks (GRPC-008) cannot
	// pin audit-stream slots indefinitely. Default 1h when unset/unparseable.
	MaxConnectionAge string `yaml:"max_connection_age,omitempty"`
	// MaxConnectionAgeGrace is how long after MaxConnectionAge the server waits for
	// active RPCs to finish before force-closing. Default 30s when unset/unparseable.
	MaxConnectionAgeGrace string `yaml:"max_connection_age_grace,omitempty"`
	// MaxConnectionIdle closes a connection that has had no RPC in flight for this
	// long. Keepalive pings alone never reclaim it: a live client acks them, so an
	// authenticated caller could otherwise park idle connections until the server
	// runs out of descriptors. Default 15m when unset/unparseable.
	MaxConnectionIdle string `yaml:"max_connection_idle,omitempty"`
	// HandshakeTimeout bounds a new connection's TLS handshake plus HTTP/2 preface.
	// grpc-go's own default is 120s, which lets a client that opens TCP and sends
	// nothing hold a connection for two minutes. Default 10s when unset/unparseable.
	HandshakeTimeout string `yaml:"handshake_timeout,omitempty"`
}

// defaultGRPCKeepaliveTime/Timeout/MinTime are the server-side keepalive defaults
// applied when the operator hasn't configured server.grpc.keepalive.* (#222/#435).
const (
	defaultGRPCKeepaliveTime         = 5 * time.Minute
	defaultGRPCKeepaliveTimeout      = 20 * time.Second
	defaultGRPCKeepaliveMinTime      = 5 * time.Minute
	defaultGRPCMaxConnectionAge      = 1 * time.Hour
	defaultGRPCMaxConnectionAgeGrace = 30 * time.Second
	defaultGRPCMaxConnectionIdle     = 15 * time.Minute
	defaultGRPCHandshakeTimeout      = 10 * time.Second
)

// GetTime returns the idle-before-ping interval (default 5m).
func (c GRPCKeepaliveConfig) GetTime() time.Duration {
	return parseDurationDefault(c.Time, defaultGRPCKeepaliveTime)
}

// GetTimeout returns the ping-ack wait before the connection is closed as dead
// (default 20s).
func (c GRPCKeepaliveConfig) GetTimeout() time.Duration {
	return parseDurationDefault(c.Timeout, defaultGRPCKeepaliveTimeout)
}

// GetMinTime returns the minimum interval a client may send keepalive pings on
// before being treated as abusive (default 5m).
func (c GRPCKeepaliveConfig) GetMinTime() time.Duration {
	return parseDurationDefault(c.MinTime, defaultGRPCKeepaliveMinTime)
}

func (c GRPCKeepaliveConfig) GetMaxConnectionAge() time.Duration {
	return parseDurationDefault(c.MaxConnectionAge, defaultGRPCMaxConnectionAge)
}

func (c GRPCKeepaliveConfig) GetMaxConnectionAgeGrace() time.Duration {
	return parseDurationDefault(c.MaxConnectionAgeGrace, defaultGRPCMaxConnectionAgeGrace)
}

// GetMaxConnectionIdle returns how long a connection may sit with no RPC in flight
// before the server closes it (default 15m).
func (c GRPCKeepaliveConfig) GetMaxConnectionIdle() time.Duration {
	return parseDurationDefault(c.MaxConnectionIdle, defaultGRPCMaxConnectionIdle)
}

// GetHandshakeTimeout returns the bound on a new connection's TLS handshake and
// HTTP/2 preface (default 10s).
func (c GRPCKeepaliveConfig) GetHandshakeTimeout() time.Duration {
	return parseDurationDefault(c.HandshakeTimeout, defaultGRPCHandshakeTimeout)
}

// defaultMaxRequestBodyBytes is the request-body cap when none is configured.
const defaultMaxRequestBodyBytes = 10 << 20 // 10 MiB

// ResolveMetricsToken returns the token GET /metrics requires: metrics_token, or
// the contents of metrics_token_file. "" with a nil error means no token is
// configured. Both set, or an unreadable/empty file, is an error, and the
// caller must not fall back to serving /metrics unauthenticated:
// Config.Validate refuses to start on it.
func (s ServerInstanceConfig) ResolveMetricsToken() (string, error) {
	switch {
	case s.MetricsToken != "" && s.MetricsTokenFile != "":
		return "", fmt.Errorf("both metrics_token and metrics_token_file are set; set exactly one")
	case s.MetricsTokenFile != "":
		v, err := secretenv.ReadFile(s.MetricsTokenFile)
		if err != nil {
			return "", fmt.Errorf("metrics_token_file %q: %w", s.MetricsTokenFile, err)
		}
		return v, nil
	}
	return s.MetricsToken, nil
}

// metricsTokenMissing reports whether either listener serves /metrics without a
// token. An unresolvable metrics_token_file counts as missing (fail closed).
func (c *Config) metricsTokenMissing() bool {
	for _, s := range []ServerInstanceConfig{c.Server.HTTP, c.Server.GRPC} {
		if tok, err := s.ResolveMetricsToken(); err != nil || tok == "" {
			return true
		}
	}
	return false
}

// EffectiveMaxRequestBodyBytes returns the request-body cap to enforce: the configured
// value, or a 10 MiB default when unset (0). A negative value is returned as-is and
// disables the cap at the middleware.
func (s ServerInstanceConfig) EffectiveMaxRequestBodyBytes() int64 {
	if s.MaxRequestBodyBytes == 0 {
		return defaultMaxRequestBodyBytes
	}
	return s.MaxRequestBodyBytes
}

type TLSConfig struct {
	Enabled  bool     `yaml:"enabled"`
	AutoCert bool     `yaml:"auto_cert,omitempty"`
	Domains  []string `yaml:"domains,omitempty"`
	// CertCacheDir is the directory autocert uses to persist ACME certificates
	// between restarts. Defaults to "certs" (relative to the working directory).
	// Use an absolute path in production to avoid ambiguity. The directory is
	// created with mode 0700 (owner-only) on startup if it does not exist.
	CertCacheDir string `yaml:"cert_cache_dir,omitempty"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	// AllowedCiphers optionally restricts the TLS 1.2 cipher suites offered to
	// SecureCipherSuiteNames' names (e.g. "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384").
	// Left empty/unset, the caller's own hardcoded secure AEAD-only default applies
	// unchanged (see ResolveCipherSuites, and server/main.go's + server/grpc/server.go's
	// applyTLSHardening, which wire this in — #333). Any name outside
	// SecureCipherSuiteNames — including weak/deprecated suites (RC4, 3DES, CBC-mode)
	// and TLS 1.3 suite names, which don't apply to CipherSuites at all — is rejected
	// at startup rather than silently ignored or accepted.
	AllowedCiphers []string `yaml:"allowed_ciphers"`
}

type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerSecond int  `yaml:"requests_per_second"`
	Burst             int  `yaml:"burst"`
}

type StorageConfig struct {
	Type string `yaml:"type"` // "local" (alias "sqlite"), "postgres", "postgresql", "remote"
	// "remote" is rejected unconditionally by Validate (validateRemoteStorageNotServer,
	// ADR-083) -- this Config type is only ever used to configure a server process, and
	// remote storage is a CLI/client mode only. There is deliberately no Remote field
	// here: a "remote" storage.type config carries no server-side settings to parse.
	Database   DatabaseConfig   `yaml:"database"`
	Encryption EncryptionConfig `yaml:"encryption"`
}

type DatabaseConfig struct {
	// SQLite
	Path string `yaml:"path"`

	// RequireExistingPath (INV-STORAGE-22, ADR-095 "Task 3", #2504) makes the
	// server REFUSE to boot when the SQLite file at Path does not already
	// exist, instead of letting gorm.Open silently vivify a fresh, empty,
	// healthy-looking store. A mistyped path or a volume mount that failed to
	// attach otherwise produces a working server with zero secrets in it and
	// no error anywhere — the operator's own data is still on disk, untouched,
	// at the path they meant.
	//
	// Default false, i.e. today's create-if-missing behaviour, DELIBERATELY:
	// nothing in the supported first-boot paths creates the database file
	// before the server starts (server/entrypoint.sh and docker-compose.yml
	// both boot the server directly; `keyorix system init --database`, the
	// explicit "yes, a fresh install belongs here" marker ADR-095 names, is
	// optional), so defaulting this to true would break every containerized
	// first boot. ADR-095 Task 3 says the flip "deserves a deliberate
	// sign-off rather than landing inside a same-day investigation" — this
	// field is that sign-off's prerequisite, not the flip itself.
	//
	// Does not apply to an in-memory DSN (":memory:", "mode=memory"), which
	// has no file to pre-exist, nor to the Postgres backend.
	RequireExistingPath bool `yaml:"require_existing_path"`

	// PostgreSQL — use DSN directly or set individual fields
	DSN      string `yaml:"dsn"` // e.g. "host=localhost user=keyorix dbname=keyorix port=5432 sslmode=require"
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Name     string `yaml:"name"`
	User     string `yaml:"user"`
	Password string `yaml:"password"` // use KEYORIX_DB_PASSWORD env var instead
	SSLMode  string `yaml:"ssl_mode"` // disable, require, verify-ca, verify-full
	// SSLRootCert is the PEM file of the CA that signed the PostgreSQL
	// server's certificate, passed to the driver as sslrootcert (or "system"
	// for the OS CA store). REQUIRED when ssl_mode is verify-full/verify-ca:
	// without it the server refuses to start rather than verify against a
	// trust store the config does not name. A relative path is anchored to
	// the config file's directory, like database.path. See database_tls.go.
	SSLRootCert string `yaml:"ssl_root_cert"`

	// Shared pool settings
	MaxOpenConns           int `yaml:"max_open_conns"`
	MaxIdleConns           int `yaml:"max_idle_conns"`
	ConnMaxLifetimeMinutes int `yaml:"conn_max_lifetime_minutes"`

	// NativeReadPoolMax caps the Postgres pool the hottest read-path statements
	// run on (the machine credential lookup and the node-stamp read; see
	// storage.NativeReadPoolMaxSize). 0 or unset is DefaultNativeReadPoolMax.
	// Never more than the request pool's own cap. Postgres only.
	NativeReadPoolMax int `yaml:"native_read_pool_max"`

	// AuditFlusherLingerWindow (SESSION-PERF, #2420 follow-up) is how long the
	// audit-chain batching flusher deliberately waits, after its first queued
	// item, for more items to arrive before committing — a Go duration string
	// (e.g. "1ms"), or empty/unset for the default. Default is "0" (no
	// deliberate wait — drain whatever's already queued and commit
	// immediately), NOT a tuned nonzero value: measurement across 0/0.5/1/2ms
	// found every nonzero window pays a fixed ~5.5-7ms tax on a single-client
	// read regardless of its nominal size, and on Postgres specifically any
	// nonzero window regresses c=10 throughput even though it roughly doubles
	// c=50 throughput (see PR #2420's body for the full data). Left
	// configurable, rather than removed, so a deployment with real production
	// batch-size telemetry (keyorix_audit_flusher_batch_size,
	// keyorix_audit_flusher_flushes_total) justifying a nonzero value can set
	// one without a code change.
	AuditFlusherLingerWindow string `yaml:"audit_flusher_linger_window"`

	// AuditDurability (ADR-112 Amendment 3, docs/specs/fast-audit-mode.md)
	// chooses whether the audit commit waits for the disk sync. Config file
	// only; no HTTP handler, gRPC RPC, env var or CLI flag can set it (the
	// guards are TestAuditDurability_NoWriteAssignment and
	// TestAuditDurability_NotSettableFromTheEnvironment). Read it through
	// EffectiveAuditDurability, never directly: the default depends on the
	// backend and on the deprecated alias below.
	//
	//   - "strict": the audit commit waits for the disk sync. No audit entry
	//     is lost to any crash or power loss. The only level on SQLite.
	//   - "standard": the audit row is still INSERTed and COMMITted before the
	//     secret is returned, and a failed audit write still fails the
	//     request; only the wait for the disk sync is skipped (`SET LOCAL
	//     synchronous_commit = off` on the audit transaction, and only that
	//     transaction). A Keyorix process crash loses nothing; an OS crash,
	//     power loss or PostgreSQL crash can lose up to ~600 ms (3 ×
	//     wal_writer_delay) of audit entries as a TAIL, never a gap or a fork.
	//     PostgreSQL only, and the PostgreSQL default.
	//   - "" (unset): the backend default -- standard on PostgreSQL, strict on
	//     SQLite.
	//
	// Non-audit writes (secret writes, revocations, rotations) commit durably
	// at both levels. SQLite refuses standard at start-up
	// (auditDurabilityStandardSQLiteUnsupportedError): its synchronous pragma
	// is per-connection and the pool is shared, so relaxing it would relax
	// every table, not only audit (Amendment 1's rejection, which stands).
	AuditDurability string `yaml:"audit_durability"`

	// InsecureAuditSkipDurableSync is the DEPRECATED alias of AuditDurability,
	// kept for one minor release (ADR-112 Amendment 3): true means standard,
	// an explicit false means strict, absent means "not set". A pointer so an
	// explicit false is distinguishable from an absent key. Setting both keys
	// to conflicting levels refuses to start (Validate); Load adds a
	// deprecation line to DeprecatedSettingWarnings whenever it is present.
	InsecureAuditSkipDurableSync *bool `yaml:"insecure_audit_skip_durable_sync"`

	// InsecureAuditSkipReads (ADR-112 Amendment 4) stops SUCCESSFUL secret-value
	// reads from writing an audit row (and their secret_access_logs row): every
	// path that discloses a value -- REST, gRPC, render, copy, federated
	// connect reads, and the CLI, sync and operator clients through the API.
	// Everything else stays audited: secret create/update/delete/version
	// changes, permission/role/share/policy changes, authentication events and
	// failures, denied reads, admin and break-glass actions, configuration and
	// key operations. Default false; config file only (the guards are
	// TestInsecureAuditSkipReads_NoWriteAssignment and
	// TestInsecureAuditSkipReads_NotSettableFromTheEnvironment). Independent of
	// AuditDurability, which governs every row still written. A compliance
	// profile refuses it (complianceProfileRefusals).
	InsecureAuditSkipReads bool `yaml:"insecure_audit_skip_reads"`

	// Pooler names the connection pooler between Keyorix and PostgreSQL:
	// "none" (the default, also when empty), "pgbouncer-session" or
	// "pgbouncer-transaction". Only pgbouncer-transaction changes behaviour;
	// see TransactionPooling and docs/postgresql-poolers.md.
	Pooler string `yaml:"pooler"`

	// SingleWriter (docs/specs/single-writer-cache.md) declares this server the
	// ONLY writer of its PostgreSQL database. Default false; false changes
	// nothing. When true the server takes a per-schema advisory lock at boot
	// and refuses to start if another server holds it, installs a write fence
	// that refuses every write to the security tables from any other session
	// while it runs, and keeps a write epoch it polls (internal/solewriter). If
	// the fence cannot be installed and verified, the server refuses to start:
	// the setting is never in effect without it.
	//
	// PostgreSQL only: a SQLite or remote backend refuses to start with it set,
	// as do auth_rate_limit_fallback.replicas > 1 (a declared multi-replica
	// deployment) and pooler pgbouncer-transaction (the lock and the session
	// tag are session-scoped).
	SingleWriter bool `yaml:"single_writer"`
}

// GetPassword returns the resolved DB password, preferring the environment variable.
func (d *DatabaseConfig) GetPassword() string {
	return resolveSecret("KEYORIX_DB_PASSWORD", d.Password)
}

// GetAuditFlusherLingerWindow returns the configured audit-flusher linger
// window, defaulting to 0 (no deliberate wait) when unset or unparseable.
// See AuditFlusherLingerWindow's doc comment for why 0, not a tuned nonzero
// value, is the default.
func (d *DatabaseConfig) GetAuditFlusherLingerWindow() time.Duration {
	return parseDurationDefault(d.AuditFlusherLingerWindow, 0)
}

// singleWriterUnsupportedBackendError / singleWriterMultiReplicaError are the
// start-up refusals for storage.database.single_writer outside its one
// supported topology (one server, PostgreSQL).
const (
	singleWriterUnsupportedBackendError = "storage.database.single_writer is only supported with storage.type postgres: " +
		"it relies on PostgreSQL session advisory locks and triggers; remove the setting"
	singleWriterMultiReplicaError = "storage.database.single_writer allows exactly one server, but " +
		"security.auth_rate_limit_fallback.replicas declares more than one; remove one of the two settings"
	singleWriterTransactionPoolingError = "storage.database.single_writer is not supported with storage.database.pooler " +
		"pgbouncer-transaction: its holder lock and session tag are session-scoped; use pgbouncer-session or connect directly"
)

// AuditDurabilityLevel is one value of storage.database.audit_durability.
type AuditDurabilityLevel string

const (
	// AuditDurabilityStrict: the audit commit waits for the disk sync.
	AuditDurabilityStrict AuditDurabilityLevel = "strict"
	// AuditDurabilityStandard: the audit row is committed before every
	// disclosure, without waiting for the disk sync. PostgreSQL only.
	AuditDurabilityStandard AuditDurabilityLevel = "standard"
)

// AuditDurabilitySettingName is the canonical dotted path of the setting.
const AuditDurabilitySettingName = "storage.database.audit_durability"

// auditDurabilityDeprecatedAliasName is the dotted path of the deprecated alias.
const auditDurabilityDeprecatedAliasName = "storage.database.insecure_audit_skip_durable_sync"

// auditDurabilityStandardSQLiteUnsupportedError is the exact start-up refusal
// for standard on a SQLite backend (ADR-112 Amendment 1's rejection, kept by
// Amendment 3). A constant so Validate and its tests cannot drift apart.
const auditDurabilityStandardSQLiteUnsupportedError = "storage.database.audit_durability: standard is only " +
	"supported with PostgreSQL; SQLite runs strict only -- remove the setting or set it to strict"

// Meaning returns the one-line, operator-facing meaning of the level, used by
// the start-up INFO line, admin validate and the posture report.
func (l AuditDurabilityLevel) Meaning() string {
	switch l {
	case AuditDurabilityStandard:
		return "committed before every disclosure; up to ~600 ms of entries can be lost to an OS crash or power loss; " +
			"set audit_durability: strict to wait for the disk sync"
	case AuditDurabilityStrict:
		return "committed and synced to disk before every disclosure; no audit entry is lost to any crash or power loss"
	default:
		return "unknown level"
	}
}

// parseAuditDurability validates an explicit audit_durability value. "" means
// unset and is valid.
func parseAuditDurability(v string) (AuditDurabilityLevel, error) {
	switch AuditDurabilityLevel(v) {
	case "", AuditDurabilityStrict, AuditDurabilityStandard:
		return AuditDurabilityLevel(v), nil
	default:
		return "", fmt.Errorf("storage.database.audit_durability: unknown value %q (allowed: strict, standard)", v)
	}
}

// explicitAuditDurability resolves the two config keys into the level the
// operator asked for, "" when neither is set. Both set with conflicting levels
// is an error: neither key may silently win over the other.
func (d *DatabaseConfig) explicitAuditDurability() (AuditDurabilityLevel, error) {
	level, err := parseAuditDurability(d.AuditDurability)
	if err != nil {
		return "", err
	}
	if d.InsecureAuditSkipDurableSync == nil {
		return level, nil
	}
	alias := AuditDurabilityStrict
	if *d.InsecureAuditSkipDurableSync {
		alias = AuditDurabilityStandard
	}
	if level != "" && level != alias {
		return "", fmt.Errorf("storage.database.audit_durability is %q but the deprecated "+
			"storage.database.insecure_audit_skip_durable_sync: %t means %q; remove the deprecated key",
			level, *d.InsecureAuditSkipDurableSync, alias)
	}
	return alias, nil
}

// validateAuditDurability is Validate's check: a known value, no conflict
// between the key and its deprecated alias, and standard only on PostgreSQL.
func (d *DatabaseConfig) validateAuditDurability(storageType string) error {
	level, err := d.explicitAuditDurability()
	if err != nil {
		return err
	}
	if level == AuditDurabilityStandard && (storageType == "local" || storageType == "sqlite") {
		return fmt.Errorf("%s", auditDurabilityStandardSQLiteUnsupportedError)
	}
	return nil
}

// AuditDurabilityStatus is the effective audit durability of one loaded
// config, the single source of truth the storage factory, the start-up line,
// admin validate, the posture report, the settings diff and GET /system/info
// all read, so they cannot disagree.
type AuditDurabilityStatus struct {
	// Level is the level the audit commit actually runs at.
	Level AuditDurabilityLevel
	// Explicit is true when the config file chose the level (audit_durability
	// or its deprecated alias), false when it is the backend default.
	Explicit bool
}

// EffectiveAuditDurability computes the effective level for storageType:
// the explicit setting when there is one, otherwise standard on PostgreSQL
// and strict everywhere else.
//
// Only postgres/postgresql can ever be standard. An allowlist on purpose: a
// backend that does not implement the SET LOCAL mechanism (SQLite, remote, an
// unknown type in a config that skipped Validate) reports strict, which is
// what it actually does, rather than claiming a relaxation nothing performs.
// An invalid or conflicting setting (refused by Validate) also reports strict.
func (d *DatabaseConfig) EffectiveAuditDurability(storageType string) AuditDurabilityStatus {
	level, err := d.explicitAuditDurability()
	explicit := err == nil && level != ""
	if storageType != "postgres" && storageType != "postgresql" {
		return AuditDurabilityStatus{Level: AuditDurabilityStrict, Explicit: explicit}
	}
	if err != nil {
		return AuditDurabilityStatus{Level: AuditDurabilityStrict}
	}
	if level == "" {
		return AuditDurabilityStatus{Level: AuditDurabilityStandard}
	}
	return AuditDurabilityStatus{Level: level, Explicit: true}
}

// StartupLine is the one INFO line every start logs for the effective level,
// e.g. "audit durability: standard (PostgreSQL default; committed before every
// disclosure; ...)".
func (s AuditDurabilityStatus) StartupLine() string {
	source := ""
	if !s.Explicit && s.Level == AuditDurabilityStandard {
		source = "PostgreSQL default; "
	}
	return fmt.Sprintf("audit durability: %s (%s%s)", s.Level, source, s.Level.Meaning())
}

// BoolPtr returns a pointer to b — for setting optional *bool config fields.
func BoolPtr(b bool) *bool { return &b }

// IntPtr returns a pointer to n — for setting optional *int config fields.
func IntPtr(n int) *int { return &n }

type ClientConfig struct {
	Endpoint string     `yaml:"endpoint"`
	Auth     AuthConfig `yaml:"auth"`
	Timeout  string     `yaml:"timeout"`
}

type AuthConfig struct {
	Type   string `yaml:"type"`    // "none", "api_key"
	APIKey string `yaml:"api_key"` // use KEYORIX_API_KEY env var instead
}

// OIDCConfig is the trusted-issuer allowlist for machine-identity federation.
type OIDCConfig struct {
	Enabled bool               `yaml:"enabled"`
	Issuers []OIDCIssuerConfig `yaml:"issuers"`
}

// OIDCIssuerConfig describes one trusted token issuer.
type OIDCIssuerConfig struct {
	Name      string   `yaml:"name"`      // operator label
	Issuer    string   `yaml:"issuer"`    // must equal the JWT `iss` exactly
	JWKSURI   string   `yaml:"jwks_uri"`  // where the issuer's signing keys live
	Audiences []string `yaml:"audiences"` // the JWT `aud` must contain one of these
	// MaxTokenAgeSeconds bounds (now - iat) for a token from this issuer; unset/0
	// uses a 24h default. exp alone doesn't bound how long ago a token was
	// minted, so without this a far-future-exp token (misconfigured or
	// malicious issuer) would verify indefinitely.
	MaxTokenAgeSeconds int `yaml:"max_token_age_seconds"`
}

// GetAPIKey returns the resolved API key, preferring the environment variable.
func (a *AuthConfig) GetAPIKey() string {
	return resolveSecret("KEYORIX_API_KEY", a.APIKey)
}

// EncryptionConfig configures the ADR-004 envelope scheme. The KEK is derived
// from the master passphrase at runtime (PBKDF2) and never touches disk, so the
// only key material on disk is the salt and the wrapped DEK.
type EncryptionConfig struct {
	Enabled  bool   `yaml:"enabled"`
	DEKPath  string `yaml:"dek_path"`
	SaltPath string `yaml:"salt_path"`
	// KeyProvider selects where the KEK comes from (ADR-038). Absent/zero value =
	// the default passphrase derivation (KEYORIX_MASTER_PASSWORD + on-disk salt),
	// byte-identical to the historical behaviour.
	KeyProvider KeyProviderConfig `yaml:"key_provider"`
	// KeyDirLock selects how a server coordinates with other processes using the
	// same key files (docs/multi-replica-keys.md). "" or "flock" (default): the
	// server holds an exclusive flock(2) on <key dir>/dek.lock for its lifetime,
	// so exactly one server can use a key directory. "database" (PostgreSQL
	// only, for several replicas): the server takes no key-directory lock; the
	// server-presence advisory lock it already holds keeps key-changing admin
	// commands out, and first-boot key generation and rotation crash recovery
	// run under a PostgreSQL advisory lock. The key directory may then be a
	// shared ReadWriteMany volume without working flock, or read-only.
	KeyDirLock string `yaml:"key_dir_lock"`
}

// Key-directory lock modes (EncryptionConfig.KeyDirLock).
const (
	KeyDirLockFlock    = "flock"
	KeyDirLockDatabase = "database"
)

// KeyDirLockIsDatabase reports whether the key-directory lock is the
// PostgreSQL-backed one (storage.encryption.key_dir_lock: database).
func (e *EncryptionConfig) KeyDirLockIsDatabase() bool {
	return e.KeyDirLock == KeyDirLockDatabase
}

// KeyProviderConfig selects the KEK source. type: "password" (default) derives the
// KEK from KEYORIX_MASTER_PASSWORD; "file" reads raw key material from FilePath;
// "env" reads it from the EnvVar's value (hex or base64); "exec" runs ExecCommand
// and reads the KEK from its stdout; "shamir" reconstructs it from K-of-N Shamir
// shares (ShamirShareFiles / ShamirShareEnv); "tpm" seals it to the host TPM 2.0
// (TPMDevice, sealed blob at WrappedKeyPath); "aws-kms" / "gcp-kms" / "azure-kms"
// envelope-wrap the KEK with a cloud KMS/HSM key (ADR-041) and store the wrapped
// blob at WrappedKeyPath. file/env/exec suit a KEK injected by a sealed/SOPS secret,
// a CSI driver, or any external secret store; shamir splits it across custodians;
// tpm binds it to host hardware; the KMS providers keep the wrapping key in the cloud HSM.
type KeyProviderConfig struct {
	Type     string `yaml:"type"`
	FilePath string `yaml:"file_path"`
	EnvVar   string `yaml:"env_var"`
	// KMSKeyID is the cloud KMS key for type aws-kms / gcp-kms / azure-kms: an AWS
	// key ID, ARN, or alias; a GCP crypto-key resource name
	// (projects/P/locations/L/keyRings/R/cryptoKeys/K); or an Azure Key Vault key
	// identifier URL (https://{vault}.vault.azure.net/keys/{name}[/{version}]).
	// Region/credentials come from the standard cloud environment, not from here.
	KMSKeyID string `yaml:"kms_key_id"`
	// WrappedKeyPath is where the KMS-wrapped KEK blob lives (aws-kms / gcp-kms /
	// azure-kms).
	WrappedKeyPath string `yaml:"wrapped_key_path"`
	// KMSEncryptionContext binds the wrapped KEK to this install (aws-kms /gcp-kms):
	// it's passed as the AWS EncryptionContext / GCP AdditionalAuthenticatedData on
	// wrap+unwrap, so a different install sharing the same CMK cannot unwrap this
	// install's KEK. Set a value unique to the install, e.g. {keyorix-install: <id>}.
	// Empty = no binding (the prior behaviour). NOT supported by azure-kms (RSA wrap
	// has no AAD) — setting it there is a hard startup error, not a silent downgrade.
	//
	// #123: on its own this is enforced (a mismatched or missing context on the
	// wrapped blob fails decryption outright) UNLESS KMSAllowContextFallback is also
	// set — see that field.
	KMSEncryptionContext map[string]string `yaml:"kms_encryption_context"`
	// KMSAllowContextFallback opts into a ONE-DIRECTION migration aid: when
	// KMSEncryptionContext is set and a context-bound Decrypt fails, retry once
	// without any context, so enabling the binding on an install with an existing
	// (pre-binding) wrapped KEK doesn't lock it out. Off by default — with it off (the
	// secure default), a KMS Decrypt failure is final: the whole point of
	// KMSEncryptionContext is that an attacker with kms:Encrypt on the shared CMK (but
	// not Keyorix's own data) cannot plant a wrapped-KEK blob that decrypts under this
	// install's identity; a fallback that auto-retries without the context on ANY
	// failure makes that binding purely advisory, since a blob encrypted with no
	// context at all (the trivial attack) always succeeds on the fallback attempt.
	// Enable this ONLY transiently while migrating an existing install onto a newly
	// configured context (`keyorix encryption migrate-provider --to-kms-encryption-
	// context=...` to durably re-wrap under the context), then disable it again —
	// every fallback use is logged loudly specifically so that migration window is
	// observable and finite, not a permanent standing weakening.
	//
	// #3398: the window ends by itself. When the stored wrapped KEK already
	// decrypts WITH its context (the migration is done), the flag is refused at
	// start-up with a message saying it can be removed
	// (crypto.ErrKMSContextFallbackNotNeeded, checked in KMSKeyProvider.KEK).
	KMSAllowContextFallback bool `yaml:"insecure_allow_kms_context_fallback"`
	// ExecCommand is the argv for type "exec": the resolver command (argv[0] is the
	// binary, the rest are arguments) whose stdout supplies the KEK as raw 32 bytes
	// or a hex/base64 encoding thereof. Run directly without a shell. Lets a
	// deployment fetch the KEK from any external secret store (e.g.
	// ["op","read","op://vault/kek/value"], ["sops","-d","kek.enc"]).
	ExecCommand []string `yaml:"exec_command"`
	// ShamirShareFiles / ShamirShareEnv list the K-of-N Shamir shares for type
	// "shamir": the KEK is reconstructed by combining the shares read from these file
	// paths and/or env-var values (each a hex/base64 share from
	// `keyorix encryption shamir-split`). Provide at least the threshold many; no
	// single share reveals the KEK.
	ShamirShareFiles []string `yaml:"shamir_share_files"`
	ShamirShareEnv   []string `yaml:"shamir_share_env"`
	// ShamirCommitment is the hex-encoded HMAC-SHA256 commitment to the original KEK
	// (crypto.CommitKEK), printed by `keyorix encryption shamir-split` alongside the
	// shares. It is verified against the RECONSTRUCTED KEK at unseal time (#429):
	// without it, reconstruction is checked only by a 4-byte magic embedded in the
	// split payload, which an attacker holding threshold-1 genuine shares can forge
	// (each byte of the reconstructed payload — magic and KEK alike — is
	// independently retargetable via the forged share's Lagrange coordinate, so a
	// bigger in-payload check wouldn't help either). The commitment is safe to store
	// in the clear here — it is one-way and reveals nothing about the KEK. Empty is
	// accepted for key material split before this field existed, but every startup
	// then logs a loud warning that verification is reduced to the forgeable magic
	// check alone.
	ShamirCommitment string `yaml:"shamir_commitment"`
	// TPMDevice is the TPM 2.0 device for type "tpm" (default /dev/tpmrm0). The KEK
	// is sealed to this TPM and the sealed blob stored at WrappedKeyPath.
	TPMDevice string `yaml:"tpm_device"`
	// Fallbacks is an ordered list of providers tried when the primary fails.
	Fallbacks []KeyProviderConfig `yaml:"fallbacks,omitempty"`
	// AllowWeakerFallback must be explicitly set to allow a Fallbacks chain that
	// downgrades KEK-sourcing strength — e.g. a hardware/HSM/cloud-KMS-backed
	// provider (tpm, aws-kms, gcp-kms, azure-kms) falling back to a software-
	// derivable one (password, file, env, exec) or to shamir. Without it, a
	// downgrading chain is a hard startup error (crypto.DetectFallbackDowngrade):
	// silently accepting one would mean a transient failure of the strong primary
	// (a momentary TPM glitch, a KMS network blip) quietly drops the deployment's
	// actual security to "whatever a local password/file/env-var can be
	// leaked/brute-forced", with only a log line marking the moment it happened. A
	// fallback chain that stays flat or gets stronger (e.g. one KMS region falling
	// back to another) is unaffected and never needs this flag.
	AllowWeakerFallback bool `yaml:"insecure_allow_weaker_kek_fallback"`
}

type SecretsConfig struct {
	Chunking ChunkingConfig `yaml:"chunking"`
	Limits   LimitsConfig   `yaml:"limits"`
}

type ChunkingConfig struct {
	Enabled            bool `yaml:"enabled"`
	MaxChunkSizeKB     int  `yaml:"max_chunk_size_kb"`
	MaxChunksPerSecret int  `yaml:"max_chunks_per_secret"`
}

type LimitsConfig struct {
	MaxSecretsPerUser int `yaml:"max_secrets_per_user"`
	// MaxSecretSize caps a secret value's size in bytes, enforced on create/update/
	// rotate (never on read/delete — a secret already stored above the cap, e.g. from
	// before this was introduced or before an operator lowered it, stays fully
	// readable and deletable; only new writes are rejected). 0 (unset) defaults to
	// DefaultMaxSecretSize; Validate rejects any configured value above
	// MaxSecretSizeHardCeiling. See DefaultMaxSecretSize's doc comment for the
	// industry-comparison rationale behind the default.
	MaxSecretSize int `yaml:"max_secret_size"`
}

// DefaultMaxSecretSize (64 KiB) is the default ceiling on a secret value's size when
// secrets.limits.max_secret_size is unset. This is the number the major managed
// secret stores have converged on, not an arbitrary round figure: AWS Secrets
// Manager and GCP Secret Manager both cap at 64 KB (AWS's limit is explicitly
// documented as non-adjustable and was raised twice, under customer pressure,
// before settling at 64 KB); Azure Key Vault caps at 25 KB; HashiCorp Vault chunks
// entries above 512 KiB and its own documentation warns that large entries degrade
// other storage operations (backend replication, snapshot/restore, KV listing).
// 64 KiB is the number defensible in this product's own docs for the same reasons.
const DefaultMaxSecretSize = 65536

// MaxSecretSizeHardCeiling (1 MiB) is the absolute upper bound secrets.limits.
// max_secret_size may be configured to — Validate rejects a configured value above
// this outright, at startup, rather than silently clamping it. An operator who
// genuinely needs to store larger blobs should use a purpose-built object store and
// reference it from a secret, not raise this ceiling; every comparable managed
// secret store (see DefaultMaxSecretSize) treats "secret" as a credential-sized
// value, not a general blob store, and this cap exists to keep that true here too.
const MaxSecretSizeHardCeiling = 1 << 20 // 1 MiB

// secretSizeEnvelopeHeadroomBytes is added on top of a secret value's base64-
// inflated size (DeriveMaxRequestBodySize) to cover the REST of a create/update/
// rotate request body: JSON field names and quoting, and the request's other
// fields (name up to 255 bytes, metadata, tags, description, etc.), none of which
// are the secret value itself and none of which max_secret_size is meant to bound.
// 16 KiB is a generous, round number chosen to comfortably clear ordinary metadata/
// tag usage without making the wire-level cap effectively unlimited -- it is a
// coarse DoS backstop, not the precise enforcement point (that's the decoded-value
// check against max_secret_size itself, applied separately after the body is
// successfully read).
const secretSizeEnvelopeHeadroomBytes = 16 * 1024

// DeriveMaxRequestBodySize returns the maximum HTTP/gRPC request body size a
// caller must be allowed to send in order to successfully submit a secret value of
// exactly maxSecretSize bytes, plus headroom for the rest of the request envelope.
//
// A secret value never travels as raw bytes: the HTTP JSON API and gRPC's
// generated string fields both carry it base64-encoded. Base64 inflates N bytes to
// exactly ceil(N/3)*4 bytes -- setting a request-body limit to maxSecretSize itself
// (the natural but wrong first instinct) would reject every valid maximum-size
// secret outright, roughly 33% before the JSON envelope is even counted. This
// function exists specifically so that mistake has one place it can't be made:
// every caller that needs a body-size limit derived from max_secret_size (the HTTP
// router's per-route secretBodyLimit middleware) calls this,
// rather than each re-deriving (and potentially mis-deriving) its own.
func DeriveMaxRequestBodySize(maxSecretSize int) int64 {
	base64Size := ((maxSecretSize + 2) / 3) * 4 // ceil(n/3)*4: the exact base64 output length
	return int64(base64Size) + secretSizeEnvelopeHeadroomBytes
}

// ADR112FilePermEnforcedMarker and ADR112RequireMFAEnforcedMarker are the
// system_metadata keys the server writes once a deployment has been enforced on
// enable_file_permission_check / require_mfa (ADR-112): a deployment whose
// database has users and no marker is an upgrade still inside that key's grace
// period (server/adr112_grace.go). The value is the RFC 3339 time first recorded.
const (
	ADR112FilePermEnforcedMarker   = "adr112.file_permission_check.enforced"
	ADR112RequireMFAEnforcedMarker = "adr112.require_mfa.enforced"
	// ADR112SCIMTokenEnforcedMarker: the SCIM token shape checks (#3397) have
	// been enforced on this deployment (a boot where they did not have to be
	// softened), so a weak token now refuses to start instead of warning.
	ADR112SCIMTokenEnforcedMarker = "adr112.scim_token_strength.enforced" // #nosec G101 -- metadata key name, not a credential
)

type SecurityConfig struct {
	// EnableFilePermissionCheck gates the file-permission/DEK-salt-size/database-
	// reachability startup checks (internal/startup.ValidateStartup) and whether
	// enforceKeyFilePermissions fails closed instead of warning. ADR-112: secure
	// by default -- Load() resolves an ABSENT key to true (and records that in
	// EnableFilePermissionCheckImplicitDefault below), not Go's bool zero value,
	// so a fresh install enforces from its first start without anyone setting this.
	EnableFilePermissionCheck bool `yaml:"enable_file_permission_check"`
	// EnableFilePermissionCheckImplicitDefault records whether Load() set
	// EnableFilePermissionCheck to true itself (the key was absent from the
	// config file) rather than the operator writing it. Computed from the raw
	// YAML (a plain bool can't tell "absent" from "explicitly false" apart --
	// both decode to false); never itself read from YAML.
	//
	// Deliberately false-by-default (unlike an "...Explicit" flag would be):
	// every caller that builds a *Config by hand instead of through Load() --
	// test fixtures across this repo, any future one-off caller -- leaves this
	// at Go's zero value, which must mean "treat EnableFilePermissionCheck as
	// if the operator meant it," the strict pre-ADR-112 behavior, not silently
	// downgrade a hand-set EnableFilePermissionCheck: true into the softened
	// grace-period path below. Only Load() ever sets this true, and only when
	// it also just set EnableFilePermissionCheck to true itself.
	//
	// An existing deployment relying on this implicit default gets a start-up
	// warning and a softened, warn-instead-of-fail-closed response to a real
	// problem the check finds, until it explicitly sets the key -- see
	// server/main.go's runStartupValidation and enforceKeyFilePermissions.
	EnableFilePermissionCheckImplicitDefault bool `yaml:"-"`
	// EnableFilePermissionCheckUpgradeGrace is the narrower fact the grace
	// period actually turns on: ImplicitDefault above AND this is an upgraded,
	// pre-existing deployment (its database already has users) that has never
	// yet booted clean under the check. Never set by Load(): only
	// server/main.go's adr112UpgradeGraceEligible sets it, at boot, from the
	// database itself. A fresh install (no database, or no users yet) and a
	// deployment that already passed once (the adr112 system_metadata marker)
	// leave it false and are enforced. False-by-default for the same reason as
	// ImplicitDefault: a hand-built *Config must never land in the softened path.
	EnableFilePermissionCheckUpgradeGrace bool `yaml:"-"`
	AutoFixFilePermissions                bool `yaml:"auto_fix_file_permissions"`
	AllowUnsafeFilePermissions            bool `yaml:"insecure_allow_unsafe_file_permissions"`
	// RequireMFA mandates TOTP MFA for interactive login: a session-authenticated
	// user without MFA enabled is confined to the MFA-enrolment endpoints until
	// they enrol. Non-interactive credentials (PAT/machine/OIDC) are exempt.
	// ADR-112: secure by default -- Load() resolves an ABSENT key to true (see
	// RequireMFAImplicitDefault below), not Go's bool zero value.
	RequireMFA bool `yaml:"require_mfa"`
	// RequireMFAImplicitDefault is RequireMFA's counterpart to
	// EnableFilePermissionCheckImplicitDefault above: true only when Load() set
	// RequireMFA to true itself because the key was absent. False-by-default for
	// the same reason -- a hand-built *Config with RequireMFA: true must not be
	// read as "inherited the default." Never read from YAML.
	RequireMFAImplicitDefault bool `yaml:"-"`
	// RequireMFAUpgradeGrace is true when server/main.go's applyADR112UpgradeGrace
	// found an UPGRADED deployment (its database already has users, and no
	// adr112.require_mfa.enforced marker) relying on the implicit default, and so
	// set RequireMFA back to false for this boot: ADR-112's grace period for MFA
	// on upgrades, with a loud start-up warning, until the key is set explicitly.
	// A fresh install is enforced and marked, so it never gets here. Never read
	// from YAML; false on every hand-built *Config.
	RequireMFAUpgradeGrace bool `yaml:"-"`
	// LoginLockout configures per-account login lockout (brute-force protection):
	// after MaxAttempts failed password logins within Window, the account is locked
	// for an exponentially-backing-off cooldown. Distinct from (and complementary to)
	// the per-IP rate limiter, which a distributed/botnet guess against one account can
	// evade. It is ENABLED BY DEFAULT — a secrets-manager login must resist online
	// guessing out of the box. Set login_lockout.insecure_disable_login_lockout
	// to opt out (deprecated alias: login_lockout.disabled).
	LoginLockout LoginLockoutConfig `yaml:"login_lockout"`
	// AuthRateLimitFallback tunes the auth rate limits' in-memory fallback, which
	// decides only while a budget's database storage is failing (ADR-040
	// amendment). Each server process keeps its own copy, so Replicas divides
	// every fallback limit by the number of replicas sharing the budgets.
	AuthRateLimitFallback AuthRateLimitFallbackConfig `yaml:"auth_rate_limit_fallback"`
	// RequireTransportTLS, when true, refuses to start an enabled HTTP/gRPC listener
	// that has no TLS configured — failing closed so bearer tokens and secret values are
	// never served in cleartext. Default false (a TLS-terminating proxy in front is a
	// common, supported deployment), but when off the server logs a prominent warning if
	// it serves cleartext, so the exposure is never silent.
	RequireTransportTLS bool `yaml:"require_transport_tls"`
	// RecoverAdmin configures `keyorix-server admin recover-admin`
	// (docs/design-b2-recover-admin.md §5).
	RecoverAdmin RecoverAdminConfig `yaml:"recover_admin"`
	// RecoveryOTPLifetime is how long the one-time password printed by
	// `keyorix-server admin recover-admin` stays valid, as a Go duration (e.g.
	// "24h", "90m"). Empty means the 24h default; a set value must be a duration
	// in (0, MaxOneTimePasswordExpiry] or Validate refuses it. There is no way to
	// configure "never expires" (OTP-EXPIRY-1).
	RecoveryOTPLifetime string `yaml:"recovery_one_time_password_ttl"`
	// OTPLifetime is the same for admin-created one-time passwords
	// (`keyorix user create --one-time-password`). Empty means the 72h default;
	// the same range check applies.
	OTPLifetime string `yaml:"one_time_password_ttl"`
}

// Defaults for the one-time-password lifetimes (see SecurityConfig). They mirror
// core.DefaultRecoveryOneTimePasswordExpiry / core.DefaultOneTimePasswordExpiry, which
// internal/config cannot import; config_test.go keeps the two in step.
const (
	DefaultRecoveryOneTimePasswordExpiry = 24 * time.Hour
	DefaultOneTimePasswordExpiry         = 72 * time.Hour
)

// GetRecoveryOneTimePasswordExpiry returns the validity of a recover-admin one-time
// password, falling back to the default for an empty or invalid value.
func (s *SecurityConfig) GetRecoveryOneTimePasswordExpiry() time.Duration {
	return parseDurationDefault(s.RecoveryOTPLifetime, DefaultRecoveryOneTimePasswordExpiry)
}

// GetOneTimePasswordExpiry returns the validity of an admin-created one-time
// password, falling back to the default for an empty or invalid value.
func (s *SecurityConfig) GetOneTimePasswordExpiry() time.Duration {
	return parseDurationDefault(s.OTPLifetime, DefaultOneTimePasswordExpiry)
}

// RecoverAdminConfig configures `keyorix-server admin recover-admin`
// (docs/design-b2-recover-admin.md §5).
type RecoverAdminConfig struct {
	// KeylessMode, when true, lets `recover-admin` proceed on host access
	// ALONE, without a valid recovery key — the labs/demo escape hatch
	// design §1's threat-model table calls out explicitly: it collapses
	// "host access" and "admin access" into one trust boundary, which is
	// exactly what the default (keyed) mode exists to avoid. Read ONLY at
	// server startup, from THIS config file — never settable over the
	// network (no HTTP handler, no gRPC RPC ever writes this field; see
	// internal/config/keyless_mode_reachability_test.go). Changing it
	// requires host-side config-file access and a server restart, the same
	// bar as any other config field, by design.
	KeylessMode bool `yaml:"insecure_keyless_admin_recovery"`
}

// parseDurationDefault parses a Go duration string, returning def when empty or
// unparseable / non-positive.
func parseDurationDefault(raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	return def
}

// AuthRateLimitFallbackConfig configures the auth rate limits' in-memory
// fallback (security.auth_rate_limit_fallback).
type AuthRateLimitFallbackConfig struct {
	// Replicas is the number of server replicas that share the auth budgets
	// (default 1). While a budget's storage is failing, each replica enforces
	// 1/Replicas of that budget's limit (never below one attempt), so the
	// cluster as a whole stays near the normal limit. Set it to your replica
	// count; a lower value only makes the outage-time limit looser, never the
	// normal one.
	Replicas int `yaml:"replicas"`
}

// GetReplicas returns Replicas, or 1 when unset or not positive.
func (c AuthRateLimitFallbackConfig) GetReplicas() int {
	if c.Replicas > 0 {
		return c.Replicas
	}
	return 1
}

// LoginLockoutConfig configures per-account login lockout. Lockout is enabled by
// default; Disabled is the explicit opt-out. Enabled is retained for backward
// compatibility and is now redundant with the default-on behavior.
type LoginLockoutConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Disabled     bool   `yaml:"insecure_disable_login_lockout"` // explicit opt-out (lockout is on by default)
	MaxAttempts  int    `yaml:"max_attempts"`                   // failures within the window before locking (default 5)
	Window       string `yaml:"window"`                         // Go duration; consecutive-failure window (default 15m)
	BaseCooldown string `yaml:"base_cooldown"`                  // lock duration for the first lockout (default 1m)
	MaxCooldown  string `yaml:"max_cooldown"`                   // cap for the exponential backoff (default 1h)
}

func (c LoginLockoutConfig) GetMaxAttempts() int {
	if c.MaxAttempts > 0 {
		return c.MaxAttempts
	}
	return 5
}

func (c LoginLockoutConfig) GetWindow() time.Duration {
	return parseDurationDefault(c.Window, 15*time.Minute)
}

func (c LoginLockoutConfig) GetBaseCooldown() time.Duration {
	return parseDurationDefault(c.BaseCooldown, time.Minute)
}

func (c LoginLockoutConfig) GetMaxCooldown() time.Duration {
	return parseDurationDefault(c.MaxCooldown, time.Hour)
}

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

// MembershipConfig configures the project membership lifecycle (ADR-022).
type MembershipConfig struct {
	// ValidationMode controls how a new invite onboards: "open" (active
	// immediately), "allowlist" (admin steps through each state), or "idp"
	// (IdP-resolved users skip the early states). Empty = allowlist.
	ValidationMode string `yaml:"validation_mode"`
	// DomainAllowlist restricts InviteToProject/InviteGlobal to these email
	// domains (ADR-022). Empty = no restriction (default, backward compatible).
	DomainAllowlist []string `yaml:"domain_allowlist"`
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

// CredentialDeliveryConfig configures the ADR-028 credential-delivery subsystem:
// how a brand-new principal receives their first-credential setup link.
type CredentialDeliveryConfig struct {
	// Mode selects the channel: auto | smtp | out_of_band | log ("" = auto).
	Mode string `yaml:"mode"`
	// SetupTokenTTL is the single-use setup/invite link lifetime (e.g. "24h").
	// Empty = DefaultSetupTokenTTLString.
	SetupTokenTTL string `yaml:"setup_token_ttl"`
	// BaseURL is required for any link-producing mode; used to build absolute setup
	// links (e.g. "https://keyorix.acme.internal"). A relative link is a
	// misconfiguration, not a fallback, so link minting refuses an empty BaseURL.
	BaseURL string               `yaml:"base_url"`
	SMTP    CredentialSMTPConfig `yaml:"smtp"`
}

// CredentialSMTPConfig is the operator's own mail relay. The password is resolved
// from KEYORIX_SMTP_PASSWORD when set, so it need not be written into the file
// (same convention as the DB password).
type CredentialSMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"` // use KEYORIX_SMTP_PASSWORD env var instead
	From     string `yaml:"from"`
	TLS      string `yaml:"tls"` // starttls | implicit | none(dev-only)
}

// DefaultSetupTokenTTLString is the fallback link lifetime when none is configured.
const DefaultSetupTokenTTLString = "24h"

// GetSetupTokenTTL parses SetupTokenTTL, falling back to 24h when empty or invalid.
func (c *CredentialDeliveryConfig) GetSetupTokenTTL() time.Duration {
	raw := c.SetupTokenTTL
	if raw == "" {
		raw = DefaultSetupTokenTTLString
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		d, _ = time.ParseDuration(DefaultSetupTokenTTLString)
	}
	return d
}

// SessionConfig tunes session-token lifetimes for short-lived tokens with silent
// auto-refresh. Absent (zero value) keeps the backward-compatible behaviour: a 24h
// access window and no absolute ceiling (refreshable indefinitely). An install that
// wants short-lived tokens sets a short access_ttl plus an absolute_ttl ceiling and
// relies on the client to refresh silently before each access window lapses.
type SessionConfig struct {
	// AccessTTL is how long an issued access token is valid before it must be
	// refreshed (e.g. "30m"). Empty = DefaultAccessTTLString (24h).
	AccessTTL string `yaml:"access_ttl"`
	// AbsoluteTTL caps total session lifetime from login: refreshing the access
	// window can never extend a session past it (e.g. "12h"). Empty or "0" = no
	// ceiling, so a session can be refreshed indefinitely (legacy behaviour).
	AbsoluteTTL string `yaml:"absolute_ttl"`
}

// DefaultAccessTTLString is the fallback access-token lifetime. It matches the
// historic hard-coded 24h so an install that does not configure a session block
// keeps exactly the old behaviour (no un-refreshing client is logged out).
const DefaultAccessTTLString = "24h"

// GetAccessTTL parses AccessTTL, falling back to 24h when empty or invalid.
func (c *SessionConfig) GetAccessTTL() time.Duration {
	raw := c.AccessTTL
	if raw == "" {
		raw = DefaultAccessTTLString
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		d, _ = time.ParseDuration(DefaultAccessTTLString)
	}
	return d
}

// GetAbsoluteTTL parses AbsoluteTTL. Empty, "0", or an unparseable/non-positive
// value means "no ceiling" and returns 0 — sessions are then refreshable forever.
func (c *SessionConfig) GetAbsoluteTTL() time.Duration {
	if c.AbsoluteTTL == "" {
		return 0
	}
	d, err := time.ParseDuration(c.AbsoluteTTL)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// GetPassword returns the resolved SMTP password, preferring the environment variable.
func (s *CredentialSMTPConfig) GetPassword() string {
	return resolveSecret("KEYORIX_SMTP_PASSWORD", s.Password)
}

// DeliveryConfig maps the credential-delivery config block onto the delivery package's
// channel selector, resolving the SMTP password from the environment. Shared by the
// server and CLI wiring (ADR-028) so the mapping lives in exactly one place.
func (c *CredentialDeliveryConfig) DeliveryConfig() delivery.Config {
	return delivery.Config{
		Mode:    c.Mode,
		BaseURL: c.BaseURL,
		SMTP: delivery.SMTPSettings{
			Host:     c.SMTP.Host,
			Port:     c.SMTP.Port,
			Username: c.SMTP.Username,
			Password: c.SMTP.GetPassword(),
			From:     c.SMTP.From,
			TLS:      c.SMTP.TLS,
		},
	}
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

// NotificationsConfig configures external delivery channels for in-app
// notifications (ISO 27001 A.5.5 / SOC 2 operational alerting). Each channel is
// opt-in; with none enabled, notifications remain in-app only. When more than one
// is enabled, each notification is fanned out to all of them.
type NotificationsConfig struct {
	Webhook NotificationWebhookConfig `yaml:"webhook"`
	Email   NotificationEmailConfig   `yaml:"email"`
	Slack   NotificationChatConfig    `yaml:"slack"`
	Teams   NotificationChatConfig    `yaml:"teams"`
}

// NotificationChatConfig configures a Slack or Teams channel: an incoming-webhook
// URL (which carries the platform's secret token, so prefer the env var).
type NotificationChatConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// GetWebhookURL returns the resolved Slack incoming-webhook URL.
func (c *NotificationsConfig) GetSlackWebhookURL() string {
	return resolveSecret("KEYORIX_NOTIFY_SLACK_WEBHOOK", c.Slack.WebhookURL)
}

// GetTeamsWebhookURL returns the resolved Teams incoming-webhook URL.
func (c *NotificationsConfig) GetTeamsWebhookURL() string {
	return resolveSecret("KEYORIX_NOTIFY_TEAMS_WEBHOOK", c.Teams.WebhookURL)
}

// ComplianceDigestConfig configures the scheduled compliance digest (ISO 27001 /
// SOC 2 continuous monitoring): a periodic posture + control-matrix summary
// broadcast to the configured notification channels. Opt-in (default off); requires
// at least one notification channel to have somewhere to deliver.
type ComplianceDigestConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// GetInterval returns the digest interval, parsing Schedule as a Go duration (e.g.
// "24h", "168h"); defaults to 24h when unset or unparseable.
func (c ComplianceDigestConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// NotificationEmailConfig configures the SMTP notification channel: each
// notification is emailed (plaintext) to the recipient via the operator's relay.
// Mirrors the credential-delivery SMTP settings (ADR-028).
type NotificationEmailConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"` // use KEYORIX_NOTIFY_SMTP_PASSWORD env var instead
	From     string `yaml:"from"`
	TLS      string `yaml:"tls"` // starttls | implicit | none(dev-only)
	// BroadcastTo is the destination address for BROADCAST notifications — the
	// scheduled compliance digest and auto-rotation-failure alerts (#221) — when
	// email is the channel carrying them. Unlike a per-user notification (whose
	// recipient is resolved from the user's account), a broadcast has no single
	// addressee, so without this the email channel has nowhere to route it and the
	// broadcast silently never sends. Optional: leave unset if Slack/Teams/webhook
	// already covers deployment-wide broadcasts, or if email-only broadcast alerting
	// isn't wanted.
	BroadcastTo string `yaml:"broadcast_to"`
}

// GetPassword returns the resolved SMTP password, preferring the environment variable.
func (c *NotificationEmailConfig) GetPassword() string {
	return resolveSecret("KEYORIX_NOTIFY_SMTP_PASSWORD", c.Password)
}

// NotificationWebhookConfig configures the webhook notification channel: each
// notification is POSTed as JSON to Endpoint, optionally bearer-authenticated.
type NotificationWebhookConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Endpoint           string `yaml:"endpoint"`
	Token              string `yaml:"token"` // use KEYORIX_NOTIFY_WEBHOOK_TOKEN env var instead
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	// AllowPrivateNetworkTarget opts the endpoint out of the SSRF guard — a
	// SEPARATE decision from InsecureSkipVerify; see notifychan.WebhookConfig.
	AllowPrivateNetworkTarget bool `yaml:"insecure_allow_private_network_notify_target"`
	// AllowInsecureTransport permits a plaintext (http://) endpoint to a
	// non-loopback host. False by default: Endpoint must be https unless it
	// targets loopback. A SEPARATE decision from AllowPrivateNetworkTarget
	// (previously conflated: enabling AllowPrivateNetworkTarget alone used to
	// ALSO silently unlock cleartext HTTP to any public host, not just a
	// private one). Every use of this opt-out is logged; see
	// notifychan.WebhookConfig.
	AllowInsecureTransport bool `yaml:"insecure_allow_plaintext_notify_transport"`
	// SigningSecret HMAC-signs each payload (X-Keyorix-Signature) so the receiver can
	// verify authenticity. Use KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET instead of the file.
	SigningSecret string `yaml:"signing_secret"`
}

// GetToken returns the resolved webhook token, preferring the environment variable.
func (c *NotificationWebhookConfig) GetToken() string {
	return resolveSecret("KEYORIX_NOTIFY_WEBHOOK_TOKEN", c.Token)
}

// GetSigningSecret returns the resolved webhook signing secret, preferring the env var.
func (c *NotificationWebhookConfig) GetSigningSecret() string {
	return resolveSecret("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", c.SigningSecret)
}

// SCIMConfig configures SCIM 2.0 provisioning (RFC 7644). When Enabled, the
// /scim/v2 endpoints are served, authenticated by a static bearer token an IdP
// presents. Opt-in (default off).
type SCIMConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"` // use KEYORIX_SCIM_TOKEN env var instead
}

// GetToken returns the resolved SCIM bearer token, preferring the env var.
func (s *SCIMConfig) GetToken() string {
	return resolveSecret("KEYORIX_SCIM_TOKEN", s.Token)
}

// SSOConfig configures human OIDC single-sign-on. Opt-in (default off). Each
// provider is an OIDC IdP; users are matched to a Keyorix account by the IdP
// subject (against the SCIM externalId) and, failing that, by email.
type SSOConfig struct {
	Enabled   bool                `yaml:"enabled"`
	Providers []SSOProviderConfig `yaml:"providers"`
}

// SSOProviderConfig is one configured OIDC provider. Endpoints are discovered from
// the issuer's /.well-known/openid-configuration at startup, so only the issuer +
// client credentials + redirect URL are required.
type SSOProviderConfig struct {
	Name string `yaml:"name"` // operator label + URL slug (e.g. "okta")
	// Type is "oidc" (default) or "saml"; it selects which block below is used.
	Type string `yaml:"type"`
	// SAML config (when type=saml). OIDC fields below are ignored for SAML providers.
	SAML *SAMLProviderConfig `yaml:"saml"`

	Issuer       string   `yaml:"issuer"`        // OIDC issuer URL
	ClientID     string   `yaml:"client_id"`     // the OAuth client id registered at the IdP
	ClientSecret string   `yaml:"client_secret"` // prefer KEYORIX_SSO_<NAME>_CLIENT_SECRET
	RedirectURL  string   `yaml:"redirect_url"`  // must equal <public-host>/auth/sso/<name>/callback
	Scopes       []string `yaml:"scopes"`        // default [openid, profile, email]

	// AutoProvision JIT-creates a Keyorix account on a first SSO login whose verified
	// identity matches no existing user — so an IdP that isn't wired for SCIM push can
	// still onboard users on demand. Opt-in (default off): when false, an unknown
	// identity is refused, exactly as before.
	AutoProvision bool `yaml:"auto_provision"`
	// DefaultRole is the install-wide baseline role granted to a JIT-provisioned user
	// (default "system_viewer"). A misconfigured/unknown role grants nothing —
	// least-privilege on misconfiguration.
	DefaultRole string `yaml:"default_role"`
	// TrustAssertedEmail opts a SAML provider (type: saml) into treating its
	// asserted email as verified for account-linking. SAML has no per-assertion
	// verified-email signal — the assertion being IdP-signed proves the IdP sent
	// it, not that the IdP verified the user owns it. Opt-in (default off):
	// without it, a SAML login can still JIT-provision a NEW account but cannot
	// claim an EXISTING one by asserting its email. Ignored for OIDC providers
	// (whose email_verified claim is checked per-login instead).
	TrustAssertedEmail bool `yaml:"insecure_trust_saml_asserted_email"`

	// GroupSync reconciles the user's NATIVE group memberships from the IdP's groups
	// claim on each login (the IdP becomes the source of truth — membership is added
	// for asserted groups and removed for non-asserted ones). Opt-in (default off).
	// Only existing native groups (provisioned by SCIM or an admin) are touched; an
	// asserted group with no native counterpart is ignored. If the groups claim is
	// absent from the id_token, the sync is a no-op.
	GroupSync bool `yaml:"group_sync"`
	// GroupsClaim is the id_token claim carrying the group names (default "groups";
	// some IdPs use "roles").
	GroupsClaim string `yaml:"groups_claim"`
	// GroupRoleMap maps an IdP group-claim value to a Keyorix (system) role name. When
	// set, each login reconciles the user's grants of the MAPPED roles to their
	// asserted groups (the IdP drives those assignments); roles outside the map are
	// untouched. Uses groups_claim as the source. e.g. {keyorix-admins: system_admin}.
	GroupRoleMap map[string]string `yaml:"group_role_map"`
}

// GetClientSecret returns the resolved client secret, preferring the per-provider
// env var KEYORIX_SSO_<NAME>_CLIENT_SECRET (name upper-cased).
func (p *SSOProviderConfig) GetClientSecret() string {
	return resolveSecret("KEYORIX_SSO_"+strings.ToUpper(p.Name)+"_CLIENT_SECRET", p.ClientSecret)
}

// SAMLProviderConfig is one configured SAML 2.0 IdP (when the provider's type=saml).
// The IdP metadata supplies the entityID, SSO URL, and signing certificate; provide it
// inline (idp_metadata_xml) or as a file path (idp_metadata_file).
type SAMLProviderConfig struct {
	IDPMetadataXML  string `yaml:"idp_metadata_xml"`
	IDPMetadataFile string `yaml:"idp_metadata_file"`
	SPEntityID      string `yaml:"sp_entity_id"` // our SP entity ID (conventionally the metadata URL)
	ACSURL          string `yaml:"acs_url"`      // <public-host>/auth/saml/<name>/acs
	// AllowIDPInitiated permits responses with no InResponseTo (loses CSRF/replay
	// protection). Off by default — enable only for IdPs that require it.
	AllowIDPInitiated bool `yaml:"insecure_allow_idp_initiated_saml"`
	// Attribute names to read from the assertion (empty → common Azure AD/ADFS defaults).
	EmailAttribute  string `yaml:"email_attribute"`
	NameAttribute   string `yaml:"name_attribute"`
	GroupsAttribute string `yaml:"groups_attribute"`
}

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

// JITAccessExpiryConfig configures the just-in-time access-expiry sweeper: a
// background job that removes time-bound role grants whose expiry has passed and
// audits each as role.expired. Expired grants stop authorizing immediately (the
// authorization queries filter on expiry); this sweep reclaims the rows. Opt-in
// (default off).
type JITAccessExpiryConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// GetInterval returns the expiry-sweep interval (Go duration, e.g. "1h"); defaults
// to 1h when unset or unparseable.
func (c JITAccessExpiryConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

// BreakGlassConfig configures self-service emergency access (break-glass): a user
// can immediately self-grant a time-bound emergency role with a written
// justification, loudly audited, for incident response (NIS2/DORA). Opt-in
// (default off — disabled means the endpoint refuses).
type BreakGlassConfig struct {
	Enabled       bool   `yaml:"enabled"`
	EmergencyRole string `yaml:"emergency_role"` // role granted on activation (e.g. "project_developer" — must be contained: no roles.assign, so use a role like project_developer, NOT project_admin)
	DefaultTTL    string `yaml:"default_ttl"`    // grant lifetime when none requested (e.g. "4h")
	MaxTTL        string `yaml:"max_ttl"`        // ceiling on a requested TTL (e.g. "24h")
	// ReviewWindow (ADR-112 §3, break-glass review item 5) is how long an
	// activation may go unreviewed before the posture report (item 4) lists it
	// as a deviation. Default 72h when unset or unparseable — long enough that
	// a reviewer out for a long weekend isn't itself a false alarm, short
	// enough that a genuinely-forgotten review surfaces within a normal work
	// week. Purely a reporting threshold: it never blocks or expires anything,
	// and never governs whether a review can still be submitted late.
	ReviewWindow string `yaml:"review_window"`
}

// GetReviewWindow returns how long an activation may go unreviewed before the
// posture report flags it; defaults to 72h.
func (c BreakGlassConfig) GetReviewWindow() time.Duration {
	if c.ReviewWindow != "" {
		if d, err := time.ParseDuration(c.ReviewWindow); err == nil && d > 0 {
			return d
		}
	}
	return 72 * time.Hour
}

// GetDefaultTTL returns the default emergency-grant lifetime; defaults to 4h.
func (c BreakGlassConfig) GetDefaultTTL() time.Duration {
	if c.DefaultTTL != "" {
		if d, err := time.ParseDuration(c.DefaultTTL); err == nil && d > 0 {
			return d
		}
	}
	return 4 * time.Hour
}

// GetMaxTTL returns the ceiling on a requested emergency-grant TTL; defaults to 24h.
func (c BreakGlassConfig) GetMaxTTL() time.Duration {
	if c.MaxTTL != "" {
		if d, err := time.ParseDuration(c.MaxTTL); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

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

// DualControlConfig configures N-of-M approval (dual control) for access-request
// grants (ISO 27001 A.5.3 / SOX): a request grants its role only once this many
// distinct approvers (none the requester) have approved. 0 or 1 = disabled (a
// single approval grants, the default behaviour).
type DualControlConfig struct {
	RequiredApprovals int `yaml:"required_approvals"`
}

// GetRequiredApprovals returns the dual-control threshold (minimum 1).
func (c DualControlConfig) GetRequiredApprovals() int {
	if c.RequiredApprovals > 1 {
		return c.RequiredApprovals
	}
	return 1
}

// ClassificationConfig configures label-driven read-time enforcement for the
// highest data-classification tier ("restricted", ISO 27001 A.5.12/A.5.13).
//
// RestrictedRequiresApproval defaults to false — off. Today, "restricted" is
// purely informational metadata (internal/core/classification.go's package doc
// documents this as a deliberate scope decision): setting it changes nothing at
// read time. Turning this on for the first time is a BREAKING BEHAVIOUR CHANGE
// for any deployment that already has "restricted" secrets, since those secrets
// were previously readable like any other with sufficient RBAC — an operator
// must opt in explicitly, which is why the default stays false rather than
// enforcing the label the moment it exists.
//
// When true, a direct read of a "restricted" secret's VALUE (not its metadata —
// GetSecret/ListSecrets are unaffected) requires an approved, secret-scoped
// access request (RequestSecretAccess / ApproveSecretAccessRequest, reusing the
// AccessRequest model/flow ADR-024 introduced for project/role requests) or is
// denied. A read whose acting principal cannot be identified as a specific user
// — a machine/service-account credential, or any other caller with no user ID to
// check an approval against — is ALWAYS denied when this is on: there is no
// "wait for approval" for automation, and no silent bypass either (fail-closed,
// matching this codebase's established posture for ambiguous authorization).
type ClassificationConfig struct {
	RestrictedRequiresApproval bool `yaml:"restricted_requires_approval"`
	// RestrictedRequiresPermission, when true, requires the acting user to hold
	// the "secrets.read.restricted" permission at the secret's project scope
	// before a "restricted"-classified secret's value may be read. Off by default
	// (purely additive: only tightens access, never removes it). Can be combined
	// with RestrictedRequiresApproval — when both are on, BOTH must be satisfied.
	RestrictedRequiresPermission bool `yaml:"restricted_requires_permission"`
	// RestrictedRequiresMFAStepUp, when true, requires the acting user to have
	// completed a second-factor MFA verification within RestrictedMFAStepUpWindowMinutes
	// before a "restricted"-classified secret's value may be read. Off by default.
	// Can be combined with the other gate flags — when multiple are on, all must pass.
	RestrictedRequiresMFAStepUp bool `yaml:"restricted_requires_mfa_stepup"`
	// RestrictedMFAStepUpWindowMinutes is how long (in minutes) a completed MFA
	// verification remains valid for restricted-secret reads. 0 = default (15 min).
	RestrictedMFAStepUpWindowMinutes int `yaml:"restricted_mfa_stepup_window_minutes"`
	// MFAStepUpGrantRetentionDays bounds how long an MFAStepUpGrant row is kept
	// past its own expiry (store-mfa-002) before the periodic maintenance sweep
	// hard-deletes it — every successful VerifyMFAStepUp inserts a new row, kept
	// briefly for audit purposes rather than deleted the instant it expires (see
	// internal/storage/store/local_mfa_stepup_grant.go), so without a bound the
	// table grows forever. This is independent of RestrictedMFAStepUpWindowMinutes
	// (how long a grant is ACTIVE) — it governs how long the row survives AFTER
	// it stops being active. 0 = default (30 days, matching
	// SoftDeleteConfig.GetRetentionDays's default). The sweep runs unconditionally
	// (like the login-attempt prune it mirrors) — this is bookkeeping cleanup, not
	// an opt-in compliance-retention feature, and a grant's CREATION is
	// independently, permanently audited (mfa.stepup_verified, never purged per
	// ADR-029), so pruning the row itself never destroys the sole evidentiary
	// record.
	MFAStepUpGrantRetentionDays int `yaml:"mfa_stepup_grant_retention_days"`
}

// GetMFAStepUpGrantRetentionDays returns the MFAStepUpGrant retention window in
// days, defaulting to 30 when unset or non-positive (matches
// SoftDeleteConfig.GetRetentionDays's default).
func (c ClassificationConfig) GetMFAStepUpGrantRetentionDays() int {
	if c.MFAStepUpGrantRetentionDays <= 0 {
		return 30
	}
	return c.MFAStepUpGrantRetentionDays
}

// WebAuthnConfig configures the WebAuthn relying party (ADR-036). RPID is the
// effective domain (e.g. "keyorix.example.com", no scheme/port); RPOrigins are the
// full origins permitted to authenticate (e.g. "https://keyorix.example.com").
type WebAuthnConfig struct {
	Enabled       bool     `yaml:"enabled"`
	RPID          string   `yaml:"rp_id"`
	RPDisplayName string   `yaml:"rp_display_name"`
	RPOrigins     []string `yaml:"rp_origins"`
}

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

// resolveSecret returns the secret named envVar: the value of envVar, or the
// contents of the file named by envVar+"_FILE" (Docker secrets / Kubernetes
// Secret volumes), or fallback (the config-file value) when neither is set.
//
// A misconfiguration -- both set, or the file unreadable/empty -- returns ""
// and NEVER the fallback: it must not quietly use a different credential than
// the operator intended. The accessors that call this return a bare string, so
// the error itself is reported by Config.ValidateSecretSources, which
// Config.Validate runs at startup; the server refuses to boot on it.
func resolveSecret(envVar, fallback string) string {
	v, found, err := secretenv.Lookup(envVar)
	if err != nil {
		return ""
	}
	if found {
		return v
	}
	return fallback
}

// SecretEnvVars lists every fixed-name secret the server resolves through
// resolveSecret. Each also accepts <NAME>_FILE. Secrets whose variable name is
// operator-chosen (SSO client secrets, key-provider and rotation/vault env
// vars) are added by secretEnvNames. TestSecretEnvVars_CoversEveryResolveSecretCall
// fails if a resolveSecret call is added without being listed here.
//
// KEYORIX_MASTER_PASSWORD (internal/crypto.ResolvePassphrase) and
// KEYORIX_BOOTSTRAP_TOKEN (server/main.go) are also *_FILE-capable; they are
// resolved outside this package and validated by their own callers, but listed
// here so the file-permission check covers their files too.
var SecretEnvVars = []string{
	"KEYORIX_DB_PASSWORD",
	"KEYORIX_API_KEY",
	"KEYORIX_SIEM_TOKEN",
	"KEYORIX_SMTP_PASSWORD",
	"KEYORIX_EVIDENCE_WEBHOOK_TOKEN",
	"KEYORIX_NOTIFY_SLACK_WEBHOOK",
	"KEYORIX_NOTIFY_TEAMS_WEBHOOK",
	"KEYORIX_NOTIFY_SMTP_PASSWORD",
	"KEYORIX_NOTIFY_WEBHOOK_TOKEN",
	"KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET",
	"KEYORIX_SCIM_TOKEN",
	"KEYORIX_MASTER_PASSWORD",
	"KEYORIX_BOOTSTRAP_TOKEN",
}

// secretEnvNames returns SecretEnvVars plus the operator-named variables this
// config points at.
func (c *Config) secretEnvNames() []string {
	names := append([]string(nil), SecretEnvVars...)
	for _, p := range c.SSO.Providers {
		names = append(names, "KEYORIX_SSO_"+strings.ToUpper(p.Name)+"_CLIENT_SECRET")
	}
	for _, b := range c.AutoRotation.Backends {
		if b.DSNEnv != "" {
			names = append(names, b.DSNEnv)
		}
	}
	for _, cn := range c.Connect.Connectors {
		if cn.Type == "vault" {
			if cn.TokenEnv != "" {
				names = append(names, cn.TokenEnv)
			} else {
				names = append(names, "VAULT_TOKEN")
			}
		}
	}
	kp := c.Storage.Encryption.KeyProvider
	if kp.EnvVar != "" {
		names = append(names, kp.EnvVar)
	}
	for _, e := range kp.ShamirShareEnv {
		if e != "" {
			names = append(names, e)
		}
	}
	return names
}

// ValidateSecretSources resolves every secret source once and reports every
// misconfiguration (both X and X_FILE set, unreadable/empty/oversized file) in
// one error. Error text names variables and paths only, never a value. It does
// not check file permissions; see SecretFilePaths and internal/startup.
func (c *Config) ValidateSecretSources() error {
	var problems []string
	for _, n := range c.secretEnvNames() {
		if _, _, err := secretenv.Lookup(n); err != nil {
			problems = append(problems, err.Error())
		}
	}
	for _, l := range []struct {
		name string
		inst ServerInstanceConfig
	}{{"server.http", c.Server.HTTP}, {"server.grpc", c.Server.GRPC}} {
		if _, err := l.inst.ResolveMetricsToken(); err != nil {
			problems = append(problems, l.name+": "+err.Error())
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("secret source misconfigured: %s", strings.Join(problems, "; "))
	}
	return nil
}

// SecretFilePaths returns the files named by the <NAME>_FILE variables that are
// set, plus the configured metrics_token_file(s), for the file-permission check
// at startup.
func (c *Config) SecretFilePaths() []string {
	paths := secretenv.FilePaths(c.secretEnvNames()...)
	seen := map[string]bool{}
	for _, p := range paths {
		seen[p] = true
	}
	for _, p := range []string{c.Server.HTTP.MetricsTokenFile, c.Server.GRPC.MetricsTokenFile} {
		if p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths
}

// EnforceSecretFilePermissions applies the key-material permission policy
// (secretenv.CheckPermissions: 0600/0400, plus group-read only for an
// orchestrator-owned file in a group the process holds) to the files named by
// SecretFilePaths. It is the one implementation behind both the server's boot
// check and every `keyorix-server admin` command, so the two refuse the same
// file with the same message.
//
// Key-material secrets (master password, KEK, Shamir shares) are refused
// unconditionally where they are read (secretenv.LookupChecked, no grace); this
// covers the rest, which follow the ADR-112 upgrade grace like the key files:
// refuse when security.enable_file_permission_check is on and
// allow_unsafe_file_permissions is off, otherwise warn. graceSoftened is true
// when the upgrade grace turned a refusal into a warning, so the caller can
// avoid recording that boot as "enforced".
func (c *Config) EnforceSecretFilePermissions() (graceSoftened bool, err error) {
	var problems []string
	for _, p := range c.SecretFilePaths() {
		if err := secretenv.CheckPermissions(p); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) == 0 {
		return false, nil
	}
	msg := strings.Join(problems, "; ")
	if c.Security.EnableFilePermissionCheck && !c.Security.AllowUnsafeFilePermissions {
		// Strict on the implicit ADR-112 default as well (only orchestrator-mounted
		// config/TLS files are softened there). The one exception is the upgrade
		// grace period, same as for the key files in enforceKeyFilePermissions:
		// warn, and record that this boot was softened. Key material never gets
		// here -- LookupChecked has already refused it.
		if c.Security.EnableFilePermissionCheckUpgradeGrace {
			log.Printf("WARNING: %s -- this now fails closed by default (ADR-112); fix the file mode (chmod 0400, or 0440 on an orchestrator-owned mount whose group the process holds) and set security.enable_file_permission_check: true explicitly once compliant.", msg)
			return true, nil
		}
		return false, fmt.Errorf("%s -- refusing to start (or set security.insecure_allow_unsafe_file_permissions to override)", msg)
	}
	log.Printf("WARNING: %s. Set security.enable_file_permission_check to fail closed instead of warning.", msg)
	return false, nil
}

const appRootDir = "."

// ResolvedPath returns the config file path Load(path) would read, without
// actually reading it: an explicit non-empty path wins, otherwise
// KEYORIX_CONFIG_PATH, otherwise "keyorix.yaml" in the application root.
// Callers that need to know exactly which file was (or will be) loaded — e.g.
// startup validation checking that file's permissions — should resolve
// through this helper rather than re-deriving the fallback chain themselves.
func ResolvedPath(path string) string {
	if path == "" {
		path = os.Getenv("KEYORIX_CONFIG_PATH") // a path, not a secret: no _FILE variant
	}
	if path == "" {
		path = filepath.Join(appRootDir, "keyorix.yaml")
	}
	return path
}

// Load loads the YAML configuration file.
//
// Path resolution when path is empty (the default / LoadConfig case):
//  1. KEYORIX_CONFIG_PATH env var, if set (used by container deployments);
//  2. otherwise "keyorix.yaml" in the application root.
//
// An explicit non-empty path argument always wins over the env var.
// Absolute paths (e.g. KEYORIX_CONFIG_PATH=/app/config/production.yaml) are read
// with the safe-read rooted at the file's own directory, so the traversal guard
// still applies; relative paths remain rooted at the application directory.
func Load(path string) (*Config, error) {
	path = ResolvedPath(path)

	baseDir, readPath := appRootDir, path
	if filepath.IsAbs(path) {
		baseDir, readPath = filepath.Dir(path), filepath.Base(path)
	}

	data, err := securefiles.SafeReadFile(baseDir, readPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	// ADR-112 opt-out rule: translate any deprecated old key (a renamed
	// insecure_ setting) to its current name BEFORE the strict KnownFields(true)
	// decode below, which would otherwise reject it outright as unrecognized.
	// See insecure_settings_aliases.go.
	data, deprecatedWarnings := resolveDeprecatedAliases(data)

	// KnownFields(true) makes an unrecognized key (e.g. a correctly-spelled field
	// nested under the wrong parent, or a typo) fail loudly at startup instead of
	// being silently dropped by yaml.Unmarshal. Without this, an operator can set
	// e.g. a top-level `encryption:` block (instead of the real `storage.encryption`)
	// and believe it took effect when it was actually discarded — see configs/dev.yaml
	// history for a real instance of exactly this bug.
	//
	// An empty, whitespace-only, or comments-only file is not an error — yaml.Decoder
	// returns io.EOF for a document with no content, whereas the package-level
	// yaml.Unmarshal silently leaves the target at its zero value. Preserve that
	// historical "no content = all defaults" behavior explicitly rather than
	// surfacing io.EOF as a confusing "failed to unmarshal config" error.
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// ADR-112 secure-by-default: resolve the two inverted-default security keys
	// against whether the operator actually wrote them, not Go's bool zero value.
	explicit, err := explicitSecurityKeys(data)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect config for explicit security keys: %w", err)
	}
	if !explicit["enable_file_permission_check"] {
		cfg.Security.EnableFilePermissionCheck = true
		cfg.Security.EnableFilePermissionCheckImplicitDefault = true
	}
	if !explicit["require_mfa"] {
		cfg.Security.RequireMFA = true
		cfg.Security.RequireMFAImplicitDefault = true
	}

	// server.http.domain/allowed_origins are the only fields documented (in
	// server/config/production.yaml) as supporting ${VAR}/${VAR:-default} interpolation.
	// Expansion is applied here, per-field, AFTER unmarshaling — not as a raw-bytes
	// preprocessing pass over the whole file before yaml.Unmarshal. (Historically this
	// also protected storage.remote.api_key, which legitimately held a literal
	// "${VAR}"-shaped string of its own; that field is gone along with the rest of
	// remote-storage's server-side config surface -- ADR-083 -- but per-field expansion
	// stays the right shape regardless, since a whole-file pass can't distinguish a
	// field that WANTS interpolation from one that doesn't without this same per-field
	// allowlist.)
	cfg.Server.HTTP.Domain = expandEnvVars(cfg.Server.HTTP.Domain)
	for i, origin := range cfg.Server.HTTP.AllowedOrigins {
		cfg.Server.HTTP.AllowedOrigins[i] = expandEnvVars(origin)
	}

	// #1636: a relative storage.database.path was resolved against the PROCESS's
	// cwd at the point internal/storage/factory.go happened to open it — not
	// against baseDir, the directory THIS config file was actually read from.
	// Two processes loading the identical config (e.g. via the same absolute
	// KEYORIX_CONFIG_PATH, the documented container pattern above) but launched
	// with different working directories silently opened two different SQLite
	// files, each successfully, neither warning. Anchoring to baseDir here
	// instead makes "same config" reliably mean "same database" regardless of
	// launch directory — matching how baseDir already anchors the config file's
	// OWN path resolution above. Anchoring to the config file's directory (not
	// an unrelated fixed root) is deliberate: it's what "keyorix.db lives next
	// to keyorix.yaml" (the template's own layout) actually means.
	resolvedDBPath, derr := resolveConfigRelativePath(baseDir, cfg.Storage.Database.Path)
	if derr != nil {
		return nil, fmt.Errorf("invalid storage.database.path: %w", derr)
	}
	cfg.Storage.Database.Path = resolvedDBPath

	// PG-VERIFYFULL-1: storage.database.ssl_root_cert is a file path in the
	// same config, so it gets database.path's anchoring for the same reason
	// (#1636): two processes reading one config must trust the same CA file
	// whatever their cwd. "system" names the OS store, not a file.
	if rc := cfg.Storage.Database.SSLRootCert; rc != "" && rc != SSLRootCertSystem {
		resolvedRootCert, rerr := resolveConfigRelativeFile(baseDir, rc)
		if rerr != nil {
			return nil, fmt.Errorf("invalid storage.database.ssl_root_cert: %w", rerr)
		}
		cfg.Storage.Database.SSLRootCert = resolvedRootCert
	}

	// ADR-112 Amendment 3: the old boolean is an alias with a value mapping,
	// not a key rename, so resolveDeprecatedAliases cannot translate it; it
	// still decodes, and Validate refuses a conflict with audit_durability.
	if alias := cfg.Storage.Database.InsecureAuditSkipDurableSync; alias != nil {
		level := AuditDurabilityStrict
		if *alias {
			level = AuditDurabilityStandard
		}
		deprecatedWarnings = append(deprecatedWarnings, fmt.Sprintf(
			"%q is deprecated and will be removed in the next minor release; %t means %s: %s, use that instead",
			auditDurabilityDeprecatedAliasName, *alias, AuditDurabilitySettingName, level))
	}
	cfg.DeprecatedSettingWarnings = deprecatedWarnings

	return &cfg, nil
}

// explicitSecurityKeys reports which top-level security.* keys the config file
// actually wrote, as a set of lowercase YAML key names. Used by Load() to tell
// "the operator explicitly set this bool to false" apart from "the operator
// never mentioned this key, so it inherits a secure-by-default value" (ADR-112)
// -- a distinction yaml.Unmarshal's own decode into SecurityConfig can't make,
// since both cases leave the struct field at Go's false zero value. Re-parses
// the same raw bytes Load() already decoded, this time into a generic map, so
// it only needs to answer "was this key present," not reproduce the typed
// decode. Deliberately permissive (no KnownFields, ignores a malformed/absent
// security: block as "nothing explicit"): Load's own strict decode above has
// already rejected a truly malformed document before this ever runs.
func explicitSecurityKeys(data []byte) (map[string]bool, error) {
	var raw struct {
		Security map[string]any `yaml:"security"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	explicit := make(map[string]bool, len(raw.Security))
	for k := range raw.Security {
		explicit[k] = true
	}
	return explicit, nil
}

// resolveConfigRelativePath anchors a relative SQLite database path to
// baseDir (the directory Load read the config file from) instead of leaving
// it to resolve against the process's cwd wherever it's later opened. Two
// shapes are deliberately left untouched, matching
// acquireSQLiteMigrationLock's own detection of the same cases (see
// internal/storage/factory_sqlite_migration_lock.go): an in-memory DSN
// (":memory:" or a "mode=memory" query parameter) names no real file to
// anchor, and any existing DSN query-string suffix (an operator-supplied
// "?_pragma=...") is preserved verbatim, resolved around rather than through.
// Already-absolute and empty paths pass through unchanged.
//
// Rejects (rather than silently resolving) a relative path containing "..":
// filepath.Abs/Join would otherwise collapse it into a clean absolute path
// OUTSIDE baseDir with no ".." substring left to detect afterward —
// internal/cli/system/init.go's initializeDatabase used to catch this itself
// (its own "invalid path for database" check), but only on the CLI's own
// init --database step, never on the server's boot path (createLocalStorage
// never ran any such check at all). Centralizing the rejection here, in
// Load() itself, closes that gap for both callers at once, not just the one
// that happened to remember to check.
func resolveConfigRelativePath(baseDir, dbPath string) (string, error) {
	if dbPath == "" || dbPath == ":memory:" || strings.Contains(dbPath, "mode=memory") {
		return dbPath, nil
	}
	base, suffix := dbPath, ""
	if idx := strings.IndexByte(dbPath, '?'); idx != -1 {
		base, suffix = dbPath[:idx], dbPath[idx:]
	}
	if base == "" || filepath.IsAbs(base) {
		return dbPath, nil
	}
	if strings.Contains(base, "..") {
		return "", fmt.Errorf("database.path %q must not contain \"..\"", dbPath)
	}
	abs, err := filepath.Abs(filepath.Join(baseDir, base))
	if err != nil {
		// filepath.Abs only fails if os.Getwd() fails -- a more fundamental
		// problem than this resolution step. Leave the path as Load found it
		// rather than fail config loading over it; the pre-existing (relative)
		// behavior is at least no worse than before this fix.
		return dbPath, nil
	}
	return abs + suffix, nil
}

// envVarPattern matches shell-style ${VAR} and ${VAR:-default} references — the
// interpolation syntax documented (and used) in server/config/production.yaml for
// server.http.domain/allowed_origins. This is intentionally narrow: it recognizes only
// this one pattern and leaves any other "${" text (including a literal one that doesn't
// match) untouched.
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// expandEnvVars resolves ${VAR} / ${VAR:-default} references in a single already-parsed
// config string value against the process environment. Go's os.ExpandEnv doesn't support
// the `:-default` bash fallback form, so this is a small, scoped helper applied only to
// the specific server.http.domain/allowed_origins fields Load() documents as supporting
// it — not a general templating engine, and not run over the raw file bytes (see Load's
// comment for why: a per-field allowlist, not a whole-file pass, is the only way to leave
// some fields' own literal "${...}"-shaped values untouched while still expanding these).
//
// Semantics match bash's ${VAR:-default}: the default is used when VAR is unset OR set to
// the empty string. A reference with no default whose variable is unset is left
// UNRESOLVED (not silently replaced with ""), so a misconfigured/missing env var fails
// loudly downstream (e.g. as an invalid domain or empty allowed_origins entry) instead of
// silently shipping a blank value.
func expandEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		sub := envVarPattern.FindStringSubmatch(match)
		name := sub[1]
		hasDefault := len(sub[2]) > 0
		v, set := os.LookupEnv(name)
		if set && v != "" {
			return v
		}
		if hasDefault {
			return sub[3]
		}
		if set {
			// Explicitly set to "" with no default — honor the explicit empty value.
			return v
		}
		return match
	})
}

// LoadConfig loads configuration using the default path.
// Used for server module compatibility.
func LoadConfig() (*Config, error) {
	return Load("")
}

// BindHost returns the host the listener binds to: Host, or DefaultBindHost
// when unset.
func (s ServerInstanceConfig) BindHost() string {
	if s.Host == "" {
		return DefaultBindHost
	}
	return s.Host
}

// ListenAddr returns the host:port the listener binds to (IPv6-safe).
func (s ServerInstanceConfig) ListenAddr() string {
	return net.JoinHostPort(s.BindHost(), s.Port)
}

func validateBindHost(field, host string) error {
	if host == "" || net.ParseIP(host) != nil || host == "localhost" {
		return nil
	}
	return fmt.Errorf("%s %q is not an IP address (use 127.0.0.1, 0.0.0.0, ::1, :: or a specific interface IP)", field, host)
}

// Validate checks the configuration for required fields and correctness.
func (c *Config) Validate() error { // NOSONAR -- cognitive complexity 32, suppress go:S3776
	// X and X_FILE both set, or an unreadable X_FILE, must stop the boot: the
	// accessors return "" for those, which would otherwise surface later as a
	// confusing connection failure (or, worse, an unauthenticated feature).
	if err := c.ValidateSecretSources(); err != nil {
		return err
	}
	if st := c.Storage.Type; st == "postgres" || st == "postgresql" {
		if _, err := ResolvePostgresConnConfig(&c.Storage.Database); err != nil {
			return err
		}
	}
	if err := validateTLSMode("server.http.tls_mode", c.Server.HTTP.TLSMode); err != nil {
		return err
	}
	if err := validateTLSMode("server.grpc.tls_mode", c.Server.GRPC.TLSMode); err != nil {
		return err
	}
	if err := validateLogFormat(c.Server.Log.Format); err != nil {
		return err
	}
	if err := validateAccessLogOnSinkStall(c.Server.AccessLog.OnSinkStall); err != nil {
		return err
	}
	if err := validateBindHost("server.http.host", c.Server.HTTP.Host); err != nil {
		return err
	}
	if err := validateBindHost("server.grpc.host", c.Server.GRPC.Host); err != nil {
		return err
	}
	if c.Server.HTTP.Enabled && c.Server.HTTP.Port == "" {
		return fmt.Errorf("HTTP server is enabled but no port is specified")
	}

	if c.Server.GRPC.Enabled && c.Server.GRPC.Port == "" {
		return fmt.Errorf("gRPC server is enabled but no port is specified")
	}

	if err := validateAllowedOrigins(c.Server.HTTP.AllowedOrigins); err != nil {
		return err
	}

	if c.Server.HTTP.TLS.Enabled {
		if c.Server.HTTP.TLS.AutoCert {
			if len(c.Server.HTTP.TLS.Domains) == 0 {
				return fmt.Errorf("autocert is enabled but no domains are specified")
			}
		} else {
			if c.Server.HTTP.TLS.CertFile == "" || c.Server.HTTP.TLS.KeyFile == "" {
				return fmt.Errorf("TLS is enabled but cert_file or key_file is missing")
			}
		}
	}

	if c.Server.GRPC.TLS.Enabled {
		// gRPC has no ACME integration: auto_cert would build a TLS config with no
		// certificate, so every handshake fails (a silent outage). Reject it explicitly
		// rather than start a server that cannot serve.
		if c.Server.GRPC.TLS.AutoCert {
			return fmt.Errorf("gRPC TLS auto_cert is not supported; provide cert_file and key_file")
		}
		if c.Server.GRPC.TLS.CertFile == "" || c.Server.GRPC.TLS.KeyFile == "" {
			return fmt.Errorf("gRPC TLS is enabled but cert_file or key_file is missing")
		}
	}

	if err := validatePooler(c.Storage.Type, &c.Storage.Database); err != nil {
		return err
	}
	if err := validateNativeReadPoolMax(c.Storage.Type, &c.Storage.Database); err != nil {
		return err
	}
	// ADR-112 Amendment 3: a known level, no conflict with the deprecated
	// alias, and standard only on PostgreSQL (a SQLite backend refuses it).
	if err := c.Storage.Database.validateAuditDurability(c.Storage.Type); err != nil {
		return err
	}
	// ADR-112 Amendment 4: a compliance profile refuses insecure_audit_skip_reads.
	if err := validateInsecureAuditSkipReads(c); err != nil {
		return err
	}

	if err := validateKeyDirLock(c); err != nil {
		return err
	}

	switch c.Storage.Type {
	case "remote":
		// remote storage uses its own connection — no local DB config required.
		// validateRemoteStorageNotServer always returns a non-nil error here (see
		// its own doc comment); return it directly rather than an if-err wrapper
		// staticcheck (correctly) flags as a tautological comparison.
		return validateRemoteStorageNotServer(c)
	case "postgres", "postgresql":
		db := c.Storage.Database
		if db.DSN == "" && (db.Host == "" || db.Name == "" || db.User == "") {
			return fmt.Errorf("postgres storage requires either database.dsn or all of host, name, and user to be set")
		}
		// PG-VERIFYFULL-1: verify-full with no CA, or an unusable CA file,
		// refuses to start here rather than at the first connection.
		if err := ValidateDatabaseTLS(&db); err != nil {
			return err
		}
		if db.SingleWriter && c.Security.AuthRateLimitFallback.GetReplicas() > 1 {
			return fmt.Errorf("%s", singleWriterMultiReplicaError)
		}
		if db.SingleWriter && db.TransactionPooling() {
			return fmt.Errorf("%s", singleWriterTransactionPoolingError)
		}
	// #1640: "sqlite" is an accepted alias for "local" -- see the matching
	// comment in internal/storage/factory.go's CreateStorage switch.
	case "local", "sqlite":
		if c.Storage.Database.Path == "" {
			return fmt.Errorf("database path is not specified")
		}
		if c.Storage.Database.SingleWriter {
			return fmt.Errorf("%s", singleWriterUnsupportedBackendError)
		}
	case "":
		// #G-blank-storage-default: a blank storage.type used to be bucketed
		// with "local"/"sqlite" here, so a config file with no storage: block
		// (or one that set database.path without type) passed validation
		// silently and then hit the storage factory's identical blank-type
		// tolerance -- two independent layers both treating "unset" as
		// "local", with no operator-visible signal either way. See
		// internal/storage/factory.go's CreateStorage (#G-blank-storage-default)
		// for the full rationale; this is that same fix's validation-layer
		// half. The ONE legitimate "no storage: block = local SQLite" shape
		// (an existing on-prem single-node server) is preserved by
		// server/main.go explicitly setting cfg.Storage.Type = "local" in the
		// server's own boot sequence BEFORE this Validate() call ever runs --
		// not here, since this function is shared by the CLI, which must NOT
		// get that default applied on its behalf.
		return fmt.Errorf("storage.type is not set: no storage configuration found -- specify \"local\", \"postgres\", \"postgresql\", or \"remote\" explicitly")
	default:
		// #463: an unrecognized storage.type (e.g. a typo like "postgress" or
		// "remot") used to fall through silently to the SQLite default in both
		// this validator and the storage factory — in a multi-replica HA
		// deployment intending shared Postgres/remote storage, that produced
		// per-replica split-brain SQLite instances with no operator-visible
		// signal. Fail fast at config-validation time instead.
		return fmt.Errorf("invalid storage.type %q: must be one of \"local\", \"sqlite\", \"postgres\", \"postgresql\", or \"remote\"", c.Storage.Type)
	}

	if c.Secrets.Limits.MaxSecretSize == 0 {
		c.Secrets.Limits.MaxSecretSize = DefaultMaxSecretSize
	}
	if c.Secrets.Limits.MaxSecretSize < 0 {
		return fmt.Errorf("secrets.limits.max_secret_size (%d) must not be negative", c.Secrets.Limits.MaxSecretSize)
	}
	if c.Secrets.Limits.MaxSecretSize > MaxSecretSizeHardCeiling {
		return fmt.Errorf("secrets.limits.max_secret_size (%d) exceeds the hard ceiling of %d bytes (1 MiB) -- "+
			"a secret store is not a general blob store; use a purpose-built object store for larger values",
			c.Secrets.Limits.MaxSecretSize, MaxSecretSizeHardCeiling)
	}

	if c.Locale.Language == "" {
		c.Locale.Language = "en"
	}
	if c.Locale.FallbackLanguage == "" {
		c.Locale.FallbackLanguage = "en"
	}

	supportedLanguages := map[string]bool{
		"en": true, "ru": true, "es": true, "fr": true, "de": true,
	}
	if !supportedLanguages[c.Locale.Language] {
		return fmt.Errorf("unsupported language: %s. Supported languages: en, ru, es, fr, de", c.Locale.Language)
	}
	if !supportedLanguages[c.Locale.FallbackLanguage] {
		return fmt.Errorf("unsupported fallback language: %s. Supported languages: en, ru, es, fr, de", c.Locale.FallbackLanguage)
	}

	if err := validateConnectTypes(c.Connect); err != nil {
		return err
	}

	if err := validateConnectScopes(c.Connect); err != nil {
		return err
	}

	if err := validateConnectGCPProjectID(c.Connect); err != nil {
		return err
	}

	if err := validateConnectAWSAccountID(c.Connect); err != nil {
		return err
	}

	if err := validateSSOIDPInitiated(c.SSO); err != nil {
		return err
	}

	if err := validateSSOAudienceIsolation(c); err != nil {
		return err
	}

	if err := validateWebAuthnRP(c.WebAuthn); err != nil {
		return err
	}

	if err := validateOneTimePasswordExpiries(c.Security); err != nil {
		return err
	}

	return nil
}

// MaxOneTimePasswordExpiry is the longest life a one-time password may be configured
// with. A credential issued out-of-band that stays valid for longer is a standing
// secret, which is what expiry exists to prevent.
const MaxOneTimePasswordExpiry = 7 * 24 * time.Hour

// validateOneTimePasswordExpiries rejects a security.one_time_password_ttl /
// security.recovery_one_time_password_ttl that is set but unusable, instead of
// letting the getters fall back to the default and hide the typo (a "7d" is not a Go
// duration: say "168h"). Empty is valid and means the default.
func validateOneTimePasswordExpiries(s SecurityConfig) error {
	for _, f := range []struct{ key, raw string }{
		{"security.one_time_password_ttl", s.OTPLifetime},
		{"security.recovery_one_time_password_ttl", s.RecoveryOTPLifetime},
	} {
		if f.raw == "" {
			continue
		}
		d, err := time.ParseDuration(f.raw)
		if err != nil {
			return fmt.Errorf("%s: %q is not a Go duration (use e.g. \"24h\" or \"90m\"; days are written in hours, \"168h\" for 7 days)", f.key, f.raw)
		}
		if d <= 0 || d > MaxOneTimePasswordExpiry {
			return fmt.Errorf("%s: %q is outside the allowed range (greater than 0, at most %s)", f.key, f.raw, MaxOneTimePasswordExpiry)
		}
	}
	return nil
}

// validateConnectTypes enforces #1476: every cfg.Connect.Connectors entry's Type
// must be one of connecttypes.KnownTypes, the single source of truth for recognized
// connector types (see that var's own doc comment for why server/main.go's
// dispatch switch stays a literal switch rather than deriving from this list, and
// how the two are kept from drifting apart). Runs BEFORE validateConnectScopes:
// an unrecognized type is a more fundamental problem than a scope-shape issue on
// a connector Keyorix would never actually construct. Aggregates every offending
// connector into one error, mirroring validateConnectScopes's own aggregation —
// an operator fixing config should not have to restart-and-discover connectors
// one at a time.
//
// This closes the same fail-open shape ADR-082 closed for scope: server/main.go's
// Connect-wiring switch used to silently skip (log.Printf, keep booting) a
// connector whose Type matched no case label — see the v0.92.0 CHANGELOG entry.
func validateConnectTypes(cc ConnectConfig) error {
	known := make(map[string]bool, len(connecttypes.KnownTypes))
	for _, t := range connecttypes.KnownTypes {
		known[t] = true
	}
	var invalid []string
	for _, connector := range cc.Connectors {
		if !known[connector.Type] {
			invalid = append(invalid, fmt.Sprintf("%s (type: %q)", connector.Name, connector.Type))
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("connect: connector(s) with unrecognized type (must be one of %s): %s",
			strings.Join(connecttypes.KnownTypes, ", "), strings.Join(invalid, ", "))
	}
	return nil
}

// validateConnectScopes enforces ADR-082 §B/§C on cfg.Connect.Connectors — pure
// config-shape validation, no DB/network access, no logging. Every check aggregates
// across ALL offending connectors into one error naming each by config name, rather
// than failing on (and hiding) the first one found — an operator fixing config
// should not have to restart-and-discover connectors one at a time. There is no
// deployment-wide escape hatch (ADR-082 §C, amended): a missing scope fails boot
// unconditionally, the same as an unrecognized value — the migration path for an
// existing deployment is to add scope: to every connector, not to opt out of the
// check. Checks run in this order, each independent of the others by construction
// (a connector can only land in one bucket): unrecognized scope, missing scope,
// scope "project" without a Project name, scope "platform" with a Project name set
// (a platform connector is not owned by any single project).
func validateConnectScopes(cc ConnectConfig) error {
	var missing, invalid, projectNeedsProject, platformRejectsProject []string
	for _, connector := range cc.Connectors {
		switch connector.Scope {
		case "":
			missing = append(missing, connector.Name)
		case "project":
			if connector.Project == "" {
				projectNeedsProject = append(projectNeedsProject, connector.Name)
			}
		case "platform":
			if connector.Project != "" {
				platformRejectsProject = append(platformRejectsProject, connector.Name)
			}
		default:
			invalid = append(invalid, connector.Name)
		}
	}

	if len(invalid) > 0 {
		return fmt.Errorf("connect: connector(s) with unrecognized scope (must be \"project\" or \"platform\"): %s", strings.Join(invalid, ", "))
	}
	if len(missing) > 0 {
		return fmt.Errorf("connect: connector(s) missing required \"scope\" (must be \"project\" or \"platform\" — ADR-082, no exceptions): %s", strings.Join(missing, ", "))
	}
	if len(projectNeedsProject) > 0 {
		return fmt.Errorf("connect: connector(s) with scope \"project\" missing required \"project\": %s", strings.Join(projectNeedsProject, ", "))
	}
	if len(platformRejectsProject) > 0 {
		return fmt.Errorf("connect: connector(s) with scope \"platform\" must not set \"project\" (a platform connector is not owned by any single project): %s", strings.Join(platformRejectsProject, ", "))
	}
	return nil
}

// validateConnectGCPProjectID closes a confused-deputy gap in the
// "gcp-secret-manager" connector: unlike the Vault/Azure Address (the backend's own
// base URL — the connector IS the tenant boundary), a GCP Secret Manager ref carries
// its own project ID embedded in the resource name
// (projects/PROJECT/secrets/NAME/versions/VERSION). validateConnectScopes above
// already binds a connector to a Keyorix-side tenant (project/platform scope), but
// that says nothing about which GCP project the ambient ADC identity actually
// reaches — a connector scoped to Keyorix project X with no project_id set would
// let any connect.read-holding caller in project X's scope read a secret from GCP
// project Y (or any other project the ADC identity can reach), as long as the
// backend IAM happens to allow it. project_id (#431) is the only thing that pins
// the GCP-side project to match the Keyorix-side scope, so — like Scope above — it
// is required unconditionally, with no deployment-wide escape hatch: a missing
// project_id fails boot for every "gcp-secret-manager" connector, aggregated into
// one error naming every offending connector by name (mirrors validateConnectScopes's
// own aggregation style). Only connectors of type "gcp-secret-manager" are checked;
// other types have their own binding field (Address) which is enforced separately.
func validateConnectGCPProjectID(cc ConnectConfig) error {
	var missing []string
	for _, connector := range cc.Connectors {
		if connector.Type == "gcp-secret-manager" && connector.ProjectID == "" {
			missing = append(missing, connector.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("connect: gcp-secret-manager connector(s) missing required \"project_id\" — an unset project_id lets a caller read secrets from ANY GCP project the ambient ADC identity can reach, regardless of this connector's Keyorix tenant scope (a confused-deputy gap; #431/ADR-082): %s", strings.Join(missing, ", "))
	}
	return nil
}

// awsAccountIDPattern is the AWS account ID format: exactly 12 digits.
var awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

// validateConnectAWSAccountID checks the OPTIONAL account_id pin on
// "aws-secrets-manager" connectors — the AWS sibling of
// validateConnectGCPProjectID above, but deliberately NOT a mandatory-field check:
// see ConnectorConfig.AccountID's own doc comment and internal/connect/awssm.go for
// why AWS's confused-deputy risk shape is narrower than GCP's (a bare secret-name
// ref, the common case, can never cross AWS accounts at all; a full-ARN ref naming
// another account additionally requires that account's own resource policy to have
// separately granted access — a double opt-in). Because the field is optional, this
// only ever rejects a connector that DID set account_id but set it to something that
// is not a well-formed AWS account ID (exactly 12 digits) — catching a typo at boot
// rather than at first read. A missing account_id is not an error here; server/main.go
// logs a startup recommendation for that case instead (mirroring the phase-in
// idiom GCP's project_id itself used before it became mandatory). Aggregates every
// offending connector into one error, mirroring validateConnectGCPProjectID's own
// aggregation style.
func validateConnectAWSAccountID(cc ConnectConfig) error {
	var malformed []string
	for _, connector := range cc.Connectors {
		if connector.Type != "aws-secrets-manager" || connector.AccountID == "" {
			continue
		}
		if !awsAccountIDPattern.MatchString(connector.AccountID) {
			malformed = append(malformed, fmt.Sprintf("%s (account_id: %q)", connector.Name, connector.AccountID))
		}
	}
	if len(malformed) > 0 {
		return fmt.Errorf("connect: aws-secrets-manager connector(s) with malformed \"account_id\" (must be exactly 12 digits, the AWS account ID format): %s", strings.Join(malformed, ", "))
	}
	return nil
}

// validateRemoteStorageNotServer enforces ADR-083: storage.type: remote is a
// CLI/client mode only — it delegates the ENTIRE storage backend to an upstream
// server over HTTP, and RemoteStorage never implements the primitives
// AuthorizePrincipal needs to resolve a permission for ANY caller (GetUserRoleIDsAt,
// GetUserGroupRoleIDsAt, RoleSetHasPermission are all hard "not supported in
// remote storage" stubs). A process with server.http.enabled or
// server.grpc.enabled registers the full RequirePermission-gated route set
// regardless of storage backend — on storage.type: remote, every one of those
// checks would fail closed, for every permission, for every caller, making the
// combination a broken feature, not a smaller one. See ADR-083 for the full
// investigation (which supersedes ADR-049's "downstream Keyorix server" framing)
// before ever considering lifting this gate.
//
// G80 follow-up (2026-08-24): rejects unconditionally now, not just when
// server.http.enabled or server.grpc.enabled. server/main.go's startSchedulers
// (main.go:157) runs EVERY time this process's main() executes, independent of
// both of those flags — #G12 deliberately unified scheduler startup so a
// gRPC-only (HTTP disabled) or even an HTTP-and-gRPC-both-disabled "worker-only"
// deployment still runs its background jobs. Three of the 17 schedulers
// (anomaly_detection, login_attempt_prune, mfa_stepup_grant_prune) have no
// enable flag at all -- they always run -- so no finite enumeration of
// `cfg.X.Enabled` checks can fully close this gap; a new scheduler added later
// would silently reopen it again. This function is safe to make unconditional
// because it is ONLY ever reached from server/main.go's own cfg.Validate() call
// (verified: internal/config.Config.Validate has no caller anywhere in the CLI --
// the old internal/cli tree and the internal/storage/remote package it used are
// both fully deleted now, and the current thin CLI, cli/, never imports this
// package at all -- ADR-108 Decision A's depguard forbids it) -- there is no
// legitimate caller this change could break.
//
// #1480: this function is enforcement, not the dead topology it forbids —
// do NOT delete it (or its test) as part of any future cleanup pass that
// removes the storage.type:-remote-as-server route registrations/proxy
// plumbing this gate makes unreachable. Deleting it would silently
// RE-ENABLE the topology, with no code left to make it work correctly —
// worse than leaving it, since a server would then boot successfully on
// storage.type: remote and 403/error on every request instead of failing
// loud at startup. The #1480 cleanup pass (docs/adr-083-remote-storage-cli-only.md's
// "Deferred work" section) removed the now-dead client/server plumbing
// this gate makes unreachable, but explicitly did NOT touch this function.
func validateRemoteStorageNotServer(c *Config) error {
	return fmt.Errorf("storage.type: remote cannot back a server process: " +
		"remote storage is a CLI/client mode only, not a deployable server backend " +
		"(this includes a scheduler-only process with server.http.enabled and " +
		"server.grpc.enabled both false -- server/main.go always starts its " +
		"background schedulers regardless of either flag) — see ADR-083")
}

// validateAllowedOrigins rejects a misconfigured CORS allowlist (server.http.
// allowed_origins) at startup rather than letting it sit silently until it's
// proven wrong in the field. A bare "*" — which matches every origin — must not
// be configurable here: the caller must list explicit origins. Every entry must
// also be a well-formed origin: an http(s) scheme, a host, and nothing else (no
// path, query, fragment, userinfo, or trailing slash) — the exact shape
// Access-Control-Allow-Origin expects an Origin header to have.
func validateAllowedOrigins(origins []string) error {
	for _, o := range origins {
		if o == "*" {
			return fmt.Errorf("server.http.allowed_origins must not contain \"*\" — list explicit origins (e.g. https://app.example.com); a wildcard origin defeats the CORS allowlist")
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return fmt.Errorf("server.http.allowed_origins entry %q is not a valid origin (expected scheme://host[:port], e.g. https://app.example.com)", o)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("server.http.allowed_origins entry %q must use http or https", o)
		}
	}
	return nil
}

// validateSSOIDPInitiated (F3, adversarial-review 2026-09-14) refuses any SAML
// provider that sets allow_idp_initiated. keyorix's SAML replay protection rests
// entirely on the single-use RelayState row CompleteSAML consumes on the ACS;
// there is no assertion-ID / NotOnOrAfter replay cache. An IdP-initiated response
// carries no InResponseTo and no RelayState to bind, so it has no replay defence
// at all — CompleteSAML already fails such a response closed today, which makes
// the option DEAD, not merely risky. A dead security toggle an operator can set
// to "true" and believe is in effect is worse than no toggle: reject it loud at
// boot so the misconfiguration surfaces as a config error rather than a false
// sense of security (and a latent trap for whoever might one day wire IdP-initiated
// up without noticing the missing replay cache). If IdP-initiated is ever genuinely
// implemented, add the assertion-ID + NotOnOrAfter replay cache first, then lift
// this check. Aggregates every offending provider into one error, mirroring the
// connect validators.
func validateSSOIDPInitiated(sso SSOConfig) error {
	var offending []string
	for _, p := range sso.Providers {
		if p.SAML != nil && p.SAML.AllowIDPInitiated {
			offending = append(offending, p.Name)
		}
	}
	if len(offending) > 0 {
		return fmt.Errorf("sso: provider(s) set insecure_allow_idp_initiated_saml (or its deprecated alias allow_idp_initiated), which is not supported — keyorix has no SAML assertion-replay cache, so an IdP-initiated response (no InResponseTo / RelayState) has no replay protection and is refused at the ACS regardless; remove it: %s", strings.Join(offending, ", "))
	}
	return nil
}

// validateSSOAudienceIsolation (F4, adversarial-review 2026-09-14) closes a
// cross-seam token-confusion gap between the two independent OIDC trust seams:
// human SSO (cfg.SSO.Providers) and machine-identity federation (cfg.OIDC.Issuers).
// A human-SSO provider's client_id must not ALSO be a trusted machine-federation
// audience for the SAME issuer. If it were, one id_token minted by that issuer for
// the human SSO client would satisfy the machine seam too (identical iss, and aud
// contains the shared client_id) — a token issued for one trust boundary replaying
// into the other, authenticating a browser SSO login as a machine identity. The
// machine seam enforces an exact issuer match, so the confusion is only reachable
// when the issuers coincide; that is exactly the condition checked here (guard the
// condition, not the conclusion). Only OIDC-type SSO providers are considered
// (SAML providers mint no OIDC id_token). No-op when machine federation is disabled.
func validateSSOAudienceIsolation(c *Config) error {
	if !c.OIDC.Enabled {
		return nil
	}
	var collisions []string
	for _, p := range c.SSO.Providers {
		if p.Type == "saml" || p.Issuer == "" || p.ClientID == "" {
			continue
		}
		providerIssuer := strings.TrimRight(p.Issuer, "/")
		for _, iss := range c.OIDC.Issuers {
			if strings.TrimRight(iss.Issuer, "/") != providerIssuer {
				continue
			}
			for _, aud := range iss.Audiences {
				if aud == p.ClientID {
					collisions = append(collisions, fmt.Sprintf("sso provider %q client_id is also a machine-federation audience on oidc issuer %q (issuer %q)", p.Name, iss.Name, providerIssuer))
				}
			}
		}
	}
	if len(collisions) > 0 {
		return fmt.Errorf("cross-seam audience collision — a human-SSO id_token would also authenticate as a machine identity: %s; use a distinct client_id per trust seam and remove the sso client_id from the machine-federation issuer's audiences", strings.Join(collisions, "; "))
	}
	return nil
}

// validateWebAuthnRP (F5, adversarial-review 2026-09-14) is a fail-loud startup
// sanity check on the WebAuthn relying-party config. The go-webauthn library
// enforces the real origin/RP-ID match per ceremony at runtime; without this
// check a misconfigured rp_origins (plaintext http, or a host that is not rp_id
// nor a subdomain of it) makes EVERY passkey ceremony fail at runtime with an
// opaque library error, instead of a clear config error at boot. Rules follow
// WebAuthn L3 effective-domain semantics:
//   - each rp_origin must parse to a URL with a host;
//   - scheme must be https, except http is allowed only for a loopback host
//     (localhost / 127.0.0.1 / ::1) for local development;
//   - the origin host must equal rp_id or be a subdomain of rp_id — a passkey is
//     scoped to the rp_id registrable domain, so an origin outside it can never
//     satisfy the ceremony.
//
// This is config hygiene, not the security boundary itself (the library remains
// the authority per ceremony); it exists so the misconfiguration is caught once,
// at boot, rather than per failed login.
func validateWebAuthnRP(wc WebAuthnConfig) error {
	if !wc.Enabled {
		return nil
	}
	if wc.RPID == "" {
		return fmt.Errorf("webauthn is enabled but rp_id is not set")
	}
	if len(wc.RPOrigins) == 0 {
		return fmt.Errorf("webauthn is enabled but no rp_origins are configured")
	}
	rpID := strings.ToLower(wc.RPID)
	for _, o := range wc.RPOrigins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			return fmt.Errorf("webauthn rp_origin %q is not a valid origin URL (expected scheme://host[:port], e.g. https://app.example.com)", o)
		}
		host := strings.ToLower(u.Hostname())
		loopback := isLoopbackConfigHost(host)
		switch u.Scheme {
		case "https":
			// ok
		case "http":
			if !loopback {
				return fmt.Errorf("webauthn rp_origin %q must use https (http is allowed only for a loopback host)", o)
			}
		default:
			return fmt.Errorf("webauthn rp_origin %q must use https (http is allowed only for a loopback host)", o)
		}
		if !loopback && host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return fmt.Errorf("webauthn rp_origin %q host %q must equal rp_id %q or be a subdomain of it", o, host, rpID)
		}
	}
	return nil
}

// isLoopbackConfigHost reports whether host is a loopback hostname/literal, for
// the http-only-on-loopback dev exception in validateWebAuthnRP. Kept as a plain
// string check (no net import) — the set of loopback spellings a browser origin
// can carry is small and fixed, and this is a config-hygiene check, not a network
// guard.
func isLoopbackConfigHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// Save saves the configuration to a YAML file. Mirrors Load's path handling:
// an absolute path is rooted at its OWN directory (so the traversal guard
// still applies, just against the right base) rather than being joined
// against appRootDir ("."), which would silently write under the current
// directory instead of the intended absolute location.
func Save(path string, cfg *Config) error {
	if path == "" {
		path = filepath.Join(appRootDir, "keyorix.yaml")
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	baseDir, writePath := appRootDir, path
	if filepath.IsAbs(path) {
		baseDir, writePath = filepath.Dir(path), filepath.Base(path)
	}

	if err := securefiles.SecureWriteFileSync(baseDir, writePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %q: %w", path, err)
	}

	return nil
}

// SecretValuePolicyConfig configures the opt-in secret-value quality gate
// (core.SecretValuePolicy). Disabled unless Enabled is true.
type SecretValuePolicyConfig struct {
	Enabled       bool     `yaml:"enabled"`
	MinLength     int      `yaml:"min_length"`     // reject values shorter than this (0 = no minimum)
	RejectCommon  bool     `yaml:"reject_common"`  // reject a built-in denylist of weak/placeholder values
	ExtraDenylist []string `yaml:"extra_denylist"` // additional rejected values (case-insensitive)
}

// SecretNamePolicyConfig configures the opt-in secret naming convention
// (core.SecretNamePolicy). Disabled unless Enabled is true.
type SecretNamePolicyConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Pattern   string `yaml:"pattern"`    // RE2 regex the name must match (anchor with ^…$); empty = no regex check
	MaxLength int    `yaml:"max_length"` // reject names longer than this (0 = no maximum)
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
