package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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

// BoolPtr returns a pointer to b — for setting optional *bool config fields.
func BoolPtr(b bool) *bool { return &b }

// IntPtr returns a pointer to n — for setting optional *int config fields.
func IntPtr(n int) *int { return &n }

// MaxSecretSizeHardCeiling (1 MiB) is the absolute upper bound secrets.limits.
// max_secret_size may be configured to — Validate rejects a configured value above
// this outright, at startup, rather than silently clamping it. An operator who
// genuinely needs to store larger blobs should use a purpose-built object store and
// reference it from a secret, not raise this ceiling; every comparable managed
// secret store (see DefaultMaxSecretSize) treats "secret" as a credential-sized
// value, not a general blob store, and this cap exists to keep that true here too.
const MaxSecretSizeHardCeiling = 1 << 20 // 1 MiB

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
// unconditionally where they are read (secretenv.LookupChecked, no grace); here a
// key-material file gets the same warn-or-refuse decision, but its message never
// offers the override. Everything follows the ADR-112 upgrade grace like the key
// files: refuse when security.enable_file_permission_check is on and
// allow_unsafe_file_permissions is off, otherwise warn. graceSoftened is true
// when the upgrade grace turned a refusal into a warning, so the caller can
// avoid recording that boot as "enforced".
func (c *Config) EnforceSecretFilePermissions() (graceSoftened bool, err error) {
	keyMaterial := map[string]bool{} // the key-material secrets, by variable name
	for _, n := range c.keyMaterialSecretEnvNames() {
		keyMaterial[n] = true
	}
	// Each file is named by the variable or config key it came from, through
	// secretenv.DescribeFile (CheckPermissionsNamed): a relative path is never
	// shown, it may be the secret itself (SECRETENV-REVIEW-1 F4).
	var problems, keyProblems []string
	seen := map[string]bool{}
	for _, fv := range secretenv.FileVars(c.secretEnvNames()...) {
		if seen[fv.Path] {
			continue
		}
		seen[fv.Path] = true
		if err := secretenv.CheckPermissionsNamed(fv.Var(), fv.Path); err != nil {
			if keyMaterial[fv.Name] {
				keyProblems = append(keyProblems, err.Error())
				continue
			}
			problems = append(problems, err.Error())
		}
	}
	for _, m := range []struct{ key, path string }{
		{"server.http.metrics_token_file", c.Server.HTTP.MetricsTokenFile},
		{"server.grpc.metrics_token_file", c.Server.GRPC.MetricsTokenFile},
	} {
		if m.path == "" || seen[m.path] {
			continue
		}
		seen[m.path] = true
		if err := secretenv.CheckPermissionsNamed(m.key, m.path); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems)+len(keyProblems) == 0 {
		return false, nil
	}
	// The hint must be true for the file it is about (BOOT-REFUSALS-1 item 4): the
	// override and the grace period soften this check, but a key-material file is
	// refused again, with no override, where it is read (secretenv.LookupChecked), so
	// offering the override for it sent operators to a setting that cannot help.
	var parts []string
	if len(problems) > 0 {
		parts = append(parts, strings.Join(problems, "; "))
	}
	if len(keyProblems) > 0 {
		parts = append(parts, strings.Join(keyProblems, "; ")+" (key material: security.insecure_allow_unsafe_file_permissions does not apply to it; the server refuses it wherever it reads it, so fix the file)")
	}
	msg := strings.Join(parts, "; ")
	if c.Security.EnableFilePermissionCheck && !c.Security.AllowUnsafeFilePermissions {
		// Strict on the implicit ADR-112 default as well (only orchestrator-mounted
		// config/TLS files are softened there). The one exception is the upgrade
		// grace period, same as for the key files in enforceKeyFilePermissions:
		// warn, and record that this boot was softened.
		if c.Security.EnableFilePermissionCheckUpgradeGrace {
			log.Printf("WARNING: %s -- this now fails closed by default (ADR-112); fix the file (chmod 0400, or 0440 on a root-owned orchestrator mount whose group the process holds; chown it to the server's user or root) and set security.enable_file_permission_check: true explicitly once compliant.", msg)
			return true, nil
		}
		if len(problems) == 0 {
			return false, fmt.Errorf("%s -- refused until the file is fixed", msg)
		}
		return false, fmt.Errorf("%s -- refused until the file is fixed (for the files that are not key material, security.insecure_allow_unsafe_file_permissions: true turns this into a warning)", msg)
	}
	if c.Security.AllowUnsafeFilePermissions {
		log.Printf("WARNING: %s. Only a warning because security.insecure_allow_unsafe_file_permissions is set; remove it to fail closed.", msg)
		return false, nil
	}
	log.Printf("WARNING: %s. Set security.enable_file_permission_check to fail closed instead of warning.", msg)
	return false, nil
}

// keyMaterialSecretEnvNames are the secrets read through secretenv.LookupChecked
// (no override): the master passphrase, the env KEK provider's variable and the
// Shamir share variables.
func (c *Config) keyMaterialSecretEnvNames() []string {
	kp := c.Storage.Encryption.KeyProvider
	names := []string{"KEYORIX_MASTER_PASSWORD"}
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
		return nil, fmt.Errorf("failed to unmarshal config: %w", describeUnknownKeys(err))
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

// Validate checks the configuration for required fields and correctness.
func (c *Config) Validate() error {
	for _, validate := range configValidators {
		if err := validate(c); err != nil {
			return err
		}
	}
	return nil
}

// configValidators are Validate's steps, in order; the first error wins. Two
// steps also write defaults into c (applySecretsLimits, validateLocaleSection),
// and storage.type remote stops at validateStorageSection, as before. A new
// config section's validation is one function in its config_<domain>.go file
// plus one line here.
var configValidators = []func(*Config) error{
	// X and X_FILE both set, or an unreadable X_FILE, must stop the boot: the
	// accessors return "" for those, which would otherwise surface later as a
	// confusing connection failure (or, worse, an unauthenticated feature).
	(*Config).ValidateSecretSources,
	validatePostgresConnConfig,
	validateServerSection,
	validateStorageSection,
	applySecretsLimits,
	validateLocaleSection,
	validateConnectSection,
	validateSSOSection,
	validateWebAuthnSection,
	validateSecuritySection,
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
