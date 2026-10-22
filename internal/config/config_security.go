package config

import (
	"fmt"
	"time"
)

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

// The require_mfa upgrade grace period's own durable facts (#2923): when it
// started (written once, by the first graced boot on the version that bounded
// it; RFC 3339) and the grace clock's high-water mark (the latest time any
// boot or check recorded; RFC 3339). The grace period ends at the first
// administrator MFA enrolment or ADR112RequireMFAGracePeriod after the start,
// whichever comes first, and the clock never reads earlier than the
// high-water mark, so a backward clock step cannot extend it.
const (
	ADR112RequireMFAGraceStartedKey = "adr112.require_mfa.grace_started"
	ADR112RequireMFAGraceClockKey   = "adr112.require_mfa.grace_clock"
	ADR112RequireMFAGracePeriod     = 30 * 24 * time.Hour
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
	// adr112.require_mfa.enforced marker) relying on the implicit default, still
	// inside ADR-112's grace period for MFA on upgrades (#2923: until the first
	// administrator enrols a second factor, at most ADR112RequireMFAGracePeriod
	// after the recorded start). RequireMFA stays true: the running server reads
	// the grace period from core.KeyorixCore.MFARequired, so it can end without
	// a restart. A fresh install is enforced and marked, so it never gets here.
	// Never read from YAML; false on every hand-built *Config.
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

// validateSecuritySection checks the security one-time-password lifetimes (Validate step).
func validateSecuritySection(c *Config) error {
	if err := validateOneTimePasswordExpiries(c.Security); err != nil {
		return err
	}
	return nil
}
