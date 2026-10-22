package config

import (
	"time"
)

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
	// DegradedTTL (BREAKGLASS-OWED-1) is the lifetime of an activation granted
	// while the audit log refuses writes: it is committed together with an
	// owed-audit record instead of its audit rows, and expires after this (or
	// after the lifetime it would get normally, whichever is shorter). Default
	// 15m when unset or unparseable.
	DegradedTTL string `yaml:"degraded_ttl"`
}

// GetDegradedTTL returns a degraded activation's lifetime; defaults to 15m.
// core caps it at the normal lifetime of the same request, so a value above
// default_ttl/max_ttl never lengthens anything.
func (c BreakGlassConfig) GetDegradedTTL() time.Duration {
	if c.DegradedTTL != "" {
		if d, err := time.ParseDuration(c.DegradedTTL); err == nil && d > 0 {
			return d
		}
	}
	return 15 * time.Minute
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
