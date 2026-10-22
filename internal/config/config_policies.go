package config

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
