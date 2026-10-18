package core

// rules_compat.go keeps core's public API stable after the pure validation and
// encoding rules moved to the leaf package internal/core/rules (see that
// package's doc for why: fuzz throughput). Types are aliases, so values are
// interchangeable; functions are thin wrappers; sentinel errors are the same
// variables, so errors.Is keeps working across the boundary.

import "github.com/keyorixhq/keyorix/internal/core/rules"

// SecretValuePolicy is rules.SecretValuePolicy.
type SecretValuePolicy = rules.SecretValuePolicy

// DefaultSecretValuePolicy returns the disabled (no-op) policy.
func DefaultSecretValuePolicy() SecretValuePolicy { return rules.DefaultSecretValuePolicy() }

// PasswordPolicy is rules.PasswordPolicy (ADR-025).
type PasswordPolicy = rules.PasswordPolicy

// DefaultPasswordPolicy returns the ADR-025 defaults.
func DefaultPasswordPolicy() PasswordPolicy { return rules.DefaultPasswordPolicy() }

// --- PAT column codecs (rules/pat_codec.go) ---

// DecodePATScopes parses a stored scopes column; fails closed on corruption.
func DecodePATScopes(raw string) []string { return rules.DecodePATScopes(raw) }

// DecodePATCIDRs parses a stored CIDR allowlist; fails closed on corruption.
func DecodePATCIDRs(raw string) []string { return rules.DecodePATCIDRs(raw) }

func encodePATScopes(scopes []string) (string, error) { return rules.EncodePATScopes(scopes) }

func encodePATCIDRs(cidrs []string) (string, error) { return rules.EncodePATCIDRs(cidrs) }

// Same backing slices as the rules sentinels (tests compare against these).
var (
	patScopeCorrupted = rules.PATScopeCorrupted
	patCIDRCorrupted  = rules.PATCIDRCorrupted
)

// --- Secret ACL, secret references, SCIM token (rules/*.go) ---

// DecodeSecretACLPerms parses a stored permissions column (nil on empty/invalid).
func DecodeSecretACLPerms(raw string) []string { return rules.DecodeSecretACLPerms(raw) }

// Sentinel errors for reference resolution: the SAME variables as in rules,
// so errors.Is matches whichever package a caller names.
var (
	ErrSecretRefInvalid  = rules.ErrSecretRefInvalid
	ErrSecretRefNotFound = rules.ErrSecretRefNotFound
)

// ParseSecretRef splits a "project/environment/name" reference.
func ParseSecretRef(ref string) (project, environment, name string, err error) {
	return rules.ParseSecretRef(ref)
}

// MinSCIMTokenLength is the minimum configured SCIM bearer token length.
const MinSCIMTokenLength = rules.MinSCIMTokenLength

// ValidateSCIMTokenStrength rejects a non-empty SCIM token shorter than the minimum.
func ValidateSCIMTokenStrength(token string) error { return rules.ValidateSCIMTokenStrength(token) }

// --- JWK parsing (rules/jwk.go) ---

type jwk = rules.JWK

const (
	maxRSABits           = rules.MaxRSABits
	minRSABits           = rules.MinRSABits
	maxRSAPublicExponent = rules.MaxRSAPublicExponent
)

func parseJWK(k jwk) (any, error) { return rules.ParseJWK(k) }

// --- SSO returnTo sanitizer (rules/return_to.go) ---

func sanitizeReturnTo(s string) string { return rules.SanitizeReturnTo(s) }

// CheckSCIMTokenShape refuses a SCIM token that passes the length floor but is
// obviously not random, or equals another configured secret (#3397).
func CheckSCIMTokenShape(token string, otherSecrets map[string]string) error {
	return rules.CheckSCIMTokenShape(token, otherSecrets)
}
