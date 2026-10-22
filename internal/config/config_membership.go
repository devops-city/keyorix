package config

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
