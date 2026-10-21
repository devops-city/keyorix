package main

// wireMembership is a core wiring step (coreWiringSteps in main.go).
func wireMembership(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Apply the project membership validation mode (ADR-022). Empty = allowlist.
	if vm := cfg.Membership.ValidationMode; vm != "" {
		coreService.SetMembershipValidationMode(vm)
	}
	// Apply the invitation domain allowlist (ADR-022). Empty = no restriction.
	if len(cfg.Membership.DomainAllowlist) > 0 {
		coreService.SetMembershipDomainAllowlist(cfg.Membership.DomainAllowlist)
	}
	return nil
}
