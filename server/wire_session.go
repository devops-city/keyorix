package main

// wireSessionTTLs is a core wiring step (coreWiringSteps in main.go).
func wireSessionTTLs(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Apply session-token lifetimes (short-lived tokens with silent auto-refresh).
	// Defaults preserve the historic 24h access window with no absolute ceiling, so
	// an install without a session block behaves exactly as before.
	coreService.SetSessionTTLs(cfg.Session.GetAccessTTL(), cfg.Session.GetAbsoluteTTL())
	return nil
}
