package main

import (
	"fmt"
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
)

// cmpOr returns a if non-empty, else b (a tiny local helper to avoid a new import).
func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// wireWebAuthn is a core wiring step (coreWiringSteps in main.go).
func wireWebAuthn(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire WebAuthn / passkeys (ADR-036) when configured. A bad RP config (no
	// origins / invalid RP ID) fails loud rather than silently disabling passkeys.
	if wa := cfg.WebAuthn; wa.Enabled {
		rp, werr := webauthn.New(&webauthn.Config{
			RPID:          wa.RPID,
			RPDisplayName: cmpOr(wa.RPDisplayName, "Keyorix"),
			RPOrigins:     wa.RPOrigins,
		})
		if werr != nil {
			return fmt.Errorf("failed to init WebAuthn: %w", werr)
		}
		coreService.SetWebAuthn(rp)
		log.Printf("WebAuthn enabled (RP ID %q, %d origin(s))", wa.RPID, len(wa.RPOrigins))
	}
	return nil
}
