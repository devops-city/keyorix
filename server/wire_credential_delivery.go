package main

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/delivery"
)

// wireSetupTokenTTL is a core wiring step (coreWiringSteps in main.go).
func wireSetupTokenTTL(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Apply the credential-delivery setup-token TTL (ADR-028). GetSetupTokenTTL
	// falls back to 24h when the block is absent or invalid.
	coreService.SetSetupTokenTTL(cfg.CredentialDelivery.GetSetupTokenTTL())
	return nil
}

// wireCredentialDelivery is a core wiring step (coreWiringSteps in main.go).
func wireCredentialDelivery(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire the credential-delivery channel (ADR-028). New selects out-of-band/SMTP/
	// log from the configured mode and fails loud on a bad mode (e.g. smtp with no
	// host), so a misconfigured install does not silently drop setup links.
	cd := cfg.CredentialDelivery
	deliverer, derr := delivery.New(cd.DeliveryConfig())
	if derr != nil {
		return fmt.Errorf("failed to init credential delivery: %w", derr)
	}
	coreService.SetCredentialDelivery(deliverer, cd.BaseURL)
	return nil
}
