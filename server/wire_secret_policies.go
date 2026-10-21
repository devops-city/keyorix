package main

import (
	"log"

	"github.com/keyorixhq/keyorix/internal/core"
)

// wireSecretValuePolicy is a core wiring step (coreWiringSteps in main.go).
func wireSecretValuePolicy(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Apply the optional secret-value quality gate (reject weak/placeholder values).
	if svp := cfg.SecretValuePolicy; svp.Enabled {
		coreService.SetSecretValuePolicy(core.SecretValuePolicy{
			Enabled:       true,
			MinLength:     svp.MinLength,
			RejectCommon:  svp.RejectCommon,
			ExtraDenylist: svp.ExtraDenylist,
		})
		log.Printf("Secret-value policy enabled (min_length=%d, reject_common=%t, denylist=%d)",
			svp.MinLength, svp.RejectCommon, len(svp.ExtraDenylist))
	}
	return nil
}

// wireMaxSecretSize is a core wiring step (coreWiringSteps in main.go).
func wireMaxSecretSize(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Apply the maximum secret VALUE size (bytes) — unlike the quality gate above,
	// this is always applied (not gated behind an Enabled flag): cfg.Secrets.Limits.
	// MaxSecretSize is already defaulted and ceiling-checked by cfg.Validate(), so
	// there is always a real, valid value to set here.
	coreService.SetMaxSecretSize(cfg.Secrets.Limits.MaxSecretSize)
	return nil
}

// wireSecretNamePolicy is a core wiring step (coreWiringSteps in main.go).
func wireSecretNamePolicy(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Apply the optional secret naming convention (regex / max-length on names).
	if snp := cfg.SecretNamePolicy; snp.Enabled {
		if err := coreService.SetSecretNamePolicy(core.SecretNamePolicy{
			Enabled:   true,
			Pattern:   snp.Pattern,
			MaxLength: snp.MaxLength,
		}); err != nil {
			log.Fatalf("Invalid secret_name_policy: %v", err)
		}
		log.Printf("Secret-name policy enabled (pattern=%q, max_length=%d)", snp.Pattern, snp.MaxLength)
	}
	return nil
}
