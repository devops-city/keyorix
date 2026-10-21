package main

import (
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// DefaultIntegrations wires every ADR-109 integration that has its own
// wireXxx helper (docs/adr-109-core-depends-on-interfaces.md): TimestampNotary
// + its receipt verifier, SAMLServiceProvider (folded into human SSO wiring
// alongside OIDC), RotationExecutorResolver, DynamicBackendFactory, and
// ConnectorResolver — steps 1 through 4. Encryption (step 5,
// EncryptionProvider) is ALSO fully behind internal/core/ports as of step 5 —
// coreIntegrationDeps is empty, machine-checked by
// TestCoreIntegrationDepsAllowlistIsEmpty — but its own wiring
// (SetSecretValueEncryptor/SetAuthEncryptor, initializeCoreService, above
// this function's own call site) was deliberately NOT moved here: it feeds
// audit-checkpoint and evidence-pack signing keys that are derived and wired
// immediately after it and before DefaultIntegrations is ever called, so
// folding it in would either reorder that dependency or require threading
// the derived keys back out of DefaultIntegrations for no decoupling benefit
// — ADR-109's target is internal/core's import graph, not where each
// integration's own bootstrapping code physically lives.
//
// A nil implementation means the feature is unavailable; wiring never fails
// open (ADR-109 decision #2). A malformed config for an explicitly ENABLED
// feature returns an error and stops boot (the ADR-082 fail-closed shape); a
// feature left disabled, or a single misconfigured provider/backend within an
// enabled one, is skipped with a warning — unchanged from this wiring's
// pre-ADR-109 behavior. DynamicBackendFactory is the one exception: it is
// always wired unconditionally (there is no top-level "enabled" flag for
// dynamic secrets — each DynamicSecretConfig opts in individually), matching
// internal/core.dynamicEngine's pre-ADR-109 unconditional fallback to
// internal/dynamic.New. wireConnect calls log.Fatalf directly, rather than
// returning an error, for the same boot-time misconfigurations the pre-ADR-109
// inline block already treated as fatal (ADR-082) — unchanged behavior, only
// the call site moved.
func DefaultIntegrations(cfg *config.Config, coreService *core.KeyorixCore) error {
	if err := wireCheckpointNotary(cfg, coreService); err != nil {
		return err
	}
	wireHumanSSO(cfg, coreService)
	if err := wireBackendRotation(cfg, coreService); err != nil {
		return err
	}
	wireDynamicSecrets(cfg, coreService)
	if err := wireConnect(cfg, coreService); err != nil {
		return err
	}
	return nil
}

// wireDefaultIntegrations is a core wiring step (coreWiringSteps in main.go).
func wireDefaultIntegrations(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire every ADR-109 integration that has its own wireXxx helper
	// (docs/adr-109-core-depends-on-interfaces.md, steps 1-4): external-notary
	// checkpoint anchoring (ADR-029), human SSO (OIDC + SAML), backend rotation,
	// dynamic secrets, and Keyorix Connect. Encryption (step 5) is wired
	// separately, above this call — see DefaultIntegrations' own doc comment
	// for why its wiring call site was not moved here too.
	if err := DefaultIntegrations(cfg, coreService); err != nil {
		return err
	}
	return nil
}
