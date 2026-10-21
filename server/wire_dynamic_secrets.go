package main

import (
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
)

// wireDynamicSecrets wires dynamic-secrets settings (ADR-035) and the default
// credential-engine factory (ports.DynamicBackendFactory, backed by
// internal/dynamic.New — the only place a concrete dynamic-secrets backend is
// still reached, now that internal/core itself depends only on
// ports.DynamicBackendEngine). There is no top-level "enabled" flag for
// dynamic secrets, so — unlike this file's other wireX helpers — the factory
// is always wired unconditionally; each DynamicSecretConfig opts a project
// into a specific backend individually.
func wireDynamicSecrets(cfg *config.Config, coreService *core.KeyorixCore) {
	// Tell core whether the auto-revoke sweeper runs (started below), so IssueLease
	// refuses to mint from backends whose lease TTL only the sweeper enforces
	// (MySQL/MongoDB) when it is disabled — otherwise the credential never expires.
	coreService.SetDynamicSweepEnabled(cfg.DynamicSecrets.SweepEnabled)
	// SSRF guard for admin DSNs: disabled (private targets allowed) only when the
	// operator explicitly opts in via dynamic_secrets.allow_private_network_targets.
	coreService.SetDynamicAllowPrivateTargets(cfg.DynamicSecrets.AllowPrivateNetworkTargets)
	// TLS-required-by-default guard for the mongodb/redis backends: disabled
	// (plaintext allowed) only when the operator explicitly opts in via
	// dynamic_secrets.allow_insecure_transport.
	coreService.SetDynamicAllowInsecureTransport(cfg.DynamicSecrets.AllowInsecureTransport)
	// Install-wide hard ceiling on any dynamic-secret lease's TTL (#97); enforced on
	// top of each config's own optional (default-unbounded) MaxTTLSeconds.
	coreService.SetDynamicMaxLeaseTTL(cfg.DynamicSecrets.GetMaxLeaseTTL())

	// dynamic.New itself re-checks allow-private/allow-insecure per call (an engine
	// that dials the admin DSN re-validates at dial time, G48) — capture the two
	// booleans once here rather than re-reading cfg on every resolve.
	allowPrivate := cfg.DynamicSecrets.AllowPrivateNetworkTargets
	allowInsecure := cfg.DynamicSecrets.AllowInsecureTransport
	coreService.SetDynamicEngineFactory(func(backendType string) (dynamic.CredentialEngine, error) {
		return dynamic.New(backendType, allowPrivate, allowInsecure)
	})
}

// wireDynamicSecretsStep is a core wiring step (coreWiringSteps in main.go). DefaultIntegrations
// also calls wireDynamicSecrets; this second call is the one initializeCoreService
// always made after the session TTLs, kept as it was.
func wireDynamicSecretsStep(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	wireDynamicSecrets(cfg, coreService)
	return nil
}
