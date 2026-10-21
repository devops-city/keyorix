package main

import (
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/rotation"
	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// resolveVaultToken returns the Vault connector token from the env var named by
// tokenEnv (default VAULT_TOKEN) or its _FILE variant; "" when unset.
func resolveVaultToken(tokenEnv string) (string, error) {
	if tokenEnv == "" {
		tokenEnv = "VAULT_TOKEN"
	}
	v, _, err := secretenv.Lookup(tokenEnv)
	return v, err
}

// wireBackendRotation wires the configured backend rotation executors (ADR-047)
// — upstream systems whose credentials the auto-rotation flow can rotate in
// place. Admin DSNs come from the environment, never the config file. A
// backend with an unknown type, or one missing its fail-closed allowed_refs
// allowlist, is skipped with a warning rather than failing startup — matching
// this wiring's pre-ADR-109 behavior. A KNOWN cloud backend type (aws-iam,
// gcp-service-account, azure-app) whose implementation this server binary
// was compiled without (a no<provider> build tag) is a different condition —
// that fails startup outright (ADR-109 step 6, S2): never fail open on a
// config the operator explicitly enabled. Returned (not log.Fatalf'd)
// specifically for that one condition so it is testable in-process — see
// server/rotation_failclosed_noaws_test.go and its nogcp sibling.
func wireBackendRotation(cfg *config.Config, coreService *core.KeyorixCore) error {
	if len(cfg.AutoRotation.Backends) == 0 {
		return nil
	}
	var execs []rotation.Executor
	for _, b := range cfg.AutoRotation.Backends {
		switch b.Type {
		case "postgresql":
			// Fail closed: a backend runs privileged DDL with an admin DSN, so an
			// explicit allow-list is required — refuse to register an unbounded one.
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			dsn := b.GetDSN()
			if dsn == "" {
				log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
			}
			execs = append(execs, rotation.NewPostgresExecutor(b.Name, dsn, b.AllowedRefs))
		case "mysql":
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			dsn := b.GetDSN()
			if dsn == "" {
				log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
			}
			execs = append(execs, rotation.NewMySQLExecutor(b.Name, dsn, b.AllowedRefs))
		case "mongodb":
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			dsn := b.GetDSN()
			if dsn == "" {
				log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
			}
			execs = append(execs, rotation.NewMongoExecutor(b.Name, dsn, b.AllowedRefs))
		case "redis":
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			dsn := b.GetDSN()
			if dsn == "" {
				log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
			}
			execs = append(execs, rotation.NewRedisExecutor(b.Name, dsn, b.AllowedRefs))
		case "aws-iam", "gcp-service-account", "azure-app":
			// Generate-upstream backends: the cloud mints the new credential;
			// credentials for the mint call itself come from the ambient cloud
			// identity chain (no DSN). Still fail-closed on allowed_refs. Routed
			// through rotation.LookupCloudExecutor (ADR-109 step 6) rather than each
			// backend's own constructor directly, because a no<x>-tagged build
			// (e.g. noaws) does not compile that constructor in at all — ok=false
			// is exactly the "not available in this build" signal, handled the
			// same as an unknown type below (S2 hardens this into a startup
			// failure for an explicitly-configured, not-compiled-in backend).
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			exec, ok := rotation.LookupCloudExecutor(b.Type, rotation.CloudExecutorParams{
				Name: b.Name, Region: b.Region, AllowedRefs: b.AllowedRefs,
			})
			if !ok {
				return fmt.Errorf("rotation backend %q has type %q, which this server binary was not built with (excluded by a no%s build tag) — rebuild without that tag, or remove this backend", b.Name, b.Type, cloudProviderTag(b.Type))
			}
			execs = append(execs, exec)
		default:
			log.Printf("Rotation backend %q: unknown type %q, skipping", b.Name, b.Type)
		}
	}
	if len(execs) > 0 {
		coreService.SetRotationManager(rotation.NewManager(execs))
		log.Printf("Backend rotation executors enabled (%d backend(s))", len(execs))
	}
	return nil
}

// cloudProviderTag maps a cloud backend/connector type to the no<provider>
// build tag that excludes it (ADR-109 step 6), for use in a boot-time error
// naming the build profile responsible — e.g. "rotation backend ... excluded
// by a noaws build tag".
func cloudProviderTag(backendOrConnectorType string) string {
	switch backendOrConnectorType {
	case "aws-iam", "aws-secrets-manager", "aws-sts", "aws-kms":
		return "aws"
	case "gcp-service-account", "gcp-secret-manager", "gcp", "gcp-kms":
		return "gcp"
	case "azure-app", "azure-key-vault", "azure", "azure-kms":
		return "azure"
	default:
		return "<provider>"
	}
}
