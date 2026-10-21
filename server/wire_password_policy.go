package main

import (
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/admin"
)

// resolvePasswordPolicy merges the configured password_policy block onto the core's
// built-in defaults (ADR-025), so a rule the operator didn't explicitly set keeps its
// safe default instead of collapsing to the Go zero value (#G37). config.PasswordPolicyConfig
// can't return a core.PasswordPolicy directly (internal/config can't import internal/core —
// it would cycle back through internal/encryption), so the conversion happens here instead.
//
// The conversion itself lives in admin.ResolvePasswordPolicy so that
// `admin check-admin-password` (#3201) applies the very same policy.
func resolvePasswordPolicy(pp config.PasswordPolicyConfig) core.PasswordPolicy {
	return admin.ResolvePasswordPolicy(pp)
}

// wirePasswordPolicy is a core wiring step (coreWiringSteps in main.go).
func wirePasswordPolicy(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Apply the configured password policy, merging any rule the operator didn't
	// explicitly set onto the core's conservative built-in defaults (ADR-025) —
	// #G37: a PARTIAL password_policy block (e.g. just reject_common_passwords)
	// must not silently zero out every other rule it didn't mention.
	coreService.SetPasswordPolicy(resolvePasswordPolicy(cfg.PasswordPolicy))
	return nil
}
