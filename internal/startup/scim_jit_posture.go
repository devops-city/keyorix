package startup

import "github.com/keyorixhq/keyorix/internal/config"

// appendSCIMJITPosture adds the SCIM+JIT warning to result.Warnings when SCIM
// is on and an SSO provider JIT-provisions accounts (see
// config.SCIMJITUnmanagedProviders for what "the same provider" means).
func appendSCIMJITPosture(cfg *config.Config, result *ValidationResult) {
	if w := config.SCIMJITUnmanagedWarning(cfg.SCIMJITUnmanagedProviders()); w != "" {
		result.Warnings = append(result.Warnings, w)
	}
}
