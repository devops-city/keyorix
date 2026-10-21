package main

import (
	"log"

	"github.com/keyorixhq/keyorix/internal/core"
)

// wireBreakGlass is a core wiring step (coreWiringSteps in main.go).
func wireBreakGlass(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire self-service emergency access (break-glass); zero value = disabled.
	coreService.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled:       cfg.BreakGlass.Enabled,
		EmergencyRole: cfg.BreakGlass.EmergencyRole,
		DefaultTTL:    cfg.BreakGlass.GetDefaultTTL(),
		MaxTTL:        cfg.BreakGlass.GetMaxTTL(),
		// #2461: GetReviewWindow had no non-test caller, so ADR-112's
		// post-activation-review deviation was computed against nothing. Wired
		// unconditionally, NOT behind cfg.BreakGlass.Enabled: an install that
		// has since turned break-glass off can still hold unreviewed
		// activations from when it was on, and those are exactly the ones that
		// must not drop off the posture report.
		ReviewWindow: cfg.BreakGlass.GetReviewWindow(),
		// BREAKGLASS-OWED-1: lifetime of an activation granted while the audit
		// log refuses writes (committed with an owed-audit record instead).
		DegradedTTL: cfg.BreakGlass.GetDegradedTTL(),
	})
	return nil
}

// wireDualControl is a core wiring step (coreWiringSteps in main.go).
func wireDualControl(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire N-of-M dual-control approval for access requests (1 = disabled).
	coreService.SetDualControlPolicy(cfg.DualControl.GetRequiredApprovals())
	if n := cfg.DualControl.GetRequiredApprovals(); n > 1 {
		log.Printf("Dual-control approval enabled: %d approvals required per access request", n)
	}
	return nil
}

// wireClassification is a core wiring step (coreWiringSteps in main.go).
func wireClassification(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire the "restricted" classification read-time gate (#128's product
	// decision); false (the default) leaves the label purely informational,
	// identical to every deployment's behaviour today.
	coreService.SetClassificationRestrictedRequiresApproval(cfg.Classification.RestrictedRequiresApproval)
	if cfg.Classification.RestrictedRequiresApproval {
		log.Printf("Classification enforcement enabled: reading a \"restricted\" secret's value now requires an approved, secret-scoped access request")
	}
	coreService.SetClassificationRestrictedRequiresPermission(cfg.Classification.RestrictedRequiresPermission)
	if cfg.Classification.RestrictedRequiresPermission {
		log.Printf("Classification enforcement enabled: reading a \"restricted\" secret's value now requires the %q permission at the project scope", core.PermSecretReadRestricted)
	}
	coreService.SetClassificationRestrictedRequiresMFAStepUp(cfg.Classification.RestrictedRequiresMFAStepUp, cfg.Classification.RestrictedMFAStepUpWindowMinutes)
	if cfg.Classification.RestrictedRequiresMFAStepUp {
		window := cfg.Classification.RestrictedMFAStepUpWindowMinutes
		if window == 0 {
			window = 15
		}
		log.Printf("Classification enforcement enabled: reading a \"restricted\" secret's value now requires a recent MFA verification (window: %d min)", window)
	}
	return nil
}
