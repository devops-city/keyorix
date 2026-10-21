package main

import (
	"context"
	"log"
)

// wireRBACPermissionCatalog is a core wiring step (coreWiringSteps in main.go).
func wireRBACPermissionCatalog(cw *coreWiring) error {
	coreService := cw.core
	// Top up the canonical RBAC permission catalog (ADR-044): adds any permission
	// introduced in a later release to an already-initialised install, granting it to
	// its baseline roles. No-op pre-bootstrap and best-effort (never blocks startup).
	if err := coreService.ReconcileRBACPermissions(context.Background()); err != nil {
		log.Printf("RBAC permission reconciliation: %v (continuing)", err)
	}
	return nil
}

// wireAlertsWriteRole is a core wiring step (coreWiringSteps in main.go).
func wireAlertsWriteRole(cw *coreWiring) error {
	coreService := cw.core
	// F1 (ADR-110 follow-up): seed the alert_operator built-in role on an
	// install that predates it, and grant alerts.write, once, to every role that
	// already holds system.write. No-op pre-bootstrap and best-effort (never
	// blocks startup); a no-op on every subsequent restart once run.
	if err := coreService.ReconcileAlertsWriteRole(context.Background()); err != nil {
		log.Printf("alerts.write role reconciliation: %v (continuing)", err)
	}
	return nil
}
