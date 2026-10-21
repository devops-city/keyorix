package main

import (
	"log"
)

// wireRecoverAdminMode is a core wiring step (coreWiringSteps in main.go).
func wireRecoverAdminMode(cw *coreWiring) error {
	cfg, store := cw.cfg, cw.store
	// keyless mode (docs/design-b2-recover-admin.md §5): flagged loudly and
	// repeatedly wherever an operator or auditor would look -- a startup
	// warning EVERY boot (not just the first), a boolean in /system/info
	// (server/http/handlers/system.go), and an audit event at every startup
	// while it's enabled, so the tamper-evident chain itself carries a
	// durable, repeated record that this install has been running in the
	// weaker mode -- an auditor reading the chain doesn't have to trust a
	// point-in-time config dump.
	if cfg.Security.RecoverAdmin.KeylessMode {
		log.Printf("WARNING: security.recover_admin.insecure_keyless_admin_recovery is ENABLED -- `keyorix-server admin recover-admin` " +
			"can restore ANY admin account on HOST ACCESS ALONE, with no recovery key required or checked. This " +
			"collapses host access and admin access into one trust boundary. Intended for labs/demo use only; " +
			"disable it for any real deployment.")
		auditKeylessModeStartup(store)
	} else {
		warnIfRecoveryKeyMissing(store)
	}
	return nil
}
