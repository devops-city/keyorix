package main

import (
	"context"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// warnIfRecoveryKeyMissing logs a prominent WARN on EVERY boot (not just the
// first) while security.recover_admin.insecure_keyless_admin_recovery is off and no recovery
// key has ever been generated -- `recover-admin` is unusable in that state
// (F6, recovery-key visibility) and, unlike keyless mode, there is no other
// startup-time signal an operator would see. Best-effort: a lookup failure
// is logged but never blocks startup, matching every other best-effort
// startup diagnostic in this function.
func warnIfRecoveryKeyMissing(store corestorage.Storage) {
	_, found, err := store.GetRecoveryKeyRecord(context.Background())
	if err != nil {
		log.Printf("note: could not check recovery-key configuration (%v)", err)
		return
	}
	if !found {
		log.Printf("WARNING: no recovery key is configured -- `keyorix-server admin recover-admin` is unusable " +
			"until one is generated. Run `keyorix-server admin recovery-key rotate` (see docs/SELF_HOSTING.md, " +
			"\"Generate your admin recovery key now\"). This warning repeats on every startup until a key is generated.")
	}
}

// auditKeylessModeStartup records, at every boot while security.recover_admin.insecure_keyless_admin_recovery is
// enabled, a system-actor audit event (no UserID, never machine-identity-typed), so the
// tamper-evident chain itself carries a repeated record of the weaker mode. Direct
// LogAuditEvent: this runs before any request context exists, the same shape as
// auditConnectorProjectBindingCreate (listed in core's auditAttributionAllowlist).
func auditKeylessModeStartup(store corestorage.Storage) {
	ok := true
	if err := store.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType:   "admin.keyless_mode_enabled_at_startup",
		Description: "server started with security.recover_admin.insecure_keyless_admin_recovery enabled -- recover-admin can restore any admin account on host access alone",
		Success:     &ok,
		ActorType:   core.ActorTypeSystem,
		EventTime:   time.Now(),
	}); err != nil {
		log.Printf("note: could not record the keyless-mode startup event to the audit chain (%v)", err)
	}
}

// auditReadsSkippedStartupEventType is written at every boot while
// storage.database.insecure_audit_skip_reads is enabled (ADR-112 Amendment 4).
const auditReadsSkippedStartupEventType = "admin.audit_reads_skipped_at_startup"

// auditReadsSkippedStartup records, at every boot while
// storage.database.insecure_audit_skip_reads is enabled, a system-actor audit
// event, the same shape and reason as auditKeylessModeStartup: the
// tamper-evident chain carries its own repeated record that successful secret
// reads were not being audited from this start on.
func auditReadsSkippedStartup(store corestorage.Storage) {
	ok := true
	if err := store.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType: auditReadsSkippedStartupEventType,
		Description: "server started with storage.database.insecure_audit_skip_reads enabled -- successful " +
			"secret-value reads are NOT audited; writes, permission changes, authentication, denied reads and " +
			"admin actions still are",
		Success:   &ok,
		ActorType: core.ActorTypeSystem,
		EventTime: time.Now(),
	}); err != nil {
		log.Printf("note: could not record the audit-reads-skipped startup event to the audit chain (%v)", err)
	}
}
