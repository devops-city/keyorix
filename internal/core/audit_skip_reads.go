// audit_skip_reads.go -- ADR-112 Amendment 4:
// storage.database.insecure_audit_skip_reads. When it is set, a SUCCESSFUL
// secret-value read writes no audit row and no secret_access_logs row. Every
// other event, including every failed or denied read, is written as before.
//
// The skip is applied at the three emit choke points every audit write in this
// package funnels through (emitAudit, emitAuditOn, emitAuditWithAccessLog;
// TestDirectLogAuditEventCallersAreSafe keeps it that way), BEFORE any storage
// call, so a skipped read opens no database transaction and takes no audit
// chain lock. Keying on the event, not on each read call site, means a new
// disclosure path that records secret.read is covered without its own wiring.
package core

import "github.com/keyorixhq/keyorix/internal/storage/models"

// successfulValueReadEventTypes are the audit event types that record a secret
// VALUE being disclosed. Only these, and only with Success=true, are skipped.
//
//   - secret.read: every native value read (REST GET /secrets/{id}
//     ?include_value=true and /secrets/value, gRPC GetSecretValue, render, and
//     the source read of a copy, environment copy and environment clone), all
//     through LogSecretReadWithProject (INV-CORE-secret-read-means-value-disclosure).
//   - connect.secret_read: a federated read through a connector (Success=true
//     on the allow path only; its six deny paths write Success=false).
//
// Deliberately NOT here, so they stay audited: secret.metadata_read and
// secret.versions_listed (no value), dynamic_lease.issued (a credential is
// minted, a create), share_access_elevated (records that access came through a
// share), secret.certificate_inspected (public certificate metadata).
var successfulValueReadEventTypes = map[string]bool{
	"secret.read":          true,
	EventConnectSecretRead: true,
}

// SetInsecureAuditSkipReads records storage.database.insecure_audit_skip_reads.
// Wired once at startup, before the server serves any request.
func (c *KeyorixCore) SetInsecureAuditSkipReads(on bool) {
	c.skipSuccessfulReadAudit = on
}

// InsecureAuditSkipReads reports whether successful secret-value reads are
// left unaudited in this process.
func (c *KeyorixCore) InsecureAuditSkipReads() bool {
	return c.skipSuccessfulReadAudit
}

// skipsSuccessfulReadAudit reports whether event must not be written: the
// setting is on, the event records a value disclosure, and it succeeded. A nil
// Success is not treated as success, so an event that does not say it
// succeeded is always written.
func (c *KeyorixCore) skipsSuccessfulReadAudit(event *models.AuditEvent) bool {
	return c.skipSuccessfulReadAudit &&
		event.Success != nil && *event.Success &&
		successfulValueReadEventTypes[event.EventType]
}
