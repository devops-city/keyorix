package store

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditEventsInCreate returns the audit events a GORM create statement is
// about to insert, whatever shape its Dest has: one *models.AuditEvent (the
// per-row path logAuditEventDirect still uses) or a slice of them (the flusher's
// multi-row INSERT, PERF-FIX-2). Fault-injection callbacks in this package's
// audit tests go through it instead of type-asserting Dest themselves.
//
// It panics on a create into audit_events whose Dest it does not recognise.
// The injectors used to assert `Dest.(*models.AuditEvent)` directly, and when
// the flusher switched to a slice insert every one of them silently stopped
// firing: the poisoned-item and contention tests then saw a clean commit and
// failed on their assertions only by luck of what they asserted. A new Dest
// shape must stop the test, not turn the injector into a no-op.
func auditEventsInCreate(tx *gorm.DB) []*models.AuditEvent {
	switch d := tx.Statement.Dest.(type) {
	case *models.AuditEvent:
		return []*models.AuditEvent{d}
	case []*models.AuditEvent:
		return d
	case *[]*models.AuditEvent:
		return *d
	}
	if tx.Statement.Schema != nil && tx.Statement.Schema.Table == "audit_events" {
		panic(fmt.Sprintf("auditEventsInCreate: unrecognised Dest %T for an audit_events create; teach the helper this shape", tx.Statement.Dest))
	}
	return nil
}
