// config_change_audit.go — shared audit-emitting helper for admin-only
// (system.write-gated) singleton/registry configuration mutations.
//
// Two independent call sites shared the same audit-trail gap: notification
// channel CRUD (notification_channels.go) and the anomaly detection config
// (anomaly_config.go) both let a system.write holder mutate the config with
// zero audit_events record. The combined threat shape is identical in both
// cases: an admin can silently redirect/disable the detection-and-alerting
// layer, act while it's blind, then restore prior state -- leaving no
// permanent record of the intervening window. Rather than adding two
// independent writeAuditEvent calls (which the next similar config surface
// would just re-duplicate), both route through this ONE helper, matching the
// writeRBACAudit precedent in audit.go (a domain-specific wrapper over the
// generic writeAuditEventDiff writer). config_change_audit_guard_test.go
// statically asserts both call sites actually reach it.
package core

import (
	"context"
	"encoding/json"
)

// configChangeDetail is the structured before/after payload stored in a config
// change audit event's Diff field. Either side may be nil (Create has no
// Before; Delete has no After).
type configChangeDetail struct {
	Before any `json:"before,omitempty"`
	After  any `json:"after,omitempty"`
}

// writeConfigChangeAuditEvent persists an audit_events row for an admin config
// mutation, carrying a structured before/after diff so an incident
// investigation can see exactly what changed (e.g. a webhook URL repointed, or
// anomaly detection disabled) and who made the change, not just that a change
// occurred. actorID is the acting user's numeric ID (0 when unknown/no
// authenticated principal, e.g. a local CLI invocation) -- mirrors every other
// writeAuditEvent* helper's actor convention (see audit.go).
// writeConfigChangeAuditEventOn is writeConfigChangeAuditEvent against an explicit
// audit target (AUDIT-TX-3): a config change writes its row inside its own
// transaction, so the change cannot commit without it.
func (c *KeyorixCore) writeConfigChangeAuditEventOn(ctx context.Context, tgt auditTarget, eventType string, actorID uint, description string, before, after any) {
	detail := configChangeDetail{Before: before, After: after}
	encoded, err := json.Marshal(detail)
	if err != nil {
		// Never let a marshal failure suppress the audit write outright -- an
		// event with no diff is still a record that the change happened.
		encoded = nil
	}
	var actor *uint
	if actorID != 0 {
		a := actorID
		actor = &a
	}
	c.writeAuditEventDiffOn(ctx, tgt, eventType, actor, nil, nil, "", description, string(encoded))
}
