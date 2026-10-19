package main

// evidence_delivery generates the signed compliance evidence pack, which embeds
// the same posture reads as compliance_digest.
func init() {
	registerSchedulerAuditRead(schedulerAuditRead{
		Job:    "evidence_delivery",
		Tables: []string{"audit_events"},
		Bounds: []auditReadBoundKind{boundTimeWindow, boundConditionalFullWalk},
		Why: "Dormant role grants: LastUser*Activity per project, event_time >= since clamped to " +
			"storage.ActivityLookbackMaxDays on idx_audit_events_project_event_time (RECERT-BOUND-1). " +
			"Audit status: AuditVerificationStatus reads only the signed verification state when incremental " +
			"verification is on; without it, the full VerifyAuditChain walk once per delivery, in 1000-row " +
			"statements with no snapshot held across the walk.",
	})
}
