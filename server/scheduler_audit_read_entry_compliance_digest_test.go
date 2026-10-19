package main

// compliance_digest builds the compliance posture, which reads audit history
// for dormant grants and the audit-chain verification status.
func init() {
	registerSchedulerAuditRead(schedulerAuditRead{
		Job:    "compliance_digest",
		Tables: []string{"audit_events"},
		Bounds: []auditReadBoundKind{boundTimeWindow, boundConditionalFullWalk},
		Why: "Dormant role grants: LastUser*Activity per project, event_time >= since clamped to " +
			"storage.ActivityLookbackMaxDays on idx_audit_events_project_event_time (RECERT-BOUND-1). " +
			"Audit status: AuditVerificationStatus reads only the signed verification state when incremental " +
			"verification is on (the audit_checkpoint scheduler runs); without it (no checkpoint signing key, or " +
			"the checkpoint scheduler disabled) it is the full VerifyAuditChain walk once per digest, in 1000-row " +
			"statements with no snapshot held across the walk.",
	})
}
