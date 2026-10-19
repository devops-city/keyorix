package main

// recertification annotates each review item with the principal's last use of
// the grant, read from audit_events.
func init() {
	registerSchedulerAuditRead(schedulerAuditRead{
		Job:    "recertification",
		Tables: []string{"audit_events"},
		Bounds: []auditReadBoundKind{boundTimeWindow},
		Why: "LastUserSecretActivity per project: event_time >= since (the recertification period) clamped to " +
			"storage.ActivityLookbackMaxDays, a range on idx_audit_events_project_event_time (RECERT-BOUND-1, the " +
			"G44 decision): the rows read are the window's, not the project's history.",
	})
}
