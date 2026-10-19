package main

// recover_admin_alert alerts on every recover-admin use exactly once.
func init() {
	registerSchedulerAuditRead(schedulerAuditRead{
		Job:    "recover_admin_alert",
		Tables: []string{"audit_events"},
		Bounds: []auditReadBoundKind{boundHighWaterMark},
		Why: "MaxAuditEventID (ORDER BY id DESC LIMIT 1), then GetAuditLogs over (mark, max] on the primary key; " +
			"the mark advances to max even when nothing matched, so a run reads only rows added since the last " +
			"one, and the one-off catch-up walks in 100k-id windows persisting the mark per window (#3371, " +
			"TestRunRecoverAdminAlerting_LargeAuditTable_SecondRunReadsOnlyNewRows).",
	})
}
