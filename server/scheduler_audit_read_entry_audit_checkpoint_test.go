package main

// audit_checkpoint is the audit chain's own verifier: its reads are the
// incremental tail and one rolling segment per tick.
func init() {
	registerSchedulerAuditRead(schedulerAuditRead{
		Job:    "audit_checkpoint",
		Tables: []string{"audit_events"},
		Bounds: []auditReadBoundKind{boundIDWindow, boundConditionalFullWalk},
		Why: "Tail check: VerifyAuditChainSegment over (checkpoint head, head + new rows], pinning the head row by " +
			"primary key (pinAuditChainSeed, AuditEntryHashByID). Rolling re-walk: one segment of max(head/N, 100k) " +
			"ids per tick (docs/specs/audit-incremental-verification.md). Conditional full walk: with no usable signed " +
			"checkpoint (first run, or after a signing-key change) the tick writes one through the full " +
			"WriteAuditCheckpoint walk. Every walk reads in 1000-row statements and holds no snapshot across the walk " +
			"(internal/core/audit_long_reader_snapshot_test.go).",
	})
}
