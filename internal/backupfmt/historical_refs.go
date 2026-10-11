package backupfmt

// HistoricalReference names one column that references a row which may
// legitimately no longer exist: the row is a historical record (an audit trail,
// a security signal, a snapshot), so it must outlive the row it points at.
// CheckDanglingReferences skips exactly these (table, column) pairs and nothing
// else (#3085); every other reference stays strictly checked.
//
// Adding an entry is a decision, not a convenience: the column must be one a
// purge or delete is NOT allowed to rewrite. A mutable table is cascaded by the
// purge instead (internal/storage/store/local_purge_secret_refs.go), and
// TestSecretReferencesAreClassified fails for a column that is in neither list.
type HistoricalReference struct {
	Table  string
	Column string
	// Parent is the table whose id the column holds: "secret_nodes" or
	// "secret_versions".
	Parent string
	Why    string
}

var historicalReferences = []HistoricalReference{
	{
		Table: "audit_events", Column: "secret_node_id", Parent: "secret_nodes",
		Why: "audit_events is append-only and hash-chained: a purge must not delete or rewrite an audit row " +
			"(audit-before-disclosure), so the row keeps naming the secret it recorded",
	},
	{
		Table: "anomaly_alerts", Column: "secret_node_id", Parent: "secret_nodes",
		Why: "an anomaly alert is a security signal about who accessed a secret; DeleteAnomalyAlertsBefore keeps an " +
			"unacknowledged alert until someone acts on it, and the row carries its own SecretName so it is " +
			"meaningful after the secret is gone. A purge (which a secrets.manage holder can trigger by " +
			"soft-deleting and shortening retention) must not destroy alerts about that holder's own access",
	},
	{
		Table: "secret_access_logs", Column: "secret_node_id", Parent: "secret_nodes",
		Why: "secret_access_logs is the append-only, exported record of who read which secret and when; it has no " +
			"retention purge of its own, so a secret purge must not be what silently destroys it",
	},
	{
		Table: "secret_access_logs", Column: "secret_version_id", Parent: "secret_versions",
		Why: "same record as secret_access_logs.secret_node_id: the version a read touched stays named after the " +
			"ciphertext-bearing version row is purged",
	},
	{
		Table: "access_review_items", Column: "secret_id", Parent: "secret_nodes",
		Why: "an access-review item is a snapshot of the grants at the time the campaign opened, kept for the " +
			"recertification record. It is not immutable forever: DeleteClosedAccessReviewsBefore removes the items " +
			"of a closed campaign on the campaign's own retention window. A secret purge must not shorten that " +
			"window, so the item keeps naming a secret that may have been purged",
	},
}

// HistoricalReferences returns the columns CheckDanglingReferences skips.
func HistoricalReferences() []HistoricalReference {
	return append([]HistoricalReference(nil), historicalReferences...)
}

func isHistoricalReference(table, column string) bool {
	for _, h := range historicalReferences {
		if h.Table == table && h.Column == column {
			return true
		}
	}
	return false
}
