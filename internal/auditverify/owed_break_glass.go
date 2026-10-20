package auditverify

import (
	"context"
	"fmt"
)

// OwedBreakGlassStatus reports break-glass activations that were granted while
// the audit log refused their rows (BREAKGLASS-OWED-1): the server committed each
// of them together with pending_audit_events records of its rows instead, and a
// backfill writes those rows into the chain later and marks the activation
// settled. An unsettled one means the chain is KNOWN to be missing an emergency
// elevation's rows right now, so Verify reports INDETERMINATE while any exist.
type OwedBreakGlassStatus struct {
	// Checked is false when break_glass_activations could not be read (a database
	// older than schema epoch 5, or a verifier role without SELECT on that table);
	// Error then says why, and the run's not_proven list says it was not checked.
	Checked       bool     `json:"checked"`
	Unsettled     int64    `json:"unsettled"`
	ActivationIDs []uint64 `json:"activation_ids,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// UnsettledBreakGlassActivationIDs returns the ids of degraded break-glass
// activations whose owed audit rows are not all in the chain yet, ascending.
func (d *DB) UnsettledBreakGlassActivationIDs(ctx context.Context) ([]uint64, error) {
	rows, err := d.sql.QueryContext(ctx, d.rebind(
		`SELECT id FROM break_glass_activations WHERE degraded = ? AND audit_settled_at IS NULL ORDER BY id ASC`), true)
	if err != nil {
		return nil, fmt.Errorf("query break_glass_activations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan break_glass_activations: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// checkOwedBreakGlass fills result.OwedBreakGlass and raises the verdict to
// INDETERMINATE while any degraded activation still owes rows. A read failure is
// not a verification failure: it is reported as not checked (not_proven), since
// older databases have no such column and a least-privilege verifier role may not
// see the table.
func checkOwedBreakGlass(ctx context.Context, db *DB, result *Result) {
	ids, err := db.UnsettledBreakGlassActivationIDs(ctx)
	if err != nil {
		result.OwedBreakGlass = OwedBreakGlassStatus{Error: err.Error()}
		return
	}
	result.OwedBreakGlass = OwedBreakGlassStatus{Checked: true, Unsettled: int64(len(ids)), ActivationIDs: ids}
	if len(ids) > 0 {
		result.escalate(VerdictIndeterminate, fmt.Sprintf(
			"%d break-glass activation(s) were granted while the audit log refused their rows and still owe them to the chain "+
				"(activation ids %v); the server's owed-audit backfill writes them once the audit log accepts writes",
			len(ids), ids))
	}
}
