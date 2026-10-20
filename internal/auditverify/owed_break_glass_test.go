package auditverify

// BREAKGLASS-OWED-1: verify-audit reports degraded break-glass activations whose
// owed audit rows are not in the chain yet, and is INDETERMINATE while any exist.
// A database without the table (or the column) is reported as not checked, never
// as clean. internal/core's TestBreakGlass_AttackerMakesAuditUnwritable runs the
// same check against the real migrated schema.

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVerify_OwedBreakGlassActivations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	seedEmptySchema(t, path)

	db, err := OpenSQLiteReadOnly(path)
	require.NoError(t, err)
	res, err := Verify(ctx, db, Options{})
	require.NoError(t, err)
	_ = db.Close()
	require.False(t, res.OwedBreakGlass.Checked, "no break_glass_activations table: not checked")
	require.NotEmpty(t, res.OwedBreakGlass.Error)
	require.Equal(t, VerdictValid, res.Verdict, "an unreadable table is a disclosed gap, not a verdict")
	require.True(t, notProvenMentions(res, "could not be read"), "not checked must be disclosed: %v", res.NotProven)

	w, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()
	_, err = w.Exec(`CREATE TABLE break_glass_activations (id INTEGER PRIMARY KEY, degraded NUMERIC NOT NULL DEFAULT false, audit_settled_at DATETIME)`)
	require.NoError(t, err)
	_, err = w.Exec(`INSERT INTO break_glass_activations (id, degraded, audit_settled_at) VALUES (1, false, NULL), (2, true, NULL), (3, true, ?), (4, true, NULL)`, time.Now())
	require.NoError(t, err)

	verify := func() *Result {
		db, err := OpenSQLiteReadOnly(path)
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		res, err := Verify(ctx, db, Options{})
		require.NoError(t, err)
		return res
	}
	res = verify()
	require.True(t, res.OwedBreakGlass.Checked)
	require.Equal(t, int64(2), res.OwedBreakGlass.Unsettled)
	require.Equal(t, []uint64{2, 4}, res.OwedBreakGlass.ActivationIDs, "only degraded AND unsettled; a normal activation owes nothing")
	require.Equal(t, VerdictIndeterminate, res.Verdict, "the chain is known to be missing rows")
	require.Contains(t, res.Reason, "break-glass")
	require.Equal(t, 2, res.ExitCode())

	_, err = w.Exec(`UPDATE break_glass_activations SET audit_settled_at = ? WHERE id IN (2, 4)`, time.Now())
	require.NoError(t, err)
	res = verify()
	require.Zero(t, res.OwedBreakGlass.Unsettled)
	require.Equal(t, VerdictValid, res.Verdict)
}

func notProvenMentions(r *Result, s string) bool {
	for _, np := range r.NotProven {
		if strings.Contains(np, s) {
			return true
		}
	}
	return false
}
