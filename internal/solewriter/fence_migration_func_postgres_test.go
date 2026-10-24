package solewriter

// fence_migration_func_postgres_test.go — the census covers the functions the
// store's migration triggers on covered tables execute (REVIEW-SOLEWRITER-1
// F1). Such a trigger runs in the session that wrote the row, the server's
// tagged one included, so its function is as much part of the fence's
// surroundings as the fence's own functions. pg-gated.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestPoll_MigrationTriggerFunctionReplacedLeavesAuthoritative re-creates each
// migration trigger's function with its own, identical definition (what an
// owner's CREATE OR REPLACE looks like when it is undone again before
// anyone reads the text): only the pg_proc row's version changes. The guard
// must leave the authoritative state, as it does for the fence's own
// functions (TestPoll_FenceTamperingLeavesAuthoritativeForGood
// "recreate-identical-function").
func TestPoll_MigrationTriggerFunctionReplacedLeavesAuthoritative(t *testing.T) {
	for _, tt := range migrationTriggers {
		table, trigger, ok := strings.Cut(tt, ".")
		require.True(t, ok, tt)
		t.Run(tt, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			var def string
			err := w.foreign.Raw(`SELECT pg_catalog.pg_get_functiondef(t.tgfoid) FROM pg_catalog.pg_trigger t
WHERE t.tgrelid = pg_catalog.to_regclass(?) AND t.tgname = ?`, table, trigger).Scan(&def).Error
			require.NoError(t, err)
			if def == "" {
				t.Skipf("%s is not installed in this schema", tt)
			}
			require.NoError(t, w.foreign.WithContext(context.Background()).Exec(def).Error)
			d := waitFor(t, 2*time.Second, func() bool { return !g.Authoritative() })
			require.GreaterOrEqual(t, d, time.Duration(0), "%s: its function was replaced and the guard still vouches", tt)
			require.Contains(t, g.Status().Reason, "write fence changed")
		})
	}
}
