package store

// PERF-LOWCONC-1 step 3: the audit flight resolves the audit_events table name
// once per store instead of with a GORM DryRun on every batch.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditEventsTable_ResolvedOnceAndCached(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()
	require.Nil(t, ls.auditTable.Load(), "nothing is resolved before the first audit flight")

	first, err := ls.auditEventsTable(ctx)
	require.NoError(t, err)
	require.Equal(t, "audit_events", first)
	cached := ls.auditTable.Load()
	require.NotNil(t, cached)

	again, err := ls.auditEventsTable(ctx)
	require.NoError(t, err)
	require.Equal(t, first, again)
	require.Same(t, cached, ls.auditTable.Load(), "a later flight reuses the cached name")
}
