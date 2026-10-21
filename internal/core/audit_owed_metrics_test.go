package core

// keyorix_audit_owed_pending must follow the real pending_audit_events table through
// a refused suspend audit write and its backfill, and must be authenticated-only.

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
)

// owedPendingScrape reads the gauge the way the authenticated endpoint serves it.
func owedPendingScrape(t *testing.T) float64 {
	t.Helper()
	mfs, err := protectedmetrics.Registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "keyorix_audit_owed_pending" {
			require.Len(t, mf.GetMetric(), 1)
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal("keyorix_audit_owed_pending is not on the protected registry")
	return 0
}

// owedFailuresScrape reads keyorix_audit_owed_failures_total the way the authenticated
// endpoint serves it.
func owedFailuresScrape(t *testing.T) float64 {
	t.Helper()
	mfs, err := protectedmetrics.Registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "keyorix_audit_owed_failures_total" {
			require.Len(t, mf.GetMetric(), 1)
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	t.Fatal("keyorix_audit_owed_failures_total is not on the protected registry")
	return 0
}

// A refused plain-suspend audit write is counted on the metric, even when the pending
// record could not be written either (the gauge above reads the database and cannot see
// that case). The suspend still succeeds. Not parallel: process-wide counter.
func TestOwedAuditFailuresCounter_CountsARefusedSuspendAudit(t *testing.T) {
	ctx := context.Background()
	w := newOwedAuditWorld(t)
	id := w.secret(t, "leaked", 1, SecretStatusActive, false)

	before := owedFailuresScrape(t)
	defer refuseSuspendAudit(t, w)()
	_, err := w.c.SuspendSecret(ctx, id, 1, "breach response")
	require.NoError(t, err, "revocation is never blocked by the audit log")
	assert.Equal(t, before+1, owedFailuresScrape(t))
}

// Not parallel: the gauge reads through one process-wide source.
func TestOwedAuditPendingGauge_FollowsThePendingTable(t *testing.T) {
	ctx := context.Background()
	w := newOwedAuditWorld(t)
	t.Cleanup(func() { owedAuditMetricSource.Store(nil) })

	owedAuditMetricSource.Store(nil)
	assert.True(t, math.IsNaN(owedPendingScrape(t)), "no source published: unknown, never a misleading 0")

	w.c.PublishOwedAuditMetric()
	assert.Equal(t, 0.0, owedPendingScrape(t), "nothing owed")

	id := w.secret(t, "leaked", 1, SecretStatusActive, false)
	recoverAudit := refuseSuspendAudit(t, w)
	_, err := w.c.SuspendSecret(ctx, id, 1, "breach response")
	require.NoError(t, err)
	require.Len(t, w.pending(t), 1)
	assert.Equal(t, 1.0, owedPendingScrape(t), "one owed row after the audit log refused it")

	recoverAudit()
	n, err := w.c.BackfillPendingAuditEvents(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	assert.Equal(t, 0.0, owedPendingScrape(t), "backfilled: back to zero")
}
