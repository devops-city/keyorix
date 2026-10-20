package store

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func histSnapshot(t *testing.T, h prometheus.Histogram) (count uint64, sum float64) {
	t.Helper()
	var m dto.Metric
	require.NoError(t, h.Write(&m))
	return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, c.Write(&m))
	return m.GetCounter().GetValue()
}

// TestAuditWriteMetrics_SuccessRecordsLatencyAndGroupCommitWait drives the real
// flusher: each append is observed once end-to-end and once as queue wait, and a
// configured linger window shows up as wait time (so the wait histogram measures
// queueing, not just the commit).
func TestAuditWriteMetrics_SuccessRecordsLatencyAndGroupCommitWait(t *testing.T) {
	ls := newAuditChainTestStore(t)
	const linger = 80 * time.Millisecond
	ls.SetAuditFlusherLingerWindow(linger)

	wc0, _ := histSnapshot(t, auditWriteDuration)
	gc0, gs0 := histSnapshot(t, auditGroupCommitWait)
	f0 := counterValue(t, auditWriteFailures)

	appendEvent(t, ls, "secret.read", "one", time.Now().UTC())
	appendEvent(t, ls, "secret.read", "two", time.Now().UTC())

	wc1, _ := histSnapshot(t, auditWriteDuration)
	gc1, gs1 := histSnapshot(t, auditGroupCommitWait)
	assert.Equal(t, uint64(2), wc1-wc0, "one write-latency observation per append")
	assert.Equal(t, uint64(2), gc1-gc0, "one group-commit-wait observation per append")
	assert.GreaterOrEqual(t, gs1-gs0, 2*linger.Seconds()*0.9, "linger window must be visible as group-commit wait")
	assert.Equal(t, f0, counterValue(t, auditWriteFailures), "successful appends are not failures")
}

// TestAuditWriteMetrics_FailureIsCounted: an append that errors to the caller
// bumps keyorix_audit_write_failures_total (asserts the effect, not a return value).
func TestAuditWriteMetrics_FailureIsCounted(t *testing.T) {
	ls := newAuditChainTestStore(t)
	appendEvent(t, ls, "secret.read", "warm", time.Now().UTC())

	sqlDB, err := ls.db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	f0 := counterValue(t, auditWriteFailures)
	wc0, _ := histSnapshot(t, auditWriteDuration)

	tr := true
	err = ls.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType: "secret.read", Description: "doomed", Success: &tr, EventTime: time.Now().UTC(), ActorType: "user",
	})
	require.Error(t, err)

	assert.Equal(t, f0+1, counterValue(t, auditWriteFailures))
	wc1, _ := histSnapshot(t, auditWriteDuration)
	assert.Equal(t, wc0+1, wc1, "failed appends still record latency")
}
