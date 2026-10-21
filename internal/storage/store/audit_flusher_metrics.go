// audit_flusher_metrics.go — Prometheus instrumentation for the audit-chain
// batching flusher (SESSION-PERF, #2403 follow-up, item 3; coordinator review
// on #2420 asked for this to be instrumented rather than tuned blind).
//
// Group commit's whole value proposition is "batch more, fsync less" — without
// visibility into the batch sizes actually achieved in production, there is no
// way to tell whether the chosen linger window (auditFlusherLingerWindow) is
// still the right tradeoff as load shape changes, or to notice a regression
// that silently shrinks batches back toward one-at-a-time. These two series
// live on the default Prometheus registry the server exposes at GET /metrics
// (same as every other counter/histogram in this codebase — see
// server/middleware/scheduler_metrics.go for the sibling pattern this mirrors).
//
// batchSize is a Summary, not a Histogram: this package has no per-instance
// aggregation need (a single server's own p50/p95 is what operators and this
// session's own benchmarking both want directly, not a cross-instance roll-up),
// and a Summary reports exact client-side quantiles with no bucket-boundary
// interpolation — the simpler, more precise choice when cross-instance
// aggregation isn't a requirement.
package store

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
)

var (
	auditFlushesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "keyorix_audit_flusher_flushes_total",
		Help: "Audit-chain batch-commit flushes (one per transaction/fsync, covering 1-N queued entries each).",
	})

	// auditPipelinedBatches counts batches sent while the batch before them was
	// still in flight (chained onto its pending last row,
	// local_audit_chain_pipelined_batches.go). Zero on SQLite and while another
	// writer keeps the chain-head cache disarmed.
	auditPipelinedBatches = promauto.NewCounter(prometheus.CounterOpts{
		Name: "keyorix_audit_flusher_pipelined_batches_total",
		Help: "Audit-chain batches sent while the previous batch was still in flight (pipelined commits).",
	})

	auditFlushBatchSize = promauto.NewSummary(prometheus.SummaryOpts{
		Name:       "keyorix_audit_flusher_batch_size",
		Help:       "Number of audit-chain entries committed per batch flush.",
		Objectives: map[float64]float64{0.5: 0.05, 0.95: 0.01, 0.99: 0.001},
	})

	// auditWriteDuration is the end-to-end latency a caller of LogAuditEvent*
	// experiences: queue wait + linger + commit (batched path) or the direct
	// transaction (fallback path). It is the number to alert on when "audit is
	// slow"; keyorix_audit_group_commit_wait_seconds says how much of it is
	// queueing rather than the commit itself.
	auditWriteDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "keyorix_audit_write_duration_seconds",
		Help:    "End-to-end latency of an audit event append (LogAuditEvent*), including group-commit queueing, whether it succeeded or failed.",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
	})

	// auditWriteFailures counts appends that returned an error to the caller. An
	// audit append failing is a compliance event, not just an error rate: the
	// mutation it records may already have committed.
	//
	// Registered on internal/protectedmetrics (authenticated scheduler-metrics only), not
	// the default registry: an anonymous reader must not see when audit appends fail.
	auditWriteFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "keyorix_audit_write_failures_total",
		Help: "Audit event appends that returned an error to the caller (the audited mutation may already have committed).",
	})

	// auditGroupCommitWait is how long each queued event waited between being
	// handed to the flusher and its batch starting to commit (queue + linger).
	auditGroupCommitWait = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "keyorix_audit_group_commit_wait_seconds",
		Help:    "Time an audit event waited in the group-commit queue (including the linger window) before its batch began committing.",
		Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
	})
)

func init() { protectedmetrics.MustRegister(auditWriteFailures) }

// observeAuditWrite records one LogAuditEvent* call's outcome and latency.
func observeAuditWrite(start time.Time, err error) {
	auditWriteDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		auditWriteFailures.Inc()
	}
}

// observeAuditGroupCommitWait records the queue wait of every item in a batch
// that is about to commit. Called once per flusher iteration, never from the
// bisection recursion in commitAuditBatch.
func observeAuditGroupCommitWait(batch []*auditBatchItem, now time.Time) {
	for _, it := range batch {
		if !it.enqueuedAt.IsZero() {
			auditGroupCommitWait.Observe(now.Sub(it.enqueuedAt).Seconds())
		}
	}
}

// recordAuditFlush records one completed flush's batch size, regardless of
// whether the commit itself succeeded — this instruments the FLUSHER's own
// batching behavior (did linger actually let batches grow?), which is a
// separate question from whether commits succeed.
func recordAuditFlush(batchSize int) {
	auditFlushesTotal.Inc()
	auditFlushBatchSize.Observe(float64(batchSize))
}
