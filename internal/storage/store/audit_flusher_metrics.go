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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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
)

// recordAuditFlush records one completed flush's batch size, regardless of
// whether the commit itself succeeded — this instruments the FLUSHER's own
// batching behavior (did linger actually let batches grow?), which is a
// separate question from whether commits succeed.
func recordAuditFlush(batchSize int) {
	auditFlushesTotal.Inc()
	auditFlushBatchSize.Observe(float64(batchSize))
}
