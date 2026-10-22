// audit_owed_metrics.go — Prometheus view of owed audit rows (audit_owed.go).
//
// keyorix_audit_owed_pending is the number of owed audit rows (every owed revocation,
// not only suspend and degraded break-glass) not yet backfilled: the audit log refused a write after the action had
// taken effect, and the pending_audit_events record is still waiting for
// BackfillPendingAuditEvents.
// Zero is the normal state. It is the same count GET /api/v1/system/info shows to
// system.write holders, so it registers on internal/protectedmetrics (served only at
// the authenticated GET /api/v1/admin/scheduler-metrics), not on public /metrics: it
// tells an anonymous reader that the audit log has been failing.
//
// The count is read from the database at scrape time, so it is cluster-wide and the
// same on every replica. A count that cannot be read is reported as NaN (unknown), never
// as 0, and no alert fires on it; an unreadable database is what the readiness and
// DB-pool alerts are for.
package core

import (
	"context"
	"math"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
)

// owedAuditScrapeTimeout bounds the database read made on behalf of one scrape.
const owedAuditScrapeTimeout = 3 * time.Second

// owedAuditMetricSource is the core the gauge reads through; set by
// PublishOwedAuditMetric. Unset (a process that never published) reads as unknown.
var owedAuditMetricSource atomic.Pointer[KeyorixCore]

func init() {
	protectedmetrics.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "keyorix_audit_owed_pending",
		Help: "Number of owed audit rows (every owed revocation, not only suspend and degraded break-glass) not yet backfilled (the audit log refused the write after the action took effect). 0 is normal; NaN means the count could not be read. Cluster-wide; alert when above 0 for 10 minutes.",
	}, func() float64 {
		c := owedAuditMetricSource.Load()
		if c == nil {
			return math.NaN()
		}
		ctx, cancel := context.WithTimeout(context.Background(), owedAuditScrapeTimeout)
		defer cancel()
		n, err := c.storage.CountPendingAuditEvents(ctx)
		if err != nil {
			return math.NaN()
		}
		return float64(n)
	}))

	// The per-process failure count behind system/info's audit_owed_failures. Unlike the
	// gauge it needs no database read, so it still moves when the pending record could
	// not be written either (the row is then logged as NOT queued for backfill).
	protectedmetrics.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "keyorix_audit_owed_failures_total",
		Help: "Owed audit rows (every owed revocation, e.g. a plain secret suspend) the audit log refused when they were due, per process. The action itself still took effect. Each one is either pending for the backfill or logged as lost (SECURITY log line naming the user and secret).",
	}, func() float64 { return float64(owedAuditFailures.Load()) }))
}

// PublishOwedAuditMetric makes c the source of keyorix_audit_owed_pending. The server
// calls it once at startup.
func (c *KeyorixCore) PublishOwedAuditMetric() { owedAuditMetricSource.Store(c) }
