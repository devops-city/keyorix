// audit_verify_metrics.go — Prometheus view of audit-chain verification.
//
// These register on internal/protectedmetrics, NOT the default registry: when a
// verification last passed and whether a break has been recorded tell an attacker
// when tampering is least likely to be noticed and whether it was noticed. They are
// served only at the authenticated GET /api/v1/admin/scheduler-metrics.
//
// They mirror the signed persisted verification state (audit_verify_state.go), set
// whenever that state is saved or loaded and trusted. Only the replica that runs the
// checkpoint scheduler saves, so alerts should aggregate across replicas with max()
// and treat a series missing on every replica as "never verified".
package core

import (
	"context"
	"math"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
)

const (
	auditVerifyCheckTail = "tail"
	auditVerifyCheckFull = "full"
)

var (
	auditVerifyLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "keyorix_audit_verify_last_success_timestamp_seconds",
		Help: "Unix time of the last audit-chain verification that passed, by check (tail = latest-checkpoint tail check; full = complete rolling or background re-walk). Absent until one has passed.",
	}, []string{"check"})

	auditVerifyFailureRecorded = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "keyorix_audit_verify_failure_recorded",
		Help: "1 while a sticky audit-chain verification failure (a detected break) is recorded; it clears only after a passing full verification. NaN until this process has read the state. Page on 1.",
	})

	auditVerifyStateRejected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "keyorix_audit_verify_state_rejected",
		Help: "1 while the persisted verification state was found untrusted (bad signature, replayed or rolled back) and the status is therefore not_proven; it clears after a passing full verification. NaN until this process has read the state.",
	})

	auditCheckpointTruncationRefused = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "keyorix_audit_checkpoint_truncation_refused_total",
		Help: "Checkpoint writes refused because the signed audit verification state, still authentic under the current key, proves the chain was truncated (a relabelled key_version cannot re-baseline it). Page on any increase.",
	})
)

func init() {
	protectedmetrics.MustRegister(auditVerifyLastSuccess, auditVerifyFailureRecorded, auditVerifyStateRejected, auditCheckpointTruncationRefused)
	// Unknown until this process has read the persisted state, never a false 0: a
	// restarted server must not report "no break recorded" before it has looked.
	auditVerifyFailureRecorded.Set(math.NaN())
	auditVerifyStateRejected.Set(math.NaN())
}

// PublishAuditVerifyState reads the persisted verification state once and publishes
// it to the audit-verify gauges. The server calls it at startup on every replica:
// otherwise a restart shows no recorded failure until the first checkpoint tick
// (deferred by up to one interval, AuditCheckpointFirstTickDelay), which resolves a
// KeyorixAuditChainBreakRecorded page while the sticky failure is still recorded.
func (c *KeyorixCore) PublishAuditVerifyState(ctx context.Context) error {
	_, _, err := c.loadAuditVerifyState(ctx)
	return err
}

func boolGauge(g prometheus.Gauge, v bool) {
	if v {
		g.Set(1)
		return
	}
	g.Set(0)
}

// observeAuditVerifyState publishes a trusted state's facts, but only if st is the
// newest generation published so far. A status reader that loaded generation N
// without the lock can reach this after a concurrent save of N+1 recorded a failure;
// publishing N then would lower the failure gauge and mask a tamper page. The check
// and the writes share one lock, so two publishers cannot interleave.
func (c *KeyorixCore) observeAuditVerifyState(st *auditVerifyState) {
	if st == nil {
		return
	}
	c.auditVerifyPubMu.Lock()
	defer c.auditVerifyPubMu.Unlock()
	if st.Gen < c.auditVerifyGenPublished {
		return
	}
	c.auditVerifyGenPublished = st.Gen
	if st.LastCheck != nil && st.LastCheck.Valid {
		auditVerifyLastSuccess.WithLabelValues(auditVerifyCheckTail).Set(float64(st.LastCheck.At.Unix()))
	}
	if st.LastFull != nil && st.LastFull.Valid {
		auditVerifyLastSuccess.WithLabelValues(auditVerifyCheckFull).Set(float64(st.LastFull.CompletedAt.Unix()))
	}
	boolGauge(auditVerifyFailureRecorded, st.Failure != nil)
	boolGauge(auditVerifyStateRejected, st.Rejected != nil)
}

// observeAuditVerifyStateUntrusted marks a load that found the persisted row
// untrusted. It only raises the flags: the rejected flag always, and the failure
// flag when the untrusted row still carries a sticky failure, which
// loadAuditVerifyStateUnobserved keeps. A later trusted save/load of a newer
// generation lowers them.
//
// Raising takes the same lock as observeAuditVerifyState and moves the published
// generation past everything this process has seen (st.Gen, and the generation
// floor, since a malformed or rolled-back row reports a low or zero Gen). Otherwise
// a status reader that loaded generation N before this load could still publish N
// afterwards, lower the flags again and mask the tamper page.
func (c *KeyorixCore) observeAuditVerifyStateUntrusted(st *auditVerifyState) {
	c.auditVerifyPubMu.Lock()
	defer c.auditVerifyPubMu.Unlock()
	next := c.auditVerifyGenSeen.Load() + 1
	if st != nil {
		next = max(next, st.Gen+1)
	}
	c.auditVerifyGenPublished = max(c.auditVerifyGenPublished, next)
	auditVerifyStateRejected.Set(1)
	if st != nil && st.Failure != nil {
		auditVerifyFailureRecorded.Set(1)
	}
}
