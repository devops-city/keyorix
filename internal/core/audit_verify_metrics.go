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
		Help: "1 while a sticky audit-chain verification failure (a detected break) is recorded; it clears only after a passing full verification. Page on 1.",
	})

	auditVerifyStateRejected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "keyorix_audit_verify_state_rejected",
		Help: "1 while the persisted verification state was found untrusted (bad signature, replayed or rolled back) and the status is therefore not_proven; it clears after a passing full verification.",
	})
)

func init() {
	protectedmetrics.MustRegister(auditVerifyLastSuccess, auditVerifyFailureRecorded, auditVerifyStateRejected)
}

func boolGauge(g prometheus.Gauge, v bool) {
	if v {
		g.Set(1)
		return
	}
	g.Set(0)
}

// observeAuditVerifyState publishes a trusted state's facts.
func observeAuditVerifyState(st *auditVerifyState) {
	if st == nil {
		return
	}
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
// untrusted. It only ever raises the flag; a later trusted save/load lowers it.
func observeAuditVerifyStateUntrusted() { auditVerifyStateRejected.Set(1) }
