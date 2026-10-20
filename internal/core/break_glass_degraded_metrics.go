// break_glass_degraded_metrics.go — Prometheus instrumentation for degraded
// break-glass activations (BREAKGLASS-OWED-1), in the package-per-counter-file
// convention of account_state_metrics.go.
//
// A degraded activation is emergency access granted while the audit log refused
// its rows: it is recorded as owed (pending_audit_events) and backfilled later.
// Any non-zero rate is worth a page: either the audit subsystem is down during an
// incident, or someone is making it refuse writes on purpose to self-elevate
// "quietly". Neither is quiet: the activation is short-lived, its rows are owed
// durably, and this counter, the SECURITY log line and the admin banner fire.
package core

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// breakGlassDegradedActivationsTotal counts break-glass activations committed on
// the degraded path (activateBreakGlassDegraded).
var breakGlassDegradedActivationsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_breakglass_degraded_activations_total",
	Help: "Count of break-glass activations committed while the audit log refused their rows (recorded as owed, short expiry, review mandatory).",
})
