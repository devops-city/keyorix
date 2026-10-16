// Package protectedmetrics is the Prometheus registry for metrics that must NOT be
// served on the unauthenticated GET /metrics endpoint.
//
// GET /metrics is open to anything that can reach the port. A metric that tells an
// anonymous caller when a security job last ran, or whether an integrity check has
// recorded a failure, hands an attacker timing and detection information. Such
// metrics are registered here instead and served by server/middleware's
// SchedulerMetricsHandler at the authenticated GET /api/v1/admin/scheduler-metrics
// (permission system.write), next to the scheduler last-run timestamps.
//
// internal/metricsdoc checks that nothing registered here also appears on the
// default registry, and that each such metric is documented as authenticated-only.
package protectedmetrics

import "github.com/prometheus/client_golang/prometheus"

// Registry holds the authenticated-only metrics.
var Registry = prometheus.NewRegistry()

// MustRegister registers collectors on the protected registry.
func MustRegister(cs ...prometheus.Collector) { Registry.MustRegister(cs...) }
