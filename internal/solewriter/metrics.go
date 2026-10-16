// metrics.go — Prometheus view of the single_writer guard (storage.database.single_writer).
//
// With single_writer on, caches skip their confirming read only while the guard is
// authoritative. If it drops to confirming (lease lapsed, poll failing) the server
// stays correct but slower and operators need to know why. The collector reads
// Current().Status() at scrape time; with single_writer off it emits only
// keyorix_single_writer_enabled 0, so the family is always present and an alert can
// distinguish "off" from "metrics missing".
package solewriter

import (
	"github.com/prometheus/client_golang/prometheus"
)

type metricsCollector struct {
	enabled     *prometheus.Desc
	state       *prometheus.Desc
	pollAge     *prometheus.Desc
	unattribute *prometheus.Desc
}

func newMetricsCollector() *metricsCollector {
	return &metricsCollector{
		enabled: prometheus.NewDesc(
			"keyorix_single_writer_enabled",
			"1 when storage.database.single_writer is on for this process, else 0.",
			nil, nil,
		),
		state: prometheus.NewDesc(
			"keyorix_single_writer_state",
			"single_writer guard state, one series per state (settling|authoritative|confirming) with value 1 for the current one. Only authoritative lets caches skip confirming reads; confirming means the lease lapsed or polls are failing.",
			[]string{"state"}, nil,
		),
		pollAge: prometheus.NewDesc(
			"keyorix_single_writer_last_poll_age_seconds",
			"Seconds since the guard's last successful epoch poll; approaching the lease length means the guard is about to leave authoritative.",
			nil, nil,
		),
		unattribute: prometheus.NewDesc(
			"keyorix_single_writer_unattributed_bumps_total",
			"Write-epoch changes no in-process write accounted for; a non-zero value means something else wrote to the fenced tables.",
			nil, nil,
		),
	}
}

func (c *metricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.enabled
	ch <- c.state
	ch <- c.pollAge
	ch <- c.unattribute
}

func (c *metricsCollector) Collect(ch chan<- prometheus.Metric) {
	g := Current()
	if g == nil {
		ch <- prometheus.MustNewConstMetric(c.enabled, prometheus.GaugeValue, 0)
		return
	}
	st := g.Status()
	ch <- prometheus.MustNewConstMetric(c.enabled, prometheus.GaugeValue, 1)
	for _, s := range []State{StateSettling, StateAuthoritative, StateConfirming} {
		v := 0.0
		if st.State == s {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.state, prometheus.GaugeValue, v, string(s))
	}
	ch <- prometheus.MustNewConstMetric(c.pollAge, prometheus.GaugeValue, float64(st.LastPollAgeMS)/1000)
	ch <- prometheus.MustNewConstMetric(c.unattribute, prometheus.CounterValue, float64(st.UnattributedBumps))
}

func init() {
	prometheus.MustRegister(newMetricsCollector())
}
