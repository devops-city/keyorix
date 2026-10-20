// db_pool_metrics.go — Prometheus view of the database/sql connection pools.
//
// "The pool is the bottleneck" is the most common production slowdown and was
// invisible: nothing exposed how many connections were in use or how long callers
// waited for one. database/sql already tracks it (sql.DBStats); this collector just
// reads it at scrape time, so it adds no work to the query path.
//
// Pools are registered by name through registerPoolMetrics; re-registering a name
// replaces the previous pool (the server creates its storage once; tests create many).
// The `pool` label values are the fixed names below, never derived from config.
package storage

import (
	"database/sql"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Pool names. These are the only values the `pool` label can take.
const (
	poolRequest       = "request"
	poolSchedulerLock = "scheduler_lock"
	poolNamedLock     = "named_lock"
)

type poolCollector struct {
	mu    sync.RWMutex
	pools map[string]*sql.DB

	open     *prometheus.Desc
	maxOpen  *prometheus.Desc
	waits    *prometheus.Desc
	waitSecs *prometheus.Desc
}

func newPoolCollector() *poolCollector {
	return &poolCollector{
		pools: map[string]*sql.DB{},
		open: prometheus.NewDesc(
			"keyorix_db_pool_connections",
			"Open database connections in a pool, by pool and state (in_use|idle). in_use close to keyorix_db_pool_max_connections means callers are queueing for a connection.",
			[]string{"pool", "state"}, nil,
		),
		maxOpen: prometheus.NewDesc(
			"keyorix_db_pool_max_connections",
			"Configured maximum open connections of a pool (0 = unlimited).",
			[]string{"pool"}, nil,
		),
		waits: prometheus.NewDesc(
			"keyorix_db_pool_wait_total",
			"Number of times a caller had to wait for a free connection in a pool.",
			[]string{"pool"}, nil,
		),
		waitSecs: prometheus.NewDesc(
			"keyorix_db_pool_wait_seconds_total",
			"Total time callers spent waiting for a free connection in a pool; rate() of it is the average number of goroutines blocked on the pool.",
			[]string{"pool"}, nil,
		),
	}
}

func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.open
	ch <- c.maxOpen
	ch <- c.waits
	ch <- c.waitSecs
}

func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for name, db := range c.pools {
		s := db.Stats()
		ch <- prometheus.MustNewConstMetric(c.open, prometheus.GaugeValue, float64(s.InUse), name, "in_use")
		ch <- prometheus.MustNewConstMetric(c.open, prometheus.GaugeValue, float64(s.Idle), name, "idle")
		ch <- prometheus.MustNewConstMetric(c.maxOpen, prometheus.GaugeValue, float64(s.MaxOpenConnections), name)
		ch <- prometheus.MustNewConstMetric(c.waits, prometheus.CounterValue, float64(s.WaitCount), name)
		ch <- prometheus.MustNewConstMetric(c.waitSecs, prometheus.CounterValue, s.WaitDuration.Seconds(), name)
	}
}

var (
	poolMetrics     = newPoolCollector()
	poolMetricsOnce sync.Once
)

// registerPoolMetrics exposes db's pool stats under the given fixed pool name.
func registerPoolMetrics(name string, db *sql.DB) {
	poolMetricsOnce.Do(func() { prometheus.MustRegister(poolMetrics) })
	poolMetrics.mu.Lock()
	poolMetrics.pools[name] = db
	poolMetrics.mu.Unlock()
}
