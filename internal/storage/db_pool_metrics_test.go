package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func poolSample(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	fams, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range fams {
		if mf.GetName() != name {
			continue
		}
	metric:
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if want, ok := labels[lp.GetName()]; ok && want != lp.GetValue() {
					continue metric
				}
			}
			if m.GetGauge() != nil {
				return m.GetGauge().GetValue(), true
			}
			return m.GetCounter().GetValue(), true
		}
	}
	return 0, false
}

// TestPoolCollector_ReportsInUseAndWait drives a real 1-connection pool: holding the
// only connection shows in_use=1, and a second caller blocked on it is counted in
// wait_total / wait_seconds_total once it gets through.
func TestPoolCollector_ReportsInUseAndWait(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	c := newPoolCollector()
	c.pools["probe"] = db
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	ctx := context.Background()
	held, err := db.Conn(ctx)
	require.NoError(t, err)

	v, ok := poolSample(t, reg, "keyorix_db_pool_connections", map[string]string{"pool": "probe", "state": "in_use"})
	require.True(t, ok)
	assert.Equal(t, float64(1), v, "the held connection must show as in_use")
	v, _ = poolSample(t, reg, "keyorix_db_pool_max_connections", map[string]string{"pool": "probe"})
	assert.Equal(t, float64(1), v)

	got := make(chan error, 1)
	go func() {
		conn, err := db.Conn(ctx) // blocks until held is released
		if err == nil {
			_ = conn.Close()
		}
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, held.Close())
	require.NoError(t, <-got)

	v, _ = poolSample(t, reg, "keyorix_db_pool_wait_total", map[string]string{"pool": "probe"})
	assert.Equal(t, float64(1), v, "the blocked caller must be counted as a wait")
	v, _ = poolSample(t, reg, "keyorix_db_pool_wait_seconds_total", map[string]string{"pool": "probe"})
	assert.GreaterOrEqual(t, v, 0.04, "wait time must reflect the ~50ms the caller was blocked")
}

// TestPoolNamesAreFixed: the pool label values are these constants only.
func TestPoolNamesAreFixed(t *testing.T) {
	assert.ElementsMatch(t, []string{"request", "scheduler_lock", "named_lock"},
		[]string{poolRequest, poolSchedulerLock, poolNamedLock})
}
