// local_audit_flusher_load_postgres_test.go — OPT-AUDIT-RT-1: a local load
// harness for the Postgres audit flusher. It drives c concurrent audited reads
// (LogAuditEventWithAccessLog, the call every secret read makes) through the
// real flusher for a fixed time and reports the caller-side latency
// distribution and the group-commit batch sizes, counted from the rows
// themselves: every batch commits in one transaction, so the rows sharing an
// xmin are one batch.
//
// It asserts only what holds under every timing (every call succeeded, the
// chain verifies, no batch exceeds auditFlusherMaxBatch), never a latency, so
// it is a measuring tool, not a performance gate. Opt-in: it runs only with
// KEYORIX_AUDIT_LOAD=1 and KEYORIX_TEST_PG_DSN; KEYORIX_AUDIT_LOAD_CLIENTS
// (default "1,10,50"), KEYORIX_AUDIT_LOAD_SECONDS (default 5) and
// KEYORIX_AUDIT_LOAD_STANDARD=1 (the standard durability level instead of
// strict) shape the run.
package store

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestAuditFlusherLoad_Postgres(t *testing.T) {
	if os.Getenv("KEYORIX_AUDIT_LOAD") != "1" {
		t.Skip("KEYORIX_AUDIT_LOAD=1 not set — opt-in local load harness")
	}
	seconds := 5
	if s := os.Getenv("KEYORIX_AUDIT_LOAD_SECONDS"); s != "" {
		v, err := strconv.Atoi(s)
		require.NoError(t, err)
		seconds = v
	}
	clients := []int{1, 10, 50}
	if s := os.Getenv("KEYORIX_AUDIT_LOAD_CLIENTS"); s != "" {
		clients = nil
		for f := range strings.SplitSeq(s, ",") {
			v, err := strconv.Atoi(strings.TrimSpace(f))
			require.NoError(t, err)
			clients = append(clients, v)
		}
	}
	standard := os.Getenv("KEYORIX_AUDIT_LOAD_STANDARD") == "1"
	for _, c := range clients {
		t.Run(fmt.Sprintf("c=%d", c), func(t *testing.T) {
			ls, _ := pipelinePGStore(t)
			ls.SetAuditSkipDurableSync(standard)
			r := runAuditFlusherLoad(t, ls, c, time.Duration(seconds)*time.Second)
			t.Logf("AUDITLOAD level=%s c=%d calls=%d rps=%.0f p50=%s p99=%s p99.9=%s max=%s batches=%d batch_mean=%.2f batch_p50=%d batch_p90=%d batch_p99=%d batch_max=%d",
				map[bool]string{false: "strict", true: "standard"}[standard], c, r.calls, r.rps,
				r.lat(0.50), r.lat(0.99), r.lat(0.999), r.lat(1),
				len(r.batches), r.batchMean(), r.batch(0.50), r.batch(0.90), r.batch(0.99), r.batch(1))
		})
	}
}

type auditLoadResult struct {
	calls     int
	rps       float64
	latencies []time.Duration // sorted
	batches   []int           // sorted
}

func (r auditLoadResult) lat(q float64) time.Duration {
	return r.latencies[min(len(r.latencies)-1, int(q*float64(len(r.latencies))))]
}

func (r auditLoadResult) batch(q float64) int {
	return r.batches[min(len(r.batches)-1, int(q*float64(len(r.batches))))]
}

func (r auditLoadResult) batchMean() float64 {
	sum := 0
	for _, b := range r.batches {
		sum += b
	}
	return float64(sum) / float64(len(r.batches))
}

// runAuditFlusherLoad runs c clients against ls for d after a short warmup and
// returns what the measured window saw.
func runAuditFlusherLoad(t *testing.T, ls *LocalStorage, c int, d time.Duration) auditLoadResult {
	t.Helper()
	ctx := context.Background()
	var seq atomic.Int64
	call := func() error {
		n := seq.Add(1)
		node := uint(1000 + n%97)
		e := &models.AuditEvent{
			EventType:    "secret.read",
			SecretNodeID: &node,
			IPAddress:    "203.0.113.7",
			Description:  fmt.Sprintf("load read %d", n),
			EventTime:    time.Now(),
		}
		l := &models.SecretAccessLog{SecretNodeID: node, Action: "read", IPAddress: "203.0.113.7", AccessTime: time.Now()}
		return ls.LogAuditEventWithAccessLog(ctx, e, l)
	}

	run := func(window time.Duration, record bool) ([]time.Duration, int64) {
		var (
			mu    sync.Mutex
			all   []time.Duration
			wg    sync.WaitGroup
			fails atomic.Int64
		)
		deadline := time.Now().Add(window)
		for range c {
			wg.Go(func() {
				var mine []time.Duration
				for time.Now().Before(deadline) {
					start := time.Now()
					if err := call(); err != nil {
						fails.Add(1)
						continue
					}
					if record {
						mine = append(mine, time.Since(start))
					}
				}
				mu.Lock()
				all = append(all, mine...)
				mu.Unlock()
			})
		}
		wg.Wait()
		require.Zero(t, fails.Load(), "audited calls failed under load")
		return all, int64(len(all))
	}

	run(time.Second, false)
	var firstID uint
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Select("COALESCE(max(id), 0)").Scan(&firstID).Error)
	start := time.Now()
	lat, calls := run(d, true)
	elapsed := time.Since(start)

	var sizes []int
	require.NoError(t, ls.db.Raw("SELECT count(*) FROM audit_events WHERE id > ? GROUP BY xmin::text", firstID).Scan(&sizes).Error)
	slices.Sort(sizes)
	slices.Sort(lat)
	require.NotEmpty(t, sizes)
	require.LessOrEqual(t, sizes[len(sizes)-1], auditFlusherMaxBatch)

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	require.True(t, v.Valid, v.Reason)
	return auditLoadResult{calls: int(calls), rps: float64(calls) / elapsed.Seconds(), latencies: lat, batches: sizes}
}
