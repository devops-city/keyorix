package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// compressedBusyTimeout scales the production 10s SQLite busy_timeout (and the
// SQLite busy handler's budget) down so the PERF-2 failure mode — a writer
// starved inside SQLite's polling busy handler until busy_timeout expires — shows
// up in a seconds-long test instead of needing minutes of sustained load at 10s.
// Every production DSN pragma other than busy_timeout is kept exactly; the write
// gate's own bound is not compressed (see newCompressedWriteWorld).
const compressedBusyTimeout = 50 * time.Millisecond

type writeWorld struct {
	c       *core.KeyorixCore
	db      *gorm.DB
	project uint
	env     uint
}

// newCompressedWriteWorld builds core on a file SQLite database opened with the
// production DSN (busy_timeout compressed), pooled by the production
// applyPoolSettings defaults and migrated by the production migrateDatabase. gated
// selects the production open path (openSQLiteGorm, write gate on) or the pre-#2630
// one (plain dialector, no gate) as the red control.
func newCompressedWriteWorld(t *testing.T, gated bool) *writeWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	// Only SQLite's own busy_timeout is compressed. The gate keeps its production
	// bound (sqliteWriteGateMaxWait): the gate's queue is FIFO, so a slow CI host
	// lengthens waits proportionally rather than starving anyone, and compressing
	// that bound too would only make the green case host-speed-dependent.

	dsn := sqliteDSN(filepath.Join(t.TempDir(), "keyorix.db"))
	prodBusy := fmt.Sprintf("_busy_timeout=%d", sqliteBusyTimeoutMillis)
	require.Contains(t, dsn, prodBusy)
	dsn = strings.Replace(dsn, prodBusy, fmt.Sprintf("_busy_timeout=%d", compressedBusyTimeout.Milliseconds()), 1)

	var db *gorm.DB
	var err error
	if gated {
		db, err = openSQLiteGorm(dsn)
	} else {
		db, err = gorm.Open(sqlite.Open(dsn), gormConfig())
	}
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, applyPoolSettings(db, &config.DatabaseConfig{}))
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))

	st := store.NewLocalStorage(db)
	ctx := context.Background()
	p, err := st.CreateProject(ctx, &models.Project{Name: "perf"})
	require.NoError(t, err)
	e, err := st.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(t, err)
	return &writeWorld{c: core.NewKeyorixCore(st), db: db, project: p.ID, env: e.ID}
}

type writeOutcome struct {
	name   string
	update bool
	err    error
	dur    time.Duration
}

// runWrites has `clients` goroutines each create `perClient` distinct secrets and
// update each once through core, also emitting the detached audit event the HTTP
// handler fires after a create (goSafe → LogSecretCreatedWithProject), so the write
// mix matches a real server's. Returns every create/update outcome.
func (w *writeWorld) runWrites(t *testing.T, clients, perClient int) []writeOutcome {
	t.Helper()
	ctx := context.Background()
	var mu sync.Mutex
	var out []writeOutcome
	var audits sync.WaitGroup
	start := make(chan struct{})
	var wg sync.WaitGroup
	for c := range clients {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			<-start
			for i := range perClient {
				name := fmt.Sprintf("s-%d-%d", c, i)
				t0 := time.Now()
				sec, err := w.c.CreateSecret(ctx, &core.CreateSecretRequest{
					Name: name, Value: []byte("v1-" + name + "-Zq9!xR"), ProjectID: w.project,
					EnvironmentID: w.env, Type: "password", CreatedBy: "perf", OwnerID: 1,
				})
				mu.Lock()
				out = append(out, writeOutcome{name: name, err: err, dur: time.Since(t0)})
				mu.Unlock()
				if err != nil {
					continue
				}
				audits.Add(1)
				go func(id uint, name string) {
					defer audits.Done()
					w.c.LogSecretCreatedWithProject(core.DetachedAuditContext(ctx), 1, id, w.project, "perf", name, "127.0.0.1", "test")
				}(sec.ID, name)
				t0 = time.Now()
				_, err = w.c.UpdateSecret(ctx, &core.UpdateSecretRequest{ID: sec.ID, Value: []byte("v2-" + name + "-Zq9!xR"), UpdatedBy: "perf"})
				mu.Lock()
				out = append(out, writeOutcome{name: name, update: true, err: err, dur: time.Since(t0)})
				mu.Unlock()
			}
		}(c)
	}
	close(start)
	wg.Wait()
	audits.Wait()
	return out
}

func summarizeOutcomes(os []writeOutcome) (errs int, p99, max time.Duration, firstErr error) {
	durs := make([]time.Duration, 0, len(os))
	for _, o := range os {
		if o.err != nil {
			errs++
			if firstErr == nil {
				firstErr = o.err
			}
		}
		durs = append(durs, o.dur)
	}
	slices.Sort(durs)
	return errs, durs[len(durs)*99/100], durs[len(durs)-1], firstErr
}

// TestSQLite_ConcurrentDistinctSecretWrites_SucceedOrFailFast is the #2630 guard
// (Detected-by: PERF-2). N clients write DISTINCT secrets through core on the SQLite
// backend, with the production DSN, pool and migration and a compressed
// busy_timeout (see compressedBusyTimeout). Distinct secrets never conflict, so:
//
//  1. every write succeeds: no SQLITE_BUSY, no "database is locked", no gate timeout;
//  2. nothing hangs (production symptom: p99 pinned at the client's 10s timeout);
//  3. no silent loss: a create is in the database if and only if it reported success.
//
// TestSQLite_ConcurrentDistinctSecretWrites_UngatedControlFails runs the same
// workload without the write gate and must see the failure, so this test cannot
// pass vacuously.
func TestSQLite_ConcurrentDistinctSecretWrites_SucceedOrFailFast(t *testing.T) {
	if testing.Short() {
		t.Skip("load-shaped test; skipped in -short")
	}
	w := newCompressedWriteWorld(t, true)
	outcomes := w.runWrites(t, 60, 6)
	errs, p99, max, firstErr := summarizeOutcomes(outcomes)
	t.Logf("gated: ops=%d errors=%d p99=%s max=%s", len(outcomes), errs, p99, max)
	require.Zero(t, errs, "every write to a distinct secret must succeed; first error: %v", firstErr)
	// Latency is not bounded by busy_timeout here: creates in one environment
	// legitimately queue on its per-environment named lock (withEnvironmentSecretGuard).
	// The bound below only detects a hang; the property under test is (1) and (3).
	require.Less(t, max, 5*time.Second, "no write may hang")

	var names []string
	require.NoError(t, w.db.Model(&models.SecretNode{}).Pluck("name", &names).Error)
	stored := make(map[string]bool, len(names))
	for _, n := range names {
		stored[n] = true
	}
	for _, o := range outcomes {
		if !o.update {
			require.Equal(t, o.err == nil, stored[o.name], "secret %s: reported success=%v but stored=%v", o.name, o.err == nil, stored[o.name])
		}
	}
}

// TestSQLite_ConcurrentDistinctSecretWrites_UngatedControlFails pins that the
// workload above genuinely exercises the failure: with the gate removed, the SAME
// harness must observe the PERF-2 symptom: a write failing with SQLITE_BUSY after
// starving in SQLite's busy handler for the whole busy_timeout. If this stops failing, the guard above has stopped proving
// anything and the compression constants need recalibrating.
func TestSQLite_ConcurrentDistinctSecretWrites_UngatedControlFails(t *testing.T) {
	if testing.Short() {
		t.Skip("load-shaped test; skipped in -short")
	}
	w := newCompressedWriteWorld(t, false)
	outcomes := w.runWrites(t, 60, 6)
	errs, p99, max, firstErr := summarizeOutcomes(outcomes)
	t.Logf("ungated control: ops=%d errors=%d (first: %v) p99=%s max=%s", len(outcomes), errs, firstErr, p99, max)
	require.Positive(t, errs, "control must reproduce SQLITE_BUSY failures without the gate (max=%s)", max)
	require.Contains(t, firstErr.Error(), "SQLITE_BUSY")
}

// TestSQLiteWriteGate_FailsFastWithClearError: a write that cannot get the gate
// within its bound fails with ErrSQLiteWriteContention (not a hang, not a raw driver
// error); a caller whose context ends while queued gets that context's error; the
// gate is free again once its holder ends; read-only transactions bypass it.
func TestSQLiteWriteGate_FailsFastWithClearError(t *testing.T) {
	prev := sqliteWriteGateMaxWait.Load()
	sqliteWriteGateMaxWait.Store(int64(50 * time.Millisecond))
	defer func() { sqliteWriteGateMaxWait.Store(prev) }()

	db, err := openSQLiteGorm(sqliteDSN(filepath.Join(t.TempDir(), "gate.db")))
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE TABLE t (x INTEGER)").Error)
	insert := func(ctx context.Context, x int) error {
		return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error { return tx.Exec("INSERT INTO t VALUES (?)", x).Error })
	}

	holder := db.Begin()
	require.NoError(t, holder.Error)

	t0 := time.Now()
	require.ErrorIs(t, insert(context.Background(), 1), ErrSQLiteWriteContention)
	require.Less(t, time.Since(t0), time.Second, "must fail fast at the gate bound")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	err = insert(ctx, 2)
	require.True(t, errors.Is(err, context.Canceled), "a queued caller whose ctx ends gets ctx's error, got %v", err)

	var n int64
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		return tx.Raw("SELECT count(*) FROM t").Scan(&n).Error
	}, &sql.TxOptions{ReadOnly: true}), "read-only transactions bypass the gate even while a writer holds it")

	require.NoError(t, holder.Rollback().Error)
	require.NoError(t, insert(context.Background(), 3), "the gate is free again once the holder ends")

	// A holder whose ctx is cancelled without ever reaching Commit/Rollback must not
	// wedge the gate (database/sql rolls such a transaction back on its own).
	hctx, hcancel := context.WithCancel(context.Background())
	leaked := db.WithContext(hctx).Begin()
	require.NoError(t, leaked.Error)
	hcancel()
	require.Eventually(t, func() bool { return insert(context.Background(), 4) == nil }, time.Second, 10*time.Millisecond)
}

// BenchmarkSQLiteConcurrentSecretWrites measures sustained create+update throughput
// of distinct secrets through core on SQLite with the PRODUCTION busy_timeout (10s),
// with and without the #2630 write gate, at 10 and 50 concurrent clients. Each b.N
// iteration is one client doing one create + one update; b.ReportMetric adds the
// failure count and the slowest single write.
//
//	go test ./internal/storage -run '^$' -bench BenchmarkSQLiteConcurrentSecretWrites -benchtime 2000x
//
// There is no Postgres leg: the gate is SQLite-only (Postgres has row-level write
// concurrency and its own lock queueing).
func BenchmarkSQLiteConcurrentSecretWrites(b *testing.B) {
	prevLog := log.Writer()
	log.SetOutput(io.Discard) // per-failure SECURITY log lines would interleave with bench output
	defer log.SetOutput(prevLog)
	for _, gated := range []bool{false, true} {
		for _, clients := range []int{10, 50} {
			name := fmt.Sprintf("ungated/c=%d", clients)
			if gated {
				name = fmt.Sprintf("gated/c=%d", clients)
			}
			b.Run(name, func(b *testing.B) {
				require.NoError(b, i18n.InitializeForTesting())
				dsn := sqliteDSN(filepath.Join(b.TempDir(), "bench.db"))
				var db *gorm.DB
				var err error
				if gated {
					db, err = openSQLiteGorm(dsn)
				} else {
					db, err = gorm.Open(sqlite.Open(dsn), gormConfig())
				}
				require.NoError(b, err)
				require.NoError(b, applyPoolSettings(db, &config.DatabaseConfig{}))
				require.NoError(b, (&DefaultStorageFactory{}).migrateDatabase(db))
				st := store.NewLocalStorage(db)
				ctx := context.Background()
				p, err := st.CreateProject(ctx, &models.Project{Name: "bench"})
				require.NoError(b, err)
				e, err := st.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
				require.NoError(b, err)
				c := core.NewKeyorixCore(st)

				var mu sync.Mutex
				var failures int
				var slowest time.Duration
				note := func(d time.Duration, err error) {
					mu.Lock()
					if err != nil {
						failures++
					}
					if d > slowest {
						slowest = d
					}
					mu.Unlock()
				}
				work := make(chan int)
				var wg, audits sync.WaitGroup
				b.ResetTimer()
				for range clients {
					wg.Go(func() {
						for i := range work {
							name := fmt.Sprintf("b-%d", i)
							t0 := time.Now()
							sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{Name: name, Value: []byte("v1-" + name + "-Zq9!xR"),
								ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", CreatedBy: "bench", OwnerID: 1})
							note(time.Since(t0), err)
							if err != nil {
								continue
							}
							audits.Add(1)
							go func(id uint, name string) {
								defer audits.Done()
								c.LogSecretCreatedWithProject(core.DetachedAuditContext(ctx), 1, id, p.ID, "bench", name, "127.0.0.1", "bench")
							}(sec.ID, name)
							t0 = time.Now()
							_, err = c.UpdateSecret(ctx, &core.UpdateSecretRequest{ID: sec.ID, Value: []byte("v2-" + name + "-Zq9!xR"), UpdatedBy: "bench"})
							note(time.Since(t0), err)
						}
					})
				}
				for i := 0; i < b.N; i++ {
					work <- i
				}
				close(work)
				wg.Wait()
				b.StopTimer()
				audits.Wait()
				time.Sleep(200 * time.Millisecond) // let core's own detached access-log writes land before Close
				b.ReportMetric(float64(failures), "failures")
				b.ReportMetric(float64(slowest.Milliseconds()), "max-ms")
				sqlDB, _ := db.DB()
				_ = sqlDB.Close()
			})
		}
	}
}
