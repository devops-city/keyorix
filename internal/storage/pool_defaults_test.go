package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// TestApplyPoolSettings_DialectDefaults pins #2631's per-dialect pool defaults:
// with max_open_conns unset, SQLite gets DefaultSQLiteMaxOpenConns and Postgres
// DefaultPostgresMaxOpenConns (pg-gated leg). An explicit max_open_conns wins on
// both. Guards against a refactor collapsing them back into one shared constant:
// the values are different on purpose (see their doc comment).
func TestApplyPoolSettings_DialectDefaults(t *testing.T) {
	require.NotEqual(t, DefaultSQLiteMaxOpenConns, DefaultPostgresMaxOpenConns,
		"the dialects are measured to want different pool sizes; a shared value is a regression")

	t.Run("sqlite", func(t *testing.T) {
		db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-sqlite.db"))
		require.NoError(t, err)
		require.NoError(t, applyPoolSettings(db, &config.DatabaseConfig{}))
		sqlDB, err := db.DB()
		require.NoError(t, err)
		assert.Equal(t, DefaultSQLiteMaxOpenConns, sqlDB.Stats().MaxOpenConnections)

		require.NoError(t, applyPoolSettings(db, &config.DatabaseConfig{MaxOpenConns: 40}))
		assert.Equal(t, 40, sqlDB.Stats().MaxOpenConnections, "operator's max_open_conns overrides the default")
	})

	t.Run("postgres", func(t *testing.T) {
		db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
		require.NoError(t, applyPoolSettings(db, &config.DatabaseConfig{}))
		sqlDB, err := db.DB()
		require.NoError(t, err)
		assert.Equal(t, DefaultPostgresMaxOpenConns, sqlDB.Stats().MaxOpenConnections)

		require.NoError(t, applyPoolSettings(db, &config.DatabaseConfig{MaxOpenConns: 12}))
		assert.Equal(t, 12, sqlDB.Stats().MaxOpenConnections)
	})
}

// TestPostgresPoolHeadroomWarning_ConfiguredNativeReadPool: a configured
// native_read_pool_max counts in the headroom check, up to the request pool's
// own cap.
func TestPostgresPoolHeadroomWarning_ConfiguredNativeReadPool(t *testing.T) {
	// 25 + 12 (lock pools) + 8 (default native pool) = 45 fits 48 usable; 20 does not.
	assert.Empty(t, postgresPoolHeadroomWarning(25, 0, 48+3, 3))
	assert.NotEmpty(t, postgresPoolHeadroomWarning(25, 20, 48+3, 3))
	// raising it past max_open_conns adds no more than max_open_conns
	assert.Equal(t, postgresPoolHeadroomWarning(25, 25, 48+3, 3), postgresPoolHeadroomWarning(25, 400, 48+3, 3))
	// lowering it frees slots: 25 + 12 + 2 = 39 fits 40 usable, the default 45 does not
	assert.Empty(t, postgresPoolHeadroomWarning(25, 2, 40+3, 3))
	assert.NotEmpty(t, postgresPoolHeadroomWarning(25, 0, 40+3, 3))
}

func TestPostgresPoolHeadroomWarning(t *testing.T) {
	cases := []struct {
		maxOpen, maxConn, reserved int
		warn                       bool
	}{
		{DefaultPostgresMaxOpenConns, 100, 3, false},
		// with the lock pools and the native read pool, exactly the usable slots
		{97 - lockPoolsSize - NativeReadPoolMaxSize, 100, 3, false},
		{98 - lockPoolsSize - NativeReadPoolMaxSize, 100, 3, true},
		// a request pool smaller than the native pool's cap caps it
		{3, 3 + lockPoolsSize + 3 + 1, 1, false},
		{3, 3 + lockPoolsSize + 3, 1, true},
		{100, 100, 3, true}, // the measured SQLSTATE 53300 case
		{100, 0, 0, false},  // setting unreadable/zero: never warn on garbage
	}
	for _, c := range cases {
		got := postgresPoolHeadroomWarning(c.maxOpen, 0, c.maxConn, c.reserved)
		assert.Equal(t, c.warn, got != "", "maxOpen=%d maxConn=%d reserved=%d: %q", c.maxOpen, c.maxConn, c.reserved, got)
		if c.warn {
			assert.Contains(t, got, "53300")
			assert.Contains(t, got, fmt.Sprintf("max_open_conns is %d", c.maxOpen))
		}
	}
}

// TestWarnPostgresPoolHeadroom_ReadsTheRealServerLimits (pg-gated) proves the
// warning is driven by the live server's settings, not by constants: a pool larger
// than the server's usable slots logs it, the default pool does not.
func TestWarnPostgresPoolHeadroom_ReadsTheRealServerLimits(t *testing.T) {
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	var maxConn int
	require.NoError(t, db.Raw("SELECT current_setting('max_connections')::int").Scan(&maxConn).Error)

	capture := func(cfg *config.DatabaseConfig) string {
		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(prev)
		warnPostgresPoolHeadroom(db, cfg)
		return buf.String()
	}
	assert.Contains(t, capture(&config.DatabaseConfig{MaxOpenConns: maxConn + 1}), "SQLSTATE 53300")
	if maxConn-10 > DefaultPostgresMaxOpenConns {
		assert.Empty(t, capture(&config.DatabaseConfig{}), "the default pool fits a server with max_connections=%d", maxConn)
	}
}

// BenchmarkPoolSize measures a mixed secret workload through core (#2631, Detected-by:
// PERF-2) at several max_open_conns values, on SQLite and, with KEYORIX_TEST_PG_DSN
// set, Postgres. 45 reader goroutines each do GetSecret + LogSecretReadWithProject
// (the handler's read-side database work: metadata read, audit append, access log)
// and 5 writer goroutines each do CreateSecret + UpdateSecret. Each b.N iteration is
// one operation; reported metrics split read and write throughput.
//
//	go test ./internal/storage -run '^$' -bench BenchmarkPoolSize -benchtime 20s
func BenchmarkPoolSize(b *testing.B) {
	require.NoError(b, i18n.InitializeForTesting())
	prevLog := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prevLog)

	type leg struct {
		dialect string
		pools   []int
	}
	legs := []leg{{"sqlite", []int{4, 8, 25}}}
	if os.Getenv("KEYORIX_TEST_PG_DSN") != "" {
		legs = append(legs, leg{"postgres", []int{10, 25, 50}})
	}
	for _, l := range legs {
		for _, pool := range l.pools {
			b.Run(fmt.Sprintf("%s/max_open_conns=%d", l.dialect, pool), func(b *testing.B) {
				var db *gorm.DB
				var err error
				if l.dialect == "sqlite" {
					db, err = gorm.Open(sqlite.Open(sqliteDSN(filepath.Join(b.TempDir(), "bench.db"))), gormConfig())
				} else {
					db, err = gorm.Open(postgres.Open(benchPGDatabase(b)), gormConfig())
				}
				require.NoError(b, err)
				require.NoError(b, applyPoolSettings(db, &config.DatabaseConfig{MaxOpenConns: pool}))
				require.NoError(b, (&DefaultStorageFactory{}).migrateDatabase(db))
				runPoolBenchmark(b, db)
				sqlDB, _ := db.DB()
				_ = sqlDB.Close()
			})
		}
	}
}

func runPoolBenchmark(b *testing.B, db *gorm.DB) {
	st := store.NewLocalStorage(db)
	ctx := context.Background()
	p, err := st.CreateProject(ctx, &models.Project{Name: "bench"})
	require.NoError(b, err)
	e, err := st.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(b, err)
	c := core.NewKeyorixCore(st)
	var ids []uint
	for i := range 200 {
		sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{Name: fmt.Sprintf("seed-%d", i), Value: []byte("seed-value-Zq9!xR"),
			ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", CreatedBy: "bench", OwnerID: 1})
		require.NoError(b, err)
		ids = append(ids, sec.ID)
	}

	const readers, writers = 45, 5
	work := make(chan int, readers+writers)
	var reads, writes, failures int64
	var readLat []time.Duration
	var mu sync.Mutex
	var wg sync.WaitGroup
	worker := func(read bool, n int) {
		defer wg.Done()
		for i := range work {
			t0 := time.Now()
			var err error
			if read {
				id := ids[(n*7919+i)%len(ids)]
				var sec *models.SecretNode
				if sec, err = c.GetSecret(ctx, id); err == nil {
					err = c.LogSecretReadWithProject(ctx, 1, sec.ID, p.ID, "bench", sec.Name, "127.0.0.1", "bench")
				}
			} else {
				name := fmt.Sprintf("w-%d-%d", n, i)
				var sec *models.SecretNode
				if sec, err = c.CreateSecret(ctx, &core.CreateSecretRequest{Name: name, Value: []byte("v1-" + name + "-Zq9!xR"),
					ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", CreatedBy: "bench", OwnerID: 1}); err == nil {
					_, err = c.UpdateSecret(ctx, &core.UpdateSecretRequest{ID: sec.ID, Value: []byte("v2-" + name + "-Zq9!xR"), UpdatedBy: "bench"})
				}
			}
			d := time.Since(t0)
			mu.Lock()
			switch {
			case err != nil:
				failures++
			case read:
				reads++
				readLat = append(readLat, d)
			default:
				writes++
			}
			mu.Unlock()
		}
	}
	b.ResetTimer()
	start := time.Now()
	for n := range readers {
		wg.Add(1)
		go worker(true, n)
	}
	for n := range writers {
		wg.Add(1)
		go worker(false, n)
	}
	for i := 0; i < b.N; i++ {
		work <- i
	}
	close(work)
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	b.StopTimer()
	slices.Sort(readLat)
	b.ReportMetric(float64(reads)/elapsed, "reads/s")
	b.ReportMetric(float64(writes)/elapsed, "writes/s")
	if len(readLat) > 0 {
		b.ReportMetric(float64(readLat[len(readLat)*99/100].Microseconds())/1000, "read-p99-ms")
	}
	b.ReportMetric(float64(failures), "failures")
	time.Sleep(200 * time.Millisecond) // let core's detached access-log/audit writes land before Close
}

// benchPGDatabase creates a throwaway database for one benchmark leg and returns its DSN.
func benchPGDatabase(b *testing.B) string {
	b.Helper()
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	admin, err := gorm.Open(postgres.Open(base), gormConfig())
	require.NoError(b, err)
	name := fmt.Sprintf("pool_bench_%d_%d", os.Getpid(), time.Now().UnixNano())
	require.NoError(b, admin.Exec("CREATE DATABASE "+name).Error)
	b.Cleanup(func() {
		_ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)").Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if strings.Contains(base, "dbname=") {
		fields := strings.Fields(base)
		for i, f := range fields {
			if strings.HasPrefix(f, "dbname=") {
				fields[i] = "dbname=" + name
			}
		}
		return strings.Join(fields, " ")
	}
	return base + " dbname=" + name
}
