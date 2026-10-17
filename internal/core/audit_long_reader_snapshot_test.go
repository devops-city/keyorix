// audit_long_reader_snapshot_test.go — AUDIT-READER-HYGIENE-1 item 1: the long
// audit readers (the audit_checkpoint tick's rolling re-walk and
// `admin verify-audit`, i.e. auditverify.Verify) must not hold ONE read snapshot
// for their whole walk.
//
// SQLite (WAL): a reader pins the WAL frames that were current when its read
// transaction started. The checkpointer cannot backfill past them (for a reader
// on read-mark 0, not at all) and the WAL cannot restart, so it grows with every
// concurrent commit for as long as that snapshot is held. The probe issues
// PRAGMA wal_checkpoint(PASSIVE) in a loop on its own connection; "progress" is
// a probe that backfilled every frame in the WAL (checkpointed == log > 0) or
// found the WAL restarted (log fell). The property: the longest stretch of the
// walk without progress is under half of the walk.
//
// PostgreSQL: a long snapshot holds back the xmin horizon (vacuum cannot remove
// dead rows, on every table). The probe reads pg_stat_activity for backends that
// hold a snapshot (backend_xmin set) and records the age of their transaction.
// The property: no snapshot lived for half of the walk.
//
// Both run while a writer commits continuously, on a 300k-row chained audit
// table, the database opened as production opens it (SQLite through the storage
// factory: WAL, _txlock=immediate, synchronous=FULL, write gate). The
// calibration tests hold one snapshot deliberately and must be reported as
// pinned, so a green property test means the walk really let go of its
// snapshots, not that the probe saw nothing.
package core

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const longReaderAuditRows = 300_000

// longReaderEnv is one backend under test.
type longReaderEnv struct {
	c  *KeyorixCore
	db *gorm.DB // the store's own handle (writes go through it, as in production)
	// openVerifier opens the database the way `admin verify-audit` does.
	openVerifier func(t *testing.T) *auditverify.DB
	// probe returns one observation: progress reports whether the checkpointer
	// could catch up (SQLite) / no snapshot is old (Postgres is judged on age).
	probe func() (longReaderSample, bool)
	// holdSnapshot starts a read transaction that keeps one snapshot until the
	// returned func is called (the calibration's deliberately bad reader).
	holdSnapshot func(t *testing.T) func()
}

type longReaderSample struct {
	at time.Time
	// SQLite: the PASSIVE checkpoint result and the WAL file size.
	log, ckpt, walBytes int64
	// Postgres: the oldest snapshot-holding transaction of another backend.
	oldestSnapshot time.Duration
}

// newFactorySQLiteLongReaderEnv opens a file-backed SQLite store through the
// production storage factory and returns a core on it with checkpoints on.
func newFactorySQLiteLongReaderEnv(t *testing.T) *longReaderEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit-long-reader.db")
	cfg := &config.Config{Storage: config.StorageConfig{
		Type:     "local",
		Database: config.DatabaseConfig{Path: path},
	}}
	st, err := kxstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "factory must return *store.LocalStorage for type local, got %T", st)
	t.Cleanup(func() {
		if sqlDB, derr := ls.DB().DB(); derr == nil {
			_ = sqlDB.Close()
		}
	})
	c := NewKeyorixCore(st)
	c.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")

	probe, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	probe.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = probe.Close() })

	return &longReaderEnv{
		c: c, db: ls.DB(),
		openVerifier: func(t *testing.T) *auditverify.DB {
			vdb, err := auditverify.OpenSQLiteReadOnly(path)
			require.NoError(t, err)
			t.Cleanup(func() { _ = vdb.Close() })
			return vdb
		},
		probe: func() (longReaderSample, bool) {
			var s longReaderSample
			var busy int64
			if err := probe.QueryRow("PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &s.log, &s.ckpt); err != nil {
				return s, false
			}
			if fi, err := os.Stat(path + "-wal"); err == nil {
				s.walBytes = fi.Size()
			}
			s.at = time.Now()
			return s, true
		},
		holdSnapshot: func(t *testing.T) func() {
			reader, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
			require.NoError(t, err)
			tx, err := reader.Begin()
			require.NoError(t, err)
			var n int
			require.NoError(t, tx.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&n))
			return func() { _ = tx.Rollback(); _ = reader.Close() }
		},
	}
}

// newPostgresLongReaderEnv is the same on a real PostgreSQL schema.
func newPostgresLongReaderEnv(t *testing.T) *longReaderEnv {
	t.Helper()
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)
	db := pgOpen(t, dsn)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4) // the checkpoint lock's session, the walk and the writer
	require.NoError(t, kxstorage.MigrateExisting(db))
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")

	probe := pgOpen(t, base)
	return &longReaderEnv{
		c: c, db: db,
		openVerifier: func(t *testing.T) *auditverify.DB {
			vdb, err := auditverify.OpenPostgres(dsn)
			require.NoError(t, err)
			t.Cleanup(func() { _ = vdb.Close() })
			return vdb
		},
		probe: func() (longReaderSample, bool) {
			var secs float64
			if err := probe.Raw(`SELECT COALESCE(MAX(EXTRACT(EPOCH FROM clock_timestamp() - xact_start)), 0)
				FROM pg_stat_activity
				WHERE datname = current_database() AND pid <> pg_backend_pid()
				  AND backend_xmin IS NOT NULL AND xact_start IS NOT NULL`).Scan(&secs).Error; err != nil {
				return longReaderSample{}, false
			}
			return longReaderSample{at: time.Now(), oldestSnapshot: time.Duration(secs * float64(time.Second))}, true
		},
		holdSnapshot: func(t *testing.T) func() {
			reader := pgOpen(t, dsn)
			tx := reader.Begin(&sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
			require.NoError(t, tx.Error)
			var n int64
			require.NoError(t, tx.Raw("SELECT COUNT(*) FROM audit_events").Scan(&n).Error)
			return func() { _ = tx.Rollback() }
		},
	}
}

// buildSyntheticAuditChain inserts n audit rows and chains them with the real
// hash function, so every walker verifies them as one valid chain. Every
// column the real writer always fills is non-NULL (auditverify rejects a NULL
// ip_address or diff as a malformed row).
func buildSyntheticAuditChain(t *testing.T, db *gorm.DB, n int) {
	t.Helper()
	const cols = `INSERT INTO audit_events (event_type, ip_address, description, success, event_time, diff, impersonation, actor_type) `
	if db.Dialector.Name() == "postgres" {
		require.NoError(t, db.Exec(cols+`SELECT 'secret.read', '10.0.0.1', 'synthetic ' || i, TRUE,
			TIMESTAMPTZ '2026-08-01 12:00:00+00', '', FALSE, 'user' FROM generate_series(1, ?) AS i`, n).Error)
	} else {
		require.NoError(t, db.Exec(`WITH RECURSIVE seq(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM seq WHERE i < ?) `+
			cols+`SELECT 'secret.read', '10.0.0.1', 'synthetic ' || i, TRUE, '2026-08-01 12:00:00', '', FALSE, 'user' FROM seq`, n).Error)
	}
	rehashAuditChain(t, db, 0)
}

// rehashAuditChain recomputes prev_hash/entry_hash for every row with id >
// after, continuing the chain from row after's entry_hash (genesis for 0).
func rehashAuditChain(t *testing.T, db *gorm.DB, after uint) {
	t.Helper()
	prev := auditverify.GenesisHash
	if after > 0 {
		var e models.AuditEvent
		require.NoError(t, db.Where("id = ?", after).Take(&e).Error)
		prev = e.EntryHash
	}
	const page = 1000
	last := after
	for {
		var rows []models.AuditEvent
		require.NoError(t, db.Where("id > ?", last).Order("id ASC").Limit(page).Find(&rows).Error)
		if len(rows) == 0 {
			return
		}
		var vals []string
		var args []any
		for i := range rows {
			e := &rows[i]
			h := store.ComputeAuditEntryHash(e, prev)
			if i == 0 {
				vals = append(vals, "(CAST(? AS BIGINT), ?, ?)")
			} else {
				vals = append(vals, "(?, ?, ?)")
			}
			args = append(args, e.ID, prev, h)
			prev = h
		}
		require.NoError(t, db.Exec(`WITH v(id, p, h) AS (VALUES `+strings.Join(vals, ", ")+`)
			UPDATE audit_events SET prev_hash = v.p, entry_hash = v.h FROM v WHERE audit_events.id = v.id`, args...).Error)
		last = rows[len(rows)-1].ID
	}
}

// longReaderObservation is what the probe saw while the walk ran.
type longReaderObservation struct {
	walk    time.Duration
	probes  int
	writes  int64
	backend string
	// longestWriterStall is the longest stretch of the walk without a commit
	// (a walk that takes the write lock blocks writers instead of pinning).
	longestWriterStall time.Duration
	// SQLite: how many probes made full checkpoint progress, and the longest
	// stretch of the walk without one (from its start, between two of them, or
	// up to its end).
	progress      int
	longestPinned time.Duration
	maxWALBytes   int64
	// Postgres: the oldest snapshot any other backend held during the walk.
	oldestSnapshot time.Duration
}

// observeDuringWalk runs walk while a writer commits through env.db and the
// probe samples in a loop.
func observeDuringWalk(t *testing.T, env *longReaderEnv, walk func(ctx context.Context) error) longReaderObservation {
	t.Helper()
	require.NoError(t, env.db.Exec("CREATE TABLE IF NOT EXISTS long_reader_load (id INTEGER PRIMARY KEY, payload TEXT)").Error)
	obs := longReaderObservation{backend: env.db.Dialector.Name()}
	if obs.backend == "sqlite" {
		// Start from a checkpointed, restarted WAL.
		require.NoError(t, env.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	var writes atomic.Int64
	var nextID atomic.Int64
	var commitsMu sync.Mutex
	var commits []time.Time
	wg.Go(func() { // writer: small committed transactions, back to back
		for ctx.Err() == nil {
			if err := env.db.Exec("INSERT INTO long_reader_load (id, payload) VALUES (?, ?)", nextID.Add(1), "x").Error; err == nil {
				writes.Add(1)
				commitsMu.Lock()
				commits = append(commits, time.Now())
				commitsMu.Unlock()
			}
			time.Sleep(time.Millisecond)
		}
	})
	for writes.Load() < 20 { // frames in the WAL before the walk starts
		time.Sleep(5 * time.Millisecond)
	}

	var mu sync.Mutex
	var samples []longReaderSample
	wg.Go(func() {
		for ctx.Err() == nil {
			if s, ok := env.probe(); ok {
				mu.Lock()
				samples = append(samples, s)
				mu.Unlock()
			}
			time.Sleep(5 * time.Millisecond)
		}
	})

	start := time.Now()
	writesBefore := writes.Load()
	require.NoError(t, walk(context.Background()))
	end := time.Now()
	cancel()
	wg.Wait()

	obs.walk, obs.writes = end.Sub(start), writes.Load()-writesBefore
	prevLog := int64(-1)
	lastProgress := start
	for _, s := range samples {
		if s.at.Before(start) || s.at.After(end) {
			continue
		}
		obs.probes++
		obs.oldestSnapshot = max(obs.oldestSnapshot, s.oldestSnapshot)
		obs.maxWALBytes = max(obs.maxWALBytes, s.walBytes)
		if (s.log > 0 && s.ckpt == s.log) || (prevLog >= 0 && s.log < prevLog) {
			obs.progress++
			obs.longestPinned = max(obs.longestPinned, s.at.Sub(lastProgress))
			lastProgress = s.at
		}
		prevLog = s.log
	}
	obs.longestPinned = max(obs.longestPinned, end.Sub(lastProgress))
	lastCommit := start
	for _, at := range commits {
		if at.Before(start) || at.After(end) {
			continue
		}
		obs.longestWriterStall = max(obs.longestWriterStall, at.Sub(lastCommit))
		lastCommit = at
	}
	obs.longestWriterStall = max(obs.longestWriterStall, end.Sub(lastCommit))
	t.Logf("%s walk %s: %d probes, %d concurrent commits, longest writer stall %s; sqlite: %d with full checkpoint progress, longest stretch without %s, max WAL %d bytes; postgres: oldest snapshot %s",
		obs.backend, obs.walk, obs.probes, obs.writes, obs.longestWriterStall, obs.progress, obs.longestPinned, obs.maxWALBytes, obs.oldestSnapshot)
	require.Positive(t, obs.writes, "the writer committed during the walk")
	require.Positive(t, obs.probes, "the probe ran during the walk")
	return obs
}

// pinned reports whether the walk held one snapshot for most of its duration,
// and why.
func (o longReaderObservation) pinned() (bool, string) {
	if o.backend == "postgres" {
		return o.oldestSnapshot >= o.walk/2, fmt.Sprintf(
			"a snapshot lived for %s of a %s walk (%d probes, %d concurrent commits)", o.oldestSnapshot, o.walk, o.probes, o.writes)
	}
	return o.longestPinned >= o.walk/2, fmt.Sprintf(
		"for %s of a %s walk no PASSIVE checkpoint could backfill the WAL and the WAL never restarted (%d probes, %d concurrent commits, max WAL %d bytes)",
		o.longestPinned, o.walk, o.probes, o.writes, o.maxWALBytes)
}

func requireNotPinned(t *testing.T, obs longReaderObservation, what string) {
	t.Helper()
	pinned, why := obs.pinned()
	require.False(t, pinned, "%s held one read snapshot across its walk: %s", what, why)
	require.Less(t, obs.longestWriterStall, obs.walk/2,
		"%s blocked the concurrent writer for %s of a %s walk (%d commits): it must read, not hold the write lock",
		what, obs.longestWriterStall, obs.walk, obs.writes)
}

func longReaderBackends() map[string]func(*testing.T) *longReaderEnv {
	return map[string]func(*testing.T) *longReaderEnv{
		"sqlite":   newFactorySQLiteLongReaderEnv,
		"postgres": newPostgresLongReaderEnv,
	}
}

// TestAuditLongReaders_CalibrationHeldSnapshotIsReportedPinned: a reader that
// holds one snapshot while the writer commits is reported as pinned on both
// backends. Without this the tests below could pass because the probe never
// observes a pinned snapshot at all.
func TestAuditLongReaders_CalibrationHeldSnapshotIsReportedPinned(t *testing.T) {
	for name, newEnv := range longReaderBackends() {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t)
			buildSyntheticAuditChain(t, env.db, 1_000)
			obs := observeDuringWalk(t, env, func(context.Context) error {
				release := env.holdSnapshot(t)
				defer release()
				time.Sleep(1500 * time.Millisecond)
				return nil
			})
			pinned, why := obs.pinned()
			require.True(t, pinned, "a reader holding one snapshot must be reported as pinned: %s", why)
		})
	}
}

// TestAuditLongReaders_RollingRewalkDoesNotHoldOneSnapshot: one audit_checkpoint
// tick re-walks the whole 300k-row chain (one segment per cycle) without
// holding one snapshot across the walk.
func TestAuditLongReaders_RollingRewalkDoesNotHoldOneSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 300k-row audit table")
	}
	for name, newEnv := range longReaderBackends() {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t)
			buildSyntheticAuditChain(t, env.db, longReaderAuditRows)
			ctx := context.Background()
			env.c.SetAuditIncrementalVerification(24*time.Hour, 1)
			_, written, err := env.c.WriteAuditCheckpoint(ctx)
			require.NoError(t, err)
			require.True(t, written)

			var res *AuditVerifyTickResult
			obs := observeDuringWalk(t, env, func(ctx context.Context) error {
				var err error
				res, err = env.c.RunAuditVerificationTick(ctx)
				return err
			})
			require.True(t, res.SegmentWalked)
			require.True(t, res.CycleCompleted, "the tick re-walked the whole chain")
			require.EqualValues(t, longReaderAuditRows, res.VerifiedThrough)
			requireNotPinned(t, obs, "the audit_checkpoint tick's rolling re-walk")
		})
	}
}

// TestAuditLongReaders_OfflineVerifyDoesNotHoldOneSnapshot: `admin verify-audit`
// (auditverify.Verify on the database opened as the command opens it) walks
// the 300k-row chain without holding one snapshot across the walk.
func TestAuditLongReaders_OfflineVerifyDoesNotHoldOneSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 300k-row audit table")
	}
	for name, newEnv := range longReaderBackends() {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t)
			buildSyntheticAuditChain(t, env.db, longReaderAuditRows)
			vdb := env.openVerifier(t)
			var res *auditverify.Result
			obs := observeDuringWalk(t, env, func(ctx context.Context) error {
				var err error
				res, err = auditverify.Verify(ctx, vdb, auditverify.Options{})
				return err
			})
			require.Equal(t, auditverify.VerdictValid, res.Verdict, res.Reason)
			require.EqualValues(t, longReaderAuditRows, res.ChainedEvents)
			requireNotPinned(t, obs, "admin verify-audit (auditverify.Verify)")
		})
	}
}
