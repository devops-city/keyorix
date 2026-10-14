package auditverify

// BenchmarkVerify_1MRows measures this package's re-walk throughput against
// a 1M-row local SQLite fixture — the same shape design §8's own throwaway
// spike measured (~900k rows/sec on that dev machine, raw modernc.org/sqlite
// + keyset-paginated batches + per-row SHA256 recompute). Report the actual
// number this measures with `go test -bench BenchmarkVerify_1MRows -run ^$
// -benchtime=1x ./internal/auditverify/` — treat it as an upper bound for
// local SQLite, not a Postgres or cold-cache estimate, exactly as design §8
// itself cautions.
//
// The fixture is built once (via a package-level sync.Once, keyed by row
// count) using direct batched INSERTs rather than the real LogAuditEvent
// write path — Go's benchmark harness re-invokes the benchmark function
// itself during calibration, and re-running the real per-row transactional
// writer a million rows at a time on every calibration pass would dominate
// the measurement. The correctness of the hash chain this produces is
// exactly the same ComputeEntryHash this package's own differential test
// already proves matches the real writer byte-for-byte — this file measures
// throughput, not correctness.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var (
	benchFixtureOnce sync.Once
	benchFixturePath string
	benchFixtureErr  error
)

func buildBenchFixture1M(tb testing.TB) string {
	tb.Helper()
	benchFixtureOnce.Do(func() {
		dir, err := os.MkdirTemp("", "auditverify-bench-*")
		if err != nil {
			benchFixtureErr = err
			return
		}
		path := filepath.Join(dir, "bench.db")
		benchFixtureErr = buildAuditChainFixture(path, 1_000_000)
		benchFixturePath = path
	})
	if benchFixtureErr != nil {
		tb.Fatalf("build 1M-row bench fixture: %v", benchFixtureErr)
	}
	return benchFixturePath
}

// buildAuditChainFixture writes n self-consistent chained audit_events rows
// (plus the two sibling tables, empty) to a fresh SQLite file at path, using
// large batched INSERTs inside a single transaction with durability pragmas
// relaxed for fixture-construction speed only (this is throwaway build-time
// state, never the artifact being verified for real).
func buildAuditChainFixture(path string, n int) error {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer func() { _ = sqlDB.Close() }()

	for _, pragma := range []string{
		`PRAGMA journal_mode=OFF`,
		`PRAGMA synchronous=OFF`,
	} {
		if _, err := sqlDB.Exec(pragma); err != nil {
			return fmt.Errorf("%s: %w", pragma, err)
		}
	}

	for _, stmt := range []string{
		`CREATE TABLE audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT, user_id INTEGER, secret_node_id INTEGER, project_id INTEGER,
			ip_address TEXT, description TEXT, success BOOLEAN, event_time DATETIME, diff TEXT,
			impersonated_by INTEGER, acting_as INTEGER, impersonation BOOLEAN, actor_type TEXT,
			machine_identity_id INTEGER, prev_hash TEXT, entry_hash TEXT
		)`,
		`CREATE TABLE audit_checkpoints (
			id INTEGER PRIMARY KEY AUTOINCREMENT, chained_events INTEGER, head_id INTEGER,
			head_hash TEXT, key_version TEXT, signature TEXT, anchor_token BLOB,
			anchored_at DATETIME, anchor_provider TEXT, created_at DATETIME
		)`,
		`CREATE TABLE system_metadata (key TEXT PRIMARY KEY, value TEXT, updated_at DATETIME)`,
	} {
		if _, err := sqlDB.Exec(stmt); err != nil {
			return err
		}
	}

	tx, err := sqlDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	stmt, err := tx.Prepare(`INSERT INTO audit_events
		(event_type, ip_address, description, success, event_time, diff, impersonation, actor_type, prev_hash, entry_hash)
		VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	// Every non-pointer AuditEventRow field (IPAddress, Description, Diff, ...)
	// is always written as a concrete value by the real GORM writer, even when
	// "empty" — never left NULL. Mirroring that here (rather than omitting
	// these columns) matches the real production row shape; leaving them out
	// would produce NULLs no genuine row ever has, which scanAuditEventRow
	// correctly rejects as malformed input (that IS the design's intended
	// "garbage in, error out" behavior — just not what a throughput fixture
	// wants to exercise).
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tr := true
	prevHash := GenesisHash
	for i := range n {
		row := &AuditEventRow{
			EventType:   "secret.read",
			IPAddress:   "10.0.0.1",
			Description: fmt.Sprintf("bench event %d", i),
			Success:     &tr,
			EventTime:   base.Add(time.Duration(i) * time.Second),
			Diff:        "",
			ActorType:   "user",
		}
		entryHash := ComputeEntryHash(row, prevHash)
		if _, err := stmt.Exec(row.EventType, row.IPAddress, row.Description, *row.Success, row.EventTime, row.Diff, row.Impersonation, row.ActorType, prevHash, entryHash); err != nil {
			return fmt.Errorf("insert row %d: %w", i, err)
		}
		prevHash = entryHash
	}
	return tx.Commit()
}

func BenchmarkVerify_1MRows(b *testing.B) {
	path := buildBenchFixture1M(b)
	db, err := OpenSQLiteReadOnly(path)
	if err != nil {
		b.Fatalf("open bench fixture: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	b.ResetTimer()
	var rows int64
	for i := 0; i < b.N; i++ {
		res, err := Verify(ctx, db, Options{})
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
		if res.Verdict != VerdictValid {
			b.Fatalf("bench fixture did not verify as VALID: %s", res.Reason)
		}
		rows += res.ChainedEvents
	}
	b.StopTimer()

	if elapsed := b.Elapsed().Seconds(); elapsed > 0 {
		b.ReportMetric(float64(rows)/elapsed, "rows/sec")
	}
}
