package serverguard

// serverguard_pooler_timeout_test.go — the transaction-scoped presence lock
// (storage.database.pooler: pgbouncer-transaction) must survive server-side
// timeouts set on the database. The lock lives in a transaction that is idle
// for the server's whole lifetime; PostgreSQL 17's transaction_timeout (and
// idle_in_transaction_session_timeout on every version) would end it and drop
// the lock while the server still relies on it, letting an admin command run
// beside a live server.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// timeoutDBCfg creates an isolated database whose timeouts are set at database
// level and returns a transaction-pooling config for it. transaction_timeout
// is dropped from settings on a server older than PostgreSQL 17.
func timeoutDBCfg(t *testing.T, settings map[string]string) *config.Config {
	t.Helper()
	base := pgTestDSN(t)
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	ctx := context.Background()
	var vnum string
	if err := admin.QueryRowContext(ctx, "SHOW server_version_num").Scan(&vnum); err != nil {
		t.Fatal(err)
	}
	t.Logf("server_version_num %s", vnum)
	if n, _ := strconv.Atoi(vnum); n < 170000 {
		// No transaction_timeout before PostgreSQL 17; the version-gated
		// statement choice is covered by config.TestPinnedLockTxSetupSQL.
		delete(settings, "transaction_timeout")
	}
	name := fmt.Sprintf("sg_timeout_%d_%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)") })
	for k, v := range settings {
		if _, err := admin.ExecContext(ctx, fmt.Sprintf("ALTER DATABASE %s SET %s = '%s'", name, k, v)); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: pdsnFor(base, name)}}}
	setTestPooler(&cfg.Storage.Database, config.PoolerPgBouncerTransaction)
	return cfg
}

func pdsnFor(base, db string) string { return pgdsn.PGReplaceDBName(base, db) }

// TestPgBouncer_ServerGuard_PresenceSurvivesServerTimeouts: with
// transaction_timeout and idle_in_transaction_session_timeout set to 300ms on
// the database, the presence lock is still held after 1.5s, so an admin
// command is still refused. The assertion is the effect (the exclusive lock is
// refused), not a return value: a dropped lock reports no error anywhere.
func TestPgBouncer_ServerGuard_PresenceSurvivesServerTimeouts(t *testing.T) {
	cfg := timeoutDBCfg(t, map[string]string{
		"transaction_timeout":                 "300ms",
		"idle_in_transaction_session_timeout": "300ms",
	})
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	defer p.Release() //nolint:errcheck
	time.Sleep(1500 * time.Millisecond)
	if x, err := AcquireExclusive(cfg); err == nil {
		_ = x.Release()
		t.Fatal("AcquireExclusive succeeded 1.5s after AcquirePresence: a database-level transaction timeout dropped the presence lock")
	}
}
