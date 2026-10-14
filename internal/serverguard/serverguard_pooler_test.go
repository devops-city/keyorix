package serverguard

// serverguard_pooler_test.go — the presence/exclusive guard behind a
// connection pooler (storage.database.pooler, docs/postgresql-poolers.md).
// Same environment as internal/storage/pgbouncer_postgres_test.go: through
// KEYORIX_TEST_PGBOUNCER_DSN when set, else straight to KEYORIX_TEST_PG_DSN
// with pooler: pgbouncer-transaction.

import (
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

func poolerGuardCfg(t *testing.T) (*config.Config, string) {
	t.Helper()
	dsn, pooler := os.Getenv("KEYORIX_TEST_PGBOUNCER_DSN"), os.Getenv("KEYORIX_TEST_PGBOUNCER_POOLER")
	if dsn == "" {
		dsn, pooler = pgTestDSN(t), "pgbouncer-transaction"
	} else if pooler == "" {
		pooler = "pgbouncer-" + os.Getenv("KEYORIX_TEST_PGBOUNCER_POOL_MODE")
	}
	cfg := &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: dsn}}}
	setTestPooler(&cfg.Storage.Database, pooler)
	return cfg, pooler
}

// TestPgBouncer_ServerGuard_PresenceExcludesAdmin: while a server holds its
// presence lock an admin command's exclusive lock must be refused, and the
// other way round; after release each succeeds. Through a transaction-mode
// pooler with session locks, both "hold" at once.
func TestPgBouncer_ServerGuard_PresenceExcludesAdmin(t *testing.T) {
	cfg, _ := poolerGuardCfg(t)
	for round := range 3 {
		p, err := AcquirePresence(cfg)
		if err != nil {
			t.Fatalf("round %d: AcquirePresence: %v", round, err)
		}
		if x, err := AcquireExclusive(cfg); err == nil {
			_ = x.Release()
			_ = p.Release()
			t.Fatalf("round %d: AcquireExclusive succeeded while a server held its presence lock", round)
		}
		if err := p.Release(); err != nil {
			t.Fatalf("release presence: %v", err)
		}
		x, err := AcquireExclusive(cfg)
		if err != nil {
			t.Fatalf("round %d: AcquireExclusive after release: %v", round, err)
		}
		if p, err := AcquirePresence(cfg); err == nil {
			_ = p.Release()
			_ = x.Release()
			t.Fatalf("round %d: AcquirePresence succeeded while an admin command held the exclusive lock", round)
		}
		if err := x.Release(); err != nil {
			t.Fatalf("release exclusive: %v", err)
		}
	}
}

// TestPgBouncer_ServerGuard_KilledHolderReleasesLock: a killed admin command's
// exclusive lock must not outlive it. Behind a transaction-mode pooler the
// client's disconnect does not end the server connection, so a session lock
// would stay held by a backend nobody owns.
func TestPgBouncer_ServerGuard_KilledHolderReleasesLock(t *testing.T) {
	cfg, pooler := poolerGuardCfg(t)
	holder := startLockHolder(t, append(os.Environ(),
		"SERVERGUARD_HELPER_MODE=postgres",
		"SERVERGUARD_HELPER_DSN="+cfg.Storage.Database.DSN,
		"SERVERGUARD_HELPER_POOLER="+pooler,
	))
	if x, err := AcquireExclusive(cfg); err == nil {
		_ = x.Release()
		_ = holder.Process.Kill()
		t.Fatal("expected AcquireExclusive to fail while the helper holds the lock")
	}
	if err := holder.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	_, _ = holder.Process.Wait()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		x, err := AcquireExclusive(cfg)
		if err == nil {
			_ = x.Release()
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected AcquireExclusive to succeed within 5s after the holder was killed, last error: %v", lastErr)
}
