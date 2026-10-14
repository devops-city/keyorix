package storage

// pgbouncer_postgres_test.go — the storage layer behind a connection pooler
// (storage.database.pooler, docs/postgresql-poolers.md).
//
// Environment (pg-gated):
//
//	KEYORIX_TEST_PG_DSN                direct to PostgreSQL (creates the test
//	                                   database, reads pg_locks)
//	KEYORIX_TEST_PGBOUNCER_DSN         the same server through PgBouncer, whose
//	                                   [databases] has a "*" fallback entry
//	KEYORIX_TEST_PGBOUNCER_POOL_MODE   that PgBouncer's pool_mode: session or
//	                                   transaction
//	KEYORIX_TEST_PGBOUNCER_POOLER      optional: the storage.database.pooler value
//	                                   to run with (default: the one matching the
//	                                   pool mode)
//
// Without KEYORIX_TEST_PGBOUNCER_DSN the slice runs straight against
// KEYORIX_TEST_PG_DSN with pooler: pgbouncer-transaction, so the transaction-
// scoped lock path is exercised wherever Postgres is (CI's pg leg).
// scripts/pgbouncer-matrix.sh runs it through PgBouncer in each mode.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// pgBouncerTarget is where the slice connects and with which pooler setting.
type pgBouncerTarget struct {
	direct string // KEYORIX_TEST_PG_DSN, isolated database
	dsn    string // what the storage connects to, same database
	mode   string // "session", "transaction", or "" (direct)
	pooler string
}

func pgBouncerTargetFor(t *testing.T) pgBouncerTarget {
	t.Helper()
	direct := pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	bouncer := os.Getenv("KEYORIX_TEST_PGBOUNCER_DSN")
	if bouncer == "" {
		return pgBouncerTarget{direct: direct, dsn: direct, pooler: config.PoolerPgBouncerTransaction}
	}
	cc, err := pgx.ParseConfig(direct)
	require.NoError(t, err)
	tg := pgBouncerTarget{
		direct: direct,
		dsn:    pgdsn.PGReplaceDBName(bouncer, cc.Database),
		mode:   os.Getenv("KEYORIX_TEST_PGBOUNCER_POOL_MODE"),
		pooler: os.Getenv("KEYORIX_TEST_PGBOUNCER_POOLER"),
	}
	require.Contains(t, []string{"session", "transaction"}, tg.mode, "KEYORIX_TEST_PGBOUNCER_POOL_MODE")
	if tg.pooler == "" {
		tg.pooler = "pgbouncer-" + tg.mode
	}
	return tg
}

func (tg pgBouncerTarget) open(t *testing.T, fastAudit bool) corestorage.Storage {
	t.Helper()
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = tg.dsn
	cfg.Storage.Database.MaxOpenConns = 5
	cfg.Storage.Database.InsecureAuditSkipDurableSync = fastAudit
	setTestPooler(&cfg.Storage.Database, tg.pooler)
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "pooler %q, pool mode %q", tg.pooler, tg.mode)
	t.Cleanup(func() {
		if c, ok := st.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	})
	return st
}

// advisoryLocks counts the advisory locks held in the test database, read
// directly from PostgreSQL (not through the pooler).
func (tg pgBouncerTarget) advisoryLocks(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pgRawOpen(t, tg.direct).Raw(
		"SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
	).Scan(&n).Error)
	return n
}

// TestPgBouncer_StorageSlice runs the parts of the storage layer that depend
// on what a server connection remembers between statements: migrations (two
// replicas at once, advisory migration lock), the secret and machine
// credential read path (both pools' statement handling), the audit group
// commit in durable and fast mode (SET LOCAL must not reach another client),
// named and scheduler locks across two replicas (mutual exclusion must hold,
// not merely "no error"), and no advisory lock left behind afterwards.
func TestPgBouncer_StorageSlice(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	tg := pgBouncerTargetFor(t)
	ctx := context.Background()

	// Two replicas booting together against a fresh database.
	var replicas [2]corestorage.Storage
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Go(func() { ; replicas[i] = tg.open(t, false) })
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	a, b := replicas[0], replicas[1]

	t.Run("SecretAndCredentialReadPath", func(t *testing.T) {
		p, err := a.CreateProject(ctx, &models.Project{Name: "pgb"})
		require.NoError(t, err)
		env, err := a.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
		require.NoError(t, err)
		s, err := a.CreateSecret(ctx, &models.SecretNode{Name: "db-pass", ProjectID: p.ID, EnvironmentID: env.ID, Status: "active"})
		require.NoError(t, err)
		mi, err := a.CreateMachineIdentity(ctx, &models.MachineIdentity{
			ProjectID: p.ID, Name: "ci", IdentityType: "ci", State: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		_, err = a.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
			MachineIdentityID: mi.ID, Name: "ci", TokenHash: "pgb-hash", TokenPrefix: "kx_machine_pgb", CreatedAt: time.Now(),
		})
		require.NoError(t, err)
		// Many times, from both replicas, so statements meet server
		// connections other than the one they were first sent on.
		for range 50 {
			for _, st := range replicas {
				got, err := st.GetSecret(ctx, s.ID)
				require.NoError(t, err)
				require.Equal(t, "db-pass", got.Name)
				cred, state, err := st.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, "pgb-hash")
				require.NoError(t, err)
				require.Equal(t, mi.ID, cred.MachineIdentityID)
				require.Equal(t, "active", state)
			}
		}
	})

	t.Run("AuditCommit", func(t *testing.T) {
		fast := tg.open(t, true)
		for i, st := range []corestorage.Storage{a, fast, b} {
			var wg sync.WaitGroup
			errs := make(chan error, 20)
			for j := range 20 {
				wg.Go(func() {
					errs <- st.LogAuditEventWithAccessLog(ctx,
						&models.AuditEvent{EventType: "secret.read", Description: fmt.Sprintf("pgb %d/%d", i, j), EventTime: time.Now()},
						&models.SecretAccessLog{SecretNodeID: 1, Action: "read", AccessTime: time.Now()})
				})
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}
		}
		v, err := a.VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, "audit chain: %+v", v)

		// The fast-mode commit's SET LOCAL must have ended with its
		// transaction: no server connection may hand it to another client.
		db := pgRawOpen(t, tg.dsn)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		conns := make([]interface{ Close() error }, 0, 5)
		for range 5 {
			c, err := sqlDB.Conn(ctx)
			require.NoError(t, err)
			conns = append(conns, c)
			var v string
			require.NoError(t, c.QueryRowContext(ctx, "SHOW synchronous_commit", pgx.QueryExecModeSimpleProtocol).Scan(&v))
			require.Equal(t, "on", v, "synchronous_commit leaked to another client")
		}
		for _, c := range conns {
			_ = c.Close()
		}
	})

	t.Run("NamedLockExcludesAcrossReplicas", func(t *testing.T) {
		for round := range 3 {
			var inA, overlap atomic.Bool
			entered := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- a.WithNamedLock(ctx, "pgb-key", func(ctx context.Context) error {
					inA.Store(true)
					close(entered)
					time.Sleep(400 * time.Millisecond)
					_, _, err := a.GetSystemMetadata(ctx, "schema_epoch")
					inA.Store(false)
					return err
				})
			}()
			<-entered
			require.NoError(t, b.WithNamedLock(ctx, "pgb-key", func(ctx context.Context) error {
				overlap.Store(inA.Load())
				// A nested, different key reuses the lock session.
				return b.WithNamedLock(ctx, "pgb-key-nested", func(context.Context) error { return nil })
			}))
			require.NoError(t, <-done)
			require.False(t, overlap.Load(), "round %d: replica B entered the named lock while replica A held it", round)
		}
	})

	t.Run("SchedulerLockExcludesAcrossReplicas", func(t *testing.T) {
		for round := range 3 {
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				_, err := a.WithSchedulerLock(ctx, 0x5047420001, func() error {
					close(entered)
					<-release
					return nil
				})
				done <- err
			}()
			<-entered
			ran, err := b.WithSchedulerLock(ctx, 0x5047420001, func() error { return nil })
			close(release)
			require.NoError(t, err)
			require.NoError(t, <-done)
			require.False(t, ran, "round %d: replica B ran the scheduler job while replica A held its lock", round)
		}
		// Released: the next attempt runs.
		ran, err := b.WithSchedulerLock(ctx, 0x5047420001, func() error { return nil })
		require.NoError(t, err)
		require.True(t, ran)
	})

	t.Run("NoAdvisoryLockLeftBehind", func(t *testing.T) {
		require.Zero(t, tg.advisoryLocks(t), "advisory locks still held after every holder returned")
	})
}

// TestPgBouncer_TransactionModeUndeclared_RefusesToStart: behind a
// transaction-mode pooler, a server that was not told so refuses to start
// instead of running with session locks the pooler shares between clients.
func TestPgBouncer_TransactionModeUndeclared_RefusesToStart(t *testing.T) {
	if os.Getenv("KEYORIX_TEST_PGBOUNCER_DSN") == "" || os.Getenv("KEYORIX_TEST_PGBOUNCER_POOL_MODE") != "transaction" {
		t.Skip("needs KEYORIX_TEST_PGBOUNCER_DSN with KEYORIX_TEST_PGBOUNCER_POOL_MODE=transaction")
	}
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	tg := pgBouncerTargetFor(t)
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = tg.dsn
	st, err := NewStorageFactory().CreateStorage(cfg)
	if st != nil {
		if c, ok := st.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "storage.database.pooler: pgbouncer-transaction"), "%v", err)
}
