package storage

// named_lock_pool_postgres_test.go — regression for the named-lock
// hold-and-wait (NAMEDLOCK-POOL-1, same class as POOL-HANG-1).
//
// WithNamedLock used to take its advisory-lock session from the request pool
// and hold it for the whole critical section, while fn's own queries need a
// SECOND connection from that same pool. The in-process queue bounds this to
// one parked connection per key, but not across keys: with as many distinct
// keys held at once as the pool has connections (one per environment for
// CreateSecret, one per project for membership changes, ...), every connection
// is a lock session waiting for one more, and the pool never drains.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// TestWithNamedLock_Postgres_SmallPool_DistinctKeysAndReadsComplete builds the
// storage the way the server does (factory, max_open_conns: 3) and runs more
// concurrent named-lock holders on distinct keys than the pool has connections,
// each holding its lock and then querying, alongside plain reads. Every holder
// and read must finish inside the deadline, and the pool must serve a read after.
func TestWithNamedLock_Postgres_SmallPool_DistinctKeysAndReadsComplete(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	const pool = 3
	cfg.Storage.Database.MaxOpenConns = pool
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	if c, ok := st.(interface{ Close() error }); ok {
		defer func() { _ = c.Close() }()
	}

	// Bounded: on the broken shape every holder parks in database/sql until this
	// context ends, so the test fails in seconds instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const holders = 4 * pool
	const readers = 6
	var wg sync.WaitGroup
	errs := make(chan error, holders+readers)
	start := make(chan struct{})
	for i := range holders {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			<-start
			errs <- st.WithNamedLock(ctx, key, func(ctx context.Context) error {
				// Hold the lock long enough that every holder's lock acquisition
				// has happened before any of them asks the pool for a connection.
				time.Sleep(100 * time.Millisecond)
				_, _, err := st.GetSystemMetadata(ctx, "schema_epoch")
				return err
			})
		}(fmt.Sprintf("namedlock-pool-%d", i))
	}
	for range readers {
		wg.Go(func() {
			<-start
			for range 20 {
				if _, _, err := st.GetSystemMetadata(ctx, "schema_epoch"); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "a named-lock holder or read did not complete: the pool is wedged")
	}

	after, cancelAfter := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelAfter()
	_, _, err = st.GetSystemMetadata(after, "schema_epoch")
	require.NoError(t, err, "the pool must still serve a read once the load stops")
}

// TestPostgresStorage_Close_ReleasesEveryPool: Close on a factory-built
// Postgres storage closes the request pool, both lock pools and the native read
// pool. After using all four (a scheduler job, a named lock whose fn queries, a
// credential lookup), no backend is left
// connected to the database.
func TestPostgresStorage_Close_ReleasesEveryPool(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dsn := pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ran, err := st.WithSchedulerLock(ctx, 0x4e4c43, func() error {
		return st.WithNamedLock(ctx, "namedlock-pool-close", func(ctx context.Context) error {
			_, _, err := st.GetSystemMetadata(ctx, "schema_epoch")
			return err
		})
	})
	require.NoError(t, err)
	require.True(t, ran)
	// The credential lookup runs on the native read pool: a session there too.
	_, _, err = st.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, "no-such-hash")
	require.Error(t, err)

	// Counted from a connection of its own to the same database, excluding itself.
	observer := pgRawOpen(t, dsn)
	backends := func() int {
		var n int
		require.NoError(t, observer.Raw("SELECT count(*) FROM pg_stat_activity "+
			"WHERE datname = current_database() AND pid <> pg_backend_pid()").Scan(&n).Error)
		return n
	}
	require.GreaterOrEqual(t, backends(), 4, "the request pool, both lock pools and the native read pool should each have a session open")

	closer, ok := st.(interface{ Close() error })
	require.True(t, ok, "Postgres storage must be closable")
	require.NoError(t, closer.Close())
	require.Eventually(t, func() bool { return backends() == 0 }, 5*time.Second, 50*time.Millisecond,
		"Close must release every connection this storage opened")
}
