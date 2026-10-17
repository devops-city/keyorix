package storage

// scheduler_lock_pool_postgres_test.go — regression for the scheduler-lock
// hold-and-wait (POOL-HANG-1, Detected-by: PERF-6).
//
// WithSchedulerLock used to pin one connection from the request pool for the
// advisory lock and then run the job, whose own queries need a SECOND
// connection from the same pool. With enough jobs ticking at once (about 20
// schedulers start together at boot and tick on identical intervals) every
// connection ends up pinned by a lock holder waiting for one more: the pool
// never frees, and every request queued behind it times out forever.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// TestWithSchedulerLock_Postgres_SmallPool_JobsAndReadsComplete builds the
// storage the way the server does (factory, max_open_conns: 5), fires more
// concurrent scheduler jobs than the pool has connections, each holding its
// lock briefly and then querying, alongside a stream of plain reads. Every job
// and every read must finish well inside the deadline, and the pool must still
// serve a read afterwards (the production hang never recovered).
func TestWithSchedulerLock_Postgres_SmallPool_JobsAndReadsComplete(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	const pool = 5
	cfg.Storage.Database.MaxOpenConns = pool
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	// Bounded: on the broken shape every waiter parks in database/sql until this
	// context ends, so the test fails in seconds instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const jobs = 4 * pool
	const readers = 10
	var wg sync.WaitGroup
	errs := make(chan error, jobs+readers)
	start := make(chan struct{})
	for i := range jobs {
		wg.Add(1)
		go func(key int64) {
			defer wg.Done()
			<-start
			_, err := st.WithSchedulerLock(ctx, key, func(context.Context) error {
				// Hold the lock long enough that every job's lock acquisition has
				// happened before any job asks the pool for its work connection.
				time.Sleep(100 * time.Millisecond)
				_, _, err := st.GetSystemMetadata(ctx, "schema_epoch")
				return err
			})
			errs <- err
		}(0x504f4f4c0000 + int64(i)) // distinct keys, like the real schedulers
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
		require.NoError(t, err, "a scheduler job or read did not complete: the pool is wedged")
	}

	after, cancelAfter := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelAfter()
	_, _, err = st.GetSystemMetadata(after, "schema_epoch")
	require.NoError(t, err, "the pool must still serve a read once the load stops")
}
