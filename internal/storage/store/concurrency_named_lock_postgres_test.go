package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_WithNamedLock_MultiInstancePostgres_SameKeySerializes
// exercises local_named_lock.go's pg_advisory_lock branch across genuinely
// independent connections, the same shape as the sibling
// WithBootstrapLock/WithAuditCheckpointLock Postgres tests: many independent
// LocalStorage instances (own *gorm.DB, own Postgres backend connection)
// racing WithNamedLock under the SAME lockKey. Only the Postgres branch can
// say anything about cross-PROCESS exclusion — the SQLite/process-mutex path
// (local_named_lock_test.go) only proves one process's own namedLockRegistry
// works, which says nothing about the pg_advisory_lock(namedLockKey(...))
// call this test is the only coverage for.
func TestConcurrency_WithNamedLock_MultiInstancePostgres_SameKeySerializes(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	const instances = 8
	const lockKey = "concurrency-named-lock-postgres-test"

	stores := make([]*LocalStorage, instances)
	for i := range instances {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
	}

	var running atomic.Int32
	var maxConcurrent atomic.Int32
	var completed atomic.Int32

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range instances {
		wg.Add(1)
		go func(ls *LocalStorage) {
			defer wg.Done()
			<-start
			err := ls.WithNamedLock(context.Background(), lockKey, func(_ context.Context) error {
				n := running.Add(1)
				for {
					m := maxConcurrent.Load()
					if n <= m || maxConcurrent.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(75 * time.Millisecond)
				running.Add(-1)
				return nil
			})
			require.NoError(t, err)
			completed.Add(1)
		}(stores[i])
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), maxConcurrent.Load(),
		"at most one holder of a given lockKey may run fn at a time, across independent connections")
	assert.Equal(t, int32(instances), completed.Load(),
		"WithNamedLock blocks rather than skips, so every racer must eventually run fn")
}

// TestConcurrency_WithNamedLock_MultiInstancePostgres_DifferentKeysDontContend
// is the mirror check: two DIFFERENT lockKeys must NOT serialize against each
// other across independent connections either — namedLockKey hashes each
// string to its own advisory-lock key, so a holder of key "A" must never
// block a concurrent holder of key "B".
func TestConcurrency_WithNamedLock_MultiInstancePostgres_DifferentKeysDontContend(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	holderA := NewLocalStorage(pgOpen(t, dsn))
	holderB := NewLocalStorage(pgOpen(t, dsn))

	release := make(chan struct{})
	aRunning := make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		aDone <- holderA.WithNamedLock(context.Background(), "distinct-key-A", func(_ context.Context) error {
			close(aRunning)
			<-release
			return nil
		})
	}()

	select {
	case <-aRunning:
	case <-time.After(5 * time.Second):
		t.Fatal("holder A never entered its critical section")
	}

	// While A holds "distinct-key-A", B must be able to acquire "distinct-key-B"
	// immediately — no shared serialization between unrelated keys.
	bDone := make(chan error, 1)
	go func() {
		bDone <- holderB.WithNamedLock(context.Background(), "distinct-key-B", func(_ context.Context) error {
			return nil
		})
	}()

	select {
	case err := <-bDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("holder B blocked on a DIFFERENT lockKey while holder A held its own -- the two keys wrongly contended")
	}

	close(release)
	select {
	case err := <-aDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("holder A never completed")
	}
}
