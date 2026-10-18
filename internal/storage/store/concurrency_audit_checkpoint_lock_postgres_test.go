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

// TestConcurrency_WithAuditCheckpointLock_MultiInstancePostgres_ExactlyOneRunsAtOnce
// exercises local_audit_checkpoint_lock.go's pg_advisory_lock across
// genuinely independent connections, the same way
// TestConcurrency_WithSchedulerLock_MultiInstancePostgres_ExactlyOneRunsAtOnce
// exercises the sibling scheduler lock: many independent LocalStorage
// instances (own *gorm.DB, own Postgres backend connection) racing the SAME
// advisory-lock key. This is the primitive #300's "chain-walk + decide +
// create checkpoint" sequence (internal/core's WriteAuditCheckpoint) is built
// on — see that function's own doc comment for the failure mode a broken
// lock reopens (a later-committed checkpoint certifying FEWER chained events
// than an earlier one, silently reopening ADR-029's truncation-detection
// gap). This test verifies the LOCK PRIMITIVE itself: at most one holder's
// critical section may run at a time, across independent connections. The
// full checkpoint decision logic (signature/truncation checks) is exercised
// separately (SQLite) in internal/core's own WriteAuditCheckpoint tests; this
// is what actually protects it on Postgres/HA, previously unverified beyond
// a single connection.
func TestConcurrency_WithAuditCheckpointLock_MultiInstancePostgres_ExactlyOneRunsAtOnce(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	const instances = 8

	stores := make([]*LocalStorage, instances)
	for i := range instances {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
	}

	var running atomic.Int32
	var maxConcurrent atomic.Int32

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range instances {
		wg.Add(1)
		go func(ls *LocalStorage) {
			defer wg.Done()
			<-start
			err := ls.WithAuditCheckpointLock(context.Background(), func(context.Context) error {
				n := running.Add(1)
				for {
					m := maxConcurrent.Load()
					if n <= m || maxConcurrent.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(150 * time.Millisecond) // hold the lock long enough for every racer to attempt while it's held
				running.Add(-1)
				return nil
			})
			require.NoError(t, err)
		}(stores[i])
	}
	close(start) // release every instance's attempt at once
	wg.Wait()

	assert.Equal(t, int32(1), maxConcurrent.Load(),
		"at most one replica's checkpoint-write critical section may run at a time")
}
