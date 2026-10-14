package store

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestConcurrency_AuditChain_MultiInstancePostgres_StaysWellFormed is the
// cross-PROCESS counterpart to TestConcurrency_AuditChain_StaysWellFormed
// (concurrency_audit_chain_test.go), which only ever exercises ONE
// LocalStorage's process-local auditChainMu — on Postgres, that alone would
// pass even if LogAuditEvent's pg_advisory_xact_lock call were deleted
// outright, because every writer in that test shares the same mutex already.
//
// This test instead builds N independent LocalStorage instances, each with
// its own *gorm.DB connection (its own process-local mutex), racing
// LogAuditEvent against the SAME Postgres schema — simulating N separate
// server replicas. The only thing that can still serialize the read-head+
// insert critical section across independent mutexes is
// pg_advisory_xact_lock. If that lock is missing or broken, two replicas can
// both read the same chain head before either inserts, forking the chain
// (two rows sharing one prev_hash) — exactly the tamper-evidence failure
// ADR-029 exists to prevent, and exactly what VerifyAuditChain is written to
// detect (a corrupted chain that fails silently until someone runs it).
func TestConcurrency_AuditChain_MultiInstancePostgres_StaysWellFormed(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	const instances = 5
	const writersPerInstance = 10
	const writers = instances * writersPerInstance

	stores := make([]*LocalStorage, instances)
	for i := range instances {
		db := pgOpen(t, dsn)
		require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
		stores[i] = NewLocalStorage(db)
	}

	baseTime := time.Now().UTC()
	errs := make(chan error, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	n := 0
	for i := range instances {
		ls := stores[i]
		for range writersPerInstance {
			wg.Add(1)
			idx := n
			n++
			go func(ls *LocalStorage, idx int) {
				defer wg.Done()
				tr := true
				e := &models.AuditEvent{
					EventType:   "secret.read",
					Description: "multi-instance concurrent append " + strconv.Itoa(idx),
					Success:     &tr,
					EventTime:   baseTime.Add(time.Duration(idx) * time.Millisecond),
					ActorType:   "user",
				}
				<-start
				if err := ls.LogAuditEvent(context.Background(), e); err != nil {
					errs <- err
				}
			}(ls, idx)
		}
	}
	close(start) // release every writer, across every instance, at once
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	// Verify from a fresh connection into the same schema — an independent
	// reader, not one of the writer instances.
	verifier := NewLocalStorage(pgOpen(t, dsn))
	v, err := verifier.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain must stay valid under concurrent multi-instance appends: %s", v.Reason)
	assert.Nil(t, v.FirstBrokenID, "no event may break the chain")
	assert.Equal(t, int64(writers), v.ChainedEvents, "every writer's append must be chained exactly once")
	assert.Equal(t, int64(0), v.UnchainedEvents)

	// No fork, no orphan, no duplicate: exactly `writers` rows, each with a
	// unique entry_hash and a unique prev_hash (a fork reuses a prev_hash
	// across two rows; an orphan/duplicate shows up as a row count mismatch).
	var rows []models.AuditEvent
	require.NoError(t, verifier.DB().Order("id ASC").Find(&rows).Error)
	require.Len(t, rows, writers, "row count must equal total writers across every instance — no lost or duplicated append")
	entrySeen := make(map[string]bool, writers)
	prevSeen := make(map[string]bool, writers)
	for _, r := range rows {
		require.NotEmpty(t, r.EntryHash)
		assert.False(t, entrySeen[r.EntryHash], "duplicate entry_hash means a fork/replay across replicas")
		assert.False(t, prevSeen[r.PrevHash], "duplicate prev_hash means two replicas linked off the same head (fork)")
		entrySeen[r.EntryHash] = true
		prevSeen[r.PrevHash] = true
	}
}
