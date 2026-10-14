// audit_checkpoint_concurrency_test.go — regression coverage for #300: the
// audit-checkpoint write path (ADR-029) must serialize its chain-walk + decide +
// create-checkpoint sequence across every trigger (scheduler, HTTP, gRPC), so two
// overlapping WriteAuditCheckpoint calls can never commit an out-of-order chain
// (a later-committed, higher-id checkpoint certifying FEWER events than an
// earlier one).
package core

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// checkpointConcurrentDB opens a temp FILE-backed SQLite with a busy timeout,
// WAL, and _txlock=immediate. Unlike store.auditConcurrentDB
// (concurrency_audit_chain_test.go), WriteAuditCheckpoint's chain-walk + decide +
// create sequence already spans several independent, non-transactional SQL
// statements (VerifyAuditChain's read, LatestAuditCheckpoint's read,
// CreateAuditCheckpoint's insert, the high-water read/write) — there is no
// single SQL transaction whose txlock mode could ever make that multi-statement
// sequence atomic. So _txlock=immediate here only avoids an unrelated SQLite
// artifact (concurrent LogAuditEvent inserts and WriteAuditCheckpoint's own
// writes deadlocking on lock-upgrade under deferred mode); it cannot mask a
// regression of the Go-level WithAuditCheckpointLock mutex under test.
func checkpointConcurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "checkpoint.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}))
	return db
}

// TestConcurrency_AuditCheckpoint_NoOutOfOrderChain drives many goroutines, each
// appending one audit event and then immediately calling WriteAuditCheckpoint, all
// released at once to maximize the race window described in #300:
// WriteAuditCheckpoint's chain-walk (VerifyAuditChain) + read-latest-checkpoint +
// decide + create-checkpoint sequence has no transaction, row lock, or advisory
// lock, so two overlapping calls can interleave and commit a checkpoint out of
// chain-length order — the row with the higher DB id certifying FEWER chained
// events than an earlier-committed row. That silently reopens the exact
// tail-truncation-detection gap ADR-029 exists to close: LatestAuditCheckpoint's
// `id DESC` pick would be a checkpoint that never actually certified an event
// that landed in the interleaving window.
//
// With WithAuditCheckpointLock serializing the whole sequence, every checkpoint
// commit is strictly ordered against every other: this test asserts that
// ChainedEvents is monotonically non-decreasing when checkpoints are read back in
// ascending id order, and that no writer is ever spuriously refused (a correctly
// serialized writer never races its own high-water floor).
func TestConcurrency_AuditCheckpoint_NoOutOfOrderChain(t *testing.T) {
	t.Parallel()
	db := checkpointConcurrentDB(t)
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v1")

	// Seed a small baseline chain so the first checkpoint isn't over an empty trail.
	logEvents(t, c, 3)

	const writers = 40
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	base := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	for i := range writers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			ctx := context.Background()
			tr := true
			// Grow the chain by exactly one event, then immediately race to
			// checkpoint it — the exact "manual call racing another trigger"
			// pattern #300 describes, just with many concurrent triggers instead
			// of the scheduler-vs-HTTP/gRPC pairing in production.
			if err := c.storage.LogAuditEvent(ctx, &models.AuditEvent{
				EventType:   "secret.read",
				Description: fmt.Sprintf("concurrent checkpoint racer %d", n),
				Success:     &tr,
				EventTime:   base.Add(time.Duration(n) * time.Millisecond),
				ActorType:   "user",
			}); err != nil {
				errs <- fmt.Errorf("racer %d: log event: %w", n, err)
				return
			}
			if _, written, err := c.WriteAuditCheckpoint(ctx); err != nil {
				errs <- fmt.Errorf("racer %d: write checkpoint: %w", n, err)
			} else if !written {
				errs <- fmt.Errorf("racer %d: checkpoint unexpectedly not written", n)
			}
		}(i)
	}
	close(start) // release every racer at once
	wg.Wait()
	close(errs)
	for err := range errs {
		// A correctly serialized writer never sees a stale floor/prior-checkpoint
		// view of its own making, so no racer should ever be refused here. Any
		// error is either a genuine defect or (pre-fix) the race itself surfacing
		// as a spurious "below high-water mark" refusal instead of silently
		// committing an out-of-order chain — both are failures of the invariant
		// this test protects.
		assert.NoError(t, err)
	}

	// The chain-of-record invariant #300 is about: read every checkpoint back in
	// ascending id (= commit) order and assert ChainedEvents never decreases. A
	// decrease means a later-committed (higher id) checkpoint certified fewer
	// events than an earlier one — exactly the out-of-order-chain defect.
	var cps []models.AuditCheckpoint
	require.NoError(t, db.Order("id ASC").Find(&cps).Error)
	require.Len(t, cps, writers, "every racer must have committed exactly one checkpoint")
	for i := 1; i < len(cps); i++ {
		assert.GreaterOrEqualf(t, cps[i].ChainedEvents, cps[i-1].ChainedEvents,
			"checkpoint #%d (committed after #%d) certifies %d events, fewer than #%d's %d — out-of-order chain",
			cps[i].ID, cps[i-1].ID, cps[i].ChainedEvents, cps[i-1].ID, cps[i-1].ChainedEvents)
	}

	// Sanity: the final checkpoint certifies the full grown chain (baseline + every
	// racer's event), and the live chain still verifies clean and checkpointed.
	assert.Equal(t, int64(3+writers), cps[len(cps)-1].ChainedEvents)
	v, err := c.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.True(t, v.Checkpointed)
	assert.Empty(t, v.CheckpointReason)
}
