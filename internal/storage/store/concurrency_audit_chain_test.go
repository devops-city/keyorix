package store

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditConcurrentDB opens a temp FILE-backed SQLite with a busy timeout and WAL, but
// deliberately WITHOUT _txlock=immediate. Each append's "read chain head + insert" is a
// read followed by a write inside one transaction; with deferred locking two appends can
// both read the same head before either inserts, which forks the chain (two events
// sharing one prev_hash). That fork is exactly what LogAuditEvent's auditChainMu prevents,
// so this DSN keeps the mutex load-bearing — an immediate write lock would serialize the
// transactions itself and mask a regression that removed the mutex.
func auditConcurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db") + "?_busy_timeout=10000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	return db
}

// TestConcurrency_AuditChain_StaysWellFormed is the tamper-evidence invariant under load
// (ADR-029): no matter how many goroutines append audit events at once, the hash chain
// must remain a single unbroken line — every prev_hash links to the preceding entry_hash
// and every entry_hash recomputes from its row. LogAuditEvent serializes the
// read-head+insert critical section (process mutex + a Postgres advisory lock); if that
// serialization regressed to check-then-act, concurrent appends would read the same head
// and fork the chain, which VerifyAuditChain would then report as broken. This drives many
// writers at once and asserts the chain verifies clean with exactly N chained events.
func TestConcurrency_AuditChain_StaysWellFormed(t *testing.T) {
	db := auditConcurrentDB(t)
	ls := NewLocalStorage(db)
	base := time.Now().UTC()

	const writers = 50

	errs := make(chan error, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tr := true
			e := &models.AuditEvent{
				EventType:   "secret.read",
				Description: "concurrent append " + strconv.Itoa(n),
				Success:     &tr,
				// Distinct timestamps so events are semantically distinct; chain order
				// is by insert id, not event_time, so the spread is irrelevant to linkage.
				EventTime: base.Add(time.Duration(n) * time.Millisecond),
				ActorType: "user",
			}
			<-start
			if err := ls.LogAuditEvent(context.Background(), e); err != nil {
				errs <- err
			}
		}(i)
	}
	close(start) // release all writers at once
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	// The chain must verify as a single unbroken line of exactly N events.
	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain must stay valid under concurrent appends")
	assert.Nil(t, v.FirstBrokenID, "no event may break the chain")
	assert.Equal(t, int64(writers), v.ChainedEvents, "every concurrent append must be chained exactly once")
	assert.Equal(t, int64(0), v.UnchainedEvents)

	// No fork: every persisted entry_hash and prev_hash is unique (a fork would reuse a
	// prev_hash across two rows), and the row count equals the writer count.
	var rows []models.AuditEvent
	require.NoError(t, db.Order("id ASC").Find(&rows).Error)
	require.Len(t, rows, writers)
	entrySeen := make(map[string]bool, writers)
	prevSeen := make(map[string]bool, writers)
	for _, r := range rows {
		require.NotEmpty(t, r.EntryHash)
		assert.False(t, entrySeen[r.EntryHash], "duplicate entry_hash means a fork/replay")
		assert.False(t, prevSeen[r.PrevHash], "duplicate prev_hash means two events linked off the same head (fork)")
		entrySeen[r.EntryHash] = true
		prevSeen[r.PrevHash] = true
	}
}
