// concurrency_audit_persist_loss_test.go — contended variant of the "any
// mutation path emits exactly one audit event" invariant.
//
// TestExpireSetupToken_Invariant_ExactlyOneAuditEventWithCorrectActor
// (internal/core/setup_token_expire_audit_test.go, #1622) and its siblings
// prove that invariant against a MockStorage: LogAuditEvent always succeeds
// instantly because it's a mock call, not a real write. That is real,
// necessary coverage for the CODE PATH (does the right call happen at all),
// but it structurally cannot fail on a defect that only appears under
// storage-level contention -- which is exactly what production hit: a
// 30-minute sustained-load measurement (docs/adr-100-mlockall-removal-
// deployment-swap-control.md) logged 704 "database is locked (SQLITE_BUSY)"
// audit-persist failures out of ~27k iterations at 25 concurrent HTTP
// clients. Traced (see #1727 and the #1679 follow-up round's Step 1
// report): the mutation (e.g. CreateSecret) and its audit write are
// separate SQLite transactions with no atomicity between them -- emitAudit
// (internal/core/service.go) logs and drops on failure, and the real HTTP
// call sites dispatch the audit write via goSafe (fire-and-forget goroutine,
// see server/http/handlers/secrets_crud.go), so a secret can be durably
// created while its audit record is silently lost.
//
// This test reproduces the storage-layer half of that gap directly: real
// concurrent goroutines, a real file-backed SQLite database with the same
// pragmas production uses, driving real LocalStorage.CreateSecret calls
// each immediately followed (same goroutine, no goSafe indirection -- that
// async-dispatch problem is separate and already reported) by a real
// LocalStorage.LogAuditEvent call. It asserts the count of persisted audit
// records equals the count of successful mutations exactly, with no
// tolerance. Fixed (#1727) by a jittered busy-retry loop inside
// LogAuditEvent itself (local_audit_chain.go) -- confirmed to fail this
// exact test before that fix landed (reverting the retry loop to a single
// attempt reproduces ~2-6% drops here, consistent with production's ~2.6%).
package store

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditPersistLossConcurrentDB opens a temp file-backed SQLite database with
// the same pragmas production's sqliteDSN (internal/storage/factory.go)
// applies -- _foreign_keys=1, _journal_mode=WAL, _txlock=immediate -- except
// _busy_timeout, which is deliberately far shorter than production's 10000ms.
//
// Why: production's real 10s busy_timeout DID eventually get exhausted
// under real sustained load (25 concurrent clients, 30 real minutes), but
// reproducing that exact timescale in a unit test is impractical -- a test
// suite cannot spend 30 minutes proving one invariant. A short busy_timeout
// makes the identical contention (multiple real transactions against the
// same database file, one on secret_nodes, one on audit_events, released
// simultaneously) exhaust its retry budget in milliseconds instead of
// minutes. This is a faithful, scaled-down reproduction of the same failure
// mechanism, not a synthetic one: the lock contention is real SQLite
// behavior, only the patience budget is compressed.
func auditPersistLossConcurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit-loss.db") + "?_foreign_keys=1&_busy_timeout=5&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.AuditEvent{}))
	return db
}

// TestConcurrency_AuditPersist_NeverLostOnContention is the invariant this
// issue is about: many goroutines each create a real secret and then
// immediately try to persist its "secret.created" audit event, all released
// at once against the same real database. Some mutations will themselves
// fail under contention (fine -- SQLite's own busy_timeout retry, exhausted
// or not, is not what's under test); what must NEVER happen is a mutation
// that DID succeed having no corresponding audit record.
func TestConcurrency_AuditPersist_NeverLostOnContention(t *testing.T) {
	db := auditPersistLossConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)

	const writers = 150
	var successfulMutations atomic.Int64

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start

			secret := &models.SecretNode{
				ProjectID:     1,
				EnvironmentID: 1,
				Name:          fmt.Sprintf("race-secret-%d", n),
				IsSecret:      true,
				Status:        "active",
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}
			created, err := ls.CreateSecret(ctx, secret, "")
			if err != nil {
				// The mutation itself lost the race for the write lock --
				// not what this test is about; there is nothing to audit
				// if the mutation never happened.
				return
			}
			successfulMutations.Add(1)

			tr := true
			event := &models.AuditEvent{
				EventType:    "secret.created",
				SecretNodeID: &created.ID,
				ProjectID:    &created.ProjectID,
				Description:  fmt.Sprintf("concurrent create %d", n),
				Success:      &tr,
				EventTime:    time.Now(),
				ActorType:    "user",
			}
			// Mirrors internal/core/service.go's emitAudit: the mutation
			// and its audit write are separate calls, exactly as every
			// real call site does it (through emitAudit) -- reproduced
			// here at the storage layer directly rather than through the
			// full core+HTTP-handler+goSafe stack, to isolate the
			// storage-contention question from the separate, already-
			// reported async-dispatch problem.
			if err := ls.LogAuditEvent(ctx, event); err != nil {
				t.Logf("writer %d: audit persist failed after a successful mutation: %v", n, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	var persistedAuditCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "secret.created").Count(&persistedAuditCount).Error)

	mutations := successfulMutations.Load()
	t.Logf("successful mutations: %d, persisted audit records: %d, dropped: %d",
		mutations, persistedAuditCount, mutations-persistedAuditCount)

	assert.Equal(t, mutations, persistedAuditCount,
		"every secret creation that succeeded must have exactly one persisted audit record -- "+
			"a mismatch means a mutation durably landed while its audit trail was silently lost")
}
