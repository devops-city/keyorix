package core

// update_user_deactivation_cleanup_tx_test.go — DEADLOCK-SHAPE-1 item 1.
//
// UpdateUser's deactivating branch wrote the user.deactivation_cleanup_failed
// audit event through c.storage from INSIDE its WithTransaction closure. On the
// SQLite backend the transaction holds the single write gate, so that audit
// write is a second writer queued behind its own caller: a self-deadlock until
// the gate's bounded wait gives up. The fix records the cleanup error inside the
// closure and writes the event after the transaction has committed.
//
// The SQLite leg opens the store the way production does (the storage factory,
// so the real in-process write gate is in place -- a bare gorm.Open has no gate
// and would not reproduce this). Assertions are on the persisted rows, not the
// return value: a swallowed audit failure returns nil at every layer.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// txClosureWorld is a write-gated SQLite store (production open path) wrapped
// in faultstorage, plus a second handle on the same file for unfaulted reads and
// seeding.
type txClosureWorld struct {
	c  *KeyorixCore
	fs *faultstorage.FaultyStorage
	db *gorm.DB
}

func newGatedSQLiteWorld(t *testing.T) *txClosureWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	cfg := &config.Config{Storage: config.StorageConfig{
		Type:     "local",
		Database: config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "gate.db")},
	}}
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	db, err := appstorage.OpenGormDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	fs := faultstorage.NewFaultyStorage(st, nil)
	return &txClosureWorld{c: NewKeyorixCore(fs), fs: fs, db: db}
}

// newPostgresWorld is the same shape over an isolated Postgres schema.
func newPostgresWorld(t *testing.T) *txClosureWorld {
	t.Helper()
	f := newCTAReview(t)
	fs := faultstorage.NewFaultyStorage(localstore.NewLocalStorage(f.dbA), nil)
	return &txClosureWorld{c: NewKeyorixCore(fs), fs: fs, db: f.dbA}
}

// txClosureBackends runs fn on write-gated SQLite (always) and Postgres (when
// KEYORIX_TEST_PG_DSN is set).
func txClosureBackends(t *testing.T, fn func(t *testing.T, w *txClosureWorld)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, newGatedSQLiteWorld(t)) })
	t.Run("postgres", func(t *testing.T) { fn(t, newPostgresWorld(t)) })
}

// seedDeactivationTarget creates an active user with one session and one PAT.
func (w *txClosureWorld) seedDeactivationTarget(t *testing.T, name string) uint {
	t.Helper()
	u := &models.User{Username: name, UsernameFolded: name, Email: name + "@example.com", IsActive: true}
	require.NoError(t, w.db.Create(u).Error)
	require.NoError(t, w.db.Create(&models.Session{UserID: u.ID, SessionToken: "sess-" + name, CreatedAt: time.Now()}).Error)
	require.NoError(t, w.db.Create(&models.PersonalAccessToken{UserID: u.ID, Name: "pat-" + name, TokenHash: "pat-" + name}).Error)
	return u.ID
}

func (w *txClosureWorld) auditCount(t *testing.T, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

// runWithDeadline fails the test (instead of hanging it) when op does not
// return: the pre-fix behaviour is a wait on the write gate.
func runWithDeadline(t *testing.T, d time.Duration, op func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		op()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("operation did not return within %s: an audit write inside an open transaction is waiting on the "+
			"write gate its own caller holds", d)
	}
}

func TestUpdateUser_DeactivationCleanupFailure_AuditedAfterCommit(t *testing.T) {
	for _, tc := range []struct {
		name, method string
	}{
		{"pat_revocation_fails", "RevokeAllPersonalAccessTokensForUser"},
		{"session_deletion_fails", "DeleteSessionsForUserExcept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
				id := w.seedDeactivationTarget(t, "victim")
				w.fs.Arm(&faultstorage.FaultSpec{
					Method: tc.method, NthCall: 1, Kind: faultstorage.KindError,
					Err: errors.New("simulated cleanup failure"),
				})

				var updated *models.User
				var err error
				runWithDeadline(t, 30*time.Second, func() {
					updated, err = w.c.UpdateUser(context.Background(), &UpdateUserRequest{ID: id, IsActive: &[]bool{false}[0]})
				})

				require.NoError(t, err, "a cleanup failure must not fail the deactivation (the conditional write already applied)")
				require.NotNil(t, updated)
				assert.True(t, w.fs.Fired(), "the armed fault must have fired, or this test proves nothing")

				var after models.User
				require.NoError(t, w.db.First(&after, id).Error)
				assert.False(t, after.IsActive, "the user must be inactive")
				assert.Equal(t, int64(1), w.auditCount(t, EventUserDeactivationCleanupFailed),
					"exactly one user.deactivation_cleanup_failed event must be recorded, after the commit")
			})
		})
	}
}

// Calibration: with no fault the deactivation records no cleanup-failed event.
func TestUpdateUser_DeactivationCleanupSuccess_NoFailureEvent(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		id := w.seedDeactivationTarget(t, "clean")
		runWithDeadline(t, 30*time.Second, func() {
			_, err := w.c.UpdateUser(context.Background(), &UpdateUserRequest{ID: id, IsActive: &[]bool{false}[0]})
			require.NoError(t, err)
		})
		assert.Zero(t, w.auditCount(t, EventUserDeactivationCleanupFailed))
		var sessions int64
		require.NoError(t, w.db.Model(&models.Session{}).Where("user_id = ?", id).Count(&sessions).Error)
		assert.Zero(t, sessions, "sessions must be deleted on deactivation")
	})
}
