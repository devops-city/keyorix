// store_s21_test.go — white-box coverage sweep for s21 gaps.
//
// Targets:
//   - local_scheduler_lock.go      WithSchedulerLock — happy path (fn=nil), panic recovery
//   - local_audit_checkpoint_lock.go WithAuditCheckpointLock — happy path (fn=nil)
//   - local_sharing.go             CreateShareRecord — validation error, owner mismatch,
//     group recipient path, upsert (existing share updated)
package store

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newS21UniqueStore opens a fresh in-memory SQLite DB with a per-test unique DSN
// so parallel tests don't share the same in-memory instance.
func newS21UniqueStore(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores21_", sqlite.Open, &gorm.Config{})
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// local_scheduler_lock.go — happy path (fn returns nil, SQLite always runs)
// ---------------------------------------------------------------------------

// TestWithSchedulerLock_S21_HappyPath verifies that WithSchedulerLock on SQLite
// calls fn, reports ran=true, and returns nil when fn succeeds.
func TestWithSchedulerLock_S21_HappyPath(t *testing.T) {
	ls := newS21UniqueStore(t)
	called := false

	ran, err := ls.WithSchedulerLock(context.Background(), 1, func(context.Context) error {
		called = true
		return nil
	})

	require.NoError(t, err)
	assert.True(t, ran)
	assert.True(t, called)
}

// TestWithSchedulerLock_S21_PanicRecovery verifies that runProtected converts a
// panic inside fn into an error rather than crashing the goroutine. On SQLite
// the panic path is exercised directly via the non-Postgres branch.
func TestWithSchedulerLock_S21_PanicRecovery(t *testing.T) {
	ls := newS21UniqueStore(t)

	ran, err := ls.WithSchedulerLock(context.Background(), 2, func(context.Context) error {
		panic("simulated scheduler panic")
	})

	assert.True(t, ran, "SQLite always returns ran=true even on a panic")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panicked")
}

// TestRunProtected_S21_NilReturn verifies that runProtected returns nil when fn
// returns nil (basic success path).
func TestRunProtected_S21_NilReturn(t *testing.T) {
	err := runProtected(context.Background(), func(context.Context) error { return nil })
	require.NoError(t, err)
}

// TestRunProtected_S21_ErrorReturn verifies that runProtected propagates fn's error.
func TestRunProtected_S21_ErrorReturn(t *testing.T) {
	sentinel := errors.New("fn error")
	err := runProtected(context.Background(), func(context.Context) error { return sentinel })
	require.ErrorIs(t, err, sentinel)
}

// TestRunProtected_S21_PanicToError verifies that runProtected converts a panic
// value into a non-nil error.
func TestRunProtected_S21_PanicToError(t *testing.T) {
	err := runProtected(context.Background(), func(context.Context) error { panic("boom") })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panicked")
}

// ---------------------------------------------------------------------------
// local_audit_checkpoint_lock.go — happy path (fn returns nil, SQLite path)
// ---------------------------------------------------------------------------

// TestWithAuditCheckpointLock_S21_HappyPath verifies that WithAuditCheckpointLock
// on SQLite calls fn and returns nil when fn succeeds.
func TestWithAuditCheckpointLock_S21_HappyPath(t *testing.T) {
	ls := newS21UniqueStore(t)
	called := false

	err := ls.WithAuditCheckpointLock(context.Background(), func(context.Context) error {
		called = true
		return nil
	})

	require.NoError(t, err)
	assert.True(t, called)
}

// ---------------------------------------------------------------------------
// local_sharing.go — CreateShareRecord uncovered paths
// ---------------------------------------------------------------------------

// shareRecordModels lists all tables CreateShareRecord depends on.
var shareRecordModels = []any{
	&models.User{},
	&models.Group{},
	&models.UserGroup{},
	&models.SecretNode{},
	&models.ShareRecord{},
}

// TestCreateShareRecord_S21_ValidationError verifies that CreateShareRecord returns
// an error immediately when the share record fails validation (SecretID=0).
func TestCreateShareRecord_S21_ValidationError(t *testing.T) {
	ls := newS21UniqueStore(t, shareRecordModels...)

	_, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		// SecretID intentionally omitted (zero) — triggers validation error.
		OwnerID:     1,
		RecipientID: 2,
		Permission:  "read",
	})

	require.Error(t, err)
	// i18n key "ErrorValidation" produces "Validation error" in the default locale.
	assert.Contains(t, err.Error(), "Validation")
}

// TestCreateShareRecord_S21_SecretNotFound verifies that CreateShareRecord returns
// an error when the referenced secret does not exist.
func TestCreateShareRecord_S21_SecretNotFound(t *testing.T) {
	ls := newS21UniqueStore(t, shareRecordModels...)

	_, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID:    9999, // does not exist
		OwnerID:     1,
		RecipientID: 2,
		Permission:  "read",
	})

	require.Error(t, err)
}

// TestCreateShareRecord_S21_OwnerMismatch verifies that CreateShareRecord returns
// an error when the caller's OwnerID does not match the secret's actual owner.
func TestCreateShareRecord_S21_OwnerMismatch(t *testing.T) {
	ls := newS21UniqueStore(t, shareRecordModels...)
	ctx := context.Background()

	owner := &models.User{Username: "alice", Email: "alice@test.io"}
	require.NoError(t, ls.db.Create(owner).Error)
	other := &models.User{Username: "eve", Email: "eve@test.io"}
	require.NoError(t, ls.db.Create(other).Error)

	secret := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1,
		Name:     "owned-secret",
		IsSecret: true, Type: "text", Status: "active",
		OwnerID: owner.ID,
	}
	require.NoError(t, ls.db.Create(secret).Error)

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     other.ID, // mismatch — other is not the owner
		RecipientID: other.ID,
		Permission:  "read",
	})

	require.Error(t, err)
	// i18n key "ErrorNotAuthorized" is returned as-is in the default locale.
	assert.Error(t, err)
}

// TestCreateShareRecord_S21_GroupRecipientNotFound verifies that CreateShareRecord
// returns an error when IsGroup=true and the referenced group does not exist.
func TestCreateShareRecord_S21_GroupRecipientNotFound(t *testing.T) {
	ls := newS21UniqueStore(t, shareRecordModels...)
	ctx := context.Background()

	owner := &models.User{Username: "carol", Email: "carol@test.io"}
	require.NoError(t, ls.db.Create(owner).Error)

	secret := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1,
		Name:     "group-secret",
		IsSecret: true, Type: "text", Status: "active",
		OwnerID: owner.ID,
	}
	require.NoError(t, ls.db.Create(secret).Error)

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: 9999, // no such group
		IsGroup:     true,
		Permission:  "read",
	})

	require.Error(t, err)
}

// TestCreateShareRecord_S21_GroupRecipientSuccess verifies the happy path for a
// group share: when IsGroup=true and the group exists, the share is created.
func TestCreateShareRecord_S21_GroupRecipientSuccess(t *testing.T) {
	ls := newS21UniqueStore(t, shareRecordModels...)
	ctx := context.Background()

	owner := &models.User{Username: "dan", Email: "dan@test.io"}
	require.NoError(t, ls.db.Create(owner).Error)

	secret := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1,
		Name:     "grp-secret",
		IsSecret: true, Type: "text", Status: "active",
		OwnerID: owner.ID,
	}
	require.NoError(t, ls.db.Create(secret).Error)

	group := &models.Group{Name: "devs", Description: "developers"}
	require.NoError(t, ls.db.Create(group).Error)

	share, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: group.ID,
		IsGroup:     true,
		Permission:  "read",
	})

	require.NoError(t, err)
	require.NotNil(t, share)
	assert.NotZero(t, share.ID)
	assert.True(t, share.IsGroup)
}

// TestCreateShareRecord_S21_UpsertUpdatesExistingShare verifies the upsert path:
// when a share record for the same (secret, recipient, is_group) already exists,
// CreateShareRecord updates its permission rather than inserting a new row.
func TestCreateShareRecord_S21_UpsertUpdatesExistingShare(t *testing.T) {
	ls := newS21UniqueStore(t, shareRecordModels...)
	ctx := context.Background()

	owner := &models.User{Username: "frank", Email: "frank@test.io"}
	require.NoError(t, ls.db.Create(owner).Error)
	recipient := &models.User{Username: "grace", Email: "grace@test.io"}
	require.NoError(t, ls.db.Create(recipient).Error)

	secret := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1,
		Name:     "upsert-secret",
		IsSecret: true, Type: "text", Status: "active",
		OwnerID: owner.ID,
	}
	require.NoError(t, ls.db.Create(secret).Error)

	// First grant: "read".
	first, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: recipient.ID,
		IsGroup:     false,
		Permission:  "read",
	})
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Equal(t, "read", first.Permission)

	// Second grant for the same tuple: permission upgraded to "write".
	second, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: recipient.ID,
		IsGroup:     false,
		Permission:  "write",
	})
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, "write", second.Permission)
	assert.Equal(t, first.ID, second.ID, "upsert must reuse the existing row, not insert a new one")

	// Confirm only one active row exists.
	var count int64
	require.NoError(t, ls.db.Model(&models.ShareRecord{}).
		Where("secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL",
			secret.ID, recipient.ID, false).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}
