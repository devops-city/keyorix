package core

// #3350 / INV-CORE-34: every share notifier runs AFTER its share write has
// committed, so a panic from the notification insert must be recovered and logged,
// never allowed to turn a committed revoke/share into a 500.
//
// The panic is a real gorm callback on replica A's connection firing inside the real
// CreateNotification insert (not a mock), so the test drives the same path the
// faultops oracle (a) did: FuzzStorageFaultOperations REST DELETE /api/v1/shares/{id}
// with CreateNotification#1/panic.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// panicOnNotificationInsert makes every INSERT into the notifications table panic on
// replica A and returns a counter of how often it fired, so a test can fail loudly if
// the notifier was never reached (a vacuous pass). The hook runs before gorm opens its
// implicit transaction: a panic inside one would leave SQLite's write lock held and
// fail every later statement with "database is locked", which is not the shape a
// storage-layer panic has at the call site this test pins.
func (f *ctaReview) panicOnNotificationInsert() (fired func() int) {
	f.t.Helper()
	n := 0
	require.NoError(f.t, f.dbA.Callback().Create().Before("gorm:begin_transaction").Register("sharing-notify-panic",
		func(tx *gorm.DB) {
			if tx.Statement.Table == "notifications" {
				n++
				panic("injected CreateNotification panic")
			}
		}))
	return func() int { return n }
}

// liveShareCount counts the share row through gorm's soft-delete scope, so a revoked
// (soft-deleted) share is 0.
func (f *ctaReview) liveShareCount(shareID uint) int64 {
	f.t.Helper()
	var n int64
	require.NoError(f.t, f.setupDB.Model(&models.ShareRecord{}).Where("id = ?", shareID).Count(&n).Error)
	return n
}

func TestShareNotifiers_PanicAfterCommit_StillSucceeds(t *testing.T) {
	f := newCTAReviewSQLite(t)
	owner := f.user("notifypanic-owner", "project_admin")
	recipient := f.user("notifypanic-recipient", "project_viewer")
	groupMember := f.user("notifypanic-member", "project_viewer")
	secret := f.secret("notifypanic-secret", owner.ID)

	group, err := f.setup.CreateGroup(f.ctx, f.adminID, &CreateGroupRequest{Name: "notifypanic-group"})
	require.NoError(t, err)
	require.NoError(t, f.setup.AddUserToGroup(f.ctx, f.adminID, false, groupMember.ID, group.ID, 0))

	fired := f.panicOnNotificationInsert()

	t.Run("RevokeShare direct", func(t *testing.T) {
		share, err := f.setup.ShareSecret(f.ctx, &ShareSecretRequest{
			SecretID: secret.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
		})
		require.NoError(t, err)
		before := fired()

		require.NoError(t, f.coreA.RevokeShare(f.ctx, share.ID, owner.ID),
			"a committed revoke must report success when the notifier panics")
		assert.Zero(t, f.liveShareCount(share.ID), "the revoke committed")
		assert.Greater(t, fired(), before, "the notifier must actually have panicked")
	})

	t.Run("RevokeShare group", func(t *testing.T) {
		share, err := f.setup.ShareSecret(f.ctx, &ShareSecretRequest{
			SecretID: secret.ID, RecipientID: group.ID, IsGroup: true, Permission: "read", SharedBy: owner.ID,
		})
		require.NoError(t, err)
		before := fired()

		require.NoError(t, f.coreA.RevokeShare(f.ctx, share.ID, owner.ID))
		assert.Zero(t, f.liveShareCount(share.ID), "the revoke committed")
		assert.Greater(t, fired(), before, "the group fan-out must actually have panicked")
	})

	t.Run("ShareSecret direct", func(t *testing.T) {
		before := fired()
		share, err := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
			SecretID: secret.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
		})
		require.NoError(t, err, "a committed share must report success when the notifier panics")
		require.NotNil(t, share)
		assert.EqualValues(t, 1, f.liveShareCount(share.ID), "the share committed")
		assert.Greater(t, fired(), before)
	})

	t.Run("ShareSecret group", func(t *testing.T) {
		before := fired()
		share, err := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
			SecretID: secret.ID, RecipientID: group.ID, IsGroup: true, Permission: "read", SharedBy: owner.ID,
		})
		require.NoError(t, err)
		require.NotNil(t, share)
		assert.EqualValues(t, 1, f.liveShareCount(share.ID))
		assert.Greater(t, fired(), before)
	})

	t.Run("TransferSecretOwnership", func(t *testing.T) {
		newOwner := f.user("notifypanic-newowner", "project_admin")
		before := fired()
		updated, err := f.coreA.TransferSecretOwnership(f.ctx, secret.ID, newOwner.ID, owner.ID, "user")
		require.NoError(t, err, "already recovered since #3092; pinned here so the sweep stays complete")
		assert.Equal(t, newOwner.ID, updated.OwnerID)
		assert.Greater(t, fired(), before)
	})
}
