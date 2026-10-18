package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// transientOwnerLookup wraps LocalStorage so GetUser(failID) returns a transient
// (non-not-found) error, simulating a momentary backend failure during the owner
// lookup. All other methods/users behave normally.
func transientOwnerLookup(inner storage.Storage, failID uint) storage.Storage {
	return hooked(inner, &storeHooks{
		GetUser: func(next storage.Storage, ctx context.Context, id uint) (*models.User, error) {
			if id == failID {
				return nil, errors.New("db timeout") // transient, NOT storage.ErrUserNotFound
			}
			return next.GetUser(ctx, id)
		},
	})
}

// newOwnershipFixture builds an in-memory core with a secret owned by user 1, plus:
//   - user 2 (alice): holds secrets.write at project 1 — a valid, already-privileged
//     transfer target and a valid recovery-path actor once ALSO granted roles.assign.
//   - user 3 (bob): holds secrets.write AND roles.assign at project 1 — a valid
//     recovery-path actor as well as a valid transfer target.
//   - user 4 (carol): holds no role at all — an invalid transfer target (no access).
//   - user 5 (dave): holds ONLY secrets.read at project 1 — the exploit's target
//     profile (project_viewer/project_auditor's exact permission shape): must be
//     rejected as a transfer target despite having SOME access to the scope.
func newOwnershipFixture(t *testing.T) (*KeyorixCore, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}))
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@test.com"},
		{ID: 2, Username: "alice", Email: "a@test.com"},
		{ID: 3, Username: "bob", Email: "b@test.com"},
		{ID: 4, Username: "carol", Email: "c@test.com"}, // no role — a transfer target with no project access
		{ID: 5, Username: "dave", Email: "d@test.com"},  // secrets.read ONLY — the exploit's target profile
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 3, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)

	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "reader"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "writer"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "assigner"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 3, PermissionID: 3}).Error)

	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2, ProjectID: 1}).Error) // alice: writer
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 2, ProjectID: 1}).Error) // bob: writer
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 3, ProjectID: 1}).Error) // bob: assigner
	require.NoError(t, db.Create(&models.UserRole{UserID: 5, RoleID: 1, ProjectID: 1}).Error) // dave: reader only

	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	secret, err := st.CreateSecret(context.Background(), &models.SecretNode{
		Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	return c, secret.ID
}

func TestTransferSecretOwnership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("owner transfers to an already-privileged user", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		updated, err := c.TransferSecretOwnership(ctx, id, 2, 1, ActorTypeUser)
		require.NoError(t, err)
		assert.EqualValues(t, 2, updated.OwnerID)
		// The new owner now has owner permission; the old owner does not.
		_, err = c.CheckSecretPermission(ctx, id, 2, PermissionOwner)
		require.NoError(t, err)
		_, err = c.CheckSecretPermission(ctx, id, 1, PermissionOwner)
		require.Error(t, err)
	})

	t.Run("non-owner cannot transfer an actively-owned secret", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		_, err := c.TransferSecretOwnership(ctx, id, 3, 2, ActorTypeUser) // actor 2 is not the owner
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only the current owner")
	})

	t.Run("recovery: a departed owner's secret can be transferred by a roles.assign-holding actor", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		// Simulate the owner (user 1) leaving: delete the account.
		require.NoError(t, c.storage.DeleteUser(ctx, 1))
		// Actor 3 (bob) holds roles.assign AND the new owner (2, alice) holds secrets.write.
		updated, err := c.TransferSecretOwnership(ctx, id, 2, 3, ActorTypeUser)
		require.NoError(t, err)
		assert.EqualValues(t, 2, updated.OwnerID)
	})

	// --- Confirmed HIGH exploit regression: read→owner privilege escalation ---

	t.Run("EXPLOIT CLOSED: rejects a new owner who holds only secrets.read", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		// User 5 (dave) has ONLY secrets.read — exactly the project_viewer/
		// project_auditor permission shape the confirmed exploit targeted. The
		// current owner (1) attempting to hand off ownership to a read-only
		// colleague must be rejected: ownership grants full (delete/re-share)
		// authority, which secrets.read alone must never reach.
		_, err := c.TransferSecretOwnership(ctx, id, 5, 1, ActorTypeUser)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must already hold secrets.write")
	})

	t.Run("EXPLOIT CLOSED: a secrets.write-only actor cannot claim an orphaned secret without roles.assign", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		// Simulate the routine ADR-023/030 orphaned state directly (OwnerID==0),
		// not merely a deleted account.
		secret, err := c.storage.GetSecret(ctx, id)
		require.NoError(t, err)
		secret.OwnerID = 0
		_, err = c.storage.UpdateSecret(ctx, secret)
		require.NoError(t, err)

		// Actor 2 (alice) holds secrets.write but NOT roles.assign, and targets a
		// valid write-tier new owner (3, bob) — even so, the recovery path itself
		// must be denied: re-homing an orphaned secret is an administrative action
		// gated on roles.assign, not on secrets.write.
		_, err = c.TransferSecretOwnership(ctx, id, 3, 2, ActorTypeUser)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "roles.assign")

		// Confirm the concrete "names themselves as the new owner" variant is
		// ALSO rejected (actor 2 tries to self-elevate to owner over the same
		// orphaned secret).
		_, err = c.TransferSecretOwnership(ctx, id, 2, 2, ActorTypeUser)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "roles.assign")
	})

	t.Run("recovery succeeds for a roles.assign-holding actor even with a read-only target rejected", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		secret, err := c.storage.GetSecret(ctx, id)
		require.NoError(t, err)
		secret.OwnerID = 0
		_, err = c.storage.UpdateSecret(ctx, secret)
		require.NoError(t, err)

		// Actor 3 (bob) holds roles.assign, but targets user 5 (dave, read-only) —
		// the actor-side gate passing must not waive the new-owner ceiling.
		_, err = c.TransferSecretOwnership(ctx, id, 5, 3, ActorTypeUser)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must already hold secrets.write")

		// The same actor targeting a write-tier user succeeds.
		updated, err := c.TransferSecretOwnership(ctx, id, 2, 3, ActorTypeUser)
		require.NoError(t, err)
		assert.EqualValues(t, 2, updated.OwnerID)
	})

	t.Run("rejects a new owner with no access to the secret's scope", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		// User 4 holds no role in project 1, so it must not be handed ownership.
		_, err := c.TransferSecretOwnership(ctx, id, 4, 1, ActorTypeUser)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must already hold secrets.write")
	})

	t.Run("rejects a non-existent new owner", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		_, err := c.TransferSecretOwnership(ctx, id, 999, 1, ActorTypeUser)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "new owner")
	})

	t.Run("rejects transferring to the current owner", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		_, err := c.TransferSecretOwnership(ctx, id, 1, 1, ActorTypeUser)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already owned")
	})

	t.Run("fail-closed: a transient owner-lookup error does NOT permit takeover", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		// Wrap storage so the OWNER lookup (user 1) fails transiently (not not-found),
		// while other users resolve normally.
		base := c.storage.(*store.LocalStorage)
		c.storage = transientOwnerLookup(base, 1)
		_, err := c.TransferSecretOwnership(ctx, id, 2, 3, ActorTypeUser) // non-owner actor, owner "errors"
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only the current owner",
			"a transient lookup error must be treated as owner-present (fail closed)")
	})

	t.Run("GetUser surfaces the typed not-found sentinel", func(t *testing.T) {
		c, _ := newOwnershipFixture(t)
		_, err := c.storage.GetUser(ctx, 999)
		require.Error(t, err)
		assert.ErrorIs(t, err, coreStorage.ErrUserNotFound)
	})

	t.Run("validates ids", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		_, err := c.TransferSecretOwnership(ctx, id, 0, 1, ActorTypeUser)
		require.Error(t, err)
		_, err = c.TransferSecretOwnership(ctx, 0, 2, 1, ActorTypeUser)
		require.Error(t, err)
	})
}
