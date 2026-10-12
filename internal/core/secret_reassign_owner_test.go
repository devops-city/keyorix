package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestReassignOwnedSecrets(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	// admin (actor), leaver (departing owner), heir (new owner), reader-only (invalid
	// new-owner target — the exploit's target profile).
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "a@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "leaver", Email: "l@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "heir", Email: "h@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 4, Username: "writeronly", Email: "w@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 5, Username: "readeronly", Email: "r@t.com"}).Error)

	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)

	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 3, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)

	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "reader"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "writer"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "assigner"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 3, PermissionID: 3}).Error)

	// The heir must hold secrets.write (not merely secrets.read) at the secrets'
	// scope to become their owner — the write-tier ownership ceiling.
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 2, ProjectID: p1.ID}).Error)
	// #G10 (partial fix): the actor (admin) independently holding secrets.write at the
	// project's scope was the original G10 check. That closed the "no actor check at
	// all" gap but NOT this bug's ceiling gap (see secret_ownership.go's doc comment):
	// bulk reassignment is always the offboarding/recovery case, so it now requires
	// roles.assign — the same administrative tier transferOwnership's recovery path
	// requires per-secret.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 3, ProjectID: p1.ID}).Error)
	// writeronly: secrets.write but NOT roles.assign — used to prove the actor-side
	// gate is enforced independently of the (unrelated) new-owner ceiling.
	require.NoError(t, db.Create(&models.UserRole{UserID: 4, RoleID: 2, ProjectID: p1.ID}).Error)
	// readeronly: secrets.read only — an invalid new-owner target.
	require.NoError(t, db.Create(&models.UserRole{UserID: 5, RoleID: 1, ProjectID: p1.ID}).Error)

	mk := func(name string, projectID, envID, ownerID uint) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: projectID, EnvironmentID: envID, Type: "password", OwnerID: ownerID, IsSecret: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		return s.ID
	}

	a := mk("a", p1.ID, e1.ID, 2)         // leaver's
	b := mk("b", p1.ID, e1.ID, 2)         // leaver's
	keep := mk("keep", p1.ID, e1.ID, 1)   // admin's — untouched
	other := mk("other", p2.ID, e2.ID, 2) // leaver's but different project — untouched

	// Offboard the leaver so the owner-gone recovery path authorizes the transfer.
	require.NoError(t, c.storage.DeleteUser(ctx, 2))

	// --- Confirmed HIGH exploit regression: the sibling bulk path must route through
	// the SAME shared transferOwnership check the single-secret path does, not a
	// re-derived one (the "variant B" mistake this fix's history explicitly avoids
	// repeating: G10 added actor authorization to only this bulk call site, leaving
	// the shared primitive itself — and so this call site too — still exploitable). ---

	t.Run("EXPLOIT CLOSED: a secrets.write-only actor cannot bulk-reassign without roles.assign", func(t *testing.T) {
		// User 4 (writeronly) holds secrets.write at p1 but NOT roles.assign — exactly
		// the actor profile the confirmed exploit used. Rejected up front, loudly, not
		// silently no-op'd via the per-secret continue-on-error.
		n, err := c.ReassignOwnedSecrets(ctx, ActorTypeUser, 4, p1.ID, 2, 3)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not authorized")
		assert.Equal(t, 0, n)

		// Confirm nothing was silently reassigned despite the error.
		for _, id := range []uint{a, b} {
			s, _ := c.storage.GetSecret(ctx, id)
			assert.Equal(t, uint(2), s.OwnerID, "leaver's secrets must be untouched when the actor lacks roles.assign")
		}
	})

	t.Run("EXPLOIT CLOSED: a roles.assign actor cannot bulk-reassign onto a read-only heir", func(t *testing.T) {
		// Admin (1) holds roles.assign, but the target (5, readeronly) holds only
		// secrets.read — the same shared transferOwnership ceiling that rejects this
		// for the single-secret path applies per-secret here too. Every per-secret
		// transfer fails the ceiling check and is skipped, so the count is 0 — but
		// critically, nothing is silently promoted to owner despite the actor-level
		// check having passed.
		n, err := c.ReassignOwnedSecrets(ctx, ActorTypeUser, 1, p1.ID, 2, 5)
		require.NoError(t, err)
		assert.Equal(t, 0, n)

		for _, id := range []uint{a, b} {
			s, _ := c.storage.GetSecret(ctx, id)
			assert.Equal(t, uint(2), s.OwnerID, "leaver's secrets must be untouched when the new owner is read-only")
		}
	})

	t.Run("reassigns only the leaver's secrets in the project", func(t *testing.T) {
		n, err := c.ReassignOwnedSecrets(ctx, ActorTypeUser, 1, p1.ID, 2, 3)
		require.NoError(t, err)
		assert.Equal(t, 2, n)

		for _, id := range []uint{a, b} {
			s, _ := c.storage.GetSecret(ctx, id)
			assert.Equal(t, uint(3), s.OwnerID, "secret reassigned to heir")
		}
		ks, _ := c.storage.GetSecret(ctx, keep)
		assert.Equal(t, uint(1), ks.OwnerID, "admin's secret untouched")
		os, _ := c.storage.GetSecret(ctx, other)
		assert.Equal(t, uint(2), os.OwnerID, "other project's secret untouched")
	})

	t.Run("a second run is a no-op (nothing left owned by the leaver)", func(t *testing.T) {
		n, err := c.ReassignOwnedSecrets(ctx, ActorTypeUser, 1, p1.ID, 2, 3)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("from == to is rejected", func(t *testing.T) {
		_, err := c.ReassignOwnedSecrets(ctx, ActorTypeUser, 1, p1.ID, 3, 3)
		require.Error(t, err)
	})

	t.Run("a non-existent new owner is rejected", func(t *testing.T) {
		_, err := c.ReassignOwnedSecrets(ctx, ActorTypeUser, 1, p1.ID, 2, 999)
		require.Error(t, err)
	})

	t.Run("zero IDs are rejected", func(t *testing.T) {
		_, err := c.ReassignOwnedSecrets(ctx, ActorTypeUser, 1, 0, 2, 3)
		require.Error(t, err)
	})
}
