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

func TestSuspendResumeProjectSecrets(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
		&models.SecretAccessLog{}, &models.ShareRecord{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{},
		&models.GroupRole{}, &models.SecretACL{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	// Two projects, each with an environment (the secret list query joins environments).
	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)

	// Actor 1 is a live project member (and owner of its own secrets) in p1 — the
	// standard "full authority" caller for the happy-path assertions below.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p1.ID}).Error)

	// Project p1: three secrets (one already suspended). Project p2: one (must be untouched).
	mk := func(name string, projectID, envID, ownerID uint, status string) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: projectID, EnvironmentID: envID, Type: "password", OwnerID: ownerID, IsSecret: true,
			Status: status, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		return s.ID
	}
	mk("a", p1.ID, e1.ID, 1, SecretStatusActive)
	mk("b", p1.ID, e1.ID, 1, SecretStatusActive)
	mk("c", p1.ID, e1.ID, 1, SecretStatusSuspended) // already suspended
	otherID := mk("z", p2.ID, e2.ID, 1, SecretStatusActive)

	t.Run("suspend-all suspends only the active secrets in the project", func(t *testing.T) {
		n, err := c.SuspendProjectSecrets(ctx, p1.ID, 1, "breach")
		require.NoError(t, err)
		assert.Equal(t, 2, n, "the already-suspended one is skipped")

		// Project 2's secret is untouched.
		other, _ := c.storage.GetSecret(ctx, otherID)
		assert.Equal(t, SecretStatusActive, other.Status)
	})

	t.Run("resume-all resumes every suspended secret in the project", func(t *testing.T) {
		n, err := c.ResumeProjectSecrets(ctx, p1.ID, 1)
		require.NoError(t, err)
		assert.Equal(t, 3, n, "all three (now suspended) are resumed")

		// A second resume is a no-op.
		n, err = c.ResumeProjectSecrets(ctx, p1.ID, 1)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("validates ids", func(t *testing.T) {
		_, err := c.SuspendProjectSecrets(ctx, 0, 1, "")
		require.Error(t, err)
		_, err = c.ResumeProjectSecrets(ctx, 1, 0)
		require.Error(t, err)
	})
}

// TestSuspendResumeProjectSecrets_PerSecretAuthzReCheck is the handlers-secrets-
// expiring-F6 regression test: SuspendProjectSecrets/ResumeProjectSecrets must
// re-check EnforceSecretWritePermission for each candidate secret — exactly like
// ExtendExpiringSecrets does — instead of trusting the project-wide route gate
// alone. It builds a mixed-authority caller directly against real permission
// resolution (no mocking of CheckSecretPermission itself): actor 1 has write
// authority over "shared" via a direct share, but no ownership, share, ACL, or
// project role gives it any authority over "unshared" in the same project. A
// caller who could not PUT-update "unshared" individually must not be able to
// suspend/resume it via the bulk project-wide op either.
func TestSuspendResumeProjectSecrets_PerSecretAuthzReCheck(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
		&models.SecretAccessLog{}, &models.ShareRecord{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{},
		&models.GroupRole{}, &models.SecretACL{}, &models.User{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)

	const actorID = uint(1)
	const otherOwnerID = uint(99)

	// CreateShareRecord verifies the recipient user row exists.
	require.NoError(t, db.Create(&models.User{ID: actorID, Username: "actor", Email: "actor@example.com"}).Error)

	// All secrets are owned by someone else and actor 1 holds no role-derived
	// authority (so it never passes via ownership or the RBAC fallback). The ONLY
	// thing that distinguishes "shared" is a per-secret ACL grant of secrets.write.
	// "writeShared" carries a direct WRITE SHARE instead: since the #3001 follow-up a
	// write share elevates only update/metadata/rotate, never suspend/resume, so the
	// bulk op must leave it alone too.
	mk := func(name string) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: otherOwnerID, IsSecret: true,
			Status: SecretStatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		return s.ID
	}
	sharedID := mk("shared")
	unsharedID := mk("unshared")
	writeSharedID := mk("write-shared")

	require.NoError(t, db.Create(&models.SecretACL{
		SecretID: sharedID, UserID: actorID, Permissions: `["secrets.read","secrets.write"]`, GrantedBy: otherOwnerID,
	}).Error)
	_, err = c.storage.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: writeSharedID, OwnerID: otherOwnerID, RecipientID: actorID, IsGroup: false, Permission: "write", CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	// #2941: a share applies only to a live member of the secret's project, so the
	// actor is a member through a project-scoped grant of a role that carries no
	// permissions (no roles/role_permissions rows exist here) — membership without
	// any role-derived authority.
	require.NoError(t, db.Create(&models.UserRole{UserID: actorID, RoleID: 999, ProjectID: p.ID}).Error)

	// Sanity check: actor 1 really can write "shared" but not "unshared" or
	// "write-shared" via the single-secret path (exactly the authority the bulk op
	// must mirror).
	_, err = c.EnforceSecretWritePermission(ctx, sharedID, actorID)
	require.NoError(t, err, "precondition: actor has write authority on the ACL-granted secret")
	_, err = c.EnforceSecretWritePermission(ctx, unsharedID, actorID)
	require.Error(t, err, "precondition: actor has no write authority on the unshared secret")
	_, err = c.EnforceSecretWritePermission(ctx, writeSharedID, actorID)
	require.Error(t, err, "precondition: a write share is not suspend/resume authority")

	t.Run("suspend-all only suspends the secret the caller has write authority over", func(t *testing.T) {
		n, err := c.SuspendProjectSecrets(ctx, p.ID, actorID, "breach")
		require.NoError(t, err)
		assert.Equal(t, 1, n, "only the shared secret is suspended")

		shared, err := c.storage.GetSecret(ctx, sharedID)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusSuspended, shared.Status)

		unshared, err := c.storage.GetSecret(ctx, unsharedID)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusActive, unshared.Status, "denied secret must be left untouched, not silently suspended")

		writeShared, err := c.storage.GetSecret(ctx, writeSharedID)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusActive, writeShared.Status, "a write share must not let the recipient suspend it")
	})

	t.Run("resume-all only resumes the secret the caller has write authority over", func(t *testing.T) {
		// Suspend the others directly (bypassing the bulk op) so all start suspended.
		_, err := c.SuspendSecret(ctx, unsharedID, otherOwnerID, "setup")
		require.NoError(t, err)
		_, err = c.SuspendSecret(ctx, writeSharedID, otherOwnerID, "incident freeze")
		require.NoError(t, err)

		n, err := c.ResumeProjectSecrets(ctx, p.ID, actorID)
		require.NoError(t, err)
		assert.Equal(t, 1, n, "only the shared secret is resumed")

		shared, err := c.storage.GetSecret(ctx, sharedID)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusActive, shared.Status)

		unshared, err := c.storage.GetSecret(ctx, unsharedID)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusSuspended, unshared.Status, "denied secret must be left untouched, not silently resumed")

		writeShared, err := c.storage.GetSecret(ctx, writeSharedID)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusSuspended, writeShared.Status, "a write share must not let the recipient undo an incident freeze")
	})
}
