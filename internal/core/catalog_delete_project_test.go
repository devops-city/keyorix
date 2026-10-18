package core_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- #313 / #528 structural regression --------------------------------------------
//
// DeleteProject's non-force guard (count-then-reject) must never run as two separate
// top-level storage calls with core-layer control flow in between — a secret created
// in that window would silently get swept into the cascade despite the caller
// expecting the delete to be rejected. #313 originally closed this by running the
// guard and the cascade inside one storage.WithTransaction call. #528 replaced that
// with DeleteProjectIfEmpty, a single atomic storage.Storage primitive doing the same
// guard+cascade in ONE call — necessary because WithTransaction is a real transaction
// only for LocalStorage; RemoteStorage.WithTransaction is a no-op passthrough over
// HTTP, so the original two-call pair reopened this exact TOCTOU window across a full
// network round trip under storage.type: remote. See the storage.Storage interface's
// DeleteProjectIfEmpty doc comment for the full rationale.
//
// deleteProjectSpy asserts that structurally: it implements ONLY DeleteProject and
// DeleteProjectIfEmpty (every other storage.Storage method is left on a nil-embedded
// interface, so calling one panics on a nil pointer dereference) — so if DeleteProject
// ever again decomposes the guard+cascade into separate ListSecrets/DeleteProject
// calls (reopening the #313/#528 TOCTOU under storage.type: remote), this test fails
// loudly instead of silently passing.

type deleteProjectSpy struct {
	storage.Storage     // left nil: any method besides the ones below panics if reached
	blockingSecretCount int
	deleteIfEmptyErr    error
	deleteErr           error
	callOrder           []string
}

func (s *deleteProjectSpy) DeleteProjectIfEmpty(_ context.Context, id uint) (int, error) {
	s.callOrder = append(s.callOrder, "DeleteProjectIfEmpty")
	if id != 7 {
		return 0, fmt.Errorf("unexpected project id %d", id)
	}
	return s.blockingSecretCount, s.deleteIfEmptyErr
}

func (s *deleteProjectSpy) DeleteProject(_ context.Context, id uint) error {
	s.callOrder = append(s.callOrder, "DeleteProject")
	if id != 7 {
		return fmt.Errorf("unexpected project id %d", id)
	}
	return s.deleteErr
}

// WithTransaction runs fn on the spy itself: DeleteProject wraps the cascade and its
// #3433 machine-identity step in one transaction. The guard+cascade is still ONE call
// inside it, which is what callOrder pins.
func (s *deleteProjectSpy) WithTransaction(_ context.Context, fn func(storage.Storage) error) error {
	return fn(s)
}

// SuspendMachineIdentitiesForDeletedProject records the #3433 step: it must follow a
// cascade that deleted, and never a guard that refused.
func (s *deleteProjectSpy) SuspendMachineIdentitiesForDeletedProject(_ context.Context, id uint) ([]*models.MachineIdentity, error) {
	s.callOrder = append(s.callOrder, "SuspendMachineIdentitiesForDeletedProject")
	if id != 7 {
		return nil, fmt.Errorf("unexpected project id %d", id)
	}
	return nil, nil
}

// ListDynamicSecretConfigs backs DeleteProject's #369 post-commit dynamic-secrets
// cascade (see revokeProjectDynamicSecretLeases's doc comment), deliberately after the
// delete itself. Returns none: these tests aren't exercising the dynamic-secrets
// cascade itself (see TestDeleteProject_RealStorage_DisablesDynamicSecretConfigsAndRevokesLeases).
func (s *deleteProjectSpy) ListDynamicSecretConfigs(_ context.Context, _, _ uint) ([]*models.DynamicSecretConfig, error) {
	return nil, nil
}

func TestDeleteProject_EmptyProjectDeletesAtomically(t *testing.T) {
	t.Parallel()
	spy := &deleteProjectSpy{blockingSecretCount: 0}
	c := core.NewKeyorixCore(spy)

	require.NoError(t, c.DeleteProject(context.Background(), 0, 7, false))
	assert.Equal(t, []string{"DeleteProjectIfEmpty", "SuspendMachineIdentitiesForDeletedProject"}, spy.callOrder,
		"force=false must call the atomic guard+cascade primitive, not a separate ListSecrets+DeleteProject pair, then the #3433 machine-identity step")
}

func TestDeleteProject_RejectsWhenSecretsExist(t *testing.T) {
	t.Parallel()
	spy := &deleteProjectSpy{blockingSecretCount: 3}
	c := core.NewKeyorixCore(spy)

	err := c.DeleteProject(context.Background(), 0, 7, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "3 secret(s)")
	assert.Equal(t, []string{"DeleteProjectIfEmpty"}, spy.callOrder,
		"a rejected guard must not additionally call the unconditional cascade")
}

func TestDeleteProject_ForceSkipsGuardEntirely(t *testing.T) {
	t.Parallel()
	// blockingSecretCount would reject if the guard ran; deleteIfEmptyErr would fail
	// the test if DeleteProjectIfEmpty were reached at all.
	spy := &deleteProjectSpy{blockingSecretCount: 99, deleteIfEmptyErr: fmt.Errorf("must not be called")}
	c := core.NewKeyorixCore(spy)

	require.NoError(t, c.DeleteProject(context.Background(), 0, 7, true))
	assert.Equal(t, []string{"DeleteProject", "SuspendMachineIdentitiesForDeletedProject"}, spy.callOrder, "force=true must skip the guard entirely")
}

// --- #313 real-storage integration (sequential, deterministic) -------------------
//
// A live goroutine race against the guard's exact microsecond-wide DB window isn't
// reproducible deterministically here: SQLite's deferred transactions don't take a
// write lock until their first write statement, so an external writer can still slip
// a statement in between the guard's read and the cascade's write — the same
// inherent limit acknowledged by the finding itself ("just fix the ordering", not
// eliminate every possible interleaving; the backlog separately calibrates the
// residual risk as no worse than an explicit force=true). Racing a *second*
// independent write path (e.g. CreateSecret) additionally entangles this test with
// that path's own liveness-check timing, which is unrelated to DeleteProject. The
// structural tests above are the precise regression for the actual fix (guard and
// cascade co-located in one transaction); these round it out against real storage.

func TestDeleteProject_RealStorage_RejectsWhenSecretsExist(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.AuditEvent{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, IsSecret: true}).Error)

	err = c.DeleteProject(ctx, 0, 1, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 secret(s)")

	var p models.Project
	require.NoError(t, db.First(&p, 1).Error, "the project must remain live after a rejected delete")
}

func TestDeleteProject_RealStorage_EmptyProjectSucceeds(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.AuditEvent{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)

	require.NoError(t, c.DeleteProject(ctx, 0, 1, false))

	var p models.Project
	err = db.First(&p, 1).Error
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound, "the project must be (soft-)deleted")
}

func TestDeleteProject_RealStorage_ForceCascadesOverSecrets(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.AuditEvent{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, IsSecret: true}).Error)

	require.NoError(t, c.DeleteProject(ctx, 0, 1, true))

	var liveSecrets int64
	require.NoError(t, db.Model(&models.SecretNode{}).Where("project_id = ? AND deleted_at IS NULL", 1).Count(&liveSecrets).Error)
	assert.Zero(t, liveSecrets, "force=true must cascade-delete the secret along with the project")
}

// TestDeleteProject_RealStorage_DisablesDynamicSecretConfigsAndRevokesLeases exercises
// the #369 fix end to end: deleting a project must not leave its dynamic-secret
// configs live (able to mint new credentials) or their outstanding leases active
// (real target credentials that should stop working) behind an orphaned/soft-deleted
// project.
func TestDeleteProject_RealStorage_DisablesDynamicSecretConfigsAndRevokesLeases(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.AuditEvent{}, &models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	fake := &dynamictest.FakeEngine{NativeExpiry: true}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetAuthEncryptor(enc)
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env"}).Error)
	// CreateDynamicSecretConfig requires admin authority on the project (#162) — seed
	// a global admin role and grant it to the requesting actor.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	const actorID = uint(42)
	require.NoError(t, db.Create(&models.UserRole{UserID: actorID, RoleID: 1}).Error)

	cfg, err := c.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name:              "app-db",
		ProjectID:         1,
		EnvironmentID:     1,
		BackendType:       "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600,
		CreatedBy:         "alice",
		ActorID:           actorID,
	})
	require.NoError(t, err)

	lease, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	require.NoError(t, c.DeleteProject(ctx, 0, 1, false))

	disabled, err := c.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.True(t, disabled.Disabled, "the config must be disabled so it can no longer mint new credentials")

	var leaseAfter models.DynamicSecretLease
	require.NoError(t, db.Where("lease_id = ?", lease.LeaseID).First(&leaseAfter).Error)
	assert.Equal(t, "revoked", leaseAfter.Status, "the outstanding lease must be revoked, not left active")
	assert.Contains(t, fake.Revoked, leaseAfter.RoleName, "the real backend credential must have been revoked too")

	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	assert.Error(t, err, "issuing against a disabled config must be refused")
}
