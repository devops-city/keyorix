package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newImpactPreviewCore builds a minimal in-memory core for impact-preview tests.
// Each call gets a fresh in-memory DB via ":memory:" — no DSN collision because
// each gorm.Open(":memory:") allocates its own SQLite database.
// impactPreviewTestActor is granted global admin below so #G32's independent
// peer-secret authorization check doesn't interfere with these tests, which are about
// the cascade-impact count/shape, not authorization.
const impactPreviewTestActor = uint(1)

func newImpactPreviewCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretDependency{},
		&models.AuditEvent{},
		&models.Project{},
		&models.Environment{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.MachineIdentityRole{}, &models.SecretACL{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p-impact"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env-impact"}).Error)
	role := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: impactPreviewTestActor, RoleID: role.ID, ProjectID: 0, EnvironmentID: 0}).Error)
	now := time.Date(2026, 7, 21, 9, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

// mkIPSecret inserts a live secret in project 1, environment 1.
func mkIPSecret(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: name, IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	return s.ID
}

// TestGetSecretImpactPreview_NoDependents: a secret with no downstream dependents
// returns all-zero counts and an empty (non-nil) slice.
func TestGetSecretImpactPreview_NoDependents(t *testing.T) {
	t.Parallel()
	c, db := newImpactPreviewCore(t)
	aID := mkIPSecret(t, db, "standalone")

	got, err := c.GetSecretImpactPreview(context.Background(), ActorTypeUser, impactPreviewTestActor, aID)
	require.NoError(t, err)
	assert.Equal(t, aID, got.SecretID)
	assert.Equal(t, 0, got.DirectDependents)
	assert.Equal(t, 0, got.TransitiveDependents)
	assert.Empty(t, got.AffectedSecretIDs)
	assert.Equal(t, 0, got.MaxDepth)
}

// TestGetSecretImpactPreview_TwoDirectDependents: two secrets directly depend on
// the focal secret; no transitive chain beyond depth 1.
func TestGetSecretImpactPreview_TwoDirectDependents(t *testing.T) {
	t.Parallel()
	c, db := newImpactPreviewCore(t)
	rootID := mkIPSecret(t, db, "root")
	depA := mkIPSecret(t, db, "dep-a")
	depB := mkIPSecret(t, db, "dep-b")
	addImpactEdge(t, db, depA, rootID)
	addImpactEdge(t, db, depB, rootID)

	got, err := c.GetSecretImpactPreview(context.Background(), ActorTypeUser, impactPreviewTestActor, rootID)
	require.NoError(t, err)
	assert.Equal(t, 2, got.DirectDependents)
	assert.Equal(t, 2, got.TransitiveDependents)
	assert.Equal(t, 1, got.MaxDepth)
	assert.ElementsMatch(t, []uint{depA, depB}, got.AffectedSecretIDs)
}

// TestGetSecretImpactPreview_TransitiveChain: A is depended on by B; B is
// depended on by C. Removing A affects B (depth 1) and C (depth 2).
func TestGetSecretImpactPreview_TransitiveChain(t *testing.T) {
	t.Parallel()
	c, db := newImpactPreviewCore(t)
	aID := mkIPSecret(t, db, "chain-a")
	bID := mkIPSecret(t, db, "chain-b")
	cID := mkIPSecret(t, db, "chain-c")
	// B depends on A; C depends on B.
	addImpactEdge(t, db, bID, aID)
	addImpactEdge(t, db, cID, bID)

	got, err := c.GetSecretImpactPreview(context.Background(), ActorTypeUser, impactPreviewTestActor, aID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.DirectDependents, "only B directly depends on A")
	assert.Equal(t, 2, got.TransitiveDependents, "B and C are both affected")
	assert.Equal(t, 2, got.MaxDepth)
	assert.ElementsMatch(t, []uint{bID, cID}, got.AffectedSecretIDs)
}

// TestGetSecretImpactPreview_CycleDetection: a hand-crafted cycle (rejected by
// core at add-time, but defensive) must not cause an infinite loop.
func TestGetSecretImpactPreview_CycleDetection(t *testing.T) {
	t.Parallel()
	c, db := newImpactPreviewCore(t)
	aID := mkIPSecret(t, db, "cycle-a")
	bID := mkIPSecret(t, db, "cycle-b")
	// A depends on B AND B depends on A — manually inserted cycle.
	addImpactEdge(t, db, aID, bID)
	addImpactEdge(t, db, bID, aID)

	// Must not hang or panic; returns safely.
	got, err := c.GetSecretImpactPreview(context.Background(), ActorTypeUser, impactPreviewTestActor, aID)
	require.NoError(t, err)
	// B is a direct dependent of A (depth 1); A is already in the visited set so
	// the back-edge is cut — transitive total is 1.
	assert.Equal(t, 1, got.DirectDependents)
	assert.Equal(t, 1, got.TransitiveDependents)
	assert.Equal(t, 1, got.MaxDepth)
	assert.Contains(t, got.AffectedSecretIDs, bID)
}

// TestGetSecretImpactPreview_SecretNotFound: a non-existent secretID propagates
// the storage error.
func TestGetSecretImpactPreview_SecretNotFound(t *testing.T) {
	t.Parallel()
	c, db := newImpactPreviewCore(t)
	_ = db
	_, err := c.GetSecretImpactPreview(context.Background(), ActorTypeUser, impactPreviewTestActor, 999999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestGetSecretImpactPreview_StorageError: when ListSecretDependenciesForProject
// fails the error is surfaced to the caller. Uses MockStorage (already defined in
// mock_storage_test.go in the same package) to inject the error.
func TestGetSecretImpactPreview_StorageError(t *testing.T) {
	t.Parallel()
	storageErr := errors.New("db unavailable")
	ms := new(MockStorage)
	liveSecret := &models.SecretNode{
		ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "test-secret", IsSecret: true,
	}
	ms.On("GetSecret", mock.Anything, uint(1)).Return(liveSecret, nil)
	ms.On("ListSecretDependenciesForProject", mock.Anything, uint(1)).Return(nil, storageErr)

	now := time.Date(2026, 7, 21, 9, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: ms, now: func() time.Time { return now }}

	_, err := c.GetSecretImpactPreview(context.Background(), ActorTypeUser, impactPreviewTestActor, 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, storageErr)

	ms.AssertExpectations(t)
}

// addImpactEdge inserts an edge directly into the DB: dependentID depends on dependsOnID.
// Separate from addIPEdge to avoid collision with other test helpers in the package
// (this file uses the shared "1" project/env, so the function name is prefixed).
func addImpactEdge(t *testing.T, db *gorm.DB, dependentID, dependsOnID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID:         1,
		DependentSecretID: dependentID,
		DependsOnSecretID: dependsOnID,
	}).Error)
}
