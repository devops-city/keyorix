package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// bulkRotateDBRaw sets up an isolated in-memory SQLite DB and returns the core and the
// raw LocalStorage for tests that need more granular control (cross-project, folder-node,
// etc.). Each call gets its own database via a unique DSN.
func bulkRotateDBRaw(t *testing.T) (*KeyorixCore, *store.LocalStorage) {
	t.Helper()
	dsn := fmt.Sprintf("file:bulk_rotate_raw_%d?mode=memory&cache=private", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretVersion{},
		&models.AuditEvent{}, &models.SecretAccessLog{},
	))
	ls := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: ls, now: time.Now}
	return c, ls
}

// bulkRotateDB sets up an in-memory SQLite DB with the tables needed for bulk rotation
// tests and returns a core + a helper to create test secrets.
func bulkRotateDB(t *testing.T) (*KeyorixCore, func(name, classification string, autoRotate bool) uint) {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "bulk_rotate_shared_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretVersion{},
		&models.AuditEvent{}, &models.SecretAccessLog{},
	))

	ctx := context.Background()
	ls := store.NewLocalStorage(db)

	p, err := ls.CreateProject(ctx, &models.Project{Name: "bulk-rotate-proj"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(t, err)

	c := &KeyorixCore{storage: ls, now: time.Now}

	mk := func(name, classification string, autoRotate bool) uint {
		s, err := ls.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: p.ID, EnvironmentID: env.ID,
			Type: "password", IsSecret: true, Status: "active",
			Classification: classification,
			AutoRotate:     autoRotate,
			OwnerID:        1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		// Seed an initial version so RotateSecret can get the latest version.
		_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{
			SecretNodeID: s.ID, VersionNumber: 1,
			EncryptedValue:     []byte("initial-value"),
			EncryptionMetadata: []byte("{}"),
			CreatedAt:          time.Now(),
		})
		require.NoError(t, err)
		return s.ID
	}

	return c, mk
}

func TestBulkRotateSecrets_ByIDs(t *testing.T) {
	t.Parallel()
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	id1 := mk("secret-alpha", "", true)
	id2 := mk("secret-beta", "", true)
	id3 := mk("secret-gamma", "", true)

	// Determine project ID from one of the secrets.
	s, err := c.storage.GetSecret(ctx, id1)
	require.NoError(t, err)
	projectID := s.ProjectID

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		SecretIDs: []uint{id1, id2, id3},
		RotatedBy: "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, result.Total)
	assert.Len(t, result.Triggered, 3)
	assert.Empty(t, result.Failed)
	assert.Contains(t, result.Triggered, id1)
	assert.Contains(t, result.Triggered, id2)
	assert.Contains(t, result.Triggered, id3)

	// Each secret now has version 2.
	for _, id := range []uint{id1, id2, id3} {
		latest, err := c.storage.GetLatestSecretVersion(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, 2, latest.VersionNumber, "secret %d should have been rotated to version 2", id)
	}
}

func TestBulkRotateSecrets_ByProject(t *testing.T) {
	t.Parallel()
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	id1 := mk("proj-secret-a", "", true)
	id2 := mk("proj-secret-b", "", true)

	s, err := c.storage.GetSecret(ctx, id1)
	require.NoError(t, err)
	projectID := s.ProjectID

	// No SecretIDs — rotate all in the project.
	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		RotatedBy: "ops",
	})
	require.NoError(t, err)
	// Total includes all secrets in the project from this and the parent test helpers
	// (each helper call creates its own DB, so total here is exactly 2).
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Triggered, 2)
	assert.Empty(t, result.Failed)
	assert.Contains(t, result.Triggered, id1)
	assert.Contains(t, result.Triggered, id2)
}

func TestBulkRotateSecrets_ByClassification(t *testing.T) {
	t.Parallel()
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	confID := mk("conf-secret", "confidential", true)
	_ = mk("public-secret", "public", true)

	s, err := c.storage.GetSecret(ctx, confID)
	require.NoError(t, err)
	projectID := s.ProjectID

	// Filter by classification — only "confidential" should be rotated.
	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID:      projectID,
		Classification: "confidential",
		RotatedBy:      "incident-response",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total, "only the confidential secret matches the filter")
	assert.Len(t, result.Triggered, 1)
	assert.Equal(t, confID, result.Triggered[0])
	assert.Empty(t, result.Failed)

	// The public secret is still on version 1.
}

func TestBulkRotateSecrets_SkipsNoConfig(t *testing.T) {
	t.Parallel()
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	withRotation := mk("has-rotation", "", true)
	noRotation := mk("no-rotation", "", false)

	s, err := c.storage.GetSecret(ctx, withRotation)
	require.NoError(t, err)
	projectID := s.ProjectID

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		RotatedBy: "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Triggered, 1)
	assert.Equal(t, withRotation, result.Triggered[0])
	require.Len(t, result.Failed, 1)
	assert.Equal(t, noRotation, result.Failed[0].SecretID)
	assert.Contains(t, result.Failed[0].Error, "no rotation config")

	// The no-rotation secret is still on version 1 — not an error, just a skip.
	latest, err := c.storage.GetLatestSecretVersion(ctx, noRotation)
	require.NoError(t, err)
	assert.Equal(t, 1, latest.VersionNumber)
}

func TestBulkRotateSecrets_PartialFailure(t *testing.T) {
	t.Parallel()
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	valid1 := mk("valid-one", "", true)
	valid2 := mk("valid-two", "", true)
	noconf := mk("no-conf", "", false)

	s, err := c.storage.GetSecret(ctx, valid1)
	require.NoError(t, err)
	projectID := s.ProjectID

	// Mix of valid IDs + an ID that doesn't exist + one with no rotation config.
	const missingID = uint(99999)
	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		SecretIDs: []uint{valid1, valid2, noconf, missingID},
		RotatedBy: "responder",
	})
	require.NoError(t, err)

	assert.Equal(t, 4, result.Total)
	// 2 succeeded, 2 failed (no-conf + missing).
	assert.Len(t, result.Triggered, 2)
	assert.Len(t, result.Failed, 2)

	failedIDs := make(map[uint]string, len(result.Failed))
	for _, f := range result.Failed {
		failedIDs[f.SecretID] = f.Error
	}
	assert.Contains(t, failedIDs[noconf], "no rotation config")
	assert.Contains(t, failedIDs[missingID], "not found")

	// valid1 and valid2 were rotated to version 2.
	for _, id := range []uint{valid1, valid2} {
		latest, err := c.storage.GetLatestSecretVersion(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, 2, latest.VersionNumber)
	}
	// no-conf stays at version 1.
	latest, err := c.storage.GetLatestSecretVersion(ctx, noconf)
	require.NoError(t, err)
	assert.Equal(t, 1, latest.VersionNumber)
}

// TestBulkRotateSecrets_MissingProjectID covers the ProjectID == 0 early-return (line 71-73).
func TestBulkRotateSecrets_MissingProjectID(t *testing.T) {
	t.Parallel()
	c, _ := bulkRotateDB(t)
	ctx := context.Background()

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: 0,
		RotatedBy: "ops",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
	assert.Nil(t, result)
}

// TestBulkRotateSecrets_DefaultRotatedBy covers the default RotatedBy assignment (line 74-76).
func TestBulkRotateSecrets_DefaultRotatedBy(t *testing.T) {
	t.Parallel()
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	id1 := mk("default-rotatedby-secret", "", true)
	s, err := c.storage.GetSecret(ctx, id1)
	require.NoError(t, err)

	// RotatedBy is intentionally empty — the code should fill it in with "system:bulk-rotate".
	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: s.ProjectID,
		SecretIDs: []uint{id1},
		RotatedBy: "",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Len(t, result.Triggered, 1)
	assert.Empty(t, result.Failed)
}

// TestBulkRotateSecrets_GetSecretsByIDsError covers the storage error on GetSecretsByIDs
// (line 86-88) using a mock storage.
func TestBulkRotateSecrets_GetSecretsByIDsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}

	storageErr := errors.New("db unavailable")
	ms.On("GetSecretsByIDs", ctx, []uint{1, 2}).Return(nil, storageErr)

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: 1,
		SecretIDs: []uint{1, 2},
		RotatedBy: "ops",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load secrets")
	assert.Nil(t, result)
	ms.AssertExpectations(t)
}

// TestBulkRotateSecrets_CrossProjectGuard covers the case where a requested secret belongs
// to a different project than the one in the request (line 107-113).
func TestBulkRotateSecrets_CrossProjectGuard(t *testing.T) {
	t.Parallel()
	c, ls := bulkRotateDBRaw(t)
	ctx := context.Background()

	p1, err := ls.CreateProject(ctx, &models.Project{Name: "project-one"})
	require.NoError(t, err)
	p2, err := ls.CreateProject(ctx, &models.Project{Name: "project-two"})
	require.NoError(t, err)

	env1, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p1.ID})
	require.NoError(t, err)
	env2, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p2.ID})
	require.NoError(t, err)

	mkSecret := func(name string, projectID, envID uint) uint {
		s, serr := ls.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: projectID, EnvironmentID: envID,
			Type: "password", IsSecret: true, Status: "active",
			AutoRotate: true, OwnerID: 1,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, serr)
		_, serr = ls.CreateSecretVersion(ctx, &models.SecretVersion{
			SecretNodeID: s.ID, VersionNumber: 1,
			EncryptedValue: []byte("v1"), EncryptionMetadata: []byte("{}"),
			CreatedAt: time.Now(),
		})
		require.NoError(t, serr)
		return s.ID
	}

	id1 := mkSecret("in-project-one", p1.ID, env1.ID)
	id2 := mkSecret("SENSITIVE-OTHER-TENANT-NAME", p2.ID, env2.ID) // belongs to p2, not p1

	// Request both IDs but scoped to project 1 — id2 must be rejected.
	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: p1.ID,
		SecretIDs: []uint{id1, id2},
		RotatedBy: "security-team",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Triggered, 1)
	assert.Equal(t, id1, result.Triggered[0])
	require.Len(t, result.Failed, 1)
	assert.Equal(t, id2, result.Failed[0].SecretID)
	// #G31: a cross-tenant secret is refused identically to a nonexistent one —
	// no name, no distinguishing "does not belong to this project" message that
	// would confirm something exists at that ID.
	assert.Empty(t, result.Failed[0].Name, "the other tenant's secret name must never be disclosed")
	assert.Equal(t, "secret not found", result.Failed[0].Error)
}

// TestBulkRotateSecrets_FolderNodeSkipped covers the IsSecret == false guard (line 115-121).
func TestBulkRotateSecrets_FolderNodeSkipped(t *testing.T) {
	t.Parallel()
	c, ls := bulkRotateDBRaw(t)
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "folder-test-proj"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(t, err)

	// Create a folder node (IsSecret: false).
	folder, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "my-folder", ProjectID: p.ID, EnvironmentID: env.ID,
		Type: "folder", IsSecret: false, Status: "active",
		AutoRotate: true, OwnerID: 1,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Create a real secret in the same project.
	real, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "real-secret", ProjectID: p.ID, EnvironmentID: env.ID,
		Type: "password", IsSecret: true, Status: "active",
		AutoRotate: true, OwnerID: 1,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: real.ID, VersionNumber: 1,
		EncryptedValue: []byte("v1"), EncryptionMetadata: []byte("{}"),
		CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: p.ID,
		SecretIDs: []uint{folder.ID, real.ID},
		RotatedBy: "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Triggered, 1)
	assert.Equal(t, real.ID, result.Triggered[0])
	require.Len(t, result.Failed, 1)
	assert.Equal(t, folder.ID, result.Failed[0].SecretID)
	assert.Contains(t, result.Failed[0].Error, "folder nodes cannot be rotated")
}

// TestBulkRotateSecrets_ListSecretsError covers the ListSecrets storage error (line 160-162)
// using a mock storage.
func TestBulkRotateSecrets_ListSecretsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}

	storageErr := errors.New("connection refused")
	ms.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).Return(nil, int64(0), storageErr)

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: 42,
		RotatedBy: "ops",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list secrets for project 42")
	assert.Nil(t, result)
	ms.AssertExpectations(t)
}

// TestBulkRotateSecrets_ByEnvID covers the EnvID filter branch (line 150-152).
func TestBulkRotateSecrets_ByEnvID(t *testing.T) {
	t.Parallel()
	c, ls := bulkRotateDBRaw(t)
	ctx := context.Background()

	p, err := ls.CreateProject(ctx, &models.Project{Name: "env-filter-proj"})
	require.NoError(t, err)
	envA, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
	require.NoError(t, err)
	envB, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(t, err)

	mkInEnv := func(name string, envID uint) uint {
		s, serr := ls.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: p.ID, EnvironmentID: envID,
			Type: "password", IsSecret: true, Status: "active",
			AutoRotate: true, OwnerID: 1,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, serr)
		_, serr = ls.CreateSecretVersion(ctx, &models.SecretVersion{
			SecretNodeID: s.ID, VersionNumber: 1,
			EncryptedValue: []byte("v1"), EncryptionMetadata: []byte("{}"),
			CreatedAt: time.Now(),
		})
		require.NoError(t, serr)
		return s.ID
	}

	stagingID := mkInEnv("staging-secret", envA.ID)
	_ = mkInEnv("prod-secret", envB.ID)

	// Rotate only staging environment.
	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: p.ID,
		EnvID:     envA.ID,
		RotatedBy: "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total, "only staging env secret should be included")
	assert.Len(t, result.Triggered, 1)
	assert.Equal(t, stagingID, result.Triggered[0])
	assert.Empty(t, result.Failed)
}

// TestBulkRotateSecrets_RotateOnDemandError covers bulkRotateOne when RotateSecretOnDemand
// fails (line 191-197): the secret is reported in Failed but the operation continues.
func TestBulkRotateSecrets_RotateOnDemandError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}

	projectID := uint(7)
	secretID := uint(11)

	// GetSecretsByIDs returns a valid rotatable secret.
	ms.On("GetSecretsByIDs", ctx, []uint{secretID}).Return([]*models.SecretNode{
		{
			ID: secretID, Name: "rotate-fail", ProjectID: projectID,
			IsSecret: true, AutoRotate: true,
			RotationLength: 32, RotationCharset: "",
		},
	}, nil)
	// RotateSecretOnDemand calls GetSecret first — return an error to make it fail.
	ms.On("GetSecret", ctx, secretID).Return(nil, errors.New("secret locked"))

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		SecretIDs: []uint{secretID},
		RotatedBy: "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Empty(t, result.Triggered)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, secretID, result.Failed[0].SecretID)
	assert.Contains(t, result.Failed[0].Error, "secret locked")
	ms.AssertExpectations(t)
}

// TestBulkRotateSecrets_ValueGenError covers bulkRotateOne when generateRotatedValueSpec
// fails (lines 184-190 and 131-135 of bulk_rotate.go). We substitute bulkValueGen with a
// stub that returns an error to simulate a crypto/rand failure.
//
// Deliberately NOT t.Parallel(): bulkValueGen is a package-level var this test mutates
// and restores via t.Cleanup, which every OTHER parallel test in this file reads through
// bulkRotateOne. Running this test in parallel with them raced a live write against a
// live read (WARNING: DATA RACE, TestBulkRotateSecrets_ByClassification vs. this test's
// cleanup) -- serial top-level tests run to completion, cleanup included, before the
// parallel group starts, which is the only way to mutate shared package state safely
// alongside t.Parallel() siblings that read it.
func TestBulkRotateSecrets_ValueGenError(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}

	projectID := uint(3)
	secretID := uint(5)

	ms.On("GetSecretsByIDs", ctx, []uint{secretID}).Return([]*models.SecretNode{
		{
			ID: secretID, Name: "gen-fail-secret", ProjectID: projectID,
			IsSecret: true, AutoRotate: true,
		},
	}, nil)

	// Substitute the value generator with one that always fails.
	origGen := bulkValueGen
	bulkValueGen = func(int, string) (string, error) {
		return "", errors.New("crypto/rand exhausted")
	}
	t.Cleanup(func() { bulkValueGen = origGen })

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		SecretIDs: []uint{secretID},
		RotatedBy: "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Empty(t, result.Triggered)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, secretID, result.Failed[0].SecretID)
	assert.Contains(t, result.Failed[0].Error, "generate value")
	ms.AssertExpectations(t)
}

// TestBulkRotateSecrets_ProjectWideRotateOnDemandError covers bulkRotateOne failure
// in the project-wide path (no SecretIDs provided).
func TestBulkRotateSecrets_ProjectWideRotateOnDemandError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}

	projectID := uint(9)
	secretID := uint(21)
	isSecret := true
	filter := &storage.SecretFilter{
		ProjectID: &projectID,
		Page:      1,
		PageSize:  10000,
		IsSecret:  &isSecret,
	}

	ms.On("ListSecrets", ctx, filter).Return([]*models.SecretNode{
		{
			ID: secretID, Name: "proj-wide-fail", ProjectID: projectID,
			IsSecret: true, AutoRotate: true,
		},
	}, int64(1), nil)
	// RotateSecretOnDemand → GetSecret returns error.
	ms.On("GetSecret", ctx, secretID).Return(nil, errors.New("disk full"))

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		RotatedBy: "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Empty(t, result.Triggered)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, secretID, result.Failed[0].SecretID)
	assert.Contains(t, result.Failed[0].Error, "disk full")
	ms.AssertExpectations(t)
}
