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

// newResumeLiveParentFixture builds a core over a real project -> environment -> suspended
// secret chain (the plain suspend fixture has no parent rows at all).
func newResumeLiveParentFixture(t *testing.T) (c *KeyorixCore, projectID, envID, secretID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.AuditEvent{}, &models.SecretAccessSchedule{}, &models.ShareRecord{},
		&models.SecretACL{}, &models.AccessRequest{}, &models.DynamicSecretConfig{}))
	c = &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "resume-parent"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	sec, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "db", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password", OwnerID: 1, IsSecret: true,
		Status: SecretStatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: sec.ID, VersionNumber: 1, EncryptedValue: []byte("v"),
	})
	require.NoError(t, err)
	_, err = c.SuspendSecret(ctx, sec.ID, 1, "incident")
	require.NoError(t, err)
	return c, proj.ID, env.ID, sec.ID
}

// #2794: DeleteEnvironment counts only ACTIVE secrets, so an environment holding a
// suspended one is deletable; ResumeSecret then flipped the secret to active inside the
// deleted environment (GetSecret does not check environment liveness), a live secret
// under a dead parent.
func TestResumeSecret_RefusedInDeletedEnvironment(t *testing.T) {
	ctx := context.Background()
	c, _, envID, secretID := newResumeLiveParentFixture(t)
	require.NoError(t, c.DeleteEnvironment(ctx, envID), "a suspended secret does not block the environment delete")

	_, err := c.ResumeSecret(ctx, secretID, 1)
	require.Error(t, err, "resume must refuse while the parent environment is deleted")

	got, gerr := c.storage.GetSecret(ctx, secretID)
	require.NoError(t, gerr)
	assert.Equal(t, SecretStatusSuspended, got.Status, "the secret must stay suspended")
}

// Calibration: with a live parent the same call still resumes.
func TestResumeSecret_LiveParentStillResumes(t *testing.T) {
	ctx := context.Background()
	c, _, _, secretID := newResumeLiveParentFixture(t)

	s, err := c.ResumeSecret(ctx, secretID, 1)
	require.NoError(t, err)
	assert.Equal(t, SecretStatusActive, s.Status)
}
