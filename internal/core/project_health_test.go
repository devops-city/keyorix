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
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newHealthTestDB opens a fresh in-memory SQLite DB with all required tables
// migrated. Each call produces a fully isolated database.
func newHealthTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // required for :memory: isolation
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.User{},
		&models.Project{},
		&models.Environment{},
		&models.SecretAccessLog{},
		&models.MachineIdentity{},
		&models.AuditEvent{},
		&models.RotationPolicy{},
		&models.ShareRecord{},
		&models.UserGroup{},
	))
	return db
}

// makeSecret creates a SecretNode in the given project/environment. Pinning a
// recent CreatedAt keeps rotation scores low so tests can be deterministic.
func makeHealthSecret(t *testing.T, c *KeyorixCore, name string, projectID, envID, ownerID uint) uint {
	t.Helper()
	s, err := c.storage.CreateSecret(context.Background(), &models.SecretNode{
		Name:          name,
		ProjectID:     projectID,
		EnvironmentID: envID,
		Type:          "password",
		OwnerID:       ownerID,
		IsSecret:      true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)
	return s.ID
}

func TestGetProjectHealthSummary_Empty(t *testing.T) {
	t.Parallel()
	db := newHealthTestDB(t)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "empty-project"})
	require.NoError(t, err)

	summary, err := c.GetProjectHealthSummary(ctx, p.ID, 20)
	require.NoError(t, err)
	assert.Equal(t, p.ID, summary.ProjectID)
	assert.Equal(t, 0, summary.TotalSecrets)
	assert.Equal(t, 0, summary.HighRiskCount)
	assert.Equal(t, 0, summary.MediumRiskCount)
	assert.Equal(t, 0, summary.LowRiskCount)
	assert.Empty(t, summary.TopRiskSecrets)
}

func TestGetProjectHealthSummary_Counts(t *testing.T) {
	t.Parallel()
	db := newHealthTestDB(t)
	ctx := context.Background()
	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "counts-project"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)

	// HIGH secret: expired 10d ago + old (400d, never rotated) + no reads + owner only.
	// expiry=100*0.30=30, rotation=100*0.30=30, usage=80*0.20=16, exposure=10*0.20=2 → 78 ≥ 67 → HIGH
	oldCreated := now.AddDate(0, 0, -400)
	expired := now.AddDate(0, 0, -10)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "expired-secret", ProjectID: p.ID, EnvironmentID: e.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		Expiration: &expired,
		CreatedAt:  oldCreated, UpdatedAt: oldCreated,
	})
	require.NoError(t, err)

	// MEDIUM secret: old (400d) but has many reads (usage=10) and no expiry (40) and owner only.
	// expiry=40*0.30=12, rotation=100*0.30=30, usage=10*0.20=2, exposure=10*0.20=2 → 46 → MEDIUM
	medS, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "old-active-secret", ProjectID: p.ID, EnvironmentID: e.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: oldCreated, UpdatedAt: oldCreated,
	})
	require.NoError(t, err)
	for range 12 {
		require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
			SecretNodeID: medS.ID, AccessedBy: "owner", Action: "read", AccessTime: now,
		}))
	}

	// LOW secret: expires far in the future, freshly created, many reads.
	// expiry=10*0.30=3, rotation=10*0.30=3, usage=10*0.20=2, exposure=10*0.20=2 → 10 → LOW
	future := now.AddDate(1, 0, 0)
	lowS, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "fresh-secret", ProjectID: p.ID, EnvironmentID: e.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		Expiration: &future,
		CreatedAt:  now, UpdatedAt: now,
	})
	require.NoError(t, err)
	for range 12 {
		require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
			SecretNodeID: lowS.ID, AccessedBy: "owner", Action: "read", AccessTime: now,
		}))
	}

	summary, err := c.GetProjectHealthSummary(ctx, p.ID, 20)
	require.NoError(t, err)
	assert.Equal(t, 3, summary.TotalSecrets)
	// Band counts must add up to total.
	assert.Equal(t, summary.TotalSecrets, summary.HighRiskCount+summary.MediumRiskCount+summary.LowRiskCount)
	// We expect exactly 1 HIGH, 1 MEDIUM, 1 LOW.
	assert.Equal(t, 1, summary.HighRiskCount, "expired-secret should be HIGH")
	assert.Equal(t, 1, summary.MediumRiskCount, "old-active-secret should be MEDIUM")
	assert.Equal(t, 1, summary.LowRiskCount, "fresh-secret should be LOW")
	// All 3 secrets must appear in TopRiskSecrets (limit=20 > 3).
	assert.Len(t, summary.TopRiskSecrets, 3)
	// Must be sorted descending.
	for i := 1; i < len(summary.TopRiskSecrets); i++ {
		assert.GreaterOrEqual(t, summary.TopRiskSecrets[i-1].Score, summary.TopRiskSecrets[i].Score)
	}
}

func TestGetProjectHealthSummary_Limit(t *testing.T) {
	t.Parallel()
	db := newHealthTestDB(t)
	ctx := context.Background()
	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "limit-project"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(t, err)

	// Create 5 secrets.
	for i := range 5 {
		makeHealthSecret(t, c, fmt.Sprintf("s%d", i), p.ID, e.ID, 1)
	}

	summary, err := c.GetProjectHealthSummary(ctx, p.ID, 2)
	require.NoError(t, err)
	assert.Equal(t, 5, summary.TotalSecrets)
	// Only the top 2 should be returned.
	assert.Len(t, summary.TopRiskSecrets, 2)
	// They must be in descending order.
	require.Equal(t, 2, len(summary.TopRiskSecrets))
	assert.GreaterOrEqual(t, summary.TopRiskSecrets[0].Score, summary.TopRiskSecrets[1].Score)
}

func TestGetProjectHealthSummary_WrongProject(t *testing.T) {
	t.Parallel()
	db := newHealthTestDB(t)
	ctx := context.Background()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}

	// Create two projects; put secrets only in p1.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p1.ID})
	require.NoError(t, err)
	makeHealthSecret(t, c, "only-in-p1", p1.ID, e.ID, 1)

	// Querying p2 must return empty, not p1's secrets.
	summary, err := c.GetProjectHealthSummary(ctx, p2.ID, 20)
	require.NoError(t, err)
	assert.Equal(t, p2.ID, summary.ProjectID)
	assert.Equal(t, 0, summary.TotalSecrets)
	assert.Empty(t, summary.TopRiskSecrets)
}

// TestGetProjectHealthSummary_LimitClamping ensures that limit values that are
// out of range (<=0 or >100) are silently clamped to the default of 20.
func TestGetProjectHealthSummary_LimitClamping(t *testing.T) {
	t.Parallel()
	db := newHealthTestDB(t)
	ctx := context.Background()
	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "clamp-project"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(t, err)

	// Create 25 secrets so we can verify the clamp to defaultHealthLimit (20).
	for i := range 25 {
		makeHealthSecret(t, c, fmt.Sprintf("clamp-s%d", i), p.ID, e.ID, 1)
	}

	// limit=0 → clamped to 20.
	summary, err := c.GetProjectHealthSummary(ctx, p.ID, 0)
	require.NoError(t, err)
	assert.Equal(t, 25, summary.TotalSecrets)
	assert.LessOrEqual(t, len(summary.TopRiskSecrets), 20, "limit=0 should clamp to defaultHealthLimit=20")

	// limit=-1 → clamped to 20.
	summary, err = c.GetProjectHealthSummary(ctx, p.ID, -1)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(summary.TopRiskSecrets), 20, "limit=-1 should clamp to defaultHealthLimit=20")

	// limit=200 → clamped to 20.
	summary, err = c.GetProjectHealthSummary(ctx, p.ID, 200)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(summary.TopRiskSecrets), 20, "limit=200 should clamp to defaultHealthLimit=20")
}

// TestGetProjectHealthSummary_Truncated is the #G24 regression: before the fix,
// TotalSecrets silently reported len(secrets) (the fetched, possibly-capped
// sample) as if it were the project's true secret count. ListSecrets' own real
// total (its second return value) was discarded. Uses MockStorage to simulate a
// project with more secrets (1500) than the fetch returns (0, so
// ComputeSecretRiskScoresBatch short-circuits on empty input) — TotalSecrets
// must reflect the TRUE total and Truncated must be set.
func TestGetProjectHealthSummary_Truncated(t *testing.T) {
	t.Parallel()
	const proj = uint(9)
	ctx := context.Background()

	ms := &MockStorage{}
	ms.On("ListSecrets", ctx, mock.MatchedBy(func(f *storage.SecretFilter) bool {
		return f.ProjectID != nil && *f.ProjectID == proj
	})).Return([]*models.SecretNode{}, int64(1500), nil)

	c := &KeyorixCore{storage: ms, now: time.Now}
	summary, err := c.GetProjectHealthSummary(ctx, proj, 20)
	require.NoError(t, err)
	assert.Equal(t, 1500, summary.TotalSecrets, "TotalSecrets must be the real total, not the fetched sample size")
	assert.True(t, summary.Truncated)

	ms.AssertExpectations(t)
}

// TestGetProjectHealthSummary_ListSecretsError verifies that a storage failure
// on ListSecrets propagates as an error rather than producing a partial result.
func TestGetProjectHealthSummary_ListSecretsError(t *testing.T) {
	t.Parallel()
	db := newHealthTestDB(t)
	ctx := context.Background()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}

	// Close the underlying connection pool to force every query to fail.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, err = c.GetProjectHealthSummary(ctx, 1, 20)
	require.Error(t, err, "expected an error when the database is closed")
}

// TestGetProjectHealthSummary_BatchScoreError verifies that a failure inside
// ComputeSecretRiskScoresBatch is propagated as an error by GetProjectHealthSummary.
//
// The test wires a MockStorage whose ListSecrets returns one secret (so the IDs
// slice is non-empty and the batch scorer is called) while GetSecretsByIDs —
// the first call inside ComputeSecretRiskScoresBatch — returns a synthetic error.
func TestGetProjectHealthSummary_BatchScoreError(t *testing.T) {
	t.Parallel()
	const proj = uint(7)
	ctx := context.Background()

	ms := &MockStorage{}
	ms.On("ListSecrets", ctx, mock.MatchedBy(func(f *storage.SecretFilter) bool {
		return f.ProjectID != nil && *f.ProjectID == proj
	})).Return([]*models.SecretNode{
		{ID: 42, ProjectID: proj, Name: "a-secret", IsSecret: true},
	}, int64(1), nil)
	// GetSecretsByIDs is the first storage call inside ComputeSecretRiskScoresBatch.
	ms.On("GetSecretsByIDs", ctx, []uint{42}).Return(nil, errors.New("storage error"))

	c := &KeyorixCore{storage: ms, now: time.Now}
	_, err := c.GetProjectHealthSummary(ctx, proj, 20)
	require.Error(t, err, "expected error when ComputeSecretRiskScoresBatch fails")
	assert.Contains(t, err.Error(), "compute risk scores")

	ms.AssertExpectations(t)
}
