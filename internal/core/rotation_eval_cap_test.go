package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// Rotation evaluation must page through ALL of a policy's secrets — a project with
// more than one page must not have the secrets past the page silently skipped
// (which would hide overdue secrets from the reminder scheduler and status views).
func TestEvaluateRotationPolicies_NoSilentCap(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.RotationPolicy{}))

	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}

	pid := uint(1)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "30-day", Scope: "project", ProjectID: &pid,
		IntervalDays: 30, AlertDaysBefore: 7, IsActive: true, CreatedBy: "x",
	}).Error)

	// 1001 secrets — more than the old single-page cap of 1000 — all created 100
	// days ago, so all overdue. A regression to a single capped ListSecrets call
	// would drop at least one and fail this test.
	const n = 1001
	secrets := make([]*models.SecretNode, 0, n)
	for i := range n {
		secrets = append(secrets, &models.SecretNode{
			ProjectID: 1, EnvironmentID: 1, Name: fmt.Sprintf("s%d", i), Type: "password",
			CreatedAt: now.AddDate(0, 0, -100),
		})
	}
	require.NoError(t, db.CreateInBatches(secrets, 200).Error)

	evals, err := c.EvaluateRotationPolicies(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Len(t, evals, n, "every overdue secret is evaluated, not capped at one page")

	status, err := c.GetRotationStatus(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Len(t, status, n, "status covers every secret too, not capped at one page")
}
