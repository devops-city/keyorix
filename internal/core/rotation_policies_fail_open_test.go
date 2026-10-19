// rotation_policies_fail_open_test.go — #363: a scopedPolicySecrets failure for one
// rotation policy must not silently vanish that policy's secrets from the result
// (undercounting rotation coverage as if the policy's secrets simply didn't exist).
// Every known caller of GetRotationStatus/EvaluateRotationPolicies already treats a
// non-nil error as "don't trust this result" (compliance posture/evidence degrade,
// the HTTP handlers 500, the reminder scheduler sends nothing) — so surfacing the
// per-policy failure as a whole-call error, after logging it, correctly reads as
// "incomplete/unknown" everywhere downstream instead of a silently short, falsely
// clean count.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// failingEnvSecretsStore wraps LocalStorage and fails ListSecrets only when the
// filter targets failEnv — simulating a transient storage error scoped to exactly
// one rotation policy while a sibling policy (a different environment) still
// succeeds, so the test can tell "one policy's query failed" apart from "the whole
// deployment is down".
func failingEnvSecretsStore(inner storage.Storage, failEnv uint) storage.Storage {
	return hooked(inner, &storeHooks{
		ListSecrets: func(next storage.Storage, ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
			if filter.EnvironmentID != nil && *filter.EnvironmentID == failEnv {
				return nil, 0, assertErrSimulated
			}
			return next.ListSecrets(ctx, filter)
		},
	})
}

var assertErrSimulated = &simulatedStorageError{"simulated storage failure"}

type simulatedStorageError struct{ msg string }

func (e *simulatedStorageError) Error() string { return e.msg }

func rotationPoliciesFailOpenCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.RotationPolicy{}, &models.Project{}))
	fixed := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "ok-env"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 1, Name: "broken-env"}).Error)
	pid := uint(1)
	okEnv, brokenEnv := uint(1), uint(2)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "ok-policy", Scope: "environment", EnvironmentID: &okEnv,
		IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 2, Name: "broken-policy", Scope: "environment", EnvironmentID: &brokenEnv,
		IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "healthy-in-ok-env", ProjectID: pid, EnvironmentID: okEnv, IsSecret: true,
		Status: "active", CreatedAt: fixed.Add(-60 * 24 * time.Hour),
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 2, Name: "overdue-in-broken-env", ProjectID: pid, EnvironmentID: brokenEnv, IsSecret: true,
		Status: "active", CreatedAt: fixed.Add(-90 * 24 * time.Hour),
	}).Error)

	c := &KeyorixCore{storage: failingEnvSecretsStore(store.NewLocalStorage(db), brokenEnv)}
	c.now = func() time.Time { return fixed }
	return c, db, fixed
}

// #363: GetRotationStatus must log the per-policy failure and must not return a
// silently-short "clean" result — before the fix, this returned (1 entry, nil error),
// indistinguishable from "rotation coverage is fully known and only 1 secret exists".
func TestGetRotationStatus_LogsAndFailsOnScopedSecretsError(t *testing.T) {
	c, _, _ := rotationPoliciesFailOpenCore(t)

	var entries []*RotationStatusEntry
	var err error
	logged := captureLog(t, func() {
		entries, err = c.GetRotationStatus(context.Background(), nil, nil)
	})

	require.Error(t, err, "a per-policy scope failure must surface as a whole-call error, not a silently-short result")
	assert.Nil(t, entries)
	assert.Contains(t, logged, "broken-policy", "the failing policy's name must appear in the operator-visible log line")
	assert.Contains(t, logged, "simulated storage failure")
}

// #363: same fix, EvaluateRotationPolicies — this result also feeds the admin-nudge
// reminder scheduler (rotation_reminders.go), which already bails on a non-nil error.
func TestEvaluateRotationPolicies_LogsAndFailsOnScopedSecretsError(t *testing.T) {
	c, _, _ := rotationPoliciesFailOpenCore(t)

	var evals []*RotationPolicyEvaluation
	var err error
	logged := captureLog(t, func() {
		evals, err = c.EvaluateRotationPolicies(context.Background(), nil, nil)
	})

	require.Error(t, err)
	assert.Nil(t, evals)
	assert.Contains(t, logged, "broken-policy")

	// The reminder scheduler must not silently send zero reminders while reporting
	// success — it must propagate the failure too.
	sent, rerr := c.SendRotationReminders(context.Background())
	require.Error(t, rerr, "the reminder scheduler must not report success when the underlying evaluation was incomplete")
	assert.Equal(t, 0, sent)
}

// A clean run (no failing policy) is unaffected: both functions still return the full
// result with no error.
func TestGetRotationStatus_NoErrorWhenAllPoliciesSucceed(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.RotationPolicy{}, &models.Project{}))
	fixed := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env"}).Error)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "policy", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "s", ProjectID: pid, EnvironmentID: 1, IsSecret: true, Status: "active",
		CreatedAt: fixed.Add(-60 * 24 * time.Hour),
	}).Error)
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	c.now = func() time.Time { return fixed }

	entries, err := c.GetRotationStatus(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}
