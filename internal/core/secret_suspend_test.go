package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newSuspendFixture(t *testing.T) (*KeyorixCore, uint, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.SecretAccessSchedule{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	// ResumeSecret requires a live parent environment and project (#2794).
	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "suspend-fixture"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "db", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password", OwnerID: 1, IsSecret: true,
		Status: SecretStatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("v"),
	})
	require.NoError(t, err)
	return c, secret.ID, db
}

func TestSuspendResumeSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("suspend blocks value reads; resume restores them", func(t *testing.T) {
		c, id, _ := newSuspendFixture(t)
		// Readable before suspension.
		_, err := c.GetSecretValue(ctx, id)
		require.NoError(t, err)

		s, err := c.SuspendSecret(ctx, id, 1, "suspected leak")
		require.NoError(t, err)
		assert.Equal(t, SecretStatusSuspended, s.Status)

		_, err = c.GetSecretValue(ctx, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "suspended")
		_, err = c.GetSecretValueByVersion(ctx, id, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "suspended")

		s, err = c.ResumeSecret(ctx, id, 1)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusActive, s.Status)
		_, err = c.GetSecretValue(ctx, id)
		require.NoError(t, err, "value is readable again after resume")
	})

	t.Run("suspend is idempotent and audited once", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecret(ctx, id, 1, "")
		require.NoError(t, err)
		_, err = c.SuspendSecret(ctx, id, 1, "") // no-op
		require.NoError(t, err)

		var count int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventSecretSuspended).Count(&count).Error)
		assert.EqualValues(t, 1, count, "re-suspending an already-suspended secret does not re-audit")
	})

	t.Run("resume on a non-suspended secret is a no-op", func(t *testing.T) {
		c, id, _ := newSuspendFixture(t)
		s, err := c.ResumeSecret(ctx, id, 1)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusActive, s.Status)
	})
}

// newMockSuspendCore builds a KeyorixCore backed by MockStorage — mirrors
// newMachineCore (machine_identities_test.go) — so SuspendSecret/ResumeSecret's
// lost-race handling can be exercised without needing a real concurrent
// second caller: TransitionSecretStatus is simply stubbed to report the race
// already lost.
func newMockSuspendCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

// TestSuspendResumeSecret_LostRace proves the StateTransitionMissingCAS fix:
// when TransitionSecretStatus reports matched=false (the row's persisted
// status moved away from the value GetSecret observed, between that read and
// this write — e.g. a concurrent suspend/resume won the race), SuspendSecret/
// ResumeSecret must surface a clear error instead of pretending the write
// landed, and must NOT write an audit event for a change that never
// persisted. Mirrors TestTransitionMachineIdentity's "lost race on the
// conditional write is reported like an illegal transition" subtest.
func TestSuspendResumeSecret_LostRace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("SuspendSecret", func(t *testing.T) {
		store := new(MockStorage)
		c := newMockSuspendCore(store)
		store.On("GetSecret", ctx, uint(10)).
			Return(&models.SecretNode{ID: 10, Name: "db", Status: SecretStatusActive}, nil)
		store.On("TransitionSecretStatus", ctx, mock.MatchedBy(func(s *models.SecretNode) bool {
			return s.Status == SecretStatusSuspended
		}), SecretStatusActive).Return(false, nil)

		_, err := c.SuspendSecret(ctx, 10, 1, "suspected leak")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "changed concurrently")
		store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	})

	t.Run("ResumeSecret", func(t *testing.T) {
		store := new(MockStorage)
		c := newMockSuspendCore(store)
		store.On("GetSecret", ctx, uint(20)).
			Return(&models.SecretNode{ID: 20, Name: "db", Status: SecretStatusSuspended}, nil)
		store.On("TransitionSecretStatus", ctx, mock.MatchedBy(func(s *models.SecretNode) bool {
			return s.Status == SecretStatusActive
		}), SecretStatusSuspended).Return(false, nil)

		_, err := c.ResumeSecret(ctx, 20, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "changed concurrently")
		store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	})
}
