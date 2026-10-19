package core_test

// secret_size_policy_test.go exercises the core-layer secret-size cap
// (internal/core/secret_size_policy.go) against CreateSecret, UpdateSecret,
// and RotateSecret -- the three write paths that call checkSecretSize. Each
// uses real sqlite-backed storage (store.NewLocalStorage), matching the
// pattern already established by concurrency_update_secret_test.go, rather
// than mocks, so the exactly-at-limit case exercises the real storeSecretVersion
// write path end to end.

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newSecretSizeTestCore returns a KeyorixCore backed by a fresh, migrated,
// file-backed sqlite DB with one project and one environment already seeded --
// enough to exercise CreateSecret/UpdateSecret/RotateSecret directly.
func newSecretSizeTestCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	dsn := "file:" + filepath.Join(t.TempDir(), "secret-size.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(20)

	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_secret_versions_node_version ON secret_versions (secret_node_id, version_number)").Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)

	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// newSecretSizeTestCoreAndStorage is newSecretSizeTestCore, but also returns
// the underlying *store.LocalStorage so a test can write directly through it,
// bypassing every core-layer check (checkSecretSize included) -- needed to
// simulate a pre-existing secret version that predates the cap.
func newSecretSizeTestCoreAndStorage(t *testing.T) (*core.KeyorixCore, *store.LocalStorage) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	dsn := "file:" + filepath.Join(t.TempDir(), "secret-size-bypass.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(20)

	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_secret_versions_node_version ON secret_versions (secret_node_id, version_number)").Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)

	ls := store.NewLocalStorage(db)
	return core.NewKeyorixCore(ls), ls
}

// TestGetAndDeleteSecret_PreExistingOversizedValue_StillWorks is Item 1's
// "1f": the cap must bound new WRITES, never break reads of data that
// predates it. A secret version inserted directly through the storage layer
// (bypassing checkSecretSize entirely, simulating a row written before the
// cap existed, or under a since-lowered configured limit) must still be
// readable via GetSecretValue and the secret must still be deletable via
// DeleteSecret -- only a new write/update of an oversized value is rejected.
func TestGetAndDeleteSecret_PreExistingOversizedValue_StillWorks(t *testing.T) {
	t.Parallel()
	c, ls := newSecretSizeTestCoreAndStorage(t)
	c.SetMaxSecretSize(100)
	ctx := context.Background()

	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "legacy-oversized", Value: []byte("seed"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", CreatedBy: "tester",
	})
	require.NoError(t, err)

	// Write version 2 directly through storage, well over the configured
	// 100-byte cap -- this is exactly the write checkSecretSize exists to
	// reject when it goes through core, so it must bypass core entirely.
	oversized := bytes.Repeat([]byte("legacy"), 50) // 300 bytes, > the 100-byte cap
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: sec.ID, VersionNumber: 2, EncryptedValue: oversized,
	})
	require.NoError(t, err, "storage-layer write of the pre-existing oversized version must succeed (it is only 300B, under the 1MiB hard ceiling)")

	value, err := c.GetSecretValue(ctx, sec.ID)
	require.NoError(t, err, "reading a pre-existing oversized secret must still succeed")
	require.Equal(t, oversized, value)

	require.NoError(t, c.DeleteSecret(ctx, sec.ID), "deleting a pre-existing oversized secret must still succeed")
}

func TestCreateSecret_SecretSizeCap(t *testing.T) {
	t.Parallel()
	c := newSecretSizeTestCore(t)
	c.SetMaxSecretSize(100)
	ctx := context.Background()

	t.Run("exactly at the limit is accepted", func(t *testing.T) {
		value := bytes.Repeat([]byte("a"), 100)
		secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: "at-limit", Value: value, ProjectID: 1, EnvironmentID: 1,
			Type: "password", CreatedBy: "tester",
		})
		require.NoError(t, err)
		require.NotNil(t, secret)
	})

	t.Run("one byte over the limit is rejected", func(t *testing.T) {
		value := bytes.Repeat([]byte("a"), 101)
		secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: "over-limit", Value: value, ProjectID: 1, EnvironmentID: 1,
			Type: "password", CreatedBy: "tester",
		})
		require.Error(t, err)
		require.Nil(t, secret)
		var tooLarge *core.SecretValueTooLargeError
		require.True(t, errors.As(err, &tooLarge), "error must be a *core.SecretValueTooLargeError, got: %v", err)
		require.Equal(t, 101, tooLarge.Size)
		require.Equal(t, 100, tooLarge.Limit)
	})
}

func TestUpdateSecret_SecretSizeCap(t *testing.T) {
	t.Parallel()
	c := newSecretSizeTestCore(t)
	c.SetMaxSecretSize(100)
	ctx := context.Background()

	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "updatable", Value: []byte("seed"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", CreatedBy: "tester",
	})
	require.NoError(t, err)

	t.Run("exactly at the limit is accepted", func(t *testing.T) {
		value := bytes.Repeat([]byte("b"), 100)
		updated, err := c.UpdateSecret(ctx, &core.UpdateSecretRequest{
			ID: sec.ID, Value: value, UpdatedBy: "tester",
		})
		require.NoError(t, err)
		require.NotNil(t, updated)
	})

	t.Run("one byte over the limit is rejected", func(t *testing.T) {
		value := bytes.Repeat([]byte("b"), 101)
		updated, err := c.UpdateSecret(ctx, &core.UpdateSecretRequest{
			ID: sec.ID, Value: value, UpdatedBy: "tester",
		})
		require.Error(t, err)
		require.Nil(t, updated)
		var tooLarge *core.SecretValueTooLargeError
		require.True(t, errors.As(err, &tooLarge), "error must be a *core.SecretValueTooLargeError, got: %v", err)
		require.Equal(t, 101, tooLarge.Size)
		require.Equal(t, 100, tooLarge.Limit)
	})
}

func TestRotateSecret_SecretSizeCap(t *testing.T) {
	t.Parallel()
	c := newSecretSizeTestCore(t)
	c.SetMaxSecretSize(100)
	ctx := context.Background()

	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "rotatable", Value: []byte("seed"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", CreatedBy: "tester",
	})
	require.NoError(t, err)

	t.Run("exactly at the limit is accepted", func(t *testing.T) {
		value := bytes.Repeat([]byte("c"), 100)
		rotated, err := c.RotateSecret(ctx, sec.ID, value, 0, "tester")
		require.NoError(t, err)
		require.NotNil(t, rotated)
	})

	t.Run("one byte over the limit is rejected", func(t *testing.T) {
		value := bytes.Repeat([]byte("c"), 101)
		rotated, err := c.RotateSecret(ctx, sec.ID, value, 0, "tester")
		require.Error(t, err)
		require.Nil(t, rotated)
		var tooLarge *core.SecretValueTooLargeError
		require.True(t, errors.As(err, &tooLarge), "error must be a *core.SecretValueTooLargeError, got: %v", err)
		require.Equal(t, 101, tooLarge.Size)
		require.Equal(t, 100, tooLarge.Limit)
	})
}

// TestSetMaxSecretSize_ZeroFallsBackToDefault documents the guard in
// SetMaxSecretSize: a zero/negative n (e.g. from a config layer that failed
// to apply its own default) must not silently disable the cap.
func TestSetMaxSecretSize_ZeroFallsBackToDefault(t *testing.T) {
	t.Parallel()
	c := newSecretSizeTestCore(t)
	c.SetMaxSecretSize(0)
	ctx := context.Background()

	value := bytes.Repeat([]byte("d"), core.DefaultMaxSecretSize+1)
	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "zero-limit-fallback", Value: value, ProjectID: 1, EnvironmentID: 1,
		Type: "password", CreatedBy: "tester",
	})
	require.Error(t, err)
	require.Nil(t, secret)
	var tooLarge *core.SecretValueTooLargeError
	require.True(t, errors.As(err, &tooLarge))
	require.Equal(t, core.DefaultMaxSecretSize, tooLarge.Limit)
}
