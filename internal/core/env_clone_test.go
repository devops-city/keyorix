package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newCloneTestCore builds a minimal KeyorixCore backed by an isolated in-memory
// SQLite DB for environment-clone integration tests. Each call gets its own DSN
// keyed by test name to prevent cross-test DB collisions.
func newCloneTestCore(t *testing.T) *KeyorixCore {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.Project{},
		&models.Environment{},
		&models.AuditEvent{},
		&models.SecretAccessLog{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{},
		&models.SecretAccessSchedule{},
	))
	// CopySecret calls GetSecretValueWithPermissionCheck which gates the owner path on
	// IsProjectMember (RBAC-001). The first project created in each test gets ID=1;
	// seed actor 1 as a project member so the copy read passes.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
}

func TestCloneEnvironment_Basic(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-basic"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
	dst, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})

	// Create 3 secrets in src.
	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: name, Value: []byte("val-" + name),
			ProjectID: p.ID, EnvironmentID: src.ID,
			Type: "generic", CreatedBy: "owner", OwnerID: 1,
		})
		require.NoError(t, err)
	}

	result, err := c.CloneEnvironment(ctx, p.ID, src.ID, dst.ID, "owner", 1)
	require.NoError(t, err)
	assert.Equal(t, "staging", result.SourceEnv)
	assert.Equal(t, "production", result.DestEnv)
	assert.Equal(t, 3, result.SecretsCloned)
	assert.Equal(t, 0, result.SecretsSkipped)
}

func TestCloneEnvironment_SkipsExisting(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-skip"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
	dst, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})

	// 3 secrets in src.
	for _, name := range []string{"db", "api", "secret3"} {
		_, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: name, Value: []byte("v"),
			ProjectID: p.ID, EnvironmentID: src.ID,
			Type: "generic", CreatedBy: "owner", OwnerID: 1,
		})
		require.NoError(t, err)
	}
	// "db" already exists in dst.
	_, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name: "db", Value: []byte("prod-val"),
		ProjectID: p.ID, EnvironmentID: dst.ID,
		Type: "generic", CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)

	result, err := c.CloneEnvironment(ctx, p.ID, src.ID, dst.ID, "owner", 1)
	require.NoError(t, err)
	assert.Equal(t, 2, result.SecretsCloned, "api and secret3 are new")
	assert.Equal(t, 1, result.SecretsSkipped, "db already exists in dst")
	assert.Len(t, result.Errors, 1)
}

func TestCloneEnvironment_EmptySource(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-empty"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
	dst, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})

	result, err := c.CloneEnvironment(ctx, p.ID, src.ID, dst.ID, "owner", 1)
	require.NoError(t, err)
	assert.Equal(t, 0, result.SecretsCloned)
	assert.Equal(t, 0, result.SecretsSkipped)
}

func TestCloneEnvironment_DifferentProject(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p1, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-diff-1"})
	p2, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-diff-2"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p1.ID})
	dst, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})

	_, err := c.CloneEnvironment(ctx, p1.ID, src.ID, dst.ID, "owner", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must belong to the given project")
}

func TestCloneEnvironment_DestNotFound(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-notfound"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})

	_, err := c.CloneEnvironment(ctx, p.ID, src.ID, 99999, "owner", 1)
	require.Error(t, err)
}

func TestCloneEnvironment_ZeroIDs(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	// projectID == 0 must be rejected immediately.
	_, err := c.CloneEnvironment(ctx, 0, 1, 2, "owner", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")

	// srcEnvID == 0 must also be rejected.
	_, err = c.CloneEnvironment(ctx, 1, 0, 2, "owner", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")

	// dstEnvID == 0 must also be rejected.
	_, err = c.CloneEnvironment(ctx, 1, 2, 0, "owner", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestCloneEnvironment_SameSrcDst(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	// srcEnvID == dstEnvID must be rejected.
	_, err := c.CloneEnvironment(ctx, 1, 5, 5, "owner", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must differ")
}

func TestCloneEnvironment_SrcNotFound(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-srcnotfound"})
	dst, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})

	// srcEnvID 99998 does not exist → GetEnvironment for source returns error.
	_, err := c.CloneEnvironment(ctx, p.ID, 99998, dst.ID, "owner", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source environment")
}

// mockEnvCloneStorage wraps MockStorage but lets GetEnvironment return an error
// for a designated "bad" env ID so we can exercise the ListSecrets error path.
//
// (testify derives the expected method name from the calling function, which a
// hook closure is not, hence MethodCalled with the name spelled out.)
func mockEnvCloneStorage(m *MockStorage) storage.Storage {
	return hooked(m, &storeHooks{
		GetEnvironment: func(_ storage.Storage, _ context.Context, id uint) (*models.Environment, error) {
			return &models.Environment{ID: id, ProjectID: 1, Name: "env"}, nil
		},
		ListSecrets: func(_ storage.Storage, ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
			args := m.MethodCalled("ListSecrets", ctx, filter)
			if args.Get(0) == nil {
				return nil, args.Get(1).(int64), args.Error(2)
			}
			return args.Get(0).([]*models.SecretNode), args.Get(1).(int64), args.Error(2)
		},
	})
}

func TestCloneEnvironment_ListSecretsError(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())

	ms := new(MockStorage)
	ms.On("ListSecrets", mock.Anything, mock.Anything).
		Return(nil, int64(0), errors.New("db unavailable"))
	c := NewKeyorixCore(mockEnvCloneStorage(ms))

	// Both envs have ProjectID=1 (returned by the override above), so the project
	// check passes, and we reach ListSecrets which returns an error.
	result, err := c.CloneEnvironment(context.Background(), 1, 2, 3, "owner", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db unavailable")
	// result is non-nil because the code returns partial data on ListSecrets error.
	assert.NotNil(t, result)
}
