// folder_test.go — tests for CreateFolder, ListFolders in core/secrets.go.
package core

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var folderCoreDBCounter atomic.Int64

func freshFolderCoreDB(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := folderCoreDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxcore_cfoldr_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.SecretVersion{}, &models.SecretAccessLog{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
	))

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "test-proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 5, ProjectID: 1, Name: "test-env"}).Error)

	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// TestCreateFolder_HappyPath verifies a root folder is created with IsSecret=false.
func TestCreateFolder_HappyPath(t *testing.T) {
	t.Parallel()
	cs, _ := freshFolderCoreDB(t)

	folder, err := cs.CreateFolder(context.Background(), 1, "my-folder", 1, 5, nil)
	require.NoError(t, err)
	require.NotNil(t, folder)

	assert.Equal(t, "my-folder", folder.Name)
	assert.False(t, folder.IsSecret)
	assert.Equal(t, uint(1), folder.ProjectID)
	assert.Equal(t, uint(5), folder.EnvironmentID)
	assert.Nil(t, folder.ParentID)
	assert.Equal(t, "folder", folder.Type)
}

// TestCreateFolder_EmptyName ensures an empty name is rejected.
func TestCreateFolder_EmptyName(t *testing.T) {
	t.Parallel()
	cs, _ := freshFolderCoreDB(t)

	_, err := cs.CreateFolder(context.Background(), 1, "  ", 1, 5, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "folder name is required")
}

// TestCreateFolder_MissingProjectID ensures zero projectID is rejected.
func TestCreateFolder_MissingProjectID(t *testing.T) {
	t.Parallel()
	cs, _ := freshFolderCoreDB(t)

	_, err := cs.CreateFolder(context.Background(), 1, "folder", 0, 5, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project_id is required")
}

// TestCreateFolder_MissingEnvID ensures zero environmentID is rejected.
func TestCreateFolder_MissingEnvID(t *testing.T) {
	t.Parallel()
	cs, _ := freshFolderCoreDB(t)

	_, err := cs.CreateFolder(context.Background(), 1, "folder", 1, 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment_id is required")
}

// TestCreateFolder_InvalidParent verifies that a non-existent parent is rejected.
func TestCreateFolder_InvalidParent(t *testing.T) {
	t.Parallel()
	cs, _ := freshFolderCoreDB(t)

	nonExistent := uint(999)
	_, err := cs.CreateFolder(context.Background(), 1, "child", 1, 5, &nonExistent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parent folder 999 not found")
}

// TestCreateFolder_ParentMustBeFolder verifies that a secret node cannot be used as a parent.
func TestCreateFolder_ParentMustBeFolder(t *testing.T) {
	t.Parallel()
	cs, _ := freshFolderCoreDB(t)

	// Create a real secret (IsSecret=true).
	secret, err := cs.CreateSecret(context.Background(), &CreateSecretRequest{
		Name: "secret-node", Value: []byte("val"), ProjectID: 1, EnvironmentID: 5,
		Type: "generic", CreatedBy: "alice", OwnerID: 1,
	})
	require.NoError(t, err)

	_, err = cs.CreateFolder(context.Background(), 1, "child", 1, 5, &secret.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is a secret, not a folder")
}

// TestCreateFolder_NestedFolder verifies that a folder can be nested under another folder.
func TestCreateFolder_NestedFolder(t *testing.T) {
	t.Parallel()
	cs, _ := freshFolderCoreDB(t)

	parent, err := cs.CreateFolder(context.Background(), 1, "parent", 1, 5, nil)
	require.NoError(t, err)

	child, err := cs.CreateFolder(context.Background(), 1, "child", 1, 5, &parent.ID)
	require.NoError(t, err)
	require.NotNil(t, child.ParentID)
	assert.Equal(t, parent.ID, *child.ParentID)
}

// TestListFolders_FiltersByIsSecret verifies that only folder nodes are returned.
func TestListFolders_FiltersByIsSecret(t *testing.T) {
	t.Parallel()
	cs, _ := freshFolderCoreDB(t)

	// Create a folder and a real secret.
	_, err := cs.CreateFolder(context.Background(), 1, "f1", 1, 5, nil)
	require.NoError(t, err)
	_, err = cs.CreateSecret(context.Background(), &CreateSecretRequest{
		Name: "real-secret", Value: []byte("v"), ProjectID: 1, EnvironmentID: 5,
		Type: "generic", CreatedBy: "alice", OwnerID: 1,
	})
	require.NoError(t, err)

	folders, total, err := cs.ListFolders(context.Background(), 1, nil, 1, 100)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, folders, 1)
	assert.Equal(t, "f1", folders[0].Name)
	assert.False(t, folders[0].IsSecret)
}

// TestCreateFolder_RefusesCrossProjectParent is the #G86 regression:
// CreateFolder previously loaded the destination parent with a bare,
// unauthorized GetSecret and never checked it belonged to the same
// project/environment being declared for the new folder — a caller with
// secrets.write on project 1 could pass project_id=1 (their own, authorized
// scope) but nest the new folder under a parent_id belonging to an entirely
// different project, and folder-inheriting ACL/sharing resolution (see
// HasSecretACL's ancestor walk in secret_acl.go) would then apply that other
// project's grants to it. Mirrors TestMoveSecret_RefusesCrossProjectParent.
func TestCreateFolder_RefusesCrossProjectParent(t *testing.T) {
	t.Parallel()
	cs, db := freshFolderCoreDB(t)
	ctx := context.Background()

	// A folder in a DIFFERENT project (2) that the actor has no stake in.
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "other-proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 6, ProjectID: 2, Name: "other-env"}).Error)
	foreignFolder, err := cs.CreateFolder(ctx, 1, "foreign-parent", 2, 6, nil)
	require.NoError(t, err)

	_, err = cs.CreateFolder(ctx, 1, "smuggled-child", 1, 5, &foreignFolder.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same project/environment")
}

// TestCreateFolder_RefusesCrossEnvironmentParent verifies the same guard
// catches a same-project, different-environment mismatch (folders/secrets in
// this codebase are scoped by project AND environment).
func TestCreateFolder_RefusesCrossEnvironmentParent(t *testing.T) {
	t.Parallel()
	cs, db := freshFolderCoreDB(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Environment{ID: 7, ProjectID: 1, Name: "other-env-same-proj"}).Error)
	foreignEnvFolder, err := cs.CreateFolder(ctx, 1, "other-env-parent", 1, 7, nil)
	require.NoError(t, err)

	_, err = cs.CreateFolder(ctx, 1, "smuggled-child-env", 1, 5, &foreignEnvFolder.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same project/environment")
}

// TestListFolders_ParentFilter verifies that parent_id filtering works.
func TestListFolders_ParentFilter(t *testing.T) {
	t.Parallel()
	cs, _ := freshFolderCoreDB(t)

	parent, err := cs.CreateFolder(context.Background(), 1, "parent", 1, 5, nil)
	require.NoError(t, err)
	_, err = cs.CreateFolder(context.Background(), 1, "child1", 1, 5, &parent.ID)
	require.NoError(t, err)
	_, err = cs.CreateFolder(context.Background(), 1, "child2", 1, 5, &parent.ID)
	require.NoError(t, err)
	// Root-level sibling (no parent).
	_, err = cs.CreateFolder(context.Background(), 1, "sibling", 1, 5, nil)
	require.NoError(t, err)

	// Filter by parent ID — should return only the two children.
	folders, total, err := cs.ListFolders(context.Background(), 1, &parent.ID, 1, 100)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, folders, 2)
}
