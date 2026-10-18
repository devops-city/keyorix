// secret_folder_test.go — core-layer tests for folder-aware secret creation.
//
// Covers:
//   - CreateSecret with valid ParentID sets ParentID on the stored node
//   - CreateSecret with ParentID pointing to a real secret (not folder) → error
//   - CreateSecret with non-existent ParentID → error
//   - CreateSecret with ParentID from a different project/environment → error
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func newFolderCoreDB(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.OpenWithDialector(t, "kxcore_folder_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.RotationPolicy{}, &models.SecretVersion{},
		&models.SecretAccessLog{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod"}).Error)
	// Second project for cross-project test.
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "other-proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "staging"}).Error)

	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// seedFolder inserts a folder node (IsSecret=false) directly into the DB.
func seedFolder(t *testing.T, db *gorm.DB, projectID, envID uint) *models.SecretNode {
	t.Helper()
	node := &models.SecretNode{
		Name:          "test-folder",
		ProjectID:     projectID,
		EnvironmentID: envID,
		IsSecret:      false,
		Type:          "folder",
		Status:        "active",
		CreatedBy:     "system",
		OwnerID:       1,
	}
	require.NoError(t, db.Create(node).Error)
	return node
}

// TestCreateSecret_ParentID_SetsParent verifies that a valid folder ParentID is
// persisted on the created secret node.
func TestCreateSecret_ParentID_SetsParent(t *testing.T) {
	t.Parallel()
	c, db := newFolderCoreDB(t)
	folder := seedFolder(t, db, 1, 10)

	req := &CreateSecretRequest{
		Name:          "child-secret",
		Value:         []byte("s3cr3t"),
		ProjectID:     1,
		EnvironmentID: 10,
		Type:          "generic",
		CreatedBy:     "user",
		OwnerID:       1,
		ParentID:      &folder.ID,
	}
	got, err := c.CreateSecret(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, got.ParentID, "expected ParentID to be set on created secret")
	assert.Equal(t, folder.ID, *got.ParentID)
}

// TestCreateSecret_RecordsActingMachineIdentity: #1573 -- a machine identity
// holding project-scoped secrets.write can create a secret. OwnerID (0,
// ADR-030) alone loses which machine did it; OwnerMachineIdentityID must
// carry it through to the persisted row.
func TestCreateSecret_RecordsActingMachineIdentity(t *testing.T) {
	t.Parallel()
	c, _ := newFolderCoreDB(t)

	req := &CreateSecretRequest{
		Name:                   "machine-created",
		Value:                  []byte("s3cr3t"),
		ProjectID:              1,
		EnvironmentID:          10,
		Type:                   "generic",
		CreatedBy:              "machine",
		OwnerID:                0,
		OwnerMachineIdentityID: 42,
	}
	got, err := c.CreateSecret(context.Background(), req)
	require.NoError(t, err)
	assert.Zero(t, got.OwnerID)
	assert.Equal(t, uint(42), got.OwnerMachineIdentityID)
}

// TestCreateSecret_ParentID_NotAFolder verifies that using a real secret as the
// parent is rejected with a validation error.
func TestCreateSecret_ParentID_NotAFolder(t *testing.T) {
	t.Parallel()
	c, _ := newFolderCoreDB(t)

	// Create a real secret first.
	realSecret, err := c.CreateSecret(context.Background(), &CreateSecretRequest{
		Name:          "real",
		Value:         []byte("val"),
		ProjectID:     1,
		EnvironmentID: 10,
		Type:          "generic",
		CreatedBy:     "user",
		OwnerID:       1,
	})
	require.NoError(t, err)

	_, err = c.CreateSecret(context.Background(), &CreateSecretRequest{
		Name:          "child",
		Value:         []byte("val2"),
		ProjectID:     1,
		EnvironmentID: 10,
		Type:          "generic",
		CreatedBy:     "user",
		OwnerID:       1,
		ParentID:      &realSecret.ID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a folder")
}

// TestCreateSecret_ParentID_NonExistent verifies that a non-existent parent ID
// is rejected with a validation error.
func TestCreateSecret_ParentID_NonExistent(t *testing.T) {
	t.Parallel()
	c, _ := newFolderCoreDB(t)
	nonExistent := uint(99999)

	_, err := c.CreateSecret(context.Background(), &CreateSecretRequest{
		Name:          "orphan",
		Value:         []byte("val"),
		ProjectID:     1,
		EnvironmentID: 10,
		Type:          "generic",
		CreatedBy:     "user",
		OwnerID:       1,
		ParentID:      &nonExistent,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parent folder")
}

// TestCreateSecret_ParentID_CrossProject verifies that a folder in a different
// project/environment cannot be used as a parent.
func TestCreateSecret_ParentID_CrossProject(t *testing.T) {
	t.Parallel()
	c, db := newFolderCoreDB(t)
	// Folder lives in project 2 / env 20.
	otherFolder := seedFolder(t, db, 2, 20)

	_, err := c.CreateSecret(context.Background(), &CreateSecretRequest{
		Name:          "cross-project-secret",
		Value:         []byte("val"),
		ProjectID:     1,
		EnvironmentID: 10,
		Type:          "generic",
		CreatedBy:     "user",
		OwnerID:       1,
		ParentID:      &otherFolder.ID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same project/environment")
}

// TestCreateSecret_ParentID_Zero verifies that ParentID=0 is treated as "no parent"
// (root level) and succeeds without validation errors.
func TestCreateSecret_ParentID_Zero(t *testing.T) {
	t.Parallel()
	c, _ := newFolderCoreDB(t)
	zero := uint(0)

	got, err := c.CreateSecret(context.Background(), &CreateSecretRequest{
		Name:          "root-level",
		Value:         []byte("val"),
		ProjectID:     1,
		EnvironmentID: 10,
		Type:          "generic",
		CreatedBy:     "user",
		OwnerID:       1,
		ParentID:      &zero,
	})
	require.NoError(t, err)
	assert.Nil(t, got.ParentID, "ParentID=0 should not set a parent")
}
