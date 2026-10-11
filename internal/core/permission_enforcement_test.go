package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestCheckSecretPermission(t *testing.T) {
	t.Parallel()
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Helper function to create test secret
	createTestSecret := func(id, ownerID uint, name string) *models.SecretNode {
		return &models.SecretNode{
			ID:      id,
			OwnerID: ownerID,
			Name:    name,
		}
	}

	// Helper function to create test share
	createTestShare := func(id, secretID, recipientID uint, permission string, isGroup bool) *models.ShareRecord {
		return &models.ShareRecord{
			ID:          id,
			SecretID:    secretID,
			RecipientID: recipientID,
			IsGroup:     isGroup,
			Permission:  permission,
			CreatedAt:   time.Now(),
		}
	}

	// Helper function to create test group
	createTestGroup := func(id uint, name string) *models.Group {
		return &models.Group{
			ID:   id,
			Name: name,
		}
	}

	tests := []struct {
		name               string
		secretID           uint
		userID             uint
		requiredPermission PermissionLevel
		action             SecretAction // set: EnforceSecretActionPermission (write) instead of CheckSecretPermission
		setupMocks         func(*MockStorage)
		expectedPermission PermissionLevel
		expectedSource     string
		expectError        bool
	}{
		{
			name:               "Owner has full access",
			secretID:           1,
			userID:             1,
			requiredPermission: PermissionRead,
			setupMocks: func(ms *MockStorage) {
				secret := &models.SecretNode{ID: 1, OwnerID: 1, ProjectID: 10, Name: "test-secret"}
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("IsProjectMember", mock.Anything, uint(1), uint(10)).Return(true, nil)
			},
			expectedPermission: PermissionOwner,
			expectedSource:     "owner",
			expectError:        false,
		},
		{
			name:               "Direct share with read permission",
			secretID:           1,
			userID:             2,
			requiredPermission: PermissionRead,
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				share := createTestShare(1, 1, 2, "read", false)

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				// #2941: a share applies only to a live member of the secret's project.
				ms.On("IsProjectMember", mock.Anything, uint(2), uint(0)).Return(true, nil)
			},
			expectedPermission: PermissionRead,
			expectedSource:     "direct_share",
			expectError:        false,
		},
		{
			name:               "Direct share to a non-member grants nothing (#2941)",
			secretID:           1,
			userID:             2,
			requiredPermission: PermissionRead,
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				share := createTestShare(1, 1, 2, "write", false)

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				ms.On("IsProjectMember", mock.Anything, uint(2), uint(0)).Return(false, nil)
				ms.On("GetSecretACL", mock.Anything, uint(1), uint(2)).Return(nil, errors.New("record not found"))
				ms.On("GetSecretAncestors", mock.Anything, uint(1)).Return([]uint{}, nil)
				ms.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
				ms.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
			},
			expectError: true,
		},
		{
			name:               "Direct share with insufficient permission",
			secretID:           1,
			userID:             2,
			requiredPermission: PermissionWrite,
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				share := createTestShare(1, 1, 2, "read", false)

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				ms.On("GetUserGroupsAt", mock.Anything, uint(2), mock.Anything).Return([]*models.Group{}, nil)
				// ACL fallback (r140): no direct grant, and no ancestor folder grant either — deny.
				ms.On("GetSecretACL", mock.Anything, uint(1), uint(2)).Return(nil, errors.New("record not found"))
				ms.On("GetSecretAncestors", mock.Anything, uint(1)).Return([]uint{}, nil)
				// RBAC fallback: no roles at this scope — deny.
				ms.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
				ms.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
			},
			expectError: true,
		},
		{
			name:               "Group share with write permission",
			secretID:           1,
			userID:             3,
			requiredPermission: PermissionWrite,
			action:             SecretActionUpdate, // #3001 follow-up: a write share elevates only allowlisted actions
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				groupShare := createTestShare(2, 1, 10, "write", true)
				group := createTestGroup(10, "test-group")

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{groupShare}, nil)
				ms.On("GetUserGroupsAt", mock.Anything, uint(3), mock.Anything).Return([]*models.Group{group}, nil)
				ms.On("IsProjectMember", mock.Anything, uint(3), uint(0)).Return(true, nil)
			},
			expectedPermission: PermissionWrite,
			expectedSource:     "group_share",
			expectError:        false,
		},
		{
			name:               "No permission",
			secretID:           1,
			userID:             4,
			requiredPermission: PermissionRead,
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
				ms.On("GetUserGroupsAt", mock.Anything, uint(4), mock.Anything).Return([]*models.Group{}, nil)
				// ACL fallback (r140): no direct grant, and no ancestor folder grant either — deny.
				ms.On("GetSecretACL", mock.Anything, uint(1), uint(4)).Return(nil, errors.New("record not found"))
				ms.On("GetSecretAncestors", mock.Anything, uint(1)).Return([]uint{}, nil)
				// RBAC fallback: no roles at this scope — deny.
				ms.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
				ms.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorage{}
			tt.setupMocks(mockStorage)

			core := NewKeyorixCore(mockStorage)

			ctx := context.Background()
			var permCtx *PermissionContext
			var err error
			if tt.action != "" {
				permCtx, err = core.EnforceSecretActionPermission(ctx, tt.secretID, tt.userID, tt.action)
			} else {
				permCtx, err = core.CheckSecretPermission(ctx, tt.secretID, tt.userID, tt.requiredPermission)
			}

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, permCtx)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, permCtx)
				assert.Equal(t, tt.expectedPermission, permCtx.Permission)
				assert.Equal(t, tt.expectedSource, permCtx.Source)
				assert.Equal(t, tt.secretID, permCtx.SecretID)
				assert.Equal(t, tt.userID, permCtx.UserID)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestHasRequiredPermission(t *testing.T) {
	t.Parallel()
	core := &KeyorixCore{}

	tests := []struct {
		name               string
		userPermission     PermissionLevel
		requiredPermission PermissionLevel
		expected           bool
	}{
		{"Owner can read", PermissionOwner, PermissionRead, true},
		{"Owner can write", PermissionOwner, PermissionWrite, true},
		{"Write can read", PermissionWrite, PermissionRead, true},
		{"Read cannot write", PermissionRead, PermissionWrite, false},
		{"None cannot read", PermissionNone, PermissionRead, false},
		{"Same level allowed", PermissionRead, PermissionRead, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := core.hasRequiredPermission(tt.userPermission, tt.requiredPermission)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnforceSecretReadPermission(t *testing.T) {
	t.Parallel()
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	mockStorage := &MockStorage{}
	mockStorage.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{
		ID:        1,
		OwnerID:   1,
		ProjectID: 10,
		Name:      "test-secret",
	}, nil)
	mockStorage.On("IsProjectMember", mock.Anything, uint(1), uint(10)).Return(true, nil)

	core := NewKeyorixCore(mockStorage)

	ctx := context.Background()
	permCtx, err := core.EnforceSecretReadPermission(ctx, 1, 1)

	assert.NoError(t, err)
	assert.NotNil(t, permCtx)
	assert.Equal(t, PermissionOwner, permCtx.Permission)
	assert.Equal(t, "owner", permCtx.Source)

	mockStorage.AssertExpectations(t)
}

func TestEnforceSecretWritePermission(t *testing.T) {
	t.Parallel()
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	mockStorage := &MockStorage{}
	mockStorage.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{
		ID:      1,
		OwnerID: 2,
		Name:    "test-secret",
	}, nil)
	mockStorage.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 1,
			IsGroup:     false,
			Permission:  "read", // Only read permission
			CreatedAt:   time.Now(),
		},
	}, nil)
	mockStorage.On("GetUserGroupsAt", mock.Anything, uint(1), mock.Anything).Return([]*models.Group{}, nil)
	// ACL fallback (r140): no direct grant, and no ancestor folder grant either — deny.
	mockStorage.On("GetSecretACL", mock.Anything, uint(1), uint(1)).Return(nil, errors.New("record not found"))
	mockStorage.On("GetSecretAncestors", mock.Anything, uint(1)).Return([]uint{}, nil)
	// RBAC fallback: no roles — deny.
	mockStorage.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
	mockStorage.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)

	core := NewKeyorixCore(mockStorage)

	ctx := context.Background()
	permCtx, err := core.EnforceSecretWritePermission(ctx, 1, 1)

	assert.Error(t, err) // Should fail because user only has read permission
	assert.Nil(t, permCtx)

	mockStorage.AssertExpectations(t)
}

func TestCanUserModifySecret(t *testing.T) {
	t.Parallel()
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Helper function to create test secret
	createTestSecret := func(id, ownerID uint, name string) *models.SecretNode {
		return &models.SecretNode{
			ID:      id,
			OwnerID: ownerID,
			Name:    name,
		}
	}

	// Helper function to create test share
	createTestShare := func(id, secretID, recipientID uint, permission string) *models.ShareRecord {
		return &models.ShareRecord{
			ID:          id,
			SecretID:    secretID,
			RecipientID: recipientID,
			IsGroup:     false,
			Permission:  permission,
			CreatedAt:   time.Now(),
		}
	}

	tests := []struct {
		name       string
		setupMocks func(*MockStorage)
		expected   bool
	}{
		{
			name: "Owner can modify",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("IsProjectMember", mock.Anything, uint(1), uint(0)).Return(true, nil)
			},
			expected: true,
		},
		{
			name: "User with write permission can modify",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")
				share := createTestShare(1, 1, 1, "write")

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				// #2941: a share applies only to a live member of the secret's project.
				ms.On("IsProjectMember", mock.Anything, uint(1), uint(0)).Return(true, nil)
			},
			expected: true,
		},
		{
			name: "User with read permission cannot modify",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")
				share := createTestShare(1, 1, 1, "read")

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				ms.On("GetUserGroupsAt", mock.Anything, uint(1), mock.Anything).Return([]*models.Group{}, nil)
				// ACL fallback (r140): no direct grant, and no ancestor folder grant either — deny.
				ms.On("GetSecretACL", mock.Anything, uint(1), uint(1)).Return(nil, errors.New("record not found"))
				ms.On("GetSecretAncestors", mock.Anything, uint(1)).Return([]uint{}, nil)
				// RBAC fallback: no roles — deny.
				ms.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
				ms.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorage{}
			tt.setupMocks(mockStorage)

			core := NewKeyorixCore(mockStorage)

			ctx := context.Background()
			canModify, err := core.CanUserModifySecret(ctx, 1, 1)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, canModify)

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestCanUserShareSecret(t *testing.T) {
	t.Parallel()
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Helper function to create test secret
	createTestSecret := func(id, ownerID uint, name string) *models.SecretNode {
		return &models.SecretNode{
			ID:      id,
			OwnerID: ownerID,
			Name:    name,
		}
	}

	// Helper function to create test share
	createTestShare := func(id, secretID, recipientID uint, permission string) *models.ShareRecord {
		return &models.ShareRecord{
			ID:          id,
			SecretID:    secretID,
			RecipientID: recipientID,
			IsGroup:     false,
			Permission:  permission,
			CreatedAt:   time.Now(),
		}
	}

	tests := []struct {
		name       string
		setupMocks func(*MockStorage)
		expected   bool
	}{
		{
			name: "Owner can share",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				// CheckSecretPermission gates the owner path on IsProjectMember (RBAC-001).
				ms.On("IsProjectMember", mock.Anything, uint(1), uint(0)).Return(true, nil)
			},
			expected: true,
		},
		{
			name: "Non-owner cannot share",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")
				share := createTestShare(1, 1, 1, "write")

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				ms.On("GetUserGroupsAt", mock.Anything, uint(1), mock.Anything).Return([]*models.Group{}, nil)
				// RBAC fallback: no roles — deny.
				ms.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
				ms.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorage{}
			tt.setupMocks(mockStorage)

			core := NewKeyorixCore(mockStorage)

			ctx := context.Background()
			canShare, err := core.CanUserShareSecret(ctx, 1, 1)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, canShare)

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestGetEffectivePermission(t *testing.T) {
	t.Parallel()
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Helper function to create test secret
	createTestSecret := func(id, ownerID uint, name string) *models.SecretNode {
		return &models.SecretNode{
			ID:      id,
			OwnerID: ownerID,
			Name:    name,
		}
	}

	// Helper function to create test share
	createTestShare := func(id, secretID, recipientID uint, permission string) *models.ShareRecord {
		return &models.ShareRecord{
			ID:          id,
			SecretID:    secretID,
			RecipientID: recipientID,
			IsGroup:     false,
			Permission:  permission,
			CreatedAt:   time.Now(),
		}
	}

	tests := []struct {
		name               string
		setupMocks         func(*MockStorage)
		expectedPermission PermissionLevel
	}{
		{
			name: "Owner has owner permission",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("IsProjectMember", mock.Anything, uint(1), uint(0)).Return(true, nil)
			},
			expectedPermission: PermissionOwner,
		},
		{
			name: "User with write permission",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")
				share := createTestShare(1, 1, 1, "write")

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				// #2941: a share applies only to a live member of the secret's project.
				ms.On("IsProjectMember", mock.Anything, uint(1), uint(0)).Return(true, nil)
			},
			expectedPermission: PermissionWrite,
		},
		{
			name: "User with no access",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")

				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
				ms.On("GetUserGroupsAt", mock.Anything, uint(1), mock.Anything).Return([]*models.Group{}, nil)
				// ACL fallback (r140): no direct grant, and no ancestor folder grant either — deny.
				ms.On("GetSecretACL", mock.Anything, uint(1), uint(1)).Return(nil, errors.New("record not found"))
				ms.On("GetSecretAncestors", mock.Anything, uint(1)).Return([]uint{}, nil)
				// RBAC fallback: no roles — deny.
				ms.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
				ms.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
			},
			expectedPermission: PermissionNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorage{}
			tt.setupMocks(mockStorage)

			core := NewKeyorixCore(mockStorage)

			ctx := context.Background()
			permission, err := core.GetEffectivePermission(ctx, 1, 1)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedPermission, permission)

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestCheckGroupPermissions(t *testing.T) {
	t.Parallel()
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	mockStorage := &MockStorage{}
	core := NewKeyorixCore(mockStorage)

	// Setup user groups
	mockStorage.On("GetUserGroupsAt", mock.Anything, uint(1), Scope{ProjectID: 7}).Return([]*models.Group{
		{ID: 10, Name: "group1"},
		{ID: 20, Name: "group2"},
	}, nil)

	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 10, // group1
			IsGroup:     true,
			Permission:  "read",
		},
		{
			ID:          2,
			SecretID:    1,
			RecipientID: 20, // group2
			IsGroup:     true,
			Permission:  "write",
		},
		{
			ID:          3,
			SecretID:    1,
			RecipientID: 30, // group3 (user not a member)
			IsGroup:     true,
			Permission:  "write",
		},
	}

	ctx := context.Background()
	permission, shareID, err := core.CheckGroupPermissions(ctx, 1, 1, shares, 7)

	assert.NoError(t, err)
	assert.Equal(t, PermissionWrite, permission) // Should get highest permission (write)
	assert.NotNil(t, shareID)
	assert.Equal(t, uint(2), *shareID) // Should be the write permission share

	mockStorage.AssertExpectations(t)
}

// TestCheckGroupPermissions_ProjectScopedMembershipDoesNotCrossProjects is the
// #G01 regression: a group share used to grant access to ANY member of the
// group returned by the unscoped GetUserGroups, even when that member's OWN
// membership in the group was scoped to a DIFFERENT project than the shared
// secret. CheckGroupPermissions now resolves membership via GetUserGroupsAt
// against the secret's own project, so a cross-project-scoped membership must
// not grant access. Uses a real SQLite-backed LocalStorage (not MockStorage)
// so the storage-layer scoping SQL itself is exercised, not just the mock's
// assumed behavior.
func TestCheckGroupPermissions_ProjectScopedMembershipDoesNotCrossProjects(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
		&models.User{}, &models.Group{}, &models.UserGroup{}, &models.ShareRecord{},
	))
	ls := store.NewLocalStorage(db)
	c := NewKeyorixCore(ls)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "member", Email: "m@x.io"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "team"}).Error)
	// user 2's membership in group 5 is scoped ONLY to project 7.
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 5, ProjectID: 7}).Error)

	projA, err := ls.CreateProject(ctx, &models.Project{Name: "project-a"})
	require.NoError(t, err)
	envA, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: projA.ID})
	require.NoError(t, err)
	// The secret is in a DIFFERENT project than the membership's scope (project 7).
	secret, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "cross-project-secret", ProjectID: projA.ID, EnvironmentID: envA.ID,
		Type: "password", IsSecret: true, Status: "active", OwnerID: 1,
	})
	require.NoError(t, err)
	_, err = ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, RecipientID: 5, IsGroup: true, OwnerID: 1, Permission: "write",
	})
	require.NoError(t, err)

	shares, err := ls.ListSharesBySecret(ctx, secret.ID, time.Now())
	require.NoError(t, err)
	perm, shareID, err := c.CheckGroupPermissions(ctx, secret.ID, 2, shares, projA.ID)
	require.NoError(t, err)
	assert.Equal(t, PermissionNone, perm, "a membership scoped to a different project must not grant access")
	assert.Nil(t, shareID)

	// The same membership DOES grant access to a secret actually in project 7.
	projB, err := ls.CreateProject(ctx, &models.Project{ID: 7, Name: "project-b"})
	require.NoError(t, err)
	envB, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: projB.ID})
	require.NoError(t, err)
	secretB, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "same-project-secret", ProjectID: projB.ID, EnvironmentID: envB.ID,
		Type: "password", IsSecret: true, Status: "active", OwnerID: 1,
	})
	require.NoError(t, err)
	_, err = ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secretB.ID, RecipientID: 5, IsGroup: true, OwnerID: 1, Permission: "write",
	})
	require.NoError(t, err)
	sharesB, err := ls.ListSharesBySecret(ctx, secretB.ID, time.Now())
	require.NoError(t, err)
	permB, shareIDB, err := c.CheckGroupPermissions(ctx, secretB.ID, 2, sharesB, projB.ID)
	require.NoError(t, err)
	assert.Equal(t, PermissionWrite, permB, "a membership scoped to the SAME project must still grant access")
	assert.NotNil(t, shareIDB)
}

// TestGetSecretWithPermissionCheck exercises the actual guarded read path
// (GetSecretWithPermissionCheck) that every real HTTP/gRPC caller uses to fetch a
// secret's value — as opposed to the bare GetSecret, which deliberately performs no
// authorization check of its own (see GetSecret's doc comment) and is only safe to
// call after a permission check has already happened, or for internal callers that
// enforce access some other way. Neither is exercised end-to-end anywhere else in the
// test suite: TestCheckSecretPermission and TestEnforceSecretReadPermission cover the
// permission-decision logic in isolation, but not the combined "check, then actually
// retrieve" behavior that GetSecretWithPermissionCheck wraps around it.
func TestGetSecretWithPermissionCheck(t *testing.T) {
	t.Parallel()
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	t.Run("authorized reader (owner) retrieves the secret", func(t *testing.T) {
		mockStorage := &MockStorage{}
		secret := &models.SecretNode{ID: 1, OwnerID: 1, ProjectID: 10, Name: "test-secret"}
		mockStorage.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
		mockStorage.On("IsProjectMember", mock.Anything, uint(1), uint(10)).Return(true, nil)

		core := NewKeyorixCore(mockStorage)

		got, err := core.GetSecretWithPermissionCheck(context.Background(), 1, 1)

		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, secret.ID, got.ID)

		mockStorage.AssertExpectations(t)
	})

	t.Run("authorized reader (direct share) retrieves the secret", func(t *testing.T) {
		mockStorage := &MockStorage{}
		secret := &models.SecretNode{ID: 1, OwnerID: 99, Name: "test-secret"}
		mockStorage.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
		mockStorage.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{
			{ID: 1, SecretID: 1, RecipientID: 2, IsGroup: false, Permission: "read", CreatedAt: time.Now()},
		}, nil)
		// #2941: a share applies only to a live member of the secret's project.
		mockStorage.On("IsProjectMember", mock.Anything, uint(2), uint(0)).Return(true, nil)

		core := NewKeyorixCore(mockStorage)

		got, err := core.GetSecretWithPermissionCheck(context.Background(), 1, 2)

		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, secret.ID, got.ID)

		mockStorage.AssertExpectations(t)
	})

	t.Run("unauthorized caller (no owner, no share) is rejected before retrieval", func(t *testing.T) {
		mockStorage := &MockStorage{}
		secret := &models.SecretNode{ID: 1, OwnerID: 99, Name: "test-secret"}
		mockStorage.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
		mockStorage.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
		mockStorage.On("GetUserGroupsAt", mock.Anything, uint(2), mock.Anything).Return([]*models.Group{}, nil)
		// ACL fallback (r140): no direct grant, and no ancestor folder grant either — deny.
		mockStorage.On("GetSecretACL", mock.Anything, uint(1), uint(2)).Return(nil, errors.New("record not found"))
		mockStorage.On("GetSecretAncestors", mock.Anything, uint(1)).Return([]uint{}, nil)
		// RBAC fallback: no roles — deny.
		mockStorage.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)
		mockStorage.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil)

		core := NewKeyorixCore(mockStorage)

		got, err := core.GetSecretWithPermissionCheck(context.Background(), 1, 2)

		assert.Error(t, err)
		assert.Nil(t, got)

		mockStorage.AssertExpectations(t)
	})
}

func TestPermissionLevelToRBACPerm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		level PermissionLevel
		want  string
	}{
		{PermissionRead, "secrets.read"},
		{PermissionWrite, "secrets.write"},
		{PermissionOwner, "secrets.delete"},
		{PermissionNone, ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, permissionLevelToRBACPerm(tc.level), "level=%s", tc.level)
	}
}

// TestCheckSecretPermission_ACLFallback_GrantsAccess verifies that a user
// with no ownership, share record, or project role, but a per-secret
// SecretACL grant covering the required permission, is admitted via the ACL
// fallback path (r140) with Source "acl" -- the success branch that
// TestCheckSecretPermission's own table only ever exercises the deny side of
// (every case there mocks GetSecretACL to return "not found").
func TestCheckSecretPermission_ACLFallback_GrantsAccess(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())

	mockStorage := &MockStorage{}
	secret := &models.SecretNode{
		ID: 1, OwnerID: 99, Name: "acl-fallback-secret",
		ProjectID: 5, EnvironmentID: 10,
	}
	mockStorage.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
	mockStorage.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	mockStorage.On("GetUserGroupsAt", mock.Anything, uint(8), mock.Anything).Return([]*models.Group{}, nil)
	// ACL fallback (r140): a direct grant on this exact secret covers read.
	mockStorage.On("GetSecretACL", mock.Anything, uint(1), uint(8)).Return(&models.SecretACL{
		SecretID: 1, UserID: 8, Permissions: `["secrets.read"]`,
	}, nil)
	// #G13: aclGrantsPermission now re-verifies the grantee is still a member
	// of the secret's project before honoring the grant.
	mockStorage.On("IsProjectMember", mock.Anything, uint(8), uint(5)).Return(true, nil)

	c := NewKeyorixCore(mockStorage)

	permCtx, err := c.CheckSecretPermission(context.Background(), 1, 8, PermissionRead)
	require.NoError(t, err)
	require.NotNil(t, permCtx)
	assert.Equal(t, "acl", permCtx.Source)
	assert.Equal(t, PermissionRead, permCtx.Permission)
	assert.Equal(t, uint(1), permCtx.SecretID)
	assert.Equal(t, uint(8), permCtx.UserID)
	mockStorage.AssertExpectations(t)
}

// TestCheckSecretPermission_RBACFallback_GrantsAccess verifies that a user
// with no ownership or share record but a project-scoped RBAC role granting
// secrets.read is still admitted via the RBAC fallback path (#r124).
func TestCheckSecretPermission_RBACFallback_GrantsAccess(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())

	mockStorage := &MockStorage{}
	// Secret owned by userID=99 (not our caller, userID=7)
	secret := &models.SecretNode{
		ID: 1, OwnerID: 99, Name: "rbac-fallback-secret",
		ProjectID: 5, EnvironmentID: 10,
	}
	mockStorage.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
	mockStorage.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	mockStorage.On("GetUserGroupsAt", mock.Anything, uint(7), mock.Anything).Return([]*models.Group{}, nil)
	// ACL fallback (r140): no direct grant, and no ancestor folder grant either — falls
	// through to the RBAC fallback below, proving ACL and RBAC compose correctly.
	mockStorage.On("GetSecretACL", mock.Anything, uint(1), uint(7)).Return(nil, errors.New("record not found"))
	mockStorage.On("GetSecretAncestors", mock.Anything, uint(1)).Return([]uint{}, nil)

	// RBAC fallback: user 7 has role [55] in this project scope.
	mockStorage.On("GetUserRoleIDsAt", mock.Anything, uint(7), mock.Anything).Return([]uint{55}, nil)
	mockStorage.On("GetUserGroupRoleIDsAt", mock.Anything, uint(7), mock.Anything).Return([]uint{}, nil)
	// Role 55 is not an admin role (ADR-084: no bypass flag).
	mockStorage.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{55}).Return(false, nil)
	// Role 55 grants secrets.read.
	mockStorage.On("RoleSetHasPermission", mock.Anything, []uint{55}, "secrets.read").Return(true, nil)

	c := NewKeyorixCore(mockStorage)

	permCtx, err := c.CheckSecretPermission(context.Background(), 1, 7, PermissionRead)
	require.NoError(t, err)
	require.NotNil(t, permCtx)
	assert.Equal(t, "rbac", permCtx.Source)
	assert.Equal(t, PermissionRead, permCtx.Permission)
	mockStorage.AssertExpectations(t)
}

// TestShareActive directly exercises the shareActive predicate at every expiry
// boundary case. This is a security-critical helper: a nil ExpiresAt is permanent
// (never expires), a non-nil ExpiresAt denies access the instant the clock reaches
// or passes it (using strict Before - equal means expired).
func TestShareActive(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	justBefore := now.Add(-time.Nanosecond)
	justAfter := now.Add(time.Nanosecond)

	cases := []struct {
		name      string
		expiresAt *time.Time
		now       time.Time
		want      bool
	}{
		{
			name:      "nil ExpiresAt is permanent",
			expiresAt: nil,
			now:       now,
			want:      true,
		},
		{
			name:      "future expiry is active",
			expiresAt: &justAfter,
			now:       now,
			want:      true,
		},
		{
			name:      "expiry exactly at now is expired (strict Before)",
			expiresAt: &now,
			now:       now,
			want:      false,
		},
		{
			name:      "expiry just before now is expired",
			expiresAt: &justBefore,
			now:       now,
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			share := &models.ShareRecord{ExpiresAt: tc.expiresAt}
			got := shareActive(share, tc.now)
			assert.Equal(t, tc.want, got)
		})
	}
}
