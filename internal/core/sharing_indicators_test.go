package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupTestCore(t *testing.T) *KeyorixCore {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	mockStorage := new(MockStorage)
	return &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
}

func TestBuildSharingIndicators(t *testing.T) {
	t.Parallel()
	core := setupTestCore(t)

	secret := &models.SecretNode{
		ID:   1,
		Name: "test-secret",
		Type: "password",
	}

	tests := []struct {
		name             string
		isOwner          bool
		userPermission   string
		shares           []*models.ShareRecord
		expectedIcon     string
		expectedBadge    string
		expectedColor    string
		expectedCanWrite bool
		expectedCanShare bool
	}{
		{
			name:             "Owner with no shares",
			isOwner:          true,
			userPermission:   "",
			shares:           []*models.ShareRecord{},
			expectedIcon:     "owned",
			expectedBadge:    "OWNER",
			expectedColor:    "blue",
			expectedCanWrite: true,
			expectedCanShare: true,
		},
		{
			name:           "Owner with shares",
			isOwner:        true,
			userPermission: "",
			shares: []*models.ShareRecord{
				{ID: 1, SecretID: 1, RecipientID: 2, Permission: "read", CreatedAt: time.Now()},
			},
			expectedIcon:     "shared-owner",
			expectedBadge:    "OWNER",
			expectedColor:    "green",
			expectedCanWrite: true,
			expectedCanShare: true,
		},
		{
			name:             "Shared with read permission",
			isOwner:          false,
			userPermission:   "read",
			shares:           []*models.ShareRecord{},
			expectedIcon:     "shared-read",
			expectedBadge:    "READ-ONLY",
			expectedColor:    "orange",
			expectedCanWrite: false,
			expectedCanShare: false,
		},
		{
			name:             "Shared with write permission",
			isOwner:          false,
			userPermission:   "write",
			shares:           []*models.ShareRecord{},
			expectedIcon:     "shared-write",
			expectedBadge:    "SHARED",
			expectedColor:    "blue",
			expectedCanWrite: true,
			expectedCanShare: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock user lookup for shares
			mockStorage := core.storage.(*MockStorage)
			if len(tt.shares) > 0 {
				mockStorage.On("GetUser", mock.Anything, uint(2)).Return(&models.User{
					ID:       2,
					Username: "alice",
				}, nil)
			}

			indicators := core.buildSharingIndicators(secret, tt.shares, tt.isOwner, tt.userPermission)

			assert.Equal(t, tt.expectedIcon, indicators.Icon)
			assert.Equal(t, tt.expectedBadge, indicators.Badge)
			assert.Equal(t, tt.expectedColor, indicators.BadgeColor)
			assert.Equal(t, tt.expectedCanWrite, indicators.CanWrite)
			assert.Equal(t, tt.expectedCanShare, indicators.CanShare)
			assert.True(t, indicators.CanRead) // All users with access can read
			assert.Equal(t, tt.isOwner, indicators.CanDelete)
		})
	}
}

func TestBuildShareDetails(t *testing.T) {
	t.Parallel()
	core := setupTestCore(t)

	// Mock user and group lookups
	mockStorage := core.storage.(*MockStorage)

	// Mock user lookup
	mockStorage.On("GetUser", mock.Anything, uint(2)).Return(&models.User{
		ID:       2,
		Username: "alice",
	}, nil)

	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 2,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now().Add(-1 * time.Hour), // Recent
		},
		{
			ID:          2,
			SecretID:    1,
			RecipientID: 3,
			IsGroup:     true,
			Permission:  "write",
			CreatedAt:   time.Now().Add(-10 * 24 * time.Hour), // Old
		},
	}

	details := core.buildShareDetails(shares)

	assert.Equal(t, 2, details.TotalShares)
	assert.Equal(t, 1, details.DirectShares)
	assert.Equal(t, 1, details.GroupShares)
	assert.Equal(t, "Shared with 1 users and 1 groups", details.ShareSummary)
	assert.Equal(t, "1 with read access, 1 with write access", details.PermissionText)

	// Check recent shares
	assert.Len(t, details.RecentShares, 2)

	// Check that user name was resolved
	userShare := details.RecentShares[0]
	assert.Equal(t, "alice", userShare.RecipientName)
	assert.Equal(t, "user", userShare.RecipientType)
	assert.True(t, userShare.IsRecent)

	// Check that group name shows as fallback (since group functionality is disabled)
	groupShare := details.RecentShares[1]
	assert.Equal(t, "Group 3", groupShare.RecipientName)
	assert.Equal(t, "group", groupShare.RecipientType)
	assert.False(t, groupShare.IsRecent)

	mockStorage.AssertExpectations(t)
}

func TestListSecretsWithSharingInfo(t *testing.T) {
	t.Parallel()
	core := setupTestCore(t)
	mockStorage := core.storage.(*MockStorage)

	userID := uint(1)

	// Mock owned secrets
	ownedSecret := &models.SecretNode{
		ID:      1,
		Name:    "owned-secret",
		OwnerID: userID,
		Type:    "password",
	}

	// Mock shared secret
	sharedSecret := &models.SecretNode{
		ID:      2,
		Name:    "shared-secret",
		OwnerID: 2,
		Type:    "password",
	}

	// Owned secrets are filtered by owner_id (the canonical ownership), not the
	// created_by username.
	mockStorage.On("ListSecrets", mock.Anything, mock.MatchedBy(func(filter *storage.SecretFilter) bool {
		return filter.OwnerID != nil && *filter.OwnerID == userID
	})).Return([]*models.SecretNode{ownedSecret}, int64(1), nil)

	// Mock shares for owned secret
	mockStorage.On("ListSharesBySecretIDs", mock.Anything, []uint{1}, mock.Anything).Return([]*models.ShareRecord{
		{ID: 1, SecretID: 1, RecipientID: 3, Permission: "read", CreatedAt: time.Now()},
	}, nil)
	mockStorage.On("GetUsernamesByIDs", mock.Anything, []uint{3}).Return(map[uint]string{3: "charlie"}, nil)

	// Mock user lookups for various user IDs
	mockStorage.On("GetUser", mock.Anything, uint(1)).Return(&models.User{ID: 1, Username: "owner"}, nil)

	// Mock storage calls for shared secrets
	mockStorage.On("ListSharesByUser", mock.Anything, userID).Return([]*models.ShareRecord{
		{ID: 2, SecretID: 2, RecipientID: userID, Permission: "write", CreatedAt: time.Now()},
	}, nil)

	// Mock getting shared secret
	mockStorage.On("GetSecretsByIDs", mock.Anything, []uint{2}).Return([]*models.SecretNode{sharedSecret}, nil)

	// Mock getting owner of shared secret
	mockStorage.On("GetUsernamesByIDs", mock.Anything, []uint{2}).Return(map[uint]string{2: "bob"}, nil)

	mockStorage.On("ListSecretACLsByUser", mock.Anything, userID).Return(([]*models.SecretACL)(nil), nil)

	filter := &models.SecretListFilter{
		Page:     1,
		PageSize: 10,
	}

	response, err := core.ListSecretsWithSharingInfo(context.Background(), userID, filter)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Len(t, response.Secrets, 2)
	assert.Equal(t, int64(2), response.Total)
	assert.Equal(t, 1, response.OwnedCount)
	assert.Equal(t, 1, response.SharedCount)

	// Check owned secret indicators
	ownedSecretInfo := response.Secrets[0]
	if ownedSecretInfo.ID == 1 {
		assert.True(t, ownedSecretInfo.IsOwnedByUser)
		assert.True(t, ownedSecretInfo.IsShared)
		assert.Equal(t, 1, ownedSecretInfo.ShareCount)
		assert.NotNil(t, ownedSecretInfo.SharingIndicators)
		assert.Equal(t, "shared-owner", ownedSecretInfo.SharingIndicators.Icon)
		assert.True(t, ownedSecretInfo.SharingIndicators.CanShare)
	}

	// Check shared secret indicators
	sharedSecretInfo := response.Secrets[1]
	if sharedSecretInfo.ID == 2 {
		assert.False(t, sharedSecretInfo.IsOwnedByUser)
		assert.True(t, sharedSecretInfo.IsShared)
		assert.Equal(t, "write", sharedSecretInfo.UserPermission)
		assert.Equal(t, "bob", sharedSecretInfo.OwnerUsername)
		assert.NotNil(t, sharedSecretInfo.SharingIndicators)
		assert.Equal(t, "shared-write", sharedSecretInfo.SharingIndicators.Icon)
		assert.False(t, sharedSecretInfo.SharingIndicators.CanShare)
		assert.True(t, sharedSecretInfo.SharingIndicators.CanWrite)
	}

	mockStorage.AssertExpectations(t)
}

func TestSecretListFiltering(t *testing.T) {
	t.Parallel()
	core := setupTestCore(t)
	mockStorage := core.storage.(*MockStorage)

	userID := uint(1)

	// Test filtering for owned secrets only
	t.Run("ShowOwnedOnly", func(t *testing.T) {
		ownedSecret := &models.SecretNode{
			ID:      1,
			Name:    "owned-secret",
			OwnerID: userID,
			Type:    "password",
		}

		mockStorage.On("GetUser", mock.Anything, uint(1)).Return(&models.User{ID: 1, Username: "owner"}, nil)
		mockStorage.On("ListSecrets", mock.Anything, mock.MatchedBy(func(filter *storage.SecretFilter) bool {
			return filter.OwnerID != nil && *filter.OwnerID == userID
		})).Return([]*models.SecretNode{ownedSecret}, int64(1), nil)

		mockStorage.On("ListSharesBySecretIDs", mock.Anything, []uint{1}, mock.Anything).Return([]*models.ShareRecord{}, nil)

		filter := &models.SecretListFilter{
			ShowOwnedOnly: true,
			Page:          1,
			PageSize:      10,
		}

		response, err := core.ListSecretsWithSharingInfo(context.Background(), userID, filter)

		assert.NoError(t, err)
		assert.Len(t, response.Secrets, 1)
		assert.Equal(t, 1, response.OwnedCount)
		assert.Equal(t, 0, response.SharedCount)
	})

	// Test filtering for shared secrets only
	t.Run("ShowSharedOnly", func(t *testing.T) {
		sharedSecret := &models.SecretNode{
			ID:      2,
			Name:    "shared-secret",
			OwnerID: 2,
			Type:    "password",
		}

		mockStorage.On("ListSharesByUser", mock.Anything, userID).Return([]*models.ShareRecord{
			{ID: 1, SecretID: 2, RecipientID: userID, Permission: "read", CreatedAt: time.Now()},
		}, nil)

		mockStorage.On("GetSecretsByIDs", mock.Anything, []uint{2}).Return([]*models.SecretNode{sharedSecret}, nil)
		mockStorage.On("GetUsernamesByIDs", mock.Anything, []uint{2}).Return(map[uint]string{2: "alice"}, nil)
		mockStorage.On("ListSecretACLsByUser", mock.Anything, userID).Return(([]*models.SecretACL)(nil), nil)

		filter := &models.SecretListFilter{
			ShowSharedOnly: true,
			Page:           1,
			PageSize:       10,
		}

		response, err := core.ListSecretsWithSharingInfo(context.Background(), userID, filter)

		assert.NoError(t, err)
		assert.Len(t, response.Secrets, 1)
		assert.Equal(t, 0, response.OwnedCount)
		assert.Equal(t, 1, response.SharedCount)
		assert.Equal(t, "read", response.Secrets[0].UserPermission)
	})

	mockStorage.AssertExpectations(t)
}
