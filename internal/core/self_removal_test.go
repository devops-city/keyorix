package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRemoveSelfFromShare_Success(t *testing.T) {
	t.Parallel()
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}

	ctx := context.Background()
	secretID := uint(1)
	userID := uint(2)

	// Mock data
	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 2,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
		},
	}

	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 3,
	}

	// Setup mocks
	mockStorage.On("ListSharesBySecret", ctx, secretID).Return(shares, nil)
	mockStorage.On("GetSecret", ctx, secretID).Return(secret, nil)
	mockStorage.On("DeleteShareRecord", ctx, uint(1)).Return(nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	// Execute
	err = core.RemoveSelfFromShare(ctx, secretID, userID)

	// Assert
	assert.NoError(t, err)
	mockStorage.AssertExpectations(t)
}

// TestRemoveSelfFromShare_NoPhantomAuditOnDeleteFailure locks in #283: when the
// storage delete fails, RemoveSelfFromShare must NOT have already logged a
// "share_self_removed" audit event — otherwise the trail would permanently assert
// a removal happened even though the share is still live.
func TestRemoveSelfFromShare_NoPhantomAuditOnDeleteFailure(t *testing.T) {
	t.Parallel()
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}

	ctx := context.Background()
	secretID := uint(1)
	userID := uint(2)

	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 2,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
		},
	}
	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 3,
	}

	mockStorage.On("ListSharesBySecret", ctx, secretID).Return(shares, nil)
	mockStorage.On("GetSecret", ctx, secretID).Return(secret, nil)
	mockStorage.On("DeleteShareRecord", ctx, uint(1)).Return(errors.New("storage unavailable"))

	err = core.RemoveSelfFromShare(ctx, secretID, userID)

	require.Error(t, err)
	mockStorage.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	mockStorage.AssertExpectations(t)
}

func TestRemoveSelfFromShare_ShareNotFound(t *testing.T) {
	t.Parallel()
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}

	ctx := context.Background()
	secretID := uint(1)
	userID := uint(2)

	// Mock data - no shares for this user
	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 3, // Different user
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
		},
	}

	// Setup mocks
	mockStorage.On("ListSharesBySecret", ctx, secretID).Return(shares, nil)

	// Execute
	err = core.RemoveSelfFromShare(ctx, secretID, userID)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Share not found")
	mockStorage.AssertExpectations(t)
}

// TestRemoveSelfFromShare_GroupShareNotSelfRemovable locks in the `!share.IsGroup`
// guard: a share whose RecipientID matches the caller but is a GROUP share grants
// access via group membership, not a direct user share. Self-remove must skip it and
// return "share not found" — deleting it would remove the secret for the whole group.
func TestRemoveSelfFromShare_GroupShareNotSelfRemovable(t *testing.T) {
	t.Parallel()
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}

	ctx := context.Background()
	secretID := uint(1)
	userID := uint(2)

	// The only share has RecipientID == userID but is a GROUP share.
	shares := []*models.ShareRecord{
		{
			ID:          9,
			SecretID:    1,
			RecipientID: 2,
			IsGroup:     true,
			Permission:  "read",
			CreatedAt:   time.Now(),
		},
	}

	mockStorage.On("ListSharesBySecret", ctx, secretID).Return(shares, nil)

	err = core.RemoveSelfFromShare(ctx, secretID, userID)

	// The group share must be skipped (not found) and never deleted.
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Share not found")
	mockStorage.AssertNotCalled(t, "DeleteShareRecord", mock.Anything, mock.Anything)
	mockStorage.AssertExpectations(t)
}

func TestRemoveSelfFromShare_ValidationErrors(t *testing.T) {
	t.Parallel()
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}

	ctx := context.Background()

	// Test invalid secret ID
	err = core.RemoveSelfFromShare(ctx, 0, 2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")

	// Test invalid user ID
	err = core.RemoveSelfFromShare(ctx, 1, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestRemoveSelfFromShare_AuditLogging(t *testing.T) {
	t.Parallel()
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}

	ctx := context.Background()
	secretID := uint(1)
	userID := uint(2)

	// Mock data
	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 2,
			IsGroup:     false,
			Permission:  "write",
			CreatedAt:   time.Now(),
		},
	}

	secret := &models.SecretNode{
		ID:      1,
		Name:    "audit-test-secret",
		OwnerID: 3,
	}

	// Setup mocks
	mockStorage.On("ListSharesBySecret", ctx, secretID).Return(shares, nil)
	mockStorage.On("GetSecret", ctx, secretID).Return(secret, nil)
	mockStorage.On("DeleteShareRecord", ctx, uint(1)).Return(nil)

	// Verify audit event details
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(event *models.AuditEvent) bool {
		return event.EventType == "share_self_removed" &&
			event.UserID != nil &&
			*event.UserID == userID &&
			event.SecretNodeID != nil &&
			*event.SecretNodeID == secretID &&
			event.Description == "User removed themselves from shared secret (permission: write) (share 1)" // #2941: names the share
	})).Return(nil)

	// Execute
	err = core.RemoveSelfFromShare(ctx, secretID, userID)

	// Assert
	assert.NoError(t, err)
	mockStorage.AssertExpectations(t)
}
