package core

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	if err := i18n.InitializeForTesting(); err != nil {
		panic("failed to initialize i18n for tests: " + err.Error())
	}
	// bcrypt_cost.go's own doc comment asks for exactly this: "Production
	// default is 12. Tests should call SetBcryptCostForTesting(bcrypt.MinCost)
	// in TestMain to avoid slowing down the test suite." Until now only
	// server/http/handlers did. Cost 12 is 2^8 = 256x the work of MinCost, and
	// this package hashes on every user create, password change and SCIM
	// provision -- plus once per failed-login test, because auth.go hashes
	// dummyBcryptHash as a timing equaliser on the user-not-found path.
	SetBcryptCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}

func TestKeyorixCore_ShareSecret(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 1,
	}
	shareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
	}
	req := &ShareSecretRequest{
		SecretID:    1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
		SharedBy:    1,
	}

	// Mock expectations
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	// ShareSecret verifies the owner is still a live project member (RBAC-001) as
	// well as that the recipient is a member of the secret's project.
	mockStorage.On("IsProjectMember", ctx, uint(1), uint(0)).Return(true, nil)
	mockStorage.On("IsProjectMember", ctx, uint(2), uint(0)).Return(true, nil)
	mockStorage.On("CreateShareRecord", ctx, mock.AnythingOfType("*models.ShareRecord")).Return(shareRecord, nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)
	// A direct share notifies the recipient (best-effort).
	mockStorage.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(&models.Notification{}, nil)

	// Execute
	result, err := core.ShareSecret(ctx, req)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shareRecord, result)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ShareSecret_ValidationError(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test cases
	testCases := []struct {
		name    string
		req     *ShareSecretRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "missing secret ID",
			req: &ShareSecretRequest{
				RecipientID: 2,
				Permission:  "read",
				SharedBy:    1,
			},
			wantErr: true,
		},
		{
			name: "missing recipient ID",
			req: &ShareSecretRequest{
				SecretID:   1,
				Permission: "read",
				SharedBy:   1,
			},
			wantErr: true,
		},
		{
			name: "invalid permission",
			req: &ShareSecretRequest{
				SecretID:    1,
				RecipientID: 2,
				Permission:  "invalid",
				SharedBy:    1,
			},
			wantErr: true,
		},
		{
			name: "missing sharedBy",
			req: &ShareSecretRequest{
				SecretID:    1,
				RecipientID: 2,
				Permission:  "read",
			},
			wantErr: true,
		},
		{
			// #252: a user cannot share a secret with themselves — meaningless at
			// best and a landmine (inflated share/audit counts, risk-scoring noise)
			// at worst.
			name: "self-share rejected",
			req: &ShareSecretRequest{
				SecretID:    1,
				RecipientID: 1,
				Permission:  "read",
				SharedBy:    1,
			},
			wantErr: true,
		},
	}

	// Execute and assert
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := core.ShareSecret(ctx, tc.req)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKeyorixCore_ShareSecret_StorageError(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	req := &ShareSecretRequest{
		SecretID:    1,
		RecipientID: 2,
		Permission:  "read",
		SharedBy:    1,
	}

	// Mock expectations - secret not found
	mockStorage.On("GetSecret", ctx, uint(1)).Return(nil, errors.New("secret not found"))

	// Execute
	_, err := core.ShareSecret(ctx, req)

	// Assert
	assert.Error(t, err)
	mockStorage.AssertExpectations(t)
}

// #252: ShareSecret must reject a self-share (RecipientID == SharedBy) — the
// storage layer must never be reached — while still allowing an ordinary share to
// a different user to proceed normally.
func TestKeyorixCore_ShareSecret_RejectsSelfShare(t *testing.T) {
	t.Parallel()
	mockStorage := new(MockStorage)
	core := &KeyorixCore{storage: mockStorage}
	ctx := context.Background()

	selfShareReq := &ShareSecretRequest{
		SecretID:    1,
		RecipientID: 1,
		IsGroup:     false,
		Permission:  "read",
		SharedBy:    1,
	}
	_, err := core.ShareSecret(ctx, selfShareReq)
	require.Error(t, err, "sharing a secret with yourself must be rejected")
	// No storage calls at all — validation must fail before GetSecret/CreateShareRecord.
	mockStorage.AssertNotCalled(t, "GetSecret", mock.Anything, mock.Anything)
	mockStorage.AssertNotCalled(t, "CreateShareRecord", mock.Anything, mock.Anything)

	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core.now = func() time.Time { return mockTime }

	// A normal share to a different user still succeeds.
	otherSecret := &models.SecretNode{ID: 3, Name: "s2", OwnerID: 1}
	otherShareRecord := &models.ShareRecord{ID: 4, SecretID: 3, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}
	mockStorage.On("GetSecret", ctx, uint(3)).Return(otherSecret, nil)
	mockStorage.On("IsProjectMember", ctx, uint(1), uint(0)).Return(true, nil) // owner's live membership
	mockStorage.On("IsProjectMember", ctx, uint(2), uint(0)).Return(true, nil)
	mockStorage.On("CreateShareRecord", ctx, mock.MatchedBy(func(s *models.ShareRecord) bool {
		return s.SecretID == 3 && !s.IsGroup
	})).Return(otherShareRecord, nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)
	mockStorage.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(&models.Notification{}, nil)
	normalReq := &ShareSecretRequest{
		SecretID:    3,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
		SharedBy:    1,
	}
	result, err := core.ShareSecret(ctx, normalReq)
	require.NoError(t, err, "an ordinary share to a different user must still succeed")
	assert.Equal(t, otherShareRecord, result)
}

// #3422: core ShareSecret must refuse IsGroup. It has no group-scope check (that is
// ShareSecretWithGroup's IsGroupProjectScoped), so accepting IsGroup here would let a
// future caller share a secret with a group that holds no role in the secret's project.
func TestKeyorixCore_ShareSecret_RejectsGroupShare(t *testing.T) {
	t.Parallel()
	for _, recipient := range []uint{1, 7} { // 1 coincides with SharedBy, 7 does not
		mockStorage := new(MockStorage)
		core := &KeyorixCore{storage: mockStorage}
		_, err := core.ShareSecret(context.Background(), &ShareSecretRequest{
			SecretID:    1,
			RecipientID: recipient,
			IsGroup:     true,
			Permission:  "read",
			SharedBy:    1,
		})
		require.Error(t, err, "a group share through ShareSecret must be refused")
		assert.Contains(t, err.Error(), "ShareSecretWithGroup")
		// Refused before any lookup or write: nothing is persisted, nothing is audited.
		mockStorage.AssertNotCalled(t, "GetSecret", mock.Anything, mock.Anything)
		mockStorage.AssertNotCalled(t, "CreateShareRecord", mock.Anything, mock.Anything)
		mockStorage.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	}
}

func TestKeyorixCore_UpdateSharePermission(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 1,
	}
	shareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
	}
	updatedShareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "write", // Updated permission
	}
	req := &UpdateShareRequest{
		ShareID:    1,
		Permission: "write",
		UpdatedBy:  1,
	}

	// Mock expectations
	mockStorage.On("GetShareRecord", ctx, uint(1)).Return(shareRecord, nil)
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	// UpdateSharePermission verifies the owner is still a live project member (RBAC-001).
	mockStorage.On("IsProjectMember", ctx, uint(1), uint(0)).Return(true, nil)
	mockStorage.On("UpdateShareRecord", ctx, mock.AnythingOfType("*models.ShareRecord")).Return(updatedShareRecord, nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	// Execute
	result, err := core.UpdateSharePermission(ctx, req)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, updatedShareRecord, result)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_RevokeShare(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 1,
	}
	shareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
	}

	// Mock expectations
	mockStorage.On("GetShareRecord", ctx, uint(1)).Return(shareRecord, nil)
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	// RevokeShare verifies the owner is still a live project member (RBAC-001).
	mockStorage.On("IsProjectMember", ctx, uint(1), uint(0)).Return(true, nil)
	mockStorage.On("DeleteShareRecord", ctx, uint(1)).Return(nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)
	// Revoking a direct share notifies the recipient (best-effort).
	mockStorage.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(&models.Notification{}, nil)

	// Execute
	err := core.RevokeShare(ctx, 1, 1)

	// Assert
	require.NoError(t, err)
	mockStorage.AssertExpectations(t)
}

// TestKeyorixCore_RevokeShare_NoPhantomAuditOnDeleteFailure locks in #283: when
// storage.DeleteShareRecord fails, RevokeShare must return the error to the
// caller and must NOT have already written a "share_revoked" audit event — a
// phantom revoke record while the share stays live is worse than no record.
func TestKeyorixCore_RevokeShare_NoPhantomAuditOnDeleteFailure(t *testing.T) {
	t.Parallel()
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := context.Background()

	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 1,
	}
	shareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
	}

	mockStorage.On("GetShareRecord", ctx, uint(1)).Return(shareRecord, nil)
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	// RevokeShare verifies the owner is still a live project member (RBAC-001).
	mockStorage.On("IsProjectMember", ctx, uint(1), uint(0)).Return(true, nil)
	mockStorage.On("DeleteShareRecord", ctx, uint(1)).Return(errors.New("storage unavailable"))

	err := core.RevokeShare(ctx, 1, 1)

	require.Error(t, err)
	mockStorage.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	mockStorage.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ListSharedSecrets(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := context.Background()

	// Test data
	secrets := []*models.SecretNode{
		{ID: 1, Name: "secret1"},
		{ID: 2, Name: "secret2"},
	}

	// Mock expectations
	mockStorage.On("ListSharedSecrets", ctx, uint(1)).Return(secrets, nil)

	// Execute
	result, err := core.ListSharedSecrets(ctx, 1)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, secrets, result)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ListSecretShares(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := context.Background()

	// Test data
	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 1,
	}
	shares := []*models.ShareRecord{
		{ID: 1, SecretID: 1, RecipientID: 2, Permission: "read"},
		{ID: 2, SecretID: 1, RecipientID: 3, Permission: "write"},
	}

	// Mock expectations
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	mockStorage.On("ListSharesBySecret", ctx, uint(1)).Return(shares, nil)

	// Execute
	result, err := core.ListSecretShares(ctx, 1)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shares, result)
	mockStorage.AssertExpectations(t)
}

// ListSecretShares must drop expired time-bound shares so the list matches what
// actually authorizes (the enforcement paths filter the same way).
func TestKeyorixCore_ListSecretShares_FiltersExpired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	mockStorage := new(MockStorage)
	core := &KeyorixCore{storage: mockStorage, now: func() time.Time { return now }}
	ctx := context.Background()

	mockStorage.On("GetSecret", ctx, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 1}, nil)
	mockStorage.On("ListSharesBySecret", ctx, uint(1)).Return([]*models.ShareRecord{
		{ID: 1, SecretID: 1, RecipientID: 2, Permission: "read"},                     // permanent
		{ID: 2, SecretID: 1, RecipientID: 3, Permission: "read", ExpiresAt: &past},   // expired → dropped
		{ID: 3, SecretID: 1, RecipientID: 4, Permission: "read", ExpiresAt: &future}, // live time-bound
	}, nil)

	result, err := core.ListSecretShares(ctx, 1)
	require.NoError(t, err)
	ids := make([]uint, 0, len(result))
	for _, s := range result {
		ids = append(ids, s.ID)
	}
	assert.Equal(t, []uint{1, 3}, ids, "the expired share is excluded")
}

func TestKeyorixCore_ListSharesByUser(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := context.Background()

	// Test data
	shares := []*models.ShareRecord{
		{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 2, Permission: "read"},
		{ID: 2, SecretID: 2, OwnerID: 1, RecipientID: 3, Permission: "write"},
	}

	// Mock expectations
	mockStorage.On("ListSharesByUser", ctx, uint(1)).Return(shares, nil)
	mockStorage.On("ListSharesByOwner", ctx, uint(1)).Return([]*models.ShareRecord{}, nil)

	// Execute
	result, err := core.ListSharesByUser(ctx, 1)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shares, result)
	mockStorage.AssertExpectations(t)
}

// TestKeyorixCore_ShareSecret_DepartedOwnerDenied is the regression test for the
// RBAC-001 gap in sharing.go (adversarial-review finding core-sharing.json#1): an
// owner who created a secret then left the secret's project (removed from
// membership; OwnerID on the secret row is untouched) must no longer be able to
// share it — mirrors CheckSecretPermission's owner branch. A still-live owner must
// be unaffected.
func TestKeyorixCore_ShareSecret_DepartedOwnerDenied(t *testing.T) {
	t.Parallel()
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	secret := &models.SecretNode{ID: 1, Name: "test-secret", OwnerID: 1, ProjectID: 5}
	req := &ShareSecretRequest{SecretID: 1, RecipientID: 2, Permission: "read", SharedBy: 1}

	t.Run("departed owner is denied", func(t *testing.T) {
		mockStorage := new(MockStorage)
		core := &KeyorixCore{storage: mockStorage, now: func() time.Time { return mockTime }}
		ctx := context.Background()
		mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
		// The owner no longer holds a live role grant in the secret's project.
		mockStorage.On("IsProjectMember", ctx, uint(1), uint(5)).Return(false, nil)

		_, err := core.ShareSecret(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), i18n.T("ErrorPermissionDenied", nil))
		mockStorage.AssertNotCalled(t, "CreateShareRecord", mock.Anything, mock.Anything)
	})

	t.Run("live owner still succeeds", func(t *testing.T) {
		mockStorage := new(MockStorage)
		core := &KeyorixCore{storage: mockStorage, now: func() time.Time { return mockTime }}
		ctx := context.Background()
		shareRecord := &models.ShareRecord{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 2, Permission: "read"}
		mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
		mockStorage.On("IsProjectMember", ctx, uint(1), uint(5)).Return(true, nil)
		mockStorage.On("IsProjectMember", ctx, uint(2), uint(5)).Return(true, nil)
		mockStorage.On("CreateShareRecord", ctx, mock.AnythingOfType("*models.ShareRecord")).Return(shareRecord, nil)
		mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)
		mockStorage.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(&models.Notification{}, nil)

		result, err := core.ShareSecret(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, shareRecord, result)
	})
}

// TestKeyorixCore_UpdateSharePermission_DepartedOwnerDenied is the RBAC-001
// regression test for UpdateSharePermission — see
// TestKeyorixCore_ShareSecret_DepartedOwnerDenied.
func TestKeyorixCore_UpdateSharePermission_DepartedOwnerDenied(t *testing.T) {
	t.Parallel()
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	secret := &models.SecretNode{ID: 1, Name: "test-secret", OwnerID: 1, ProjectID: 5}
	shareRecord := &models.ShareRecord{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}
	req := &UpdateShareRequest{ShareID: 1, Permission: "write", UpdatedBy: 1}

	t.Run("departed owner is denied", func(t *testing.T) {
		mockStorage := new(MockStorage)
		core := &KeyorixCore{storage: mockStorage, now: func() time.Time { return mockTime }}
		ctx := context.Background()
		mockStorage.On("GetShareRecord", ctx, uint(1)).Return(shareRecord, nil)
		mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
		mockStorage.On("IsProjectMember", ctx, uint(1), uint(5)).Return(false, nil)

		_, err := core.UpdateSharePermission(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), i18n.T("ErrorPermissionDenied", nil))
		mockStorage.AssertNotCalled(t, "UpdateShareRecord", mock.Anything, mock.Anything)
	})

	t.Run("live owner still succeeds", func(t *testing.T) {
		mockStorage := new(MockStorage)
		core := &KeyorixCore{storage: mockStorage, now: func() time.Time { return mockTime }}
		ctx := context.Background()
		updatedShareRecord := &models.ShareRecord{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "write"}
		mockStorage.On("GetShareRecord", ctx, uint(1)).Return(shareRecord, nil)
		mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
		mockStorage.On("IsProjectMember", ctx, uint(1), uint(5)).Return(true, nil)
		mockStorage.On("UpdateShareRecord", ctx, mock.AnythingOfType("*models.ShareRecord")).Return(updatedShareRecord, nil)
		mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

		result, err := core.UpdateSharePermission(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, updatedShareRecord, result)
	})
}

// TestKeyorixCore_RevokeShare_DepartedOwnerDenied is the RBAC-001 regression test
// for RevokeShare — see TestKeyorixCore_ShareSecret_DepartedOwnerDenied.
func TestKeyorixCore_RevokeShare_DepartedOwnerDenied(t *testing.T) {
	t.Parallel()
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	secret := &models.SecretNode{ID: 1, Name: "test-secret", OwnerID: 1, ProjectID: 5}
	shareRecord := &models.ShareRecord{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}

	t.Run("departed owner is denied", func(t *testing.T) {
		mockStorage := new(MockStorage)
		core := &KeyorixCore{storage: mockStorage, now: func() time.Time { return mockTime }}
		ctx := context.Background()
		mockStorage.On("GetShareRecord", ctx, uint(1)).Return(shareRecord, nil)
		mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
		mockStorage.On("IsProjectMember", ctx, uint(1), uint(5)).Return(false, nil)

		err := core.RevokeShare(ctx, 1, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), i18n.T("ErrorPermissionDenied", nil))
		mockStorage.AssertNotCalled(t, "DeleteShareRecord", mock.Anything, mock.Anything)
	})

	t.Run("live owner still succeeds", func(t *testing.T) {
		mockStorage := new(MockStorage)
		core := &KeyorixCore{storage: mockStorage, now: func() time.Time { return mockTime }}
		ctx := context.Background()
		mockStorage.On("GetShareRecord", ctx, uint(1)).Return(shareRecord, nil)
		mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
		mockStorage.On("IsProjectMember", ctx, uint(1), uint(5)).Return(true, nil)
		mockStorage.On("DeleteShareRecord", ctx, uint(1)).Return(nil)
		mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)
		mockStorage.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(&models.Notification{}, nil)

		err := core.RevokeShare(ctx, 1, 1)
		require.NoError(t, err)
	})
}

func TestKeyorixCore_CheckSharePermission(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := context.Background()

	// Mock expectations
	mockStorage.On("CheckSharePermission", ctx, uint(1), uint(2)).Return("read", nil)

	// Execute
	permission, err := core.CheckSharePermission(ctx, 1, 2)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "read", permission)
	mockStorage.AssertExpectations(t)
}
