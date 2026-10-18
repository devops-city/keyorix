package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestKeyorixCore_ShareSecretWithGroup(t *testing.T) {
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
		RecipientID: 2, // Group ID
		IsGroup:     true,
		Permission:  "read",
	}
	req := &GroupShareSecretRequest{
		SecretID:   1,
		GroupID:    2,
		Permission: "read",
		SharedBy:   1,
	}

	// Mock expectations
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	// ShareSecretWithGroup verifies the owner is still a live project member (RBAC-001).
	mockStorage.On("IsProjectMember", ctx, uint(1), uint(0)).Return(true, nil)
	// ShareSecretWithGroup verifies the group is scoped to the secret's project.
	mockStorage.On("IsGroupProjectScoped", ctx, uint(2), uint(0)).Return(true, nil)
	mockStorage.On("CreateShareRecord", ctx, mock.AnythingOfType("*models.ShareRecord")).Return(shareRecord, nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	// Execute
	result, err := core.ShareSecretWithGroup(ctx, req)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shareRecord, result)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ShareSecretWithGroup_ValidationError(t *testing.T) {
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

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := context.Background()

	// Test cases
	testCases := []struct {
		name    string
		req     *GroupShareSecretRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "missing secret ID",
			req: &GroupShareSecretRequest{
				GroupID:    2,
				Permission: "read",
				SharedBy:   1,
			},
			wantErr: true,
		},
		{
			name: "missing group ID",
			req: &GroupShareSecretRequest{
				SecretID:   1,
				Permission: "read",
				SharedBy:   1,
			},
			wantErr: true,
		},
		{
			name: "invalid permission",
			req: &GroupShareSecretRequest{
				SecretID:   1,
				GroupID:    2,
				Permission: "invalid",
				SharedBy:   1,
			},
			wantErr: true,
		},
		{
			name: "missing sharedBy",
			req: &GroupShareSecretRequest{
				SecretID:   1,
				GroupID:    2,
				Permission: "read",
			},
			wantErr: true,
		},
	}

	// Execute and assert
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := core.ShareSecretWithGroup(ctx, tc.req)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKeyorixCore_ShareSecretWithGroup_StorageError(t *testing.T) {
	t.Parallel()
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := context.Background()

	// Test data
	req := &GroupShareSecretRequest{
		SecretID:   1,
		GroupID:    2,
		Permission: "read",
		SharedBy:   1,
	}

	// Mock expectations - secret not found
	mockStorage.On("GetSecret", ctx, uint(1)).Return(nil, errors.New("secret not found"))

	// Execute
	_, err := core.ShareSecretWithGroup(ctx, req)

	// Assert
	assert.Error(t, err)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ListGroupShares(t *testing.T) {
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
		{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: true, Permission: "read"},
		{ID: 2, SecretID: 2, OwnerID: 1, RecipientID: 2, IsGroup: true, Permission: "write"},
	}

	// Mock expectations
	stubAuthorizedPrincipal(mockStorage, 1, Scope{}, permSecretsRead)
	mockStorage.On("ListSharesByGroup", ctx, uint(2)).Return(shares, nil)

	// Execute
	result, err := core.ListGroupShares(ctx, ActorTypeUser, 1, 2)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shares, result)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ListGroupShares_ValidationError(t *testing.T) {
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

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := context.Background()

	// Execute
	_, err = core.ListGroupShares(ctx, ActorTypeUser, 1, 0)

	// Assert
	assert.Error(t, err)
}

func TestKeyorixCore_ListGroupSharedSecrets(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: func() time.Time { return now }}
	ctx := context.Background()

	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	shares := []*models.ShareRecord{
		{ID: 1, SecretID: 1, RecipientID: 2, IsGroup: true, Permission: "read"},                     // live
		{ID: 2, SecretID: 1, RecipientID: 2, IsGroup: true, Permission: "write"},                    // dup secret → deduped
		{ID: 3, SecretID: 2, RecipientID: 2, IsGroup: true, Permission: "read", ExpiresAt: &past},   // expired → excluded
		{ID: 4, SecretID: 3, RecipientID: 2, IsGroup: true, Permission: "read", ExpiresAt: &future}, // live time-bound
		{ID: 5, SecretID: 4, RecipientID: 2, IsGroup: true, Permission: "read"},                     // secret gone → skipped
	}
	stubAuthorizedPrincipal(ms, 1, Scope{}, permSecretsRead)
	ms.On("ListSharesByGroup", ctx, uint(2)).Return(shares, nil)
	ms.On("GetSecret", ctx, uint(1)).Return(&models.SecretNode{ID: 1, Name: "alpha"}, nil)
	ms.On("GetSecret", ctx, uint(3)).Return(&models.SecretNode{ID: 3, Name: "gamma"}, nil)
	ms.On("GetSecret", ctx, uint(4)).Return((*models.SecretNode)(nil), errors.New("not found"))

	result, err := c.ListGroupSharedSecrets(ctx, ActorTypeUser, 1, 2)
	require.NoError(t, err)

	ids := make([]uint, 0, len(result))
	for _, s := range result {
		ids = append(ids, s.ID)
	}
	assert.Equal(t, []uint{1, 3}, ids, "live + future shares only, deduped, missing skipped")
	// The expired share's secret is never even loaded.
	ms.AssertNotCalled(t, "GetSecret", ctx, uint(2))
}

func TestKeyorixCore_ListGroupSharedSecrets_ValidationError(t *testing.T) {
	t.Parallel()
	c := &KeyorixCore{storage: new(MockStorage), now: time.Now}
	_, err := c.ListGroupSharedSecrets(context.Background(), ActorTypeUser, 1, 0)
	assert.Error(t, err)
}

// TestShareSecretWithGroup_DepartedOwnerDenied is the RBAC-001 regression test for
// ShareSecretWithGroup (adversarial-review finding core-sharing.json#1): an owner
// who created a secret then left the secret's project (removed from membership;
// OwnerID on the secret row is untouched) must no longer be able to group-share it
// — mirrors CheckSecretPermission's owner branch. A still-live owner is unaffected.
func TestShareSecretWithGroup_DepartedOwnerDenied(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	secret := &models.SecretNode{ID: 1, Name: "test-secret", OwnerID: 1, ProjectID: 5}
	req := &GroupShareSecretRequest{SecretID: 1, GroupID: 2, Permission: "read", SharedBy: 1}

	t.Run("departed owner is denied", func(t *testing.T) {
		ms := new(MockStorage)
		c := &KeyorixCore{storage: ms, now: time.Now}
		ctx := context.Background()
		ms.On("GetSecret", ctx, uint(1)).Return(secret, nil)
		// The owner no longer holds a live role grant in the secret's project.
		ms.On("IsProjectMember", ctx, uint(1), uint(5)).Return(false, nil)

		_, err := c.ShareSecretWithGroup(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not authorized")
		ms.AssertNotCalled(t, "CreateShareRecord", mock.Anything, mock.Anything)
	})

	t.Run("live owner still succeeds", func(t *testing.T) {
		ms := new(MockStorage)
		mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
		c := &KeyorixCore{storage: ms, now: func() time.Time { return mockTime }}
		ctx := context.Background()
		shareRecord := &models.ShareRecord{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: true, Permission: "read"}
		ms.On("GetSecret", ctx, uint(1)).Return(secret, nil)
		ms.On("IsProjectMember", ctx, uint(1), uint(5)).Return(true, nil)
		// ShareSecretWithGroup also verifies the group is scoped to the secret's project.
		ms.On("IsGroupProjectScoped", ctx, uint(2), uint(5)).Return(true, nil)
		ms.On("CreateShareRecord", ctx, mock.AnythingOfType("*models.ShareRecord")).Return(shareRecord, nil)
		ms.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

		result, err := c.ShareSecretWithGroup(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, shareRecord, result)
	})
}

// Regression (security review): a non-owner must not be able to group-share a
// secret they don't own, even with secrets.write — the owner check in
// ShareSecretWithGroup enforces it (previously missing).
func TestShareSecretWithGroup_NonOwnerDenied(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 1}, nil)

	_, err := c.ShareSecretWithGroup(context.Background(), &GroupShareSecretRequest{
		SecretID: 1, GroupID: 2, Permission: "read", SharedBy: 99, // not the owner
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
	ms.AssertNotCalled(t, "CreateShareRecord", mock.Anything, mock.Anything)
}

// TestShareSecretWithGroup_CrossProjectRefused is the regression test for
// findings-core/core-sharing.json#2: ShareSecretWithGroup used to grant
// standing access to an arbitrary GroupID with no check tying that group to
// the secret's project — unlike ShareSecret's direct-user path, which already
// rejects cross-project recipients. The exploit: a secret owner shares with a
// group that belongs to a completely different project, permanently exposing
// the secret to every current and future member of that unrelated group, with
// no project boundary enforced anywhere downstream (CheckGroupPermissions
// checks group membership only, never project affiliation). Uses the real
// sqlite-backed LocalStorage (no mocks) so the assertions exercise the actual
// group-role-scope query, not a hand-rolled double.
func TestShareSecretWithGroup_CrossProjectRefused(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		// AuditEvent: a share commits with its audit row (AUDIT-TX-2).
		&models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.GroupRole{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@t.com"}).Error)

	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	ctx := context.Background()

	// Secret S lives in project A (1).
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	// ShareSecretWithGroup also gates the owner on live project membership
	// (RBAC-001, requireLiveOwnerAuthority) — give user 1 a project-scoped role,
	// or every call below fails before ever reaching the group-scope check this
	// test exercises. models.Role isn't migrated in this fixture (RoleID is an
	// unenforced FK here, matching the GroupRole grants below), so no Role row
	// is needed.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)

	// Group G belongs to a COMPLETELY DIFFERENT project (B, 2) — the exact
	// exploit scenario from the finding: G has no relationship to project A.
	require.NoError(t, db.Create(&models.Group{ID: 20, Name: "other-project-group"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 20, RoleID: 1, ProjectID: 2}).Error)

	_, err = c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{
		SecretID: secret.ID, GroupID: 20, Permission: "read", SharedBy: 1,
	})
	require.Error(t, err, "sharing a secret with a group from an unrelated project must be refused")

	shares, lerr := c.storage.ListSharesBySecret(ctx, secret.ID, time.Now())
	require.NoError(t, lerr)
	assert.Empty(t, shares, "the refused cross-project group share must not have been persisted")

	// A group with NO project scope at all must be refused too — there is no
	// legitimate tie to project A to fall back on.
	require.NoError(t, db.Create(&models.Group{ID: 21, Name: "unscoped-group"}).Error)
	_, err = c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{
		SecretID: secret.ID, GroupID: 21, Permission: "read", SharedBy: 1,
	})
	require.Error(t, err, "a group with no project scope at all must be refused")

	// Sharing with a group that IS scoped to the secret's own project (A, 1)
	// must still work.
	require.NoError(t, db.Create(&models.Group{ID: 22, Name: "same-project-group"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 22, RoleID: 1, ProjectID: 1}).Error)
	rec, err := c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{
		SecretID: secret.ID, GroupID: 22, Permission: "read", SharedBy: 1,
	})
	require.NoError(t, err, "sharing with a group scoped to the secret's own project must succeed")
	assert.Equal(t, uint(22), rec.RecipientID)
}
