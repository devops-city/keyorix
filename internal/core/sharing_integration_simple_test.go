package core

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// sharingIntegrationDBSeq makes each in-memory DB unique within the process
// so that repeated invocations (e.g. `go test -count=N`) don't attach to the
// same SQLite shared-cache in-memory database left open by a prior iteration.
var sharingIntegrationDBSeq atomic.Int64

// TestSharingIntegrationSimple tests the complete sharing workflow with real storage
func TestSharingIntegrationSimple(t *testing.T) {
	t.Parallel()
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	// Note: do not defer ResetForTesting here — TestMain owns the i18n lifecycle for this package

	// Create test database (in-memory for isolation).
	// Use WAL journal mode to allow concurrent reads alongside writes,
	// and limit to a single connection so SQLite doesn't deadlock itself.
	dsn := fmt.Sprintf("file:kx_sharing_simple_%d?mode=memory&cache=shared&_journal_mode=WAL", sharingIntegrationDBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, err)

	// Auto-migrate tables
	err = db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.AuditEvent{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
	)
	require.NoError(t, err)

	// Seed users and groups required by CreateShareRecord validation
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@test.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "recipient", Email: "recipient@test.com"}).Error)
	for i := 10; i <= 20; i++ {
		require.NoError(t, db.Create(&models.User{ID: uint(i), Username: fmt.Sprintf("user%d", i), Email: fmt.Sprintf("user%d@test.com", i)}).Error)
	}
	// ShareSecret verifies recipient is a project member (RBAC-001); seed all test users in project 1.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)
	for i := 10; i <= 20; i++ {
		require.NoError(t, db.Create(&models.UserRole{UserID: uint(i), RoleID: 1, ProjectID: 1}).Error)
	}
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "test-group"}).Error)
	// ShareSecretWithGroup verifies the group is scoped to the secret's project (1).
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1, ProjectID: 1}).Error)

	// Initialize storage
	storage := store.NewLocalStorage(db)

	// Create core service (without encryption for simplicity)
	core := &KeyorixCore{
		storage: storage,
		now:     time.Now,
	}

	ctx := context.Background()

	t.Run("Complete Sharing Workflow", func(t *testing.T) {
		// Step 1: Create a secret
		secret := &models.SecretNode{
			Name:          "integration-test-secret",
			ProjectID:     1,
			EnvironmentID: 1,
			Type:          "password",
			OwnerID:       1,
			IsSecret:      true,
			Metadata:      models.JSON(`{"test": "integration"}`),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		createdSecret, err := storage.CreateSecret(ctx, secret)
		require.NoError(t, err)
		secretID := createdSecret.ID

		// Step 2: Share the secret
		shareReq := &ShareSecretRequest{
			SecretID:    secretID,
			RecipientID: 2,
			IsGroup:     false,
			Permission:  "read",
			SharedBy:    1,
		}

		shareRecord, err := core.ShareSecret(ctx, shareReq)
		require.NoError(t, err)
		assert.Equal(t, secretID, shareRecord.SecretID)
		assert.Equal(t, uint(2), shareRecord.RecipientID)
		assert.Equal(t, "read", shareRecord.Permission)

		// Step 3: Verify shared secrets list
		sharedSecrets, err := core.ListSharedSecrets(ctx, 2)
		require.NoError(t, err)
		assert.Len(t, sharedSecrets, 1)
		assert.Equal(t, secretID, sharedSecrets[0].ID)

		// Step 4: Update share permission
		updateReq := &UpdateShareRequest{
			ShareID:    shareRecord.ID,
			Permission: "write",
			UpdatedBy:  1,
		}

		updatedShare, err := core.UpdateSharePermission(ctx, updateReq)
		require.NoError(t, err)
		assert.Equal(t, "write", updatedShare.Permission)

		// Step 5: List secret shares
		shares, err := core.ListSecretShares(ctx, secretID)
		require.NoError(t, err)
		assert.Len(t, shares, 1)
		assert.Equal(t, "write", shares[0].Permission)

		// Step 6: Revoke share
		err = core.RevokeShare(ctx, shareRecord.ID, 1)
		require.NoError(t, err)

		// Step 7: Verify share is revoked
		sharesAfterRevoke, err := core.ListSecretShares(ctx, secretID)
		require.NoError(t, err)
		assert.Len(t, sharesAfterRevoke, 0)

		// Step 8: Verify shared secrets list is empty
		sharedSecretsAfterRevoke, err := core.ListSharedSecrets(ctx, 2)
		require.NoError(t, err)
		assert.Len(t, sharedSecretsAfterRevoke, 0)
	})

	t.Run("Group Sharing Workflow", func(t *testing.T) {
		// Create a secret for group sharing
		secret := &models.SecretNode{
			Name:          "group-test-secret",
			ProjectID:     1,
			EnvironmentID: 1,
			Type:          "password",
			OwnerID:       1,
			IsSecret:      true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		createdSecret, err := storage.CreateSecret(ctx, secret)
		require.NoError(t, err)

		// Share with group
		groupShareReq := &GroupShareSecretRequest{
			SecretID:   createdSecret.ID,
			GroupID:    1,
			Permission: "read",
			SharedBy:   1,
		}

		groupShare, err := core.ShareSecretWithGroup(ctx, groupShareReq)
		require.NoError(t, err)
		assert.True(t, groupShare.IsGroup)
		assert.Equal(t, "read", groupShare.Permission)

		// Update group permission
		updateReq := &UpdateShareRequest{
			ShareID:    groupShare.ID,
			Permission: "write",
			UpdatedBy:  1,
		}

		updatedGroupShare, err := core.UpdateSharePermission(ctx, updateReq)
		require.NoError(t, err)
		assert.Equal(t, "write", updatedGroupShare.Permission)

		// Revoke group share
		err = core.RevokeShare(ctx, groupShare.ID, 1)
		require.NoError(t, err)

		// Verify revocation
		shares, err := core.ListSecretShares(ctx, createdSecret.ID)
		require.NoError(t, err)
		assert.Len(t, shares, 0)
	})

	t.Run("Permission Enforcement", func(t *testing.T) {
		// Create a secret
		secret := &models.SecretNode{
			Name:          "permission-test-secret",
			ProjectID:     1,
			EnvironmentID: 1,
			Type:          "password",
			OwnerID:       1,
			IsSecret:      true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		createdSecret, err := storage.CreateSecret(ctx, secret)
		require.NoError(t, err)

		// Share with read permission
		shareReq := &ShareSecretRequest{
			SecretID:    createdSecret.ID,
			RecipientID: 2,
			Permission:  "read",
			SharedBy:    1,
		}

		shareRecord, err := core.ShareSecret(ctx, shareReq)
		require.NoError(t, err)

		// Verify permission check
		permission, err := core.CheckSharePermission(ctx, createdSecret.ID, 2)
		require.NoError(t, err)
		assert.Equal(t, "read", permission)

		// Test unauthorized update (recipient trying to update)
		unauthorizedUpdateReq := &UpdateShareRequest{
			ShareID:    shareRecord.ID,
			Permission: "write",
			UpdatedBy:  2, // Recipient, not owner
		}

		_, err = core.UpdateSharePermission(ctx, unauthorizedUpdateReq)
		assert.Error(t, err, "Recipient should not be able to update share")

		// Owner can update
		ownerUpdateReq := &UpdateShareRequest{
			ShareID:    shareRecord.ID,
			Permission: "write",
			UpdatedBy:  1, // Owner
		}

		_, err = core.UpdateSharePermission(ctx, ownerUpdateReq)
		require.NoError(t, err, "Owner should be able to update share")

		// Clean up
		err = core.RevokeShare(ctx, shareRecord.ID, 1)
		require.NoError(t, err)
	})

	t.Run("Error Scenarios", func(t *testing.T) {
		// Test sharing non-existent secret
		shareReq := &ShareSecretRequest{
			SecretID:    99999, // Non-existent
			RecipientID: 2,
			Permission:  "read",
			SharedBy:    1,
		}

		_, err := core.ShareSecret(ctx, shareReq)
		assert.Error(t, err, "Should fail when sharing non-existent secret")

		// Test invalid permission
		secret := &models.SecretNode{
			Name:          "error-test-secret",
			ProjectID:     1,
			EnvironmentID: 1,
			Type:          "password",
			OwnerID:       1,
			IsSecret:      true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		createdSecret, err := storage.CreateSecret(ctx, secret)
		require.NoError(t, err)

		invalidShareReq := &ShareSecretRequest{
			SecretID:    createdSecret.ID,
			RecipientID: 2,
			Permission:  "invalid", // Invalid permission
			SharedBy:    1,
		}

		_, err = core.ShareSecret(ctx, invalidShareReq)
		assert.Error(t, err, "Should fail with invalid permission")

		// Test updating non-existent share
		updateReq := &UpdateShareRequest{
			ShareID:    99999, // Non-existent
			Permission: "write",
			UpdatedBy:  1,
		}

		_, err = core.UpdateSharePermission(ctx, updateReq)
		assert.Error(t, err, "Should fail when updating non-existent share")

		// Test revoking non-existent share
		err = core.RevokeShare(ctx, 99999, 1) // Non-existent share
		assert.Error(t, err, "Should fail when revoking non-existent share")
	})

	t.Run("Concurrent Operations", func(t *testing.T) {
		// Create a secret for concurrent testing
		secret := &models.SecretNode{
			Name:          "concurrent-test-secret",
			ProjectID:     1,
			EnvironmentID: 1,
			Type:          "password",
			OwnerID:       1,
			IsSecret:      true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		createdSecret, err := storage.CreateSecret(ctx, secret)
		require.NoError(t, err)

		// Perform concurrent share operations
		const numConcurrentShares = 5
		results := make(chan error, numConcurrentShares)

		for i := range numConcurrentShares {
			go func(recipientID uint) {
				shareReq := &ShareSecretRequest{
					SecretID:    createdSecret.ID,
					RecipientID: recipientID,
					Permission:  "read",
					SharedBy:    1,
				}

				_, err := core.ShareSecret(ctx, shareReq)
				results <- err
			}(uint(i + 10)) // Use recipient IDs 10-14
		}

		// Collect results
		successCount := 0
		for range numConcurrentShares {
			select {
			case err := <-results:
				if err == nil {
					successCount++
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Timeout waiting for concurrent operations")
			}
		}

		// Verify all operations succeeded
		assert.Equal(t, numConcurrentShares, successCount)

		// Verify all shares were created
		shares, err := core.ListSecretShares(ctx, createdSecret.ID)
		require.NoError(t, err)
		assert.Len(t, shares, numConcurrentShares)
	})
}
