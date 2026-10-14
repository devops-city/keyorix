package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newSharingTestCore creates a minimal *core.KeyorixCore for sharing tests.
func newSharingTestCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Limit to one connection to prevent SQLite "table is locked" errors
	// under concurrent write load in tests.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	err = db.AutoMigrate(
		&models.Project{},
		&models.Project{},
		&models.Environment{},
		&models.User{},
		&models.Role{},
		&models.Permission{},
		&models.RolePermission{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.SecretACL{},
		&models.SecretAccessSchedule{}, // DeleteSecret's cleanup step queries this table
		&models.SecretAccessLog{},
		&models.SecretMetadataHistory{},
		&models.ShareRecord{},
		&models.Session{},
		&models.PasswordReset{},
		&models.Tag{},
		&models.SecretTag{},
		&models.Notification{},
		&models.AuditEvent{},
		&models.Setting{},
		&models.SystemMetadata{},
		&models.APIClient{},
		&models.APIToken{},
		&models.RateLimit{},
		&models.APICallLog{},
		&models.GRPCService{},
		&models.IdentityProvider{},
		&models.ExternalIdentity{},
	)
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "admin", Email: "admin@example.com", IsActive: true, CreatedAt: now, UpdatedAt: now,
	}).Error)
	require.NoError(t, db.Create(&models.User{
		ID: 2, Username: "user2", Email: "user2@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now,
	}).Error)
	for i := 10; i < 70; i++ {
		require.NoError(t, db.Create(&models.User{
			ID: uint(i), Username: fmt.Sprintf("u%d", i), Email: fmt.Sprintf("u%d@test.com", i),
			IsActive: true, CreatedAt: now, UpdatedAt: now,
		}).Error)
	}
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "test-group", Description: "HTTP sharing test"}).Error)

	// Seed project + environment so secret creation with environment_id=1 succeeds.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "test-project"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "test-env"}).Error)

	// Seed a stable secret (ID 1) so share-validation error tests resolve a real
	// target (the body is rejected before any sharing happens).
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "seed-secret",
		OwnerID: 1, CreatedBy: "admin", Status: "active", IsSecret: true,
	}).Error)

	// Seed an admin role + user_role so user 1 is a global admin (bypasses scope).
	adminRole := &models.Role{ID: 1, Name: "admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	// ShareSecret/UpdateSharePermission/RevokeShare also gate the OWNER on live
	// project membership (RBAC-001, requireLiveOwnerAuthority) — the global grant
	// above doesn't count (IsProjectMember only counts a project-scoped grant),
	// so give user 1 one too. Without this, every "Share Secret" step below fails
	// with "not authorized to share this secret".
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)

	// Seed a viewer role (secrets.read) for user 2 (recipient) so it can read.
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "viewer", Description: "Reader"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	// ShareSecretWithGroup rejects a group with no live role grant at the secret's
	// project (group_sharing.go's IsGroupProjectScoped gate) — give test-group
	// (ID 1) one, or every "Share Secret (group)" step below fails.
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 2, ProjectID: 1}).Error)
	// Also grant it scoped to project 1: ShareSecret rejects a non-group share to a
	// recipient who isn't a member of the secret's project (sharing.go's
	// IsProjectMember gate), and IsProjectMember only counts a project-scoped role
	// grant (UserRole.ProjectID), not the global grant above. Without this, every
	// "Share Secret" step below fails with "permission denied".
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2, ProjectID: 1}).Error)

	// Same project-1 membership grant for the bulk-seeded users 10-69 (used as
	// share recipients by TestSharingHTTPConcurrency) -- without it,
	// core.ShareSecret's IsProjectMember cross-project check rejects every one
	// of them with "permission denied", the same gap fixed above for user 2.
	for i := 10; i < 70; i++ {
		require.NoError(t, db.Create(&models.UserRole{UserID: uint(i), RoleID: 2, ProjectID: 1}).Error)
	}

	// Seed sessions for "valid-token" and "owner-token" (user 1, admin), "recipient-token" (user 2, reader).
	seedSession(t, db, 1, "valid-token")
	seedSession(t, db, 1, "owner-token")
	seedSession(t, db, 2, "recipient-token")

	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// TestSharingHTTPIntegration tests the complete HTTP API sharing workflow
func TestSharingHTTPIntegration(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	// Create test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled:        true,
				Port:           "8080",
				SwaggerEnabled: true,
			},
		},
	}

	// Create router
	router, err := NewRouter(cfg, newSharingTestCore(t))
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(router)
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	baseURL := server.URL

	t.Run("Complete Sharing Workflow via HTTP API", func(t *testing.T) {
		var secretID uint
		var shareID uint

		// Step 1: Create a secret to share
		t.Run("Create Secret", func(t *testing.T) {
			secretData := map[string]any{
				"name":           "http-sharing-test-secret",
				"value":          "http-sharing-secret-value",
				"project_id":     uint(1),
				"environment_id": uint(1),
				"type":           "password",
				"metadata": map[string]string{
					"test":  "http-sharing",
					"owner": "test-user",
				},
				"tags": []string{"http", "sharing", "integration"},
			}

			body, err := json.Marshal(secretData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			secretID = uint(data["id"].(float64))
		})

		// Step 2: Share the secret with another user
		t.Run("Share Secret", func(t *testing.T) {
			shareData := map[string]any{
				"recipient_id": 2,
				"is_group":     false,
				"permission":   "read",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/secrets/%d/share", baseURL, secretID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			// require, not assert: a wrong status code here means the rest of this
			// block's unchecked type assertions on the response body would panic
			// and crash the whole test binary instead of failing this one subtest.
			require.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			shareID = uint(data["id"].(float64))
			assert.Equal(t, float64(secretID), data["secret_id"])
			assert.Equal(t, float64(2), data["recipient_id"])
			assert.Equal(t, "read", data["permission"])
		})

		// Step 3: List shares for the secret
		t.Run("List Secret Shares", func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d/shares", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			shares := data["shares"].([]any)
			// require, not assert: shares[0] just below would panic on an empty
			// slice instead of failing this subtest cleanly.
			require.Len(t, shares, 1)

			share := shares[0].(map[string]any)
			assert.Equal(t, float64(shareID), share["id"])
			assert.Equal(t, "read", share["permission"])
		})

		// Step 4: List shared secrets (from recipient's perspective)
		t.Run("List Shared Secrets", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/shared-secrets", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer recipient-token") // Different user token

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			secrets := data["secrets"].([]any)
			assert.Len(t, secrets, 1)

			secret := secrets[0].(map[string]any)
			assert.Equal(t, float64(secretID), secret["id"])
			assert.Equal(t, "http-sharing-test-secret", secret["name"])
		})

		// Step 5: Update share permission
		t.Run("Update Share Permission", func(t *testing.T) {
			updateData := map[string]any{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			assert.Equal(t, "write", data["permission"])
		})

		// Step 6: List all shares for current user
		t.Run("List User Shares", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/shares", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			// GET /api/v1/shares returns a paginated list of enriched ShareViews
			// (camelCase): {data: [...], total, page, pageSize, totalPages} (#288).
			data := response["data"].(map[string]any)
			shares := data["data"].([]any)
			assert.GreaterOrEqual(t, len(shares), 1)

			// Find our share
			var foundShare map[string]any
			for _, s := range shares {
				share := s.(map[string]any)
				if uint(share["id"].(float64)) == shareID {
					foundShare = share
					break
				}
			}
			require.NotNil(t, foundShare)
			assert.Equal(t, "write", foundShare["permission"])
		})

		// Step 7: Revoke the share
		t.Run("Revoke Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})

		// Step 8: Verify share is revoked
		t.Run("Verify Share Revoked", func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d/shares", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			shares := data["shares"].([]any)
			assert.Len(t, shares, 0)
		})

		// Step 9: Verify shared secrets list is empty for recipient
		t.Run("Verify Shared Secrets Empty", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/shared-secrets", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer recipient-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			secrets := data["secrets"].([]any)
			assert.Len(t, secrets, 0)
		})

		// Clean up: Delete the secret
		t.Run("Cleanup Secret", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	})

	t.Run("Group Sharing via HTTP API", func(t *testing.T) {
		var secretID uint
		var groupShareID uint

		// Step 1: Create a secret for group sharing
		t.Run("Create Secret for Group", func(t *testing.T) {
			secretData := map[string]any{
				"name":           "group-sharing-test-secret",
				"value":          "group-sharing-secret-value",
				"project_id":     uint(1),
				"environment_id": uint(1),
				"type":           "password",
				"metadata": map[string]string{
					"test": "group-sharing",
				},
				"tags": []string{"group", "sharing", "test"},
			}

			body, err := json.Marshal(secretData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			secretID = uint(data["id"].(float64))
		})

		// Step 2: Share with a group
		t.Run("Share with Group", func(t *testing.T) {
			shareData := map[string]any{
				"recipient_id": 1, // Group ID
				"is_group":     true,
				"permission":   "read",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/secrets/%d/share", baseURL, secretID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			groupShareID = uint(data["id"].(float64))
			assert.Equal(t, true, data["is_group"])
			assert.Equal(t, "read", data["permission"])
		})

		// Step 3: Update group permission
		t.Run("Update Group Permission", func(t *testing.T) {
			updateData := map[string]any{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, groupShareID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			assert.Equal(t, "write", data["permission"])
		})

		// Step 4: Revoke group share
		t.Run("Revoke Group Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, groupShareID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})

		// Clean up
		t.Run("Cleanup Group Secret", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	})

	t.Run("Error Scenarios via HTTP API", func(t *testing.T) {
		// Test unauthorized access
		t.Run("Unauthorized Access", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/shares", nil)
			require.NoError(t, err)
			// No authorization header

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		})

		// Test sharing non-existent secret
		t.Run("Share Non-existent Secret", func(t *testing.T) {
			shareData := map[string]any{
				"recipient_id": 2,
				"permission":   "read",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets/99999/share", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})

		// Test invalid JSON
		t.Run("Invalid JSON", func(t *testing.T) {
			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets/1/share", bytes.NewBufferString("{invalid json}"))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		// Test missing required fields
		t.Run("Missing Required Fields", func(t *testing.T) {
			shareData := map[string]any{
				// Missing recipient_id and permission
				"is_group": false,
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets/1/share", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		// Test invalid permission value
		t.Run("Invalid Permission", func(t *testing.T) {
			shareData := map[string]any{
				"recipient_id": 2,
				"permission":   "invalid",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets/1/share", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		// Test updating non-existent share
		t.Run("Update Non-existent Share", func(t *testing.T) {
			updateData := map[string]any{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", baseURL+"/api/v1/shares/99999", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})

		// Test revoking non-existent share
		t.Run("Revoke Non-existent Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", baseURL+"/api/v1/shares/99999", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	})

	t.Run("Permission Enforcement via HTTP API", func(t *testing.T) {
		var secretID uint
		var shareID uint

		// Step 1: Create a secret as owner
		t.Run("Create Secret as Owner", func(t *testing.T) {
			secretData := map[string]any{
				"name":           "permission-test-secret",
				"value":          "permission-test-value",
				"project_id":     uint(1),
				"environment_id": uint(1),
				"type":           "password",
			}

			body, err := json.Marshal(secretData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			secretID = uint(data["id"].(float64))
		})

		// Step 2: Share with read-only permission
		t.Run("Share with Read Permission", func(t *testing.T) {
			shareData := map[string]any{
				"recipient_id": 2,
				"permission":   "read",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/secrets/%d/share", baseURL, secretID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]any
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]any)
			shareID = uint(data["id"].(float64))
		})

		// Step 3: Try to update share as recipient (should fail)
		t.Run("Recipient Cannot Update Share", func(t *testing.T) {
			updateData := map[string]any{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer recipient-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		})

		// Step 4: Try to revoke share as recipient (should fail)
		t.Run("Recipient Cannot Revoke Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer recipient-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		})

		// Step 5: Owner can still manage the share
		t.Run("Owner Can Update Share", func(t *testing.T) {
			updateData := map[string]any{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})

		// Clean up
		t.Run("Owner Can Revoke Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})

		t.Run("Cleanup Permission Secret", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	})
}

// TestSharingHTTPConcurrency tests concurrent access to sharing endpoints
func TestSharingHTTPConcurrency(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "8080",
			},
		},
	}

	router, err := NewRouter(cfg, newSharingTestCore(t))
	require.NoError(t, err)

	server := httptest.NewServer(router)
	defer server.Close()

	t.Run("Concurrent Share Operations", func(t *testing.T) {
		const numGoroutines = 10
		const requestsPerGoroutine = 5

		results := make(chan int, numGoroutines*requestsPerGoroutine)

		// Create a secret first
		client := &http.Client{Timeout: 10 * time.Second}
		secretData := map[string]any{
			"name":           "concurrent-test-secret",
			"value":          "concurrent-test-value",
			"project_id":     uint(1),
			"environment_id": uint(1),
			"type":           "password",
		}

		body, err := json.Marshal(secretData)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", server.URL+"/api/v1/secrets", bytes.NewBuffer(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		var response map[string]any
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		data := response["data"].(map[string]any)
		secretID := uint(data["id"].(float64))

		// Perform concurrent share operations
		for i := range numGoroutines {
			go func(goroutineID int) {
				client := &http.Client{Timeout: 10 * time.Second}
				for j := range requestsPerGoroutine {
					shareData := map[string]any{
						"recipient_id": goroutineID*requestsPerGoroutine + j + 10, // Unique recipient IDs
						"permission":   "read",
					}

					body, err := json.Marshal(shareData)
					if err != nil {
						results <- 0
						continue
					}

					req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/secrets/%d/share", server.URL, secretID), bytes.NewBuffer(body))
					if err != nil {
						results <- 0
						continue
					}
					req.Header.Set("Authorization", "Bearer valid-token")
					req.Header.Set("Content-Type", "application/json")

					resp, err := client.Do(req)
					if err != nil {
						results <- 0
						continue
					}
					_ = resp.Body.Close()
					results <- resp.StatusCode
				}
			}(i)
		}

		// Collect results
		successCount := 0
		for range numGoroutines * requestsPerGoroutine {
			select {
			case code := <-results:
				if code == http.StatusCreated {
					successCount++
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Timeout waiting for concurrent requests")
			}
		}

		// At least 80% success rate (some might fail due to conflicts)
		expectedMinSuccess := int(float64(numGoroutines*requestsPerGoroutine) * 0.8)
		assert.GreaterOrEqual(t, successCount, expectedMinSuccess)
	})
}
