// secrets_folder_test.go — tests for folder-aware secret create and list.
//
// Covers:
//   - POST /api/v1/secrets with parent_id → ParentID set on the created node
//   - POST /api/v1/secrets with non-folder parent_id → 400
//   - GET /api/v1/secrets?parent_id=N → returns only children of that folder
//   - GET /api/v1/secrets?folder_only=true → returns only folder nodes
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// decodeFolderListResponse decodes a list-secrets HTTP response envelope.
func decodeFolderListResponse(t *testing.T, body []byte) *secretListResponseWire {
	t.Helper()
	var wrapper struct {
		Success bool                    `json:"success"`
		Data    *secretListResponseWire `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &wrapper))
	require.NotNil(t, wrapper.Data, "response.Data must not be nil")
	return wrapper.Data
}

// freshFolderFixture builds an isolated named in-memory SQLite DB with a project,
// environment, one system_admin user, and one folder node ready for use.
func freshSecretFolderFixture(t *testing.T) (*SecretHandler, *core.KeyorixCore, *models.SecretNode, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxsecfolder_")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.RotationPolicy{}, &models.Notification{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.LoginAttempt{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
		&models.WebAuthnCredential{}, &models.WebAuthnSession{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.ConnectRefGrant{}, &models.Session{}, &models.SetupToken{},
		&models.MFAChallenge{}, &models.SSOLoginState{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
		&models.SecretDependency{}, &models.RiskException{},
		&models.MFASecret{}, &models.MFARecoveryCode{},
		&models.IdentityProvider{}, &models.ExternalIdentity{},
		&models.LegalHold{}, &models.ShareRecord{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
		&models.SecretVersion{},
		&models.SecretACL{},
	))

	// Seed user 1 as system_admin so in-handler authorization passes.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice-folder", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "system_admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-folder"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod-folder"}).Error)

	// Seed a folder node (IsSecret=false) directly into the DB.
	folder := &models.SecretNode{
		Name:          "my-folder",
		ProjectID:     1,
		EnvironmentID: 10,
		IsSecret:      false,
		Type:          "folder",
		Status:        "active",
		CreatedBy:     "alice-folder",
		OwnerID:       1,
	}
	require.NoError(t, db.Create(folder).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	return h, cs, folder, db
}

func withAdminCtxFolder(r *http.Request) *http.Request {
	uc := &middleware.UserContext{
		UserID: 1, Username: "alice-folder",
		ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// ── HTTP: create secret with parent_id ────────────────────────────────────────

// TestCreateSecret_WithParentID verifies that POST /api/v1/secrets with a valid
// parent_id places the new secret inside the folder (ParentID set on the response).
func TestCreateSecret_WithParentID(t *testing.T) {
	h, _, folder, _ := freshSecretFolderFixture(t)

	body := map[string]interface{}{
		"name":           "child-secret",
		"value":          "topsecret",
		"project_id":     1,
		"environment_id": 10,
		"type":           "generic",
		"parent_id":      folder.ID,
	}
	b, _ := json.Marshal(body)
	r := withAdminCtxFolder(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(b)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSecret(w, r)

	assert.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	// The create response wraps a SecretNodeWire (snake_case) in "data".
	var resp struct {
		Data *SecretNodeWire `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Data, "expected data in response")
	require.NotNil(t, resp.Data.ParentID, "expected ParentID to be set")
	assert.Equal(t, folder.ID, *resp.Data.ParentID)
}

// TestCreateSecret_NonFolderParentID verifies that POST /api/v1/secrets with a
// parent_id that points to a real secret (not a folder) is rejected with 400.
func TestCreateSecret_NonFolderParentID(t *testing.T) {
	h, cs, _, _ := freshSecretFolderFixture(t)

	// Create a real secret to use as (invalid) parent.
	realSecret, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "real-secret", Value: []byte("val"), ProjectID: 1, EnvironmentID: 10,
		Type: "generic", CreatedBy: "alice-folder", OwnerID: 1,
	})
	require.NoError(t, err)

	body := map[string]interface{}{
		"name":           "child-of-secret",
		"value":          "topsecret",
		"project_id":     1,
		"environment_id": 10,
		"type":           "generic",
		"parent_id":      realSecret.ID,
	}
	b, _ := json.Marshal(body)
	r := withAdminCtxFolder(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(b)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSecret(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected 400 for non-folder parent; body: %s", w.Body.String())
}

// TestCreateSecret_NonExistentParentID verifies that POST /api/v1/secrets with a
// parent_id that does not exist is rejected with 400.
func TestCreateSecret_NonExistentParentID(t *testing.T) {
	h, _, _, _ := freshSecretFolderFixture(t)

	body := map[string]interface{}{
		"name":           "orphan-secret",
		"value":          "val",
		"project_id":     1,
		"environment_id": 10,
		"type":           "generic",
		"parent_id":      99999,
	}
	b, _ := json.Marshal(body)
	r := withAdminCtxFolder(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(b)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSecret(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected 400 for non-existent parent; body: %s", w.Body.String())
}

// ── HTTP: list with ?parent_id=N ──────────────────────────────────────────────

// TestListSecrets_ParentID verifies that GET /api/v1/secrets?parent_id=N returns
// only the secrets that are direct children of that folder.
func TestListSecrets_ParentID(t *testing.T) {
	h, cs, folder, _ := freshSecretFolderFixture(t)

	// Create a child secret inside the folder.
	child, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "folder-child", Value: []byte("val"), ProjectID: 1, EnvironmentID: 10,
		Type: "generic", CreatedBy: "alice-folder", OwnerID: 1,
		ParentID: &folder.ID,
	})
	require.NoError(t, err)

	// Create a root-level secret (no parent) to confirm it is excluded.
	_, err = cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "root-secret", Value: []byte("val2"), ProjectID: 1, EnvironmentID: 10,
		Type: "generic", CreatedBy: "alice-folder", OwnerID: 1,
	})
	require.NoError(t, err)

	url := fmt.Sprintf("/api/v1/secrets?project_id=1&parent_id=%d", folder.ID)
	r := withAdminCtxFolder(httptest.NewRequest(http.MethodGet, url, nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	resp := decodeFolderListResponse(t, w.Body.Bytes())
	assert.Equal(t, int64(1), resp.Total, "expected exactly 1 child secret")
	require.Len(t, resp.Secrets, 1)
	assert.Equal(t, child.ID, resp.Secrets[0].ID)
}

// TestListSecrets_FolderOnly verifies that GET /api/v1/secrets?folder_only=true
// returns only folder nodes (IsSecret=false).
func TestListSecrets_FolderOnly(t *testing.T) {
	h, cs, _, _ := freshSecretFolderFixture(t)

	// Create a real secret to confirm it is excluded.
	_, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "real-secret-folderonly", Value: []byte("val"), ProjectID: 1, EnvironmentID: 10,
		Type: "generic", CreatedBy: "alice-folder", OwnerID: 1,
	})
	require.NoError(t, err)

	r := withAdminCtxFolder(httptest.NewRequest(http.MethodGet, "/api/v1/secrets?project_id=1&folder_only=true", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	resp := decodeFolderListResponse(t, w.Body.Bytes())
	// The fixture seeds one folder; the real secret must be excluded.
	assert.Equal(t, int64(1), resp.Total, "expected exactly 1 folder node")
	for _, s := range resp.Secrets {
		assert.False(t, s.IsSecret, "folder_only=true returned a real secret (id=%d)", s.ID)
	}
}
