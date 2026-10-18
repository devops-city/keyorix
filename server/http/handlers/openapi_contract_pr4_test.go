// openapi_contract_pr4_test.go — ADR-074 registry population for the operations
// docs/cli-split-inventory.md §7 PR 4 (secret core CRUD + metadata) added response
// schemas for. Each test below drives the real handler through a happy path and
// calls contracttest.AssertOpenAPIResponse so the operation moves from "pending" to
// genuinely enforced -- see CLAUDE.md's "a mechanism must be validated against a
// failure that actually happened" and openapi_contract_pr2_test.go's identical
// convention (reused here: withUserCtx, withChiParamsPR2). Each test is
// self-contained (its own fixture) rather than grafted onto an existing test, so
// this batch is auditable as one unit and never risks changing an existing test's
// behavior.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// freshSecretFixturePR4 builds an isolated named in-memory SQLite DB, migrates the
// same model set freshCoreS12WithAdmin uses (see that helper's own comment) plus
// SecretTemplate and SecretVersionComment (needed for PR 4's template/comment
// operations, absent from that shared set), seeds user 1 as system_admin, and
// seeds a project+environment. Returns handler, core service, raw DB, project ID,
// environment ID.
func freshSecretFixturePR4(t *testing.T) (*SecretHandler, *core.KeyorixCore, *gorm.DB, uint, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxpr4_")
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
		&models.LegalHold{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
		&models.SecretVersion{},
		&models.SecretACL{}, &models.SecretAccessSchedule{},
		&models.SecretTemplate{}, &models.SecretVersionComment{},
		&models.Tag{}, &models.SecretTag{},
	))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "pr4-admin", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "system_admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	proj := &models.Project{Name: "pr4-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{ProjectID: proj.ID, Name: "pr4-env"}
	require.NoError(t, db.Create(env).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	return h, cs, db, proj.ID, env.ID
}

// pr4CreateSecret creates a secret owned by user 1 via the core service directly
// (setup only -- the CreateSecret operation itself gets its own dedicated test
// below, driven through the handler).
func pr4CreateSecret(t *testing.T, cs *core.KeyorixCore, projID, envID uint, name string) *models.SecretNode {
	t.Helper()
	s, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: name, Value: []byte("pr4-value"), ProjectID: projID, EnvironmentID: envID,
		Type: "static", CreatedBy: "pr4-admin", OwnerID: 1,
	})
	require.NoError(t, err)
	return s
}

// pr4SecretIDStr formats a secret/project/environment ID for use as a chi URL param.
func pr4SecretIDStr(id uint) string { return fmt.Sprintf("%d", id) }

func TestContractPR4_ListSecrets(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	pr4CreateSecret(t, cs, projID, envID, "pr4-list-target")

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_CreateSecret(t *testing.T) {
	h, _, _, projID, envID := freshSecretFixturePR4(t)

	body, _ := json.Marshal(map[string]any{
		"name": "pr4-created", "value": "s3cr3t", "type": "static",
		"project_id": projID, "environment_id": envID,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR4_GetSecret(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-get-target")

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_UpdateSecret(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-update-target")

	body, _ := json.Marshal(map[string]any{"value": "new-value"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/1", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_GetSecretVersions(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-versions-target")

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/versions", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecretVersions(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_GrantSecretACL(t *testing.T) {
	h, cs, db, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-acl-target")

	require.NoError(t, db.Create(&models.User{ID: 2, Username: "pr4-acl-grantee", AccountState: "active"}).Error)
	memberRole := &models.Role{Name: "member"}
	require.NoError(t, db.Create(memberRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: memberRole.ID, ProjectID: projID}).Error)

	body, _ := json.Marshal(map[string]any{"user_id": 2, "permissions": []string{"secrets.read"}})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/acl", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_RevokeSecretACL(t *testing.T) {
	h, cs, db, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-acl-revoke-target")

	require.NoError(t, db.Create(&models.User{ID: 2, Username: "pr4-acl-revokee", AccountState: "active"}).Error)
	memberRole := &models.Role{Name: "member"}
	require.NoError(t, db.Create(memberRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: memberRole.ID, ProjectID: projID}).Error)
	require.NoError(t, cs.GrantSecretACL(context.Background(), 1, secret.ID, 2, []string{"secrets.read"}))
	acls, err := cs.ListSecretACLs(context.Background(), secret.ID)
	require.NoError(t, err)
	require.Len(t, acls, 1)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/1/acl/1", nil),
		"id", pr4SecretIDStr(secret.ID), "aclId", pr4SecretIDStr(acls[0].ID),
	))
	w := httptest.NewRecorder()
	h.RevokeSecretACL(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_ClassifySecret(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-classify-target")

	body, _ := json.Marshal(map[string]any{"classification": "confidential"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/classification", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifySecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_GetSecretByName(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	pr4CreateSecret(t, cs, projID, envID, "pr4-byname-target")

	url := fmt.Sprintf("/api/v1/secrets/by-name?name=pr4-byname-target&project_id=%d&environment_id=%d", projID, envID)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, url, nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_GetSecretValueByRef(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-byref-target")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref=pr4-proj/pr4-env/pr4-byref-target", nil)
	req = withUserCtx(req)
	req = req.WithContext(middleware.WithResolvedSecretRef(req.Context(), secret))
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_DiffSecretVersions(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-diff-target")
	_, err := cs.UpdateSecretWithPermissionCheck(context.Background(), &core.UpdateSecretRequest{
		ID: secret.ID, Value: []byte("v2"), UpdatedBy: "pr4-admin", UserID: 1,
	})
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/versions/1/diff/2", nil),
		"id", pr4SecretIDStr(secret.ID), "from", "1", "to", "2",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_ListSecretVersionComments(t *testing.T) {
	_, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-comments-list-target")
	versions, err := cs.GetSecretVersionsWithPermissionCheck(context.Background(), secret.ID, 1)
	require.NoError(t, err)
	require.NotEmpty(t, versions)

	h := NewSecretVersionCommentHandler(cs)
	_, err = cs.CreateSecretVersionComment(context.Background(), core.CreateVersionCommentRequest{
		SecretID: secret.ID, VersionID: versions[0].ID, Comment: "seed comment", UserID: 1, Username: "pr4-admin",
	})
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/versions/1/comments", nil),
		"id", pr4SecretIDStr(secret.ID), "versionId", pr4SecretIDStr(versions[0].ID),
	))
	w := httptest.NewRecorder()
	h.ListComments(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_AddSecretVersionComment(t *testing.T) {
	_, csAdmin, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, csAdmin, projID, envID, "pr4-comments-add-target")
	versions, err := csAdmin.GetSecretVersionsWithPermissionCheck(context.Background(), secret.ID, 1)
	require.NoError(t, err)
	require.NotEmpty(t, versions)

	h := NewSecretVersionCommentHandler(csAdmin)
	body, _ := json.Marshal(map[string]any{"comment": "looks good"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/versions/1/comments", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID), "versionId", pr4SecretIDStr(versions[0].ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateComment(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR4_GetSecretTags(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-tags-get-target")

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/tags", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetTags(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_SetSecretTags(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-tags-set-target")

	body, _ := json.Marshal(map[string]any{"tags": []string{"db", "prod"}})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/1/tags", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetTags(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_DescribeSecret(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-describe-target")

	body, _ := json.Marshal(map[string]any{"description": "a test secret"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/description", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_MoveSecret(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-move-target")
	folder, err := cs.CreateFolder(context.Background(), 1, "pr4-move-folder", projID, envID, nil)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"parent_id": folder.ID})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/move", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.MoveSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_CopySecret(t *testing.T) {
	h, cs, db, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-copy-target")
	targetEnv := &models.Environment{ProjectID: projID, Name: "pr4-copy-target-env"}
	require.NoError(t, db.Create(targetEnv).Error)

	body, _ := json.Marshal(map[string]any{"environment_id": targetEnv.ID, "name": "pr4-copy-target-copy"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/copy", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CopySecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_ListSecretDependencies(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-deps-list-target")

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/dependencies", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.ListSecretDependencies(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_AddSecretDependency(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-deps-add-target")
	dependsOn := pr4CreateSecret(t, cs, projID, envID, "pr4-deps-add-upstream")

	body, _ := json.Marshal(map[string]any{"depends_on_id": dependsOn.ID, "note": "needs this"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/dependencies", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_GetSecretImpact(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-impact-target")

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/impact", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecretImpact(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_ListAccessors(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-accessors-target")

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/access", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.ListAccessors(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_GetSecretAccessLog(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-accesslog-target")

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/access-log", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_GetSecretSchedule(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-schedule-get-target")
	_, err := cs.SetSecretSchedule(context.Background(), secret.ID, "1,2,3,4,5", 9, 17, "UTC")
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/schedule", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecretSchedule(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_SetSecretSchedule(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-schedule-set-target")

	body, _ := json.Marshal(map[string]any{
		"allowed_days": "1,2,3,4,5", "start_hour": 9, "end_hour": 17, "timezone": "UTC",
	})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/1/schedule", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetSecretSchedule(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_SuspendSecret(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-suspend-target")

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/suspend", bytes.NewReader([]byte(`{}`))),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SuspendSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_ResumeSecret(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-resume-target")
	_, err := cs.SuspendSecret(context.Background(), secret.ID, 1, "incident response")
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/resume", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.ResumeSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_RollbackSecret(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-rollback-target")
	_, err := cs.UpdateSecretWithPermissionCheck(context.Background(), &core.UpdateSecretRequest{
		ID: secret.ID, Value: []byte("v2"), UpdatedBy: "pr4-admin", UserID: 1,
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"version": 1})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/rollback", bytes.NewReader(body)),
		"id", pr4SecretIDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_RestoreSecret(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-restore-target")
	require.NoError(t, cs.DeleteSecretWithPermissionCheck(context.Background(), secret.ID, 1))

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/restore", nil),
		"id", pr4SecretIDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.RestoreSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_ListDeletedSecrets(t *testing.T) {
	h, cs, _, projID, envID := freshSecretFixturePR4(t)
	secret := pr4CreateSecret(t, cs, projID, envID, "pr4-deleted-list-target")
	require.NoError(t, cs.DeleteSecretWithPermissionCheck(context.Background(), secret.ID, 1))

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/deleted", nil),
		"id", pr4SecretIDStr(projID),
	))
	w := httptest.NewRecorder()
	h.DeletedSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_CopyEnvironmentSecrets(t *testing.T) {
	h, cs, db, projID, envID := freshSecretFixturePR4(t)
	pr4CreateSecret(t, cs, projID, envID, "pr4-copyenv-target")
	targetEnv := &models.Environment{ProjectID: projID, Name: "pr4-copyenv-target-env"}
	require.NoError(t, db.Create(targetEnv).Error)

	body, _ := json.Marshal(map[string]any{"target_environment_id": targetEnv.ID})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/copy-secrets", bytes.NewReader(body)),
		"id", pr4SecretIDStr(projID), "envId", pr4SecretIDStr(envID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CopyEnvironmentSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_ListFolders(t *testing.T) {
	_, cs, _, projID, envID := freshSecretFixturePR4(t)
	h := NewFolderHandler(cs)
	_, err := cs.CreateFolder(context.Background(), 1, "pr4-list-folders-target", projID, envID, nil)
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/folders?project_id=%d", projID), nil))
	w := httptest.NewRecorder()
	h.ListFolders(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_CreateFolder(t *testing.T) {
	_, cs, _, projID, envID := freshSecretFixturePR4(t)
	h := NewFolderHandler(cs)

	body, _ := json.Marshal(map[string]any{"name": "pr4-create-folder-target", "project_id": projID, "environment_id": envID})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR4_ListSecretTemplates(t *testing.T) {
	_, cs, _, _, _ := freshSecretFixturePR4(t)
	h := NewSecretTemplateHandler(cs)
	_, err := cs.CreateSecretTemplate(context.Background(), &core.CreateSecretTemplateRequest{
		Name: "pr4-list-templates-target", CreatedBy: 1,
	})
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secret-templates", nil))
	w := httptest.NewRecorder()
	h.List(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR4_CreateSecretTemplate(t *testing.T) {
	_, cs, _, _, _ := freshSecretFixturePR4(t)
	h := NewSecretTemplateHandler(cs)

	body, _ := json.Marshal(map[string]any{"name": "pr4-create-template-target"})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/secret-templates", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}
