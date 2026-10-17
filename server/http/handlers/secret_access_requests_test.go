// secret_access_requests_test.go — HTTP-layer tests for the
// /api/v1/secret-access-requests family (secret_access_requests.go).
package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var sarHandlerCounter int

// secretAccessRequestFixture is a full, RBAC-bootstrapped CatalogHandler plus
// a restricted secret, a requester (project_viewer at the secret's project),
// and an approver (global admin) — the same population
// internal/core/classification_gate_test.go's seedClassificationGateFixture
// builds, replicated here at the HTTP layer via the same exported
// BootstrapSystem path so role/permission names match production exactly.
type secretAccessRequestFixture struct {
	handler     *CatalogHandler
	core        *core.KeyorixCore
	st          *store.LocalStorage
	secretID    uint
	projectID   uint
	requesterID uint
	approverID  uint
}

func newSecretAccessRequestFixture(t *testing.T) *secretAccessRequestFixture {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	sarHandlerCounter++
	dsn := fmt.Sprintf("file:sar%d?mode=memory&cache=private", sarHandlerCounter)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{},
		&models.PersonalAccessToken{}, &models.Session{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.AuditEvent{}, &models.Notification{},
		&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.ProjectMembership{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.DynamicSecretConfig{}, &models.SoDPolicy{},
		&models.StatsSnapshot{}, &models.DeploymentStatsSnapshot{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{},
		&models.SecretACL{}, &models.PasswordHistory{},
		&models.SecretAccessSchedule{},
	))
	t.Cleanup(func() { sqlDB, _ := db.DB(); _ = sqlDB.Close() })

	st := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")
	ctx := context.Background()
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)

	proj, err := st.CreateProject(ctx, &models.Project{Name: "sar-test-project"})
	require.NoError(t, err)

	requester, err := st.CreateUser(ctx, &models.User{Username: "sar-requester", Email: "sar-requester@example.com", IsActive: true})
	require.NoError(t, err)
	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, requester.ID, viewerRole.ID, storage.Scope{ProjectID: proj.ID}))

	approver, err := st.CreateUser(ctx, &models.User{Username: "sar-approver", Email: "sar-approver@example.com", IsActive: true})
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, approver.ID, adminRole.ID, storage.Scope{}))

	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db-password", ProjectID: proj.ID, EnvironmentID: 1, Type: "password",
		IsSecret: true, OwnerID: requester.ID, Status: "active", Classification: core.ClassificationRestricted,
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t-value"),
	})
	require.NoError(t, err)

	return &secretAccessRequestFixture{
		handler:     NewCatalogHandler(c),
		core:        c,
		st:          st,
		secretID:    secret.ID,
		projectID:   proj.ID,
		requesterID: requester.ID,
		approverID:  approver.ID,
	}
}

func withUserCtxSAR(r *http.Request, userID uint) *http.Request {
	userCtx := &customMiddleware.UserContext{UserID: userID, Username: fmt.Sprintf("user-%d", userID)}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

// ── CreateSecretAccessRequest ────────────────────────────────────────────────

func TestCreateSecretAccessRequest_NilUser(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"secret_id":1,"reason":"x"}`))
	w := httptest.NewRecorder()
	f.handler.CreateSecretAccessRequest(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateSecretAccessRequest_ReasonRequired(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	body := fmt.Sprintf(`{"secret_id":%d,"reason":""}`, f.secretID)
	req := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)), f.requesterID)
	w := httptest.NewRecorder()
	f.handler.CreateSecretAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "reason")
}

func TestCreateSecretAccessRequest_SecretIDRequired(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	req := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"reason":"need it"}`)), f.requesterID)
	w := httptest.NewRecorder()
	f.handler.CreateSecretAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Anti-enumeration: a nonexistent secret ID and a real secret the caller
// cannot see must produce the IDENTICAL 404 response.
func TestCreateSecretAccessRequest_NoExistenceOracle(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	stranger, err := f.st.CreateUser(context.Background(), &models.User{Username: "sar-stranger", Email: "sar-stranger@example.com", IsActive: true})
	require.NoError(t, err)

	bogusBody := `{"secret_id":999999,"reason":"need it"}`
	bogusReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(bogusBody)), stranger.ID)
	bogusW := httptest.NewRecorder()
	f.handler.CreateSecretAccessRequest(bogusW, bogusReq)

	realBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	realReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(realBody)), stranger.ID)
	realW := httptest.NewRecorder()
	f.handler.CreateSecretAccessRequest(realW, realReq)

	assert.Equal(t, http.StatusNotFound, bogusW.Code)
	assert.Equal(t, http.StatusNotFound, realW.Code)
	assert.Equal(t, bogusW.Code, realW.Code)
	assert.Equal(t, bogusW.Body.String(), realW.Body.String(), "an invisible secret and a nonexistent one must read identically")
}

func TestCreateSecretAccessRequest_Success(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	body := fmt.Sprintf(`{"secret_id":%d,"reason":"need it for an incident"}`, f.secretID)
	req := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)), f.requesterID)
	w := httptest.NewRecorder()
	f.handler.CreateSecretAccessRequest(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "access_request")
}

func TestCreateSecretAccessRequest_DuplicatePending(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	body := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	req1 := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)), f.requesterID)
	f.handler.CreateSecretAccessRequest(httptest.NewRecorder(), req1)

	req2 := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)), f.requesterID)
	w2 := httptest.NewRecorder()
	f.handler.CreateSecretAccessRequest(w2, req2)
	assert.Equal(t, http.StatusConflict, w2.Code)
}

// ── ListSecretAccessRequests ─────────────────────────────────────────────────

func TestListSecretAccessRequests_NilUser(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	f.handler.ListSecretAccessRequests(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListSecretAccessRequests_MineAndPendingApproval(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	createBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	createReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(createBody)), f.requesterID)
	f.handler.CreateSecretAccessRequest(httptest.NewRecorder(), createReq)

	mineReq := withUserCtxSAR(httptest.NewRequest(http.MethodGet, "/", nil), f.requesterID)
	mineW := httptest.NewRecorder()
	f.handler.ListSecretAccessRequests(mineW, mineReq)
	require.Equal(t, http.StatusOK, mineW.Code)
	assert.Contains(t, mineW.Body.String(), `"mine":[{`)
	assert.Contains(t, mineW.Body.String(), `"pending_approval":null`)

	approverReq := withUserCtxSAR(httptest.NewRequest(http.MethodGet, "/", nil), f.approverID)
	approverW := httptest.NewRecorder()
	f.handler.ListSecretAccessRequests(approverW, approverReq)
	require.Equal(t, http.StatusOK, approverW.Code)
	assert.Contains(t, approverW.Body.String(), `"pending_approval":[{`)
}

// ── GetSecretAccessRequest ───────────────────────────────────────────────────

func TestGetSecretAccessRequest_NoExistenceOracle(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	createBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	createReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(createBody)), f.requesterID)
	createW := httptest.NewRecorder()
	f.handler.CreateSecretAccessRequest(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	stranger, err := f.st.CreateUser(context.Background(), &models.User{Username: "sar-getter-stranger", Email: "sar-getter-stranger@example.com", IsActive: true})
	require.NoError(t, err)

	realReq := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodGet, "/", nil), stranger.ID), "requestId", "1")
	realW := httptest.NewRecorder()
	f.handler.GetSecretAccessRequest(realW, realReq)

	bogusReq := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodGet, "/", nil), stranger.ID), "requestId", "999999")
	bogusW := httptest.NewRecorder()
	f.handler.GetSecretAccessRequest(bogusW, bogusReq)

	assert.Equal(t, http.StatusNotFound, realW.Code)
	assert.Equal(t, bogusW.Code, realW.Code)
	assert.Equal(t, bogusW.Body.String(), realW.Body.String())
}

func TestGetSecretAccessRequest_RequesterAndApproverCanSee(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	createBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	createReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(createBody)), f.requesterID)
	f.handler.CreateSecretAccessRequest(httptest.NewRecorder(), createReq)

	for _, uid := range []uint{f.requesterID, f.approverID} {
		req := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodGet, "/", nil), uid), "requestId", "1")
		w := httptest.NewRecorder()
		f.handler.GetSecretAccessRequest(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

// ── ResolveSecretAccessRequest ───────────────────────────────────────────────

func TestResolveSecretAccessRequest_ApproveByNonAdminForbidden(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	createBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	createReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(createBody)), f.requesterID)
	f.handler.CreateSecretAccessRequest(httptest.NewRecorder(), createReq)

	nonAdmin, err := f.st.CreateUser(context.Background(), &models.User{Username: "sar-resolve-nonadmin", Email: "sar-resolve-nonadmin@example.com", IsActive: true})
	require.NoError(t, err)

	req := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"action":"approve"}`)), nonAdmin.ID), "requestId", "1")
	w := httptest.NewRecorder()
	f.handler.ResolveSecretAccessRequest(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestResolveSecretAccessRequest_SelfApprovalForbidden(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	createBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	createReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(createBody)), f.requesterID)
	f.handler.CreateSecretAccessRequest(httptest.NewRecorder(), createReq)

	req := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"action":"approve"}`)), f.requesterID), "requestId", "1")
	w := httptest.NewRecorder()
	f.handler.ResolveSecretAccessRequest(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestResolveSecretAccessRequest_ApproveThenReadSucceeds(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	f.core.SetClassificationRestrictedRequiresApproval(true)
	createBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	createReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(createBody)), f.requesterID)
	f.handler.CreateSecretAccessRequest(httptest.NewRecorder(), createReq)

	req := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"action":"approve"}`)), f.approverID), "requestId", "1")
	w := httptest.NewRecorder()
	f.handler.ResolveSecretAccessRequest(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	val, err := f.core.GetSecretValueWithPermissionCheck(context.Background(), f.secretID, f.requesterID)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t-value", string(val))
}

func TestResolveSecretAccessRequest_RejectThenReadStillRefused(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	f.core.SetClassificationRestrictedRequiresApproval(true)
	createBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	createReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(createBody)), f.requesterID)
	f.handler.CreateSecretAccessRequest(httptest.NewRecorder(), createReq)

	req := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"action":"reject","reason":"no"}`)), f.approverID), "requestId", "1")
	w := httptest.NewRecorder()
	f.handler.ResolveSecretAccessRequest(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	_, err := f.core.GetSecretValueWithPermissionCheck(context.Background(), f.secretID, f.requesterID)
	require.Error(t, err, "a rejected request must not unlock the read")
}

func TestResolveSecretAccessRequest_InvalidAction(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	req := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"action":"bogus"}`)), f.approverID), "requestId", "1")
	w := httptest.NewRecorder()
	f.handler.ResolveSecretAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── WithdrawSecretAccessRequest ──────────────────────────────────────────────

func TestWithdrawSecretAccessRequest_OwnerSucceeds(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	createBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	createReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(createBody)), f.requesterID)
	f.handler.CreateSecretAccessRequest(httptest.NewRecorder(), createReq)

	req := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", nil), f.requesterID), "requestId", "1")
	w := httptest.NewRecorder()
	f.handler.WithdrawSecretAccessRequest(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWithdrawSecretAccessRequest_OtherUserNotFound(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	createBody := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, f.secretID)
	createReq := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(createBody)), f.requesterID)
	f.handler.CreateSecretAccessRequest(httptest.NewRecorder(), createReq)

	req := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", nil), f.approverID), "requestId", "1")
	w := httptest.NewRecorder()
	f.handler.WithdrawSecretAccessRequest(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
