package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

func setupRotationPolicyTest(t *testing.T) (*RotationPolicyHandler, *core.KeyorixCore) {
	t.Helper()

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(
		&models.AuditEvent{}, &models.PendingAuditEvent{}, // AUDIT-TX-3: rotation policy changes are audited in their transaction
		&models.Project{},
		&models.Environment{},
		&models.RotationPolicy{},
		&models.Role{},
		&models.Permission{},
		&models.RolePermission{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
	)
	require.NoError(t, err)

	// Make the test user (ID 1) a global admin so in-handler authorization on
	// create passes via the admin bypass.
	adminRole := &models.Role{Name: "admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	storage := store.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(storage)
	handler := NewRotationPolicyHandler(coreService)
	return handler, coreService
}

func withUserCtx(r *http.Request) *http.Request {
	userCtx := &customMiddleware.UserContext{
		UserID:   1,
		Username: "testuser",
		Email:    "testuser@example.com",
	}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

func withChiParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestRotationPolicyCreate201(t *testing.T) {
	handler, _ := setupRotationPolicyTest(t)

	body := `{"name":"Monthly Policy","scope":"project","project_id":1,"interval_days":30,"alert_days_before":7,"notify_on_breach":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rotation-policies", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(req)

	w := httptest.NewRecorder()
	handler.Create(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestRotationPolicyList200(t *testing.T) {
	handler, _ := setupRotationPolicyTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies", nil)
	req = withUserCtx(req)

	w := httptest.NewRecorder()
	handler.List(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRotationPolicyGet404(t *testing.T) {
	handler, _ := setupRotationPolicyTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies/9999", nil)
	req = withUserCtx(withChiParam(req, "id", "9999"))

	w := httptest.NewRecorder()
	handler.Get(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotationPolicyDelete204(t *testing.T) {
	handler, coreService := setupRotationPolicyTest(t)

	projectID := uint(1)
	policy, err := coreService.CreateRotationPolicy(context.Background(), 1, &core.CreateRotationPolicyRequest{
		Name:            "To Delete",
		Scope:           "project",
		ProjectID:       &projectID,
		IntervalDays:    30,
		AlertDaysBefore: 7,
		CreatedBy:       "testuser",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/rotation-policies/%d", policy.ID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", policy.ID)))

	w := httptest.NewRecorder()
	handler.Delete(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}
