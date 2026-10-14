package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	"github.com/keyorixhq/keyorix/server/middleware"
)

// TestCreateSecret_MaxReadsValidation is a regression guard for #347 HIGH: a
// pointer-typed `MaxReads *int validate:"omitempty,min=1"` field must reject
// max_reads=0/negative, not silently accept it as "unlimited reads" (the
// opposite of a burn-after-N-reads secret). Confirmed empirically before the
// fix: both values produced err=nil from the validator.
func TestCreateSecret_MaxReadsValidation(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// A pooled sqlite ":memory:" connection hands out a fresh, empty database
	// per connection unless pinned to a single connection — pin it so every
	// query in this test (across subtests) sees the migrated schema.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{}, &models.Group{}, &models.GroupRole{},
		&models.UserGroup{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessLog{}))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod"}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler, err := NewSecretHandler(coreService)
	require.NoError(t, err)

	userCtx := &middleware.UserContext{UserID: 1, Username: "alice", ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true}

	post := func(name string, maxReads *int) *httptest.ResponseRecorder {
		body := map[string]any{
			"name": name, "value": "v", "project_id": uint(1),
			"environment_id": uint(10), "type": "static",
		}
		if maxReads != nil {
			body["max_reads"] = *maxReads
		}
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(raw))
		r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), userCtx))
		rr := httptest.NewRecorder()
		handler.CreateSecret(rr, r)
		return rr
	}

	intPtr := func(i int) *int { return &i }

	t.Run("max_reads=0 is rejected", func(t *testing.T) {
		rr := post("S1", intPtr(0))
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "ValidationError")
	})

	t.Run("max_reads=-100 is rejected", func(t *testing.T) {
		rr := post("S2", intPtr(-100))
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "ValidationError")
	})

	t.Run("max_reads=5 is accepted and creates the secret", func(t *testing.T) {
		rr := post("S3", intPtr(5))
		assert.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	})

	t.Run("omitted max_reads is accepted (unlimited reads, unchanged behavior)", func(t *testing.T) {
		rr := post("S4", nil)
		assert.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	})
}

// TestUpdateSecret_MaxReadsValidation exercises the same #347 regression via
// PUT /api/v1/secrets/{id}, the other declared, wired call site for the
// pointer-typed MaxReads field.
func TestUpdateSecret_MaxReadsValidation(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// A pooled sqlite ":memory:" connection hands out a fresh, empty database
	// per connection unless pinned to a single connection — pin it so every
	// query in this test (across subtests) sees the migrated schema.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{}, &models.Group{}, &models.GroupRole{},
		&models.UserGroup{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessLog{}))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)
	// Project-scoped membership required by CheckSecretPermission's IsProjectMember gate.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID, ProjectID: 1}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod"}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler, err := NewSecretHandler(coreService)
	require.NoError(t, err)

	created, err := coreService.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "target", Value: []byte("v"), ProjectID: 1, EnvironmentID: 10, Type: "static",
		CreatedBy: "alice", OwnerID: 1,
	})
	require.NoError(t, err)

	userCtx := &middleware.UserContext{UserID: 1, Username: "alice", ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true}

	put := func(maxReads int) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"max_reads": maxReads})
		r := httptest.NewRequest(http.MethodPut, "/api/v1/secrets/1", bytes.NewReader(raw))
		r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), userCtx))
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", strconv.FormatUint(uint64(created.ID), 10))
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
		rr := httptest.NewRecorder()
		handler.UpdateSecret(rr, r)
		return rr
	}

	t.Run("max_reads=0 is rejected", func(t *testing.T) {
		rr := put(0)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "ValidationError")
	})

	t.Run("max_reads=-100 is rejected", func(t *testing.T) {
		rr := put(-100)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "ValidationError")
	})

	t.Run("max_reads=3 is accepted", func(t *testing.T) {
		rr := put(3)
		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})
}
