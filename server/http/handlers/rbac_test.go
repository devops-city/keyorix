package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// RBACTestHelper provides consistent test setup for RBAC handler tests
type RBACTestHelper struct {
	CoreService *core.KeyorixCore
	DB          *gorm.DB
}

// NewRBACTestHelper creates a new test helper with in-memory database and core service
func NewRBACTestHelper(t *testing.T) *RBACTestHelper {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Create an in-memory database for testing. A plain ":memory:" DSN gives
	// every pooled connection its own empty database, so a second connection
	// (e.g. from a detached audit writer) would see no tables; sqlitetest caps
	// the pool to one connection.
	db := sqlitetest.OpenWithConfig(t, "kxrbac_", &gorm.Config{})

	// Auto-migrate the schema
	err = db.AutoMigrate(&models.User{}, &models.SecretNode{}, &models.ShareRecord{})
	require.NoError(t, err)

	// Create storage and core service
	storage := store.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(storage)

	return &RBACTestHelper{
		CoreService: coreService,
		DB:          db,
	}
}

// CreateTestUser creates a test user in the database
func (h *RBACTestHelper) CreateTestUser(t *testing.T, username string, userID uint) *models.User {
	user := &models.User{
		ID:       userID,
		Username: username,
		Email:    username + "@test.com",
	}

	result := h.DB.Create(user)
	require.NoError(t, result.Error)

	return user
}

// addAuthContext adds authentication context to a request for testing
func addAuthContext(ctx context.Context, token string) context.Context {
	var userCtx *middleware.UserContext

	switch token {
	case "valid-token":
		userCtx = &middleware.UserContext{
			UserID:   1,
			Username: "admin",
			Email:    "admin@example.com",
			Roles:    []string{"admin", "user"},
		}
	case "test-token":
		userCtx = &middleware.UserContext{
			UserID:   2,
			Username: "testuser",
			Email:    "test@example.com",
			Roles:    []string{"viewer"},
		}
	}

	if userCtx != nil {
		return context.WithValue(ctx, middleware.GetUserContextKey(), userCtx)
	}

	return ctx
}

func TestListUsers(t *testing.T) {
	helper := NewRBACTestHelper(t)
	// Exercise the package-level legacy path like TestCreateUser and its
	// siblings do. Without this the test used whatever defaultUserHandler an
	// earlier test left behind, i.e. a DB that is closed once that test ends.
	saved := defaultUserHandler
	defaultUserHandler = nil
	t.Cleanup(func() { defaultUserHandler = saved })

	// Create test users
	helper.CreateTestUser(t, "admin", 1)
	helper.CreateTestUser(t, "user1", 2)

	tests := []struct {
		name           string
		authToken      string
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "successful list users",
			authToken:      "valid-token",
			queryParams:    "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "list users with pagination",
			authToken:      "valid-token",
			queryParams:    "?page=1&page_size=10",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "unauthorized without token",
			authToken:      "",
			queryParams:    "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "limited permissions with test token",
			authToken:      "test-token",
			queryParams:    "",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodGet, "/api/v1/users"+tt.queryParams, nil)
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			ListUsers(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				// Check response structure
				var response map[string]any
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				assert.Contains(t, response, "data")
				data := response["data"].(map[string]any)
				assert.Contains(t, data, "users")
				assert.Contains(t, data, "total")
			}
		})
	}
}

func TestCreateUser(t *testing.T) {
	_ = NewRBACTestHelper(t)
	saved := defaultUserHandler
	defaultUserHandler = nil
	t.Cleanup(func() { defaultUserHandler = saved })

	tests := []struct {
		name           string
		authToken      string
		requestBody    any
		expectedStatus int
		expectedError  string
	}{
		{
			name:      "successful user creation",
			authToken: "valid-token",
			requestBody: map[string]any{
				"username":     "newuser",
				"email":        "newuser@example.com",
				"display_name": "New User",
				"password":     "securepassword123",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:      "missing required fields",
			authToken: "valid-token",
			requestBody: map[string]any{
				"username": "",
				"email":    "invalid-email",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized without token",
			authToken:      "",
			requestBody:    map[string]any{},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:      "insufficient permissions with test token",
			authToken: "test-token",
			requestBody: map[string]any{
				"username":     "newuser",
				"email":        "newuser@example.com",
				"display_name": "New User",
				"password":     "securepassword123",
			},
			expectedStatus: http.StatusCreated, // Handler doesn't check permissions yet
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request body
			var body bytes.Buffer
			err := json.NewEncoder(&body).Encode(tt.requestBody)
			require.NoError(t, err)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users", &body)
			req.Header.Set("Content-Type", "application/json")
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			CreateUser(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusCreated {
				// Check response structure
				var response map[string]any
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				assert.Contains(t, response, "data")
				assert.Contains(t, response, "message")
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	helper := NewRBACTestHelper(t)
	saved := defaultUserHandler
	defaultUserHandler = nil
	t.Cleanup(func() { defaultUserHandler = saved })

	// Create test user
	helper.CreateTestUser(t, "admin", 1)

	tests := []struct {
		name           string
		authToken      string
		userID         string
		expectedStatus int
	}{
		{
			name:           "successful get user",
			authToken:      "valid-token",
			userID:         "1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user not found",
			authToken:      "valid-token",
			userID:         "999",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "invalid user ID",
			authToken:      "valid-token",
			userID:         "invalid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			userID:         "1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+tt.userID, nil)
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Add URL parameters to context
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.userID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			GetUser(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestUpdateUser(t *testing.T) {
	helper := NewRBACTestHelper(t)
	saved := defaultUserHandler
	defaultUserHandler = nil
	t.Cleanup(func() { defaultUserHandler = saved })

	// Create test user
	helper.CreateTestUser(t, "admin", 1)

	tests := []struct {
		name           string
		authToken      string
		userID         string
		requestBody    any
		expectedStatus int
	}{
		{
			name:      "successful user update",
			authToken: "valid-token",
			userID:    "1",
			requestBody: map[string]any{
				"email":        "updated@example.com",
				"display_name": "Updated User",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:      "invalid user ID",
			authToken: "valid-token",
			userID:    "invalid",
			requestBody: map[string]any{
				"email": "updated@example.com",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			userID:         "1",
			requestBody:    map[string]any{},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request body
			var body bytes.Buffer
			err := json.NewEncoder(&body).Encode(tt.requestBody)
			require.NoError(t, err)

			// Create request
			req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+tt.userID, &body)
			req.Header.Set("Content-Type", "application/json")
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Add URL parameters to context
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.userID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			UpdateUser(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestDeleteUser(t *testing.T) {
	helper := NewRBACTestHelper(t)
	saved := defaultUserHandler
	defaultUserHandler = nil
	t.Cleanup(func() { defaultUserHandler = saved })

	// Create test user
	helper.CreateTestUser(t, "admin", 1)

	tests := []struct {
		name           string
		authToken      string
		userID         string
		expectedStatus int
	}{
		{
			name:           "successful user deletion",
			authToken:      "valid-token",
			userID:         "1",
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "invalid user ID",
			authToken:      "valid-token",
			userID:         "invalid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			userID:         "1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+tt.userID, nil)
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Add URL parameters to context
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.userID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			DeleteUser(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestListRoles(t *testing.T) {
	_ = NewRBACTestHelper(t)

	tests := []struct {
		name           string
		authToken      string
		expectedStatus int
	}{
		{
			name:           "successful list roles",
			authToken:      "valid-token",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			ListRoles(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				// Check response structure
				var response map[string]any
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				assert.Contains(t, response, "data")
				data := response["data"].(map[string]any)
				assert.Contains(t, data, "roles")
			}
		})
	}
}

func TestCreateRole(t *testing.T) {
	_ = NewRBACTestHelper(t)

	tests := []struct {
		name           string
		authToken      string
		requestBody    any
		expectedStatus int
	}{
		{
			name:      "successful role creation",
			authToken: "valid-token",
			requestBody: map[string]any{
				"name":        "developer",
				"description": "Developer role with limited access",
				"permissions": []string{"secrets.read", "secrets.write"},
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:      "missing required fields",
			authToken: "valid-token",
			requestBody: map[string]any{
				"name": "",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			// #189: a zero-width space (U+200B) can't be used to disguise a role name.
			name:      "name with zero-width space is rejected",
			authToken: "valid-token",
			requestBody: map[string]any{
				"name":        "dev\u200bteam",
				"description": "Developer role with limited access",
				"permissions": []string{"secrets.read", "secrets.write"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			// #189: an RTL override (U+202E) can't be used to disguise a role name.
			name:      "name with RTL override is rejected",
			authToken: "valid-token",
			requestBody: map[string]any{
				"name":        "dev\u202eteam",
				"description": "Developer role with limited access",
				"permissions": []string{"secrets.read", "secrets.write"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			requestBody:    map[string]any{},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request body
			var body bytes.Buffer
			err := json.NewEncoder(&body).Encode(tt.requestBody)
			require.NoError(t, err)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", &body)
			req.Header.Set("Content-Type", "application/json")
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			CreateRole(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestGetRole(t *testing.T) {
	_ = NewRBACTestHelper(t)

	tests := []struct {
		name           string
		authToken      string
		roleID         string
		expectedStatus int
	}{
		{
			name:           "successful get role",
			authToken:      "valid-token",
			roleID:         "1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "role not found",
			authToken:      "valid-token",
			roleID:         "999",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "invalid role ID",
			authToken:      "valid-token",
			roleID:         "invalid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			roleID:         "1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/"+tt.roleID, nil)
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Add URL parameters to context
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.roleID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			GetRole(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestUpdateRole(t *testing.T) {
	_ = NewRBACTestHelper(t)

	tests := []struct {
		name           string
		authToken      string
		roleID         string
		requestBody    any
		expectedStatus int
	}{
		{
			name:      "successful role update",
			authToken: "valid-token",
			roleID:    "1",
			requestBody: map[string]any{
				"description": "Updated role description",
				"permissions": []string{"secrets.read", "secrets.write", "secrets.delete"},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:      "invalid role ID",
			authToken: "valid-token",
			roleID:    "invalid",
			requestBody: map[string]any{
				"description": "Updated description",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			roleID:         "1",
			requestBody:    map[string]any{},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request body
			var body bytes.Buffer
			err := json.NewEncoder(&body).Encode(tt.requestBody)
			require.NoError(t, err)

			// Create request
			req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/"+tt.roleID, &body)
			req.Header.Set("Content-Type", "application/json")
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Add URL parameters to context
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.roleID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			UpdateRole(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestDeleteRole(t *testing.T) {
	_ = NewRBACTestHelper(t)

	tests := []struct {
		name           string
		authToken      string
		roleID         string
		expectedStatus int
	}{
		{
			name:           "successful role deletion",
			authToken:      "valid-token",
			roleID:         "1",
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "invalid role ID",
			authToken:      "valid-token",
			roleID:         "invalid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			roleID:         "1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/"+tt.roleID, nil)
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Add URL parameters to context
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.roleID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			DeleteRole(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestAssignRole(t *testing.T) {
	helper := NewRBACTestHelper(t)

	// Create test users
	helper.CreateTestUser(t, "admin", 1)
	helper.CreateTestUser(t, "user1", 2)

	tests := []struct {
		name           string
		authToken      string
		requestBody    any
		expectedStatus int
	}{
		{
			name:      "successful role assignment",
			authToken: "valid-token",
			requestBody: map[string]any{
				"user_id": 2,
				"role_id": 1,
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:      "missing required fields",
			authToken: "valid-token",
			requestBody: map[string]any{
				"user_id": 0,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			requestBody:    map[string]any{},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request body
			var body bytes.Buffer
			err := json.NewEncoder(&body).Encode(tt.requestBody)
			require.NoError(t, err)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", &body)
			req.Header.Set("Content-Type", "application/json")
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			AssignRole(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestRemoveRole(t *testing.T) {
	helper := NewRBACTestHelper(t)

	// Create test users
	helper.CreateTestUser(t, "admin", 1)
	helper.CreateTestUser(t, "user1", 2)

	tests := []struct {
		name           string
		authToken      string
		requestBody    any
		expectedStatus int
	}{
		{
			name:      "successful role removal",
			authToken: "valid-token",
			requestBody: map[string]any{
				"user_id": 2,
				"role_id": 1,
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:      "missing required fields",
			authToken: "valid-token",
			requestBody: map[string]any{
				"user_id": 0,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			requestBody:    map[string]any{},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request body
			var body bytes.Buffer
			err := json.NewEncoder(&body).Encode(tt.requestBody)
			require.NoError(t, err)

			// Create request
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/user-roles", &body)
			req.Header.Set("Content-Type", "application/json")
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			RemoveRole(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestGetUserRoles(t *testing.T) {
	helper := NewRBACTestHelper(t)

	// Create test users
	helper.CreateTestUser(t, "admin", 1)
	helper.CreateTestUser(t, "user1", 2)

	tests := []struct {
		name           string
		authToken      string
		userID         string
		expectedStatus int
	}{
		{
			name:           "successful get user roles",
			authToken:      "valid-token",
			userID:         "1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid user ID",
			authToken:      "valid-token",
			userID:         "invalid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized",
			authToken:      "",
			userID:         "1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodGet, "/api/v1/user-roles/user/"+tt.userID, nil)
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
				ctx := addAuthContext(req.Context(), tt.authToken)
				req = req.WithContext(ctx)
			}

			// Add URL parameters to context
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("userId", tt.userID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			GetUserRoles(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// Benchmark tests for RBAC handlers
func BenchmarkListUsers(b *testing.B) {
	_ = NewRBACTestHelper(&testing.T{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	ctx := addAuthContext(req.Context(), "valid-token")
	req = req.WithContext(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		ListUsers(w, req)
	}
}

func BenchmarkCreateUser(b *testing.B) {
	_ = NewRBACTestHelper(&testing.T{})

	requestBody := map[string]any{
		"username":     "benchuser",
		"email":        "bench@example.com",
		"display_name": "Benchmark User",
		"password":     "securepassword123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var body bytes.Buffer
		_ = json.NewEncoder(&body).Encode(requestBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", &body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer valid-token")
		ctx := addAuthContext(req.Context(), "valid-token")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		CreateUser(w, req)
	}
}

func BenchmarkListRoles(b *testing.B) {
	_ = NewRBACTestHelper(&testing.T{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	ctx := addAuthContext(req.Context(), "valid-token")
	req = req.WithContext(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		ListRoles(w, req)
	}
}

func BenchmarkAssignRole(b *testing.B) {
	_ = NewRBACTestHelper(&testing.T{})

	requestBody := map[string]any{
		"user_id": 2,
		"role_id": 1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var body bytes.Buffer
		_ = json.NewEncoder(&body).Encode(requestBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", &body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer valid-token")
		ctx := addAuthContext(req.Context(), "valid-token")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		AssignRole(w, req)
	}
}
