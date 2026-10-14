package handlers

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newMatrixHandlerCore returns an RBACHandler backed by a fully-seeded
// in-memory DB so GetPermissionMatrix returns real data rows.
func newMatrixHandlerCore(t *testing.T) (*RBACHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.User{},
	))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	return NewRBACHandler(c), db
}

// seedMatrixHandlerData seeds a minimal (user, role, permission, grant) set.
func seedMatrixHandlerData(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "alice@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0, EnvironmentID: 0}).Error)
}

// TestGetPermissionMatrixHandler_JSONWithData — JSON response contains seeded row.
func TestGetPermissionMatrixHandler_JSONWithData(t *testing.T) {
	h, db := newMatrixHandlerCore(t)
	seedMatrixHandlerData(t, db)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/system/rbac/permission-matrix", nil))
	w := httptest.NewRecorder()
	h.GetPermissionMatrix(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	rows, ok := data["rows"].([]any)
	require.True(t, ok)
	require.Len(t, rows, 1, "one seeded grant should produce exactly one row")

	row := rows[0].(map[string]any)
	assert.Equal(t, "alice", row["username"])
	assert.Equal(t, "admin", row["role_name"])
	assert.Equal(t, "global", row["scope"])
}

// TestGetPermissionMatrixHandler_CSVWithData — CSV response includes a data row.
func TestGetPermissionMatrixHandler_CSVWithData(t *testing.T) {
	h, db := newMatrixHandlerCore(t)
	seedMatrixHandlerData(t, db)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/system/rbac/permission-matrix?format=csv", nil))
	w := httptest.NewRecorder()
	h.GetPermissionMatrix(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	assert.Equal(t, `attachment; filename="permission-matrix.csv"`, w.Header().Get("Content-Disposition"))

	records, err := csv.NewReader(w.Body).ReadAll()
	require.NoError(t, err)
	// header + 1 data row
	require.Len(t, records, 2, "CSV must have header + 1 data row")
	assert.Contains(t, records[0], "username")
	assert.Contains(t, records[1], "alice")
	assert.Contains(t, records[1], "secrets.read")
}

// TestGetPermissionMatrixHandler_CSVEmpty — CSV response with no grants: only header.
func TestGetPermissionMatrixHandler_CSVEmpty(t *testing.T) {
	h, _ := newMatrixHandlerCore(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/system/rbac/permission-matrix?format=csv", nil))
	w := httptest.NewRecorder()
	h.GetPermissionMatrix(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	records, err := csv.NewReader(w.Body).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 1, "empty DB: CSV should have header row only")
	assert.Contains(t, records[0], "username")
}

// TestGetPermissionMatrixHandler_ProjectFilter — project_id query param is accepted
// and returns 200 (empty for an empty DB).
func TestGetPermissionMatrixHandler_ProjectFilter(t *testing.T) {
	h, _ := newMatrixHandlerCore(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/system/rbac/permission-matrix?project_id=42", nil))
	w := httptest.NewRecorder()
	h.GetPermissionMatrix(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetPermissionMatrixHandler_CSVWithExpiry — CSV response includes an ExpiresAt
// value when the grant has a non-nil expiry, exercising the time-format branch.
func TestGetPermissionMatrixHandler_CSVWithExpiry(t *testing.T) {
	h, db := newMatrixHandlerCore(t)

	exp := time.Date(2028, 6, 1, 12, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "alice@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: 1, ProjectID: 0, EnvironmentID: 0, ExpiresAt: &exp,
	}).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/system/rbac/permission-matrix?format=csv", nil))
	w := httptest.NewRecorder()
	h.GetPermissionMatrix(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "2028-06-01T12:00:00Z", "CSV must contain formatted ExpiresAt")
}

// TestGetPermissionMatrixHandler_CSVFormulaInjection — a project name starting with a
// formula-injection character (=, +, -, @) must be escaped with a leading single quote
// in the CSV export (G49: csvSafe() formula-injection escaping).
func TestGetPermissionMatrixHandler_CSVFormulaInjection(t *testing.T) {
	h, db := newMatrixHandlerCore(t)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "alice@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 9, Name: "=cmd|' /C calc'!A1"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 9, EnvironmentID: 0}).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/system/rbac/permission-matrix?format=csv", nil))
	w := httptest.NewRecorder()
	h.GetPermissionMatrix(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	records, err := csv.NewReader(w.Body).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2, "CSV must have header + 1 data row")

	// project is column index 7 in the header:
	// username, email, role, permission, resource, action, scope, project, environment, expires_at
	projectCell := records[1][7]
	assert.True(t, strings.HasPrefix(projectCell, "'"), "formula-injection prefix must be neutralized with a leading quote, got %q", projectCell)
	assert.Equal(t, "'=cmd|' /C calc'!A1", projectCell)
}

// TestGetPermissionMatrixHandler_StorageError — a storage failure produces HTTP 500.
func TestGetPermissionMatrixHandler_StorageError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	// Build a core whose ListAllUserRoleGrants will fail by closing the DB.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.User{},
	))
	// Close the underlying SQL connection so all queries fail.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	_ = sqlDB.Close()

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	h := NewRBACHandler(c)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/system/rbac/permission-matrix", nil))
	w := httptest.NewRecorder()
	h.GetPermissionMatrix(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
