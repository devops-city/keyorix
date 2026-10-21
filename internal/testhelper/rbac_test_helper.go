package testhelper

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	permAuditAdmin    = "audit.admin"
	permAuditRead     = "audit.read"
	permRolesAssign   = "roles.assign"
	permRolesRead     = "roles.read"
	permSecretsDelete = "secrets.delete"
	permSecretsRead   = "secrets.read"
	permSecretsWrite  = "secrets.write"
	permSystemRead    = "system.read"
	permUsersRead     = "users.read"
	permUsersWrite    = "users.write"
)

type testContextKey string

const (
	testContextKeyUserID   testContextKey = "user_id"
	testContextKeyUsername testContextKey = "username"
)

// RBACTestHelper provides consistent test setup for RBAC tests
type RBACTestHelper struct {
	CoreService *core.KeyorixCore
	DB          *gorm.DB
	SqlDB       *sql.DB
	Storage     *store.LocalStorage
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

	// Create an in-memory database for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Get underlying SQL DB for raw queries if needed
	sqlDB, err := db.DB()
	require.NoError(t, err)

	// Auto-migrate the schema with all RBAC tables
	err = db.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.ShareRecord{},
		&models.ConnectRefGrant{},
		&models.MachineIdentity{},
		&models.MachineIdentityRole{},
		&models.PersonalAccessToken{},
		&models.Session{},
		&models.SystemMetadata{},
		// #419: every role-grant choke point now calls ListSoDPolicies (the
		// separation-of-duties preventive gate, sod.go) — migrated unconditionally
		// here so any test exercising a grant path gets a real (empty-by-default)
		// sod_policies table instead of a "no such table" storage error.
		&models.SoDPolicy{},
		// GetSecret now queries secret_access_schedules for temporal-access enforcement.
		&models.SecretAccessSchedule{},
		// AUDIT-TX-2: every grant path (role, group, permission, share, machine
		// identity, PAT, user/project create) commits its audit row in its own
		// transaction and fails closed without it, so the table must exist.
		&models.AuditEvent{}, &models.PendingAuditEvent{},
	)
	require.NoError(t, err)

	// Create storage and core service
	storage := store.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(storage)

	helper := &RBACTestHelper{
		CoreService: coreService,
		DB:          db,
		SqlDB:       sqlDB,
		Storage:     storage,
	}

	// Seed basic test data
	helper.seedTestData(t)

	return helper
}

// seedTestData creates basic test data for RBAC tests
func (h *RBACTestHelper) seedTestData(t *testing.T) {
	// Create default projects
	projects := []models.Project{
		{ID: 1, Name: "default", Description: "Default project"},
		{ID: 2, Name: "production", Description: "Production project"},
		{ID: 3, Name: "staging", Description: "Staging project"},
	}
	for _, p := range projects {
		result := h.DB.Create(&p)
		require.NoError(t, result.Error)
	}

	// Create default environments
	environments := []models.Environment{
		{ID: 1, Name: "production"},
		{ID: 2, Name: "staging"},
		{ID: 3, Name: "development"},
	}
	for _, env := range environments {
		result := h.DB.Create(&env)
		require.NoError(t, result.Error)
	}

	// Create default roles using raw SQL to match migration structure
	roles := []struct {
		ID          uint
		Name        string
		Description string
	}{
		{1, "super_admin", "Super Administrator with full system access"},
		{2, "admin", "Administrator with full access to assigned projects"},
		{3, "editor", "Can create, read, update secrets in assigned projects"},
		{4, "viewer", "Read-only access to secrets in assigned projects"},
		{5, "auditor", "Can view audit logs and system information"},
		{6, "system_viewer", "Minimal install baseline (ADR-021)"},
	}

	for _, role := range roles {
		// name_folded is NOT NULL (#1642); every seeded role name here is
		// already pure-lowercase ASCII, so it's its own folded form.
		// ADR-084: bypasses_permission_checks is the structural admin-bypass
		// flag, not the name — set true here for super_admin/admin exactly
		// as real bootstrap seeding would, so tests using this helper to
		// exercise the admin bypass keep working.
		_, _ = h.SqlDB.Exec("INSERT OR IGNORE INTO roles (id, name, name_folded, description, bypasses_permission_checks) VALUES (?, ?, ?, ?, ?)",
			role.ID, role.Name, role.Name, role.Description, role.Name == "super_admin" || role.Name == "admin")
	}

	// Create default permissions using raw SQL
	permissions := []struct {
		ID          uint
		Name        string
		Description string
		Resource    string
		Action      string
	}{
		{1, permSecretsRead, "Read secrets", "secrets", "read"},
		{2, permSecretsWrite, "Create and update secrets", "secrets", "write"},
		{3, permSecretsDelete, "Delete secrets", "secrets", "delete"},
		{4, "secrets.admin", "Full administrative access to secrets", "secrets", "admin"},
		{5, permUsersRead, "View user information", "users", "read"},
		{6, permUsersWrite, "Create and update users", "users", "write"},
		{7, "users.delete", "Delete users", "users", "delete"},
		{8, "users.admin", "Full administrative access to users", "users", "admin"},
		{9, permRolesRead, "View roles", "roles", "read"},
		{10, "roles.write", "Create and update roles", "roles", "write"},
		{11, "roles.delete", "Delete roles", "roles", "delete"},
		{12, "roles.admin", "Full administrative access to roles", "roles", "admin"},
		{13, permRolesAssign, "Assign and remove roles from users", "roles", "assign"},
		{14, permSystemRead, "View system information", "system", "read"},
		{15, "system.write", "Modify system settings", "system", "write"},
		{16, "system.admin", "Full administrative access to system", "system", "admin"},
		{17, permAuditRead, "View audit logs", "audit", "read"},
		{18, permAuditAdmin, "Full administrative access to audit system", "audit", "admin"},
		{19, "connect.read", "Read secrets from external stores via Keyorix Connect (ADR-043)", "connect", "read"},
	}

	// Create permissions table if it doesn't exist
	_, _ = h.SqlDB.Exec(`CREATE TABLE IF NOT EXISTS permissions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		description TEXT,
		resource TEXT NOT NULL,
		action TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)

	// Create role_permissions table if it doesn't exist
	_, _ = h.SqlDB.Exec(`CREATE TABLE IF NOT EXISTS role_permissions (
		role_id INTEGER NOT NULL,
		permission_id INTEGER NOT NULL,
		PRIMARY KEY (role_id, permission_id)
	)`)

	for _, perm := range permissions {
		_, _ = h.SqlDB.Exec("INSERT OR IGNORE INTO permissions (id, name, description, resource, action) VALUES (?, ?, ?, ?, ?)",
			perm.ID, perm.Name, perm.Description, perm.Resource, perm.Action)
	}

	// Assign permissions to roles
	rolePermissions := map[string][]string{
		"super_admin": {permSecretsRead, permSecretsWrite, permSecretsDelete, "secrets.admin",
			permUsersRead, permUsersWrite, "users.delete", "users.admin",
			permRolesRead, "roles.write", "roles.delete", "roles.admin", permRolesAssign,
			permSystemRead, "system.write", "system.admin",
			permAuditRead, permAuditAdmin, "connect.read"},
		"admin": {permSecretsRead, permSecretsWrite, permSecretsDelete,
			permUsersRead, permUsersWrite,
			permRolesRead, permRolesAssign,
			permSystemRead, permAuditRead},
		"editor":        {permSecretsRead, permSecretsWrite, permUsersRead},
		"viewer":        {permSecretsRead, permUsersRead},
		"auditor":       {permAuditRead, permAuditAdmin, permSystemRead, permUsersRead, permRolesRead},
		"system_viewer": {permSystemRead},
	}

	for roleName, permNames := range rolePermissions {
		for _, permName := range permNames {
			_, _ = h.SqlDB.Exec(`INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
				SELECT r.id, p.id FROM roles r, permissions p
				WHERE r.name = ? AND p.name = ?`, roleName, permName)
		}
	}
}

// CreateTestUser creates a test user in the database
func (h *RBACTestHelper) CreateTestUser(t *testing.T, username string, userID uint) *models.User {
	user := &models.User{
		ID:             userID,
		Username:       username,
		UsernameFolded: strings.ToLower(username),
		Email:          username + "@test.com",
		EmailFolded:    strings.ToLower(username) + "@test.com",
	}

	result := h.DB.Create(user)
	require.NoError(t, result.Error)

	return user
}

// CreateTestRole creates a test role in the database
func (h *RBACTestHelper) CreateTestRole(t *testing.T, name, description string, roleID uint) *models.Role {
	role := &models.Role{
		ID:          roleID,
		Name:        name,
		Description: description,
	}

	result := h.DB.Create(role)
	require.NoError(t, result.Error)

	return role
}

// CreateTestGroup creates a test group in the database
func (h *RBACTestHelper) CreateTestGroup(t *testing.T, name, description string, groupID uint) *models.Group {
	group := &models.Group{
		ID:          groupID,
		Name:        name,
		NameFolded:  strings.ToLower(name),
		Description: description,
	}

	result := h.DB.Create(group)
	require.NoError(t, result.Error)

	return group
}

// AssignUserRole assigns a role to a user
func (h *RBACTestHelper) AssignUserRole(t *testing.T, userID, roleID uint, projectID *uint) {
	userRole := &models.UserRole{
		UserID:    userID,
		RoleID:    roleID,
		ProjectID: derefScope(projectID),
	}

	result := h.DB.Create(userRole)
	require.NoError(t, result.Error)
}

// AssignUserToGroup assigns a user to a group
func (h *RBACTestHelper) AssignUserToGroup(t *testing.T, userID, groupID uint) {
	userGroup := &models.UserGroup{
		UserID:  userID,
		GroupID: groupID,
	}

	result := h.DB.Create(userGroup)
	require.NoError(t, result.Error)
}

// AssignGroupRole assigns a role to a group
func (h *RBACTestHelper) AssignGroupRole(t *testing.T, groupID, roleID uint, projectID *uint) {
	groupRole := &models.GroupRole{
		GroupID:   groupID,
		RoleID:    roleID,
		ProjectID: derefScope(projectID),
	}

	result := h.DB.Create(groupRole)
	require.NoError(t, result.Error)
}

// derefScope converts a nullable scope pointer to the 0 = global sentinel.
func derefScope(id *uint) uint {
	if id == nil {
		return 0
	}
	return *id
}

// CreateTestSecret creates a test secret in the database
func (h *RBACTestHelper) CreateTestSecret(t *testing.T, name string, ownerID uint, secretID uint) *models.SecretNode {
	secret := &models.SecretNode{
		ID:            secretID,
		ProjectID:     1, // default project
		EnvironmentID: 1, // production environment
		Name:          name,
		IsSecret:      true,
		Type:          "text",
		OwnerID:       ownerID,
		CreatedBy:     "test",
		Status:        "active",
	}

	result := h.DB.Create(secret)
	require.NoError(t, result.Error)

	return secret
}

// GetUserRoles returns all roles assigned to a user
func (h *RBACTestHelper) GetUserRoles(t *testing.T, userID uint) []models.Role {
	var roles []models.Role
	result := h.DB.Table("roles").
		Joins("JOIN user_roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Find(&roles)
	require.NoError(t, result.Error)
	return roles
}

// GetUserPermissions returns all permissions for a user (direct and through groups)
func (h *RBACTestHelper) GetUserPermissions(t *testing.T, userID uint) []string {
	var permissions []string

	// Get direct permissions through user roles
	rows, err := h.SqlDB.Query(`
		SELECT DISTINCT p.name 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = ?
	`, userID)
	require.NoError(t, err)
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)
		require.NoError(t, err)
		permissions = append(permissions, permission)
	}

	// Get permissions through group roles
	rows, err = h.SqlDB.Query(`
		SELECT DISTINCT p.name 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN group_roles gr ON rp.role_id = gr.role_id
		JOIN user_groups ug ON gr.group_id = ug.group_id
		WHERE ug.user_id = ?
	`, userID)
	require.NoError(t, err)
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)
		require.NoError(t, err)
		permissions = append(permissions, permission)
	}

	return permissions
}

// HasPermission checks if a user has a specific permission
func (h *RBACTestHelper) HasPermission(t *testing.T, userID uint, permission string) bool {
	permissions := h.GetUserPermissions(t, userID)
	return slices.Contains(permissions, permission)
}

// CreateTestContext creates a context with user information for testing
func (h *RBACTestHelper) CreateTestContext(userID uint, username string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, testContextKeyUserID, userID)
	ctx = context.WithValue(ctx, testContextKeyUsername, username)
	return ctx
}

// Cleanup cleans up test resources
func (h *RBACTestHelper) Cleanup() {
	if h.SqlDB != nil {
		_ = h.SqlDB.Close()
	}
}

// ExecuteRawSQL executes raw SQL for complex test scenarios
func (h *RBACTestHelper) ExecuteRawSQL(t *testing.T, query string, args ...any) {
	_, err := h.SqlDB.Exec(query, args...)
	require.NoError(t, err)
}

// QueryRawSQL executes a raw SQL query and returns results
func (h *RBACTestHelper) QueryRawSQL(t *testing.T, query string, args ...any) *sql.Rows {
	rows, err := h.SqlDB.Query(query, args...)
	require.NoError(t, err)
	return rows
}
