package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// rbacRoute is one (method, path) -> responder pair for rbacTestServer.
type rbacRoute struct {
	method, path string
	respond      func(w http.ResponseWriter, r *http.Request)
}

// rbacTestServer dispatches to the first matching route; an unmatched request 404s,
// failing the test loudly via the response the CLI command under test observes.
func rbacTestServer(t *testing.T, routes ...rbacRoute) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, route := range routes {
			if r.Method == route.method && r.URL.Path == route.path {
				route.respond(w, r)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func jsonRoute(method, path, body string) rbacRoute {
	return rbacRoute{method, path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}}
}

func jsonRouteStatus(method, path string, status int, body string) rbacRoute {
	return rbacRoute{method, path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}}
}

// usersRoute resolves any email lookup to user id 42.
func usersRoute() rbacRoute {
	return jsonRoute(http.MethodGet, "/api/v1/users",
		`{"data":{"users":[{"id":42,"email":"user@example.test","username":"user"}]}}`)
}

// rolesRoute resolves any role-name lookup to role id 7 ("viewer").
func rolesRoute() rbacRoute {
	return jsonRoute(http.MethodGet, "/api/v1/roles",
		`{"data":{"roles":[{"ID":7,"Name":"viewer","Description":"Read-only"}],"total":1}}`)
}

// ── assign-role / remove-role ───────────────────────────────────────────────────

func TestRunRBACAssignRole_RequiresUserAndRole(t *testing.T) {
	rbacUserEmail, rbacRoleName = "", ""
	if err := runRBACAssignRole(rbacAssignRoleCmd, nil); err == nil {
		t.Fatal("expected an error when --user/--role are omitted")
	}
}

func TestRunRBACAssignRole_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, usersRoute(), rolesRoute(),
		jsonRouteStatus(http.MethodPost, "/api/v1/user-roles", http.StatusCreated, `{"data":{"user_id":42,"role_id":7}}`))
	setPATCreds(t, srv)
	rbacUserEmail, rbacRoleName = "user@example.test", "viewer"
	defer func() { rbacUserEmail, rbacRoleName = "", "" }()

	out := captureStdout(t, func() {
		if err := runRBACAssignRole(rbacAssignRoleCmd, nil); err != nil {
			t.Fatalf("runRBACAssignRole: %v", err)
		}
	})
	if out != "Successfully assigned role 'viewer' to user 'user@example.test'\n" {
		t.Fatalf("output = %q, want the old CLI's exact confirmation", out)
	}
}

func TestRunRBACAssignRole_EnvironmentRequiresProject(t *testing.T) {
	rbacUserEmail, rbacRoleName, rbacAssignEnv = "user@example.test", "viewer", "prod"
	defer func() { rbacUserEmail, rbacRoleName, rbacAssignEnv = "", "", "" }()
	if err := runRBACAssignRole(rbacAssignRoleCmd, nil); err == nil {
		t.Fatal("expected an error when --environment is set without --project")
	}
}

func TestRunRBACRemoveRole_RequiresUserAndRole(t *testing.T) {
	rbacRemoveUserEmail, rbacRemoveRoleName = "", ""
	if err := runRBACRemoveRole(rbacRemoveRoleCmd, nil); err == nil {
		t.Fatal("expected an error when --user/--role are omitted")
	}
}

func TestRunRBACRemoveRole_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, usersRoute(), rolesRoute(),
		rbacRoute{http.MethodDelete, "/api/v1/user-roles", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }})
	setPATCreds(t, srv)
	rbacRemoveUserEmail, rbacRemoveRoleName = "user@example.test", "viewer"
	defer func() { rbacRemoveUserEmail, rbacRemoveRoleName = "", "" }()

	out := captureStdout(t, func() {
		if err := runRBACRemoveRole(rbacRemoveRoleCmd, nil); err != nil {
			t.Fatalf("runRBACRemoveRole: %v", err)
		}
	})
	if out != "Successfully removed role 'viewer' from user 'user@example.test'\n" {
		t.Fatalf("output = %q, want the old CLI's exact confirmation", out)
	}
}

// ── list-roles / list-user-roles / list-permissions / check-permission ─────────

func TestRunRBACListRoles_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, rolesRoute())
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRBACListRoles(rbacListRolesCmd, nil); err != nil {
			t.Fatalf("runRBACListRoles: %v", err)
		}
	})
	if out != "Available roles:\n  - viewer: Read-only\n" {
		t.Fatalf("output = %q, want the old CLI's exact list format", out)
	}
}

func TestRunRBACListRoles_EmptyPrintsNoRolesMessage(t *testing.T) {
	srv := rbacTestServer(t, jsonRoute(http.MethodGet, "/api/v1/roles", `{"data":{"roles":[],"total":0}}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRBACListRoles(rbacListRolesCmd, nil); err != nil {
			t.Fatalf("runRBACListRoles: %v", err)
		}
	})
	if out != "No roles found\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

func TestRunRBACListUserRoles_RequiresUser(t *testing.T) {
	rbacListUserRolesEmail = ""
	if err := runRBACListUserRoles(rbacListUserRolesCmd, nil); err == nil {
		t.Fatal("expected an error when --user is omitted")
	}
}

func TestRunRBACListUserRoles_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, usersRoute(),
		jsonRoute(http.MethodGet, "/api/v1/users/42/roles", `{"data":{"roles":[{"id":7,"name":"viewer"}]}}`))
	setPATCreds(t, srv)
	rbacListUserRolesEmail = "user@example.test"
	defer func() { rbacListUserRolesEmail = "" }()

	out := captureStdout(t, func() {
		if err := runRBACListUserRoles(rbacListUserRolesCmd, nil); err != nil {
			t.Fatalf("runRBACListUserRoles: %v", err)
		}
	})
	if out != "Roles assigned to user 'user@example.test':\n  - viewer\n" {
		t.Fatalf("output = %q, want the old CLI's exact list format", out)
	}
}

func TestRunRBACListPermissions_RequiresUser(t *testing.T) {
	rbacListPermissionsEmail = ""
	if err := runRBACListPermissions(rbacListPermissionsCmd, nil); err == nil {
		t.Fatal("expected an error when --user is omitted")
	}
}

func TestRunRBACListPermissions_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, usersRoute(),
		jsonRoute(http.MethodGet, "/api/v1/users/42/roles", `{"data":{"roles":[{"id":7,"name":"viewer"}]}}`),
		jsonRoute(http.MethodGet, "/api/v1/roles/7/permissions", `{"data":{"role_id":7,"role_name":"viewer","permissions":[{"ID":1,"Name":"secrets.read"}]}}`))
	setPATCreds(t, srv)
	rbacListPermissionsEmail = "user@example.test"
	defer func() { rbacListPermissionsEmail = "" }()

	out := captureStdout(t, func() {
		if err := runRBACListPermissions(rbacListPermissionsCmd, nil); err != nil {
			t.Fatalf("runRBACListPermissions: %v", err)
		}
	})
	if out != "Permissions for user 'user@example.test':\n  - secrets.read\n" {
		t.Fatalf("output = %q, want the old CLI's exact list format", out)
	}
}

func TestRunRBACCheckPermission_RejectsMalformedName(t *testing.T) {
	rbacCheckUserEmail, rbacCheckPermName = "user@example.test", "not-a-permission"
	defer func() { rbacCheckUserEmail, rbacCheckPermName = "", "" }()
	if err := runRBACCheckPermission(rbacCheckPermissionCmd, nil); err == nil {
		t.Fatal("expected an error for a permission name without a '.'")
	}
}

func TestRunRBACCheckPermission_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, usersRoute(),
		jsonRoute(http.MethodGet, "/api/v1/users/42/roles", `{"data":{"roles":[{"id":7,"name":"viewer"}]}}`),
		jsonRoute(http.MethodGet, "/api/v1/roles/7/permissions", `{"data":{"role_id":7,"role_name":"viewer","permissions":[{"ID":1,"Name":"secrets.read"}]}}`))
	setPATCreds(t, srv)
	rbacCheckUserEmail, rbacCheckPermName = "user@example.test", "secrets.read"
	defer func() { rbacCheckUserEmail, rbacCheckPermName = "", "" }()

	out := captureStdout(t, func() {
		if err := runRBACCheckPermission(rbacCheckPermissionCmd, nil); err != nil {
			t.Fatalf("runRBACCheckPermission: %v", err)
		}
	})
	if out != "User 'user@example.test' has permission 'secrets.read'\n" {
		t.Fatalf("output = %q, want the old CLI's exact confirmation", out)
	}
}

// ── group-role commands ─────────────────────────────────────────────────────────

func groupsRoute() rbacRoute {
	return jsonRoute(http.MethodGet, "/api/v1/groups", `{"data":{"groups":[{"id":5,"name":"platform-team","description":""}],"total":1}}`)
}

func TestRunRBACAssignRoleToGroup_RequiresGroupAndRole(t *testing.T) {
	rbacGroupRoleGroupFlag, rbacGroupRoleName = "", ""
	if err := runRBACAssignRoleToGroup(rbacAssignRoleToGroupCmd, nil); err == nil {
		t.Fatal("expected an error when --group/--role are omitted")
	}
}

func TestRunRBACAssignRoleToGroup_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, groupsRoute(), rolesRoute(),
		jsonRouteStatus(http.MethodPost, "/api/v1/groups/5/roles", http.StatusCreated, `{"data":{"group_id":5,"role_id":7}}`))
	setPATCreds(t, srv)
	rbacGroupRoleGroupFlag, rbacGroupRoleName = "platform-team", "viewer"
	defer func() { rbacGroupRoleGroupFlag, rbacGroupRoleName = "", "" }()

	out := captureStdout(t, func() {
		if err := runRBACAssignRoleToGroup(rbacAssignRoleToGroupCmd, nil); err != nil {
			t.Fatalf("runRBACAssignRoleToGroup: %v", err)
		}
	})
	if out != "Successfully assigned role 'viewer' to group 'platform-team'\n" {
		t.Fatalf("output = %q, want the old CLI's exact confirmation", out)
	}
}

func TestRunRBACRemoveRoleFromGroup_RequiresGroupAndRole(t *testing.T) {
	rbacRemoveGroupRoleGroupFlag, rbacRemoveGroupRoleName = "", ""
	if err := runRBACRemoveRoleFromGroup(rbacRemoveRoleFromGroupCmd, nil); err == nil {
		t.Fatal("expected an error when --group/--role are omitted")
	}
}

func TestRunRBACRemoveRoleFromGroup_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, groupsRoute(), rolesRoute(),
		rbacRoute{http.MethodDelete, "/api/v1/groups/5/roles/7", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }})
	setPATCreds(t, srv)
	rbacRemoveGroupRoleGroupFlag, rbacRemoveGroupRoleName = "platform-team", "viewer"
	defer func() { rbacRemoveGroupRoleGroupFlag, rbacRemoveGroupRoleName = "", "" }()

	out := captureStdout(t, func() {
		if err := runRBACRemoveRoleFromGroup(rbacRemoveRoleFromGroupCmd, nil); err != nil {
			t.Fatalf("runRBACRemoveRoleFromGroup: %v", err)
		}
	})
	if out != "Successfully removed role 'viewer' from group 'platform-team'\n" {
		t.Fatalf("output = %q, want the old CLI's exact confirmation", out)
	}
}

func TestRunRBACListGroupRoles_RequiresGroup(t *testing.T) {
	rbacListGroupRolesGroupFlag = ""
	if err := runRBACListGroupRoles(rbacListGroupRolesCmd, nil); err == nil {
		t.Fatal("expected an error when --group is omitted")
	}
}

func TestRunRBACListGroupRoles_EmptyPrintsNoRolesMessage(t *testing.T) {
	srv := rbacTestServer(t, groupsRoute(),
		jsonRoute(http.MethodGet, "/api/v1/groups/5/roles", `{"data":{"group_id":5,"roles":null}}`))
	setPATCreds(t, srv)
	rbacListGroupRolesGroupFlag = "platform-team"
	defer func() { rbacListGroupRolesGroupFlag = "" }()

	out := captureStdout(t, func() {
		if err := runRBACListGroupRoles(rbacListGroupRolesCmd, nil); err != nil {
			t.Fatalf("runRBACListGroupRoles: %v", err)
		}
	})
	if out != "No roles assigned to group 'platform-team'\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

// ── audit-logs / export-matrix ──────────────────────────────────────────────────

func TestRunRBACAuditLogs_EmptyPrintsNoLogsMessage(t *testing.T) {
	srv := rbacTestServer(t, jsonRoute(http.MethodGet, "/api/v1/audit/rbac-logs", `{"data":{"logs":[],"total":0}}`))
	setPATCreds(t, srv)
	rbacAuditLimit = 50

	out := captureStdout(t, func() {
		if err := runRBACAuditLogs(rbacAuditLogsCmd, nil); err != nil {
			t.Fatalf("runRBACAuditLogs: %v", err)
		}
	})
	if out != "No RBAC audit logs found\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

func TestRunRBACAuditLogs_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, jsonRoute(http.MethodGet, "/api/v1/audit/rbac-logs",
		`{"data":{"logs":[{"id":1,"action":"role.assigned","actor_user_id":9,"target_user_id":42,"project_id":0,"created_at":"2026-01-02T00:00:00Z"}],"total":1}}`))
	setPATCreds(t, srv)
	rbacAuditLimit = 50

	out := captureStdout(t, func() {
		if err := runRBACAuditLogs(rbacAuditLogsCmd, nil); err != nil {
			t.Fatalf("runRBACAuditLogs: %v", err)
		}
	})
	if !containsAll(out, "RBAC audit logs (showing 1 of 1):", "role.assigned", "by user 9", "→ user 42") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunRBACExportMatrix_MatchesOldCLIOutputShape(t *testing.T) {
	srv := rbacTestServer(t, jsonRoute(http.MethodGet, "/api/v1/rbac/permission-matrix",
		`{"data":{"rows":[{"username":"user","email":"user@example.test","role_name":"viewer","permission_name":"secrets.read","scope":"global","project_name":"","expires_at":null}],"total":1}}`))
	setPATCreds(t, srv)
	rbacExportMatrixFormat = "table"

	out := captureStdout(t, func() {
		if err := runRBACExportMatrix(rbacExportMatrixCmd, nil); err != nil {
			t.Fatalf("runRBACExportMatrix: %v", err)
		}
	})
	if !containsAll(out, "USERNAME", "EMAIL", "ROLE", "PERMISSION", "SCOPE", "PROJECT", "EXPIRES",
		"user", "user@example.test", "viewer", "secrets.read", "global", "never") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunRBACExportMatrix_JSONFormat(t *testing.T) {
	srv := rbacTestServer(t, jsonRoute(http.MethodGet, "/api/v1/rbac/permission-matrix",
		`{"data":{"rows":[{"username":"user","email":"user@example.test","role_name":"viewer","permission_name":"secrets.read"}],"total":1}}`))
	setPATCreds(t, srv)
	rbacExportMatrixFormat = "json"
	defer func() { rbacExportMatrixFormat = "table" }()

	out := captureStdout(t, func() {
		if err := runRBACExportMatrix(rbacExportMatrixCmd, nil); err != nil {
			t.Fatalf("runRBACExportMatrix: %v", err)
		}
	})
	if !containsAll(out, `"username": "user"`, `"permission_name": "secrets.read"`) {
		t.Fatalf("json output missing expected fields, got: %q", out)
	}
}

// TestMatrixRowToCSV_NeutralizesFormulaInjection guards against CWE-1236
// (spreadsheet formula injection, CI's repo-wide internal/core/guards/csv_writer_completeness_test.go):
// a role/username/etc. value beginning with =, +, -, or @ must be prefixed with
// a leading single quote so Excel/Sheets/LibreOffice treat it as text, not a
// formula, when an auditor opens the export.
func TestMatrixRowToCSV_NeutralizesFormulaInjection(t *testing.T) {
	malicious := "=cmd|' /C calc'!A0"
	row := apiclient.PermissionMatrixRow{Username: &malicious}
	got := matrixRowToCSV(row)
	if got[0] != "'"+malicious {
		t.Fatalf("username field = %q, want a leading single quote to neutralize the formula", got[0])
	}
}
