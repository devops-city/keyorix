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

// setupScopedRBACCore builds a core whose DB has two projects (A=1, B=2), a
// secret in each, an admin user (1, global) and a viewer user (2) scoped to
// project A only. Sessions: "admin-tok" → user 1, "viewerA-tok" → user 2.
func setupScopedRBACCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.SecretNode{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Session{},
		&models.SecretACL{}, // ListSecretsWithSharingInfo calls ListSecretACLsByUser
	))

	now := time.Now()
	// Projects A=1, B=2, each with one environment.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "project-a"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "project-b"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "prod"}).Error)

	// One secret in each project.
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "a-secret", OwnerID: 1, CreatedBy: "admin", Status: "active", IsSecret: true}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 2, ProjectID: 2, EnvironmentID: 2, Name: "b-secret", OwnerID: 1, CreatedBy: "admin", Status: "active", IsSecret: true}).Error)

	// Users.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "viewerA", Email: "viewera@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)

	// Roles + permissions: admin (global, via bypass) and viewer (secrets.read).
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)

	// user 1 → global admin; user 2 → viewer scoped to project A only.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2, ProjectID: 1}).Error)

	seedSession(t, db, 1, "admin-tok")
	seedSession(t, db, 2, "viewerA-tok")

	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

func TestScopedRBACEnforcement(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	router, err := NewRouter(&config.Config{}, setupScopedRBACCore(t))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	do := func(t *testing.T, method, path, token string) int {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// listSecretCount performs a GET and returns (status, len(data.secrets)) --
	// used for the scoped-listing path, which by design (see secrets_list.go's
	// doc comment on ListSecrets, and core.TestListSecretsWithSharingInfo_
	// ProjectFilter_HonoursACL) returns 200 with an empty result for a scope
	// the caller can't see into, rather than 403 -- a hard 403 there would
	// incorrectly block an ACL-only principal who holds a valid per-secret
	// grant in the requested scope. What actually matters for this test is
	// that no out-of-scope secret is ever returned in the body, not the
	// status code.
	listSecretCount := func(t *testing.T, path, token string) (int, int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var body struct {
			Data struct {
				Secrets []struct {
					ID uint `json:"ID"`
				} `json:"secrets"`
			} `json:"data"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		return resp.StatusCode, len(body.Data.Secrets)
	}

	// Per-secret reads: viewer-A may read project-A's secret, not project-B's.
	// /risk avoids decrypting the value while still exercising ScopeFromSecretParam,
	// and (unlike /shares, which is owner-only by design — see #246) has no
	// additional per-secret ownership gate, so it isolates the route-scoping check
	// this test is about.
	assert.Equal(t, http.StatusOK, do(t, "GET", "/api/v1/secrets/1/risk", "viewerA-tok"),
		"viewer-A reads a secret in project A")
	assert.Equal(t, http.StatusForbidden, do(t, "GET", "/api/v1/secrets/2/risk", "viewerA-tok"),
		"viewer-A must be denied a secret in project B")

	// Admin (global) reads both.
	assert.Equal(t, http.StatusOK, do(t, "GET", "/api/v1/secrets/1/risk", "admin-tok"))
	assert.Equal(t, http.StatusOK, do(t, "GET", "/api/v1/secrets/2/risk", "admin-tok"))

	// Listing: viewer-A's project-scoped viewer role (secrets.read at project
	// A) now makes ListSecrets surface project A's secret even though
	// viewer-A neither owns it nor holds an ACL/share grant on it -- matching
	// what /risk (per-secret GET) already granted via RequireScopedPermission
	// (core.ListSecretsInScopeWithSharingInfo). viewer-A must NEVER see
	// project B's secret in the body regardless of query scope, since
	// viewer-A holds no role/ownership/ACL grant there at all.
	statusA, countA := listSecretCount(t, "/api/v1/secrets?project_id=1", "viewerA-tok")
	assert.Equal(t, http.StatusOK, statusA, "viewer-A lists project A")
	assert.Equal(t, 1, countA, "viewer-A's project-A role grant surfaces project A's secret in the list")

	statusB, countB := listSecretCount(t, "/api/v1/secrets?project_id=2", "viewerA-tok")
	assert.Equal(t, http.StatusOK, statusB, "viewer-A querying project B gets 200, not an error")
	assert.Equal(t, 0, countB, "viewer-A must never see project B's secret in the response body")

	statusUnscoped, countUnscoped := listSecretCount(t, "/api/v1/secrets", "viewerA-tok")
	assert.Equal(t, http.StatusOK, statusUnscoped,
		"viewer-A unscoped list returns union of accessible project-A secrets (scoped-union, not 403)")
	assert.Equal(t, 1, countUnscoped, "viewer-A's unscoped list also surfaces project A's role-visible secret")

	// Admin lists globally.
	assert.Equal(t, http.StatusOK, do(t, "GET", "/api/v1/secrets", "admin-tok"))

	// Write is denied to viewer-A even in project A (delete a secret it can read).
	assert.Equal(t, http.StatusForbidden, do(t, "DELETE", "/api/v1/secrets/1", "viewerA-tok"),
		"viewer-A has no delete permission")
}

// setupACLOnlyRBACCore builds a core with one project/environment and TWO
// secrets in it, plus an "acl-only" user (ID 3) who holds a project-membership
// role that grants NO permissions at all (mirroring the membership-only
// UserRole pattern internal/core/secret_acl_test.go's newACLCore uses to seed a
// GrantSecretACL target: GrantSecretACL requires the grantee to already be a
// project member, but that membership role need not itself confer secrets.read/
// write). User 3's only possible path to secrets.read/write is therefore a
// SecretACL grant. Sessions: "admin-tok3" -> user 1 (global admin, used to
// perform the grant through the real HTTP ACL endpoint), "aclonly-tok" -> user 3.
func setupACLOnlyRBACCore(t *testing.T) (cs *core.KeyorixCore, secretWithACL, secretWithoutACL uint) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.SecretNode{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Session{},
		&models.SecretACL{}, &models.AuditEvent{},
		&models.SecretAccessSchedule{}, &models.Tag{}, &models.SecretTag{},
	))

	now := time.Now()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "project-acl"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "acl-granted-secret", OwnerID: 1, CreatedBy: "admin", Status: "active", IsSecret: true}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 2, ProjectID: 1, EnvironmentID: 1, Name: "no-acl-secret", OwnerID: 1, CreatedBy: "admin", Status: "active", IsSecret: true}).Error)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin3@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "aclonly", Email: "aclonly@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)

	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	// member-noperm: gives user 3 project membership (so GrantSecretACL's
	// IsProjectMember precondition passes) WITHOUT granting any RBAC permission
	// — no RolePermission row exists for this role. This is what proves the ACL
	// grant, not a role, is what authorizes user 3 below.
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "member-noperm"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 2, ProjectID: 1}).Error)

	seedSession(t, db, 1, "admin-tok3")
	seedSession(t, db, 3, "aclonly-tok")

	return core.NewKeyorixCore(store.NewLocalStorage(db)), 1, 2
}

// TestSecretACL_EndToEnd_PerSecretRoutes is the r140 regression test: it proves
// that a per-secret SecretACL grant — documented since RBAC Phase 3 as usable
// "without needing a project role at all" — actually authorizes the per-secret
// GET/write HTTP routes, not just ListSecrets. Before this fix, AuthorizeSecret
// (the ACL-aware check) had zero production callers: an ACL-only user was 403'd
// on every per-secret route despite holding a valid grant.
func TestSecretACL_EndToEnd_PerSecretRoutes(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cs, secretWithACL, secretWithoutACL := setupACLOnlyRBACCore(t)
	router, err := NewRouter(&config.Config{}, cs)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	do := func(t *testing.T, method, path, token string, body string) int {
		t.Helper()
		var reqBody *bytes.Reader
		if body != "" {
			reqBody = bytes.NewReader([]byte(body))
		} else {
			reqBody = bytes.NewReader(nil)
		}
		req, err := http.NewRequest(method, server.URL+path, reqBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// Sanity: before any grant, the ACL-only user (project member, zero-permission
	// role) is denied read on BOTH secrets — proves the negative case (neither a
	// qualifying role nor an ACL grant) still 403s, i.e. nothing was loosened.
	assert.Equal(t, http.StatusForbidden, do(t, "GET", fmt.Sprintf("/api/v1/secrets/%d", secretWithACL), "aclonly-tok", ""),
		"acl-only user must be denied before any grant exists")
	assert.Equal(t, http.StatusForbidden, do(t, "GET", fmt.Sprintf("/api/v1/secrets/%d", secretWithoutACL), "aclonly-tok", ""),
		"acl-only user must be denied on a secret it is never granted")

	// Admin grants user 3 secrets.read AND secrets.write on secretWithACL only,
	// through the real HTTP ACL endpoint (exercising the same grant path an
	// operator would use).
	grantBody := `{"user_id":3,"permissions":["secrets.read","secrets.write"]}`
	assert.Equal(t, http.StatusOK, do(t, "POST", fmt.Sprintf("/api/v1/secrets/%d/acl", secretWithACL), "admin-tok3", grantBody),
		"admin grants the ACL")

	// The ACL-only user can now GET the granted secret (middleware layer +
	// GetSecretWithPermissionCheck's core.CheckSecretPermission both must honor
	// the grant) ...
	assert.Equal(t, http.StatusOK, do(t, "GET", fmt.Sprintf("/api/v1/secrets/%d", secretWithACL), "aclonly-tok", ""),
		"acl-only user reads the secret it was granted, with no project role")
	// ... and a write-tier route (tags) also succeeds, proving the grant covers
	// secrets.write end to end through core.SetSecretTags -> EnforceSecretWritePermission.
	assert.Equal(t, http.StatusOK, do(t, "PUT", fmt.Sprintf("/api/v1/secrets/%d/tags", secretWithACL), "aclonly-tok", `{"tags":["env:prod"]}`),
		"acl-only user writes tags on the secret it was granted write on")

	// The grant is scoped to exactly that one secret: the ACL-only user is still
	// denied on the sibling secret in the SAME project that carries no grant —
	// proves the fix is additive/per-secret, not an accidental project-wide loosening.
	assert.Equal(t, http.StatusForbidden, do(t, "GET", fmt.Sprintf("/api/v1/secrets/%d", secretWithoutACL), "aclonly-tok", ""),
		"acl-only user remains denied on a secret it was never granted")
}
