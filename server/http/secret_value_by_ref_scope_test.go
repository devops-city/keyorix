package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// setupByRefScopeCore builds a core with two projects, a value-bearing secret in each
// (viewerA owns project-A's so it can read the value), an admin (global) and viewerA
// (scoped to project A only). No encryption service is configured, so a version's
// EncryptedValue is returned verbatim.
func setupByRefScopeCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	// A private in-memory DB per call (sqlitetest): the unique name isolates it from other
	// tests, and the counter in the name means repeated invocations within one process
	// (e.g. go test -count=N) each get a fresh DB instead of re-attaching to a prior
	// iteration's live leftover.
	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Session{},
		&models.SecretAccessSchedule{},
		// AuditEvent/SecretAccessLog: a successful value-by-ref read now writes
		// these synchronously and checks the result (SESSION-PERF, #2403 follow-up,
		// item 3, audit-before-disclosure) — previously fire-and-forget, so this
		// fixture's missing tables went unnoticed (the write failed silently in a
		// background goroutine while the response had already gone out with the
		// value). Pre-existing coverage gap, surfaced by the new synchronous check,
		// not a behavior regression — fixing the fixture, not weakening the check.
		&models.AuditEvent{}, &models.SecretAccessLog{},
	))

	now := time.Now()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "project-a"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "project-b"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "prod"}).Error)

	// a-secret is owned by viewerA (so the per-user value-read check passes); b-secret by admin.
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "a-secret", OwnerID: 2, CreatedBy: "viewerA", Status: "active", IsSecret: true}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 2, ProjectID: 2, EnvironmentID: 2, Name: "b-secret", OwnerID: 1, CreatedBy: "admin", Status: "active", IsSecret: true}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{ID: 1, SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("a-value")}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{ID: 2, SecretNodeID: 2, VersionNumber: 1, EncryptedValue: []byte("b-value")}).Error)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "viewerA", Email: "viewera@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)

	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)               // admin: global
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2, ProjectID: 1}).Error) // viewerA: project A only

	seedSession(t, db, 1, "admin-tok")
	seedSession(t, db, 2, "viewerA-tok")

	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// TestByRefRead_CrossProjectDenied locks in the security invariant for the by-reference
// value endpoint (ADR-059): the scope resolver authorizes against the RESOLVED secret's
// project, so a user scoped to project A cannot read a project-B secret by reference —
// the denial fires at the scope gate, before any value is read.
func TestByRefRead_CrossProjectDenied(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	router, err := NewRouter(&config.Config{}, setupByRefScopeCore(t))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	get := func(ref, token string) (int, string) {
		q := url.Values{}
		q.Set("ref", ref)
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/secrets/value?"+q.Encode(), nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// THE invariant: viewer scoped to project A is denied a by-ref read in project B.
	code, _ := get("project-b/prod/b-secret", "viewerA-tok")
	assert.Equal(t, http.StatusForbidden, code,
		"a viewer scoped to project A must NOT read a project-B secret by reference")

	// Contrast — the same viewer reads its own project-A secret by reference.
	code, body := get("project-a/prod/a-secret", "viewerA-tok")
	assert.Equal(t, http.StatusOK, code, "viewer-A reads a project-A secret by reference")
	assert.Contains(t, body, "a-value")

	// Global admin reads the project-B secret by reference.
	code, body = get("project-b/prod/b-secret", "admin-tok")
	assert.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "b-value")

	// Unauthenticated is rejected before resolution.
	code, _ = get("project-a/prod/a-secret", "")
	assert.Equal(t, http.StatusUnauthorized, code)
}
