package http

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

// roleExpiryTestEnv bundles the pieces needed by each role-expiry sub-test.
type roleExpiryTestEnv struct {
	server *httptest.Server
	token  string
	c      *core.KeyorixCore
	db     *gorm.DB
}

// newRoleExpiryEnv creates a minimal server with a bootstrapped admin.
func newRoleExpiryEnv(t *testing.T) *roleExpiryTestEnv {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	return &roleExpiryTestEnv{server: server, token: token, c: c, db: db}
}

// postRoleExpiryCheck POSTs to the role-expiry-check endpoint and returns
// the status code plus the parsed data map.
func postRoleExpiryCheck(t *testing.T, env *roleExpiryTestEnv, authHeader string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/api/v1/admin/jobs/role-expiry-check", nil)
	require.NoError(t, err)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.Unmarshal(body, &envelope))
	}
	return resp.StatusCode, envelope.Data
}

// seedExpiringRole inserts a UserRole row for the bootstrapped admin user that
// expires at the given time. It uses the "viewer" role (also seeded by
// BootstrapSystem) so the composite PK (user, role, project=0, env=0) does not
// collide with the admin's existing permanent "admin" role grant.
func seedExpiringRole(t *testing.T, env *roleExpiryTestEnv, expiresAt time.Time) {
	t.Helper()
	ctx := context.Background()

	// Look up the admin user seeded by createTestToken.
	user, err := env.c.GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)
	require.NotNil(t, user)

	// Use "viewer" — always seeded by BootstrapSystem and not yet held by testadmin.
	var role models.Role
	require.NoError(t, env.db.Where("name = ?", "viewer").First(&role).Error)

	// Write an expiring UserRole directly (bypasses SoD gates which aren't relevant here).
	require.NoError(t, env.db.Save(&models.UserRole{
		UserID:    user.ID,
		RoleID:    role.ID,
		ProjectID: 0,
		ExpiresAt: &expiresAt,
	}).Error)
}

// TestRoleExpiryCheck_NoExpiringRoles verifies that when no role grants are
// near expiry the endpoint returns 200 with {warnings:0, criticals:0}.
func TestRoleExpiryCheck_NoExpiringRoles(t *testing.T) {
	env := newRoleExpiryEnv(t)
	code, data := postRoleExpiryCheck(t, env, "Bearer "+env.token)
	assert.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 0, data["warnings"])
	assert.EqualValues(t, 0, data["criticals"])
}

// TestRoleExpiryCheck_RoleExpiringIn3Days verifies that a grant expiring in
// 3 days triggers a warning notification ({warnings:1, criticals:0}).
func TestRoleExpiryCheck_RoleExpiringIn3Days(t *testing.T) {
	env := newRoleExpiryEnv(t)
	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	seedExpiringRole(t, env, expiresAt)

	code, data := postRoleExpiryCheck(t, env, "Bearer "+env.token)
	assert.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 1, data["warnings"], "expected 1 warning for a grant expiring in 3 days")
	assert.EqualValues(t, 0, data["criticals"])
}

// TestRoleExpiryCheck_RoleExpiringIn12Hours verifies that a grant expiring
// within 24 hours triggers a critical notification ({warnings:0, criticals:1}).
func TestRoleExpiryCheck_RoleExpiringIn12Hours(t *testing.T) {
	env := newRoleExpiryEnv(t)
	expiresAt := time.Now().Add(12 * time.Hour)
	seedExpiringRole(t, env, expiresAt)

	code, data := postRoleExpiryCheck(t, env, "Bearer "+env.token)
	assert.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 0, data["warnings"])
	assert.EqualValues(t, 1, data["criticals"], "expected 1 critical for a grant expiring in 12 hours")
}

// TestRoleExpiryCheck_AlreadyExpiredRoleNotCounted verifies that a grant that
// has already expired is not counted (it is past the deadline, not approaching it).
func TestRoleExpiryCheck_AlreadyExpiredRoleNotCounted(t *testing.T) {
	env := newRoleExpiryEnv(t)
	// Expired 1 hour ago.
	expiresAt := time.Now().Add(-1 * time.Hour)
	seedExpiringRole(t, env, expiresAt)

	code, data := postRoleExpiryCheck(t, env, "Bearer "+env.token)
	assert.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 0, data["warnings"], "already-expired grant must not be counted")
	assert.EqualValues(t, 0, data["criticals"], "already-expired grant must not be counted")
}

// TestRoleExpiryCheck_Unauthenticated verifies that a request without a valid
// Bearer token is rejected with 401.
func TestRoleExpiryCheck_Unauthenticated(t *testing.T) {
	env := newRoleExpiryEnv(t)
	code, _ := postRoleExpiryCheck(t, env, "") // no Authorization header
	assert.Equal(t, http.StatusUnauthorized, code)
}

// TestRoleExpiryCheck_Idempotent verifies that calling the endpoint twice for
// the same expiring grant does not double-count (the second call skips the
// standing unread notification and returns {warnings:0, criticals:0}).
func TestRoleExpiryCheck_Idempotent(t *testing.T) {
	env := newRoleExpiryEnv(t)
	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	seedExpiringRole(t, env, expiresAt)

	// First call — creates the notification.
	code1, data1 := postRoleExpiryCheck(t, env, "Bearer "+env.token)
	require.Equal(t, http.StatusOK, code1)
	assert.EqualValues(t, 1, data1["warnings"])

	// Second call — the standing unread notification deduplicates, so no new ones.
	code2, data2 := postRoleExpiryCheck(t, env, "Bearer "+env.token)
	require.Equal(t, http.StatusOK, code2)
	assert.EqualValues(t, 0, data2["warnings"], "second call must not re-notify the same grant")
	assert.EqualValues(t, 0, data2["criticals"])
}
