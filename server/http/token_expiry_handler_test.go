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

// tokenExpiryTestEnv bundles the pieces needed by each token-expiry sub-test.
type tokenExpiryTestEnv struct {
	server *httptest.Server
	token  string
	c      *core.KeyorixCore
	db     *gorm.DB
}

// newTokenExpiryEnv creates a minimal server with a bootstrapped admin.
func newTokenExpiryEnv(t *testing.T) *tokenExpiryTestEnv {
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

	return &tokenExpiryTestEnv{server: server, token: token, c: c, db: db}
}

// postTokenExpiryCheck POSTs to the token-expiry-check endpoint and returns
// the status code plus the parsed data map.
func postTokenExpiryCheck(t *testing.T, env *tokenExpiryTestEnv, authHeader string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/api/v1/admin/jobs/token-expiry-check", nil)
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

// seedExpiringPAT inserts a PersonalAccessToken for the admin user that expires
// at the given time.
func seedExpiringPAT(t *testing.T, env *tokenExpiryTestEnv, expiresAt time.Time) {
	t.Helper()
	ctx := context.Background()

	user, err := env.c.GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)
	require.NotNil(t, user)

	require.NoError(t, env.db.Create(&models.PersonalAccessToken{
		UserID:    user.ID,
		Name:      "test-pat",
		TokenHash: "testhash-" + expiresAt.String(),
		ExpiresAt: &expiresAt,
		Revoked:   false,
	}).Error)
}

// seedExpiringMachineCredential inserts a MachineIdentityCredential that expires
// at the given time. It requires a MachineIdentity to exist.
func seedExpiringMachineCredential(t *testing.T, env *tokenExpiryTestEnv, expiresAt time.Time) {
	t.Helper()

	// Create a machine identity first.
	machine := models.MachineIdentity{
		ProjectID:    1,
		Name:         "test-machine",
		IdentityType: "ci",
		State:        "active",
	}
	require.NoError(t, env.db.Create(&machine).Error)

	require.NoError(t, env.db.Create(&models.MachineIdentityCredential{
		MachineIdentityID: machine.ID,
		Name:              "test-machine-cred",
		TokenHash:         "mhash-" + expiresAt.String(),
		ExpiresAt:         &expiresAt,
		Revoked:           false,
	}).Error)
}

// ── Tests ────────────────────────────────────────────────────────────────────

// TestTokenExpiryCheck_NoExpiringTokens verifies that when no tokens are near
// expiry the endpoint returns 200 with all-zero counts.
func TestTokenExpiryCheck_NoExpiringTokens(t *testing.T) {
	env := newTokenExpiryEnv(t)
	code, data := postTokenExpiryCheck(t, env, "Bearer "+env.token)
	assert.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 0, data["pat_warnings"])
	assert.EqualValues(t, 0, data["pat_criticals"])
	assert.EqualValues(t, 0, data["machine_warnings"])
	assert.EqualValues(t, 0, data["machine_criticals"])
}

// TestTokenExpiryCheck_ExpiringPAT verifies that a PAT expiring in 3 days
// triggers a warning.
func TestTokenExpiryCheck_ExpiringPAT(t *testing.T) {
	env := newTokenExpiryEnv(t)
	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	seedExpiringPAT(t, env, expiresAt)

	code, data := postTokenExpiryCheck(t, env, "Bearer "+env.token)
	assert.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 1, data["pat_warnings"], "expected 1 pat_warning for a PAT expiring in 3 days")
	assert.EqualValues(t, 0, data["pat_criticals"])
}

// TestTokenExpiryCheck_CriticalPAT verifies that a PAT expiring in 12 hours
// triggers a critical.
func TestTokenExpiryCheck_CriticalPAT(t *testing.T) {
	env := newTokenExpiryEnv(t)
	expiresAt := time.Now().Add(12 * time.Hour)
	seedExpiringPAT(t, env, expiresAt)

	code, data := postTokenExpiryCheck(t, env, "Bearer "+env.token)
	assert.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 0, data["pat_warnings"])
	assert.EqualValues(t, 1, data["pat_criticals"], "expected 1 pat_critical for a PAT expiring in 12 hours")
}

// TestTokenExpiryCheck_ExpiringMachineCredential verifies that a machine credential
// expiring in 3 days triggers a machine_warnings count.
func TestTokenExpiryCheck_ExpiringMachineCredential(t *testing.T) {
	env := newTokenExpiryEnv(t)
	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	seedExpiringMachineCredential(t, env, expiresAt)

	code, data := postTokenExpiryCheck(t, env, "Bearer "+env.token)
	assert.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 1, data["machine_warnings"], "expected 1 machine_warning for a credential expiring in 3 days")
	assert.EqualValues(t, 0, data["machine_criticals"])
}

// TestTokenExpiryCheck_Unauthenticated verifies that a request without a valid
// Bearer token is rejected with 401.
func TestTokenExpiryCheck_Unauthenticated(t *testing.T) {
	env := newTokenExpiryEnv(t)
	code, _ := postTokenExpiryCheck(t, env, "") // no Authorization header
	assert.Equal(t, http.StatusUnauthorized, code)
}

// TestTokenExpiryCheck_ScopedPAT_Forbidden verifies that a PAT with a limited
// scope (secrets.read only, no system.write) is rejected with 403.
func TestTokenExpiryCheck_ScopedPAT_Forbidden(t *testing.T) {
	env := newTokenExpiryEnv(t)
	ctx := context.Background()

	// Find the bootstrapped admin user.
	user, err := env.c.GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)
	require.NotNil(t, user)

	// Create a PAT scoped to secrets.read only — no system.write.
	result, err := env.c.CreateOwnPAT(ctx, user.ID, "limited-pat", nil, []string{"secrets.read"}, 0, 0, nil)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/api/v1/admin/jobs/token-expiry-check", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+result.PlainToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
