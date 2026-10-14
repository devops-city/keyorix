// compliance_trend_handler_test.go — handler-level integration tests for the
// compliance posture trend field (GET /api/v1/compliance/posture → data.trend).
package http

import (
	"context"
	"encoding/json"
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

// complianceTrendSetup bundles the core and its underlying LocalStorage so tests
// that need to seed snapshot rows with custom timestamps can do so via the storage
// interface without going around the production code.
type complianceTrendSetup struct {
	core    *core.KeyorixCore
	storage *store.LocalStorage
}

// newComplianceTrendCore creates a minimal *core.KeyorixCore backed by an isolated
// in-memory SQLite DB that includes CompliancePostureSnapshot in its AutoMigrate list,
// alongside all the standard models required by the real router.
func newComplianceTrendCore(t *testing.T) complianceTrendSetup {
	t.Helper()
	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	err := db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.ShareRecord{},
		&models.AuditEvent{},
		&models.Session{},
		&models.Project{},
		&models.Environment{},
		&models.Permission{},
		&models.RolePermission{},
		&models.SystemMetadata{},
		&models.LoginAttempt{},
		&models.PasswordHistory{},
		&models.PersonalAccessToken{},
		&models.Tag{},
		&models.SecretTag{},
		&models.ProjectInvitation{},
		&models.DynamicSecretConfig{},
		&models.DynamicSecretLease{},
		&models.Notification{},
		&models.SetupToken{},
		&models.ProjectMembership{},
		&models.MFASecret{},
		&models.MFARecoveryCode{},
		&models.MFAChallenge{},
		&models.SecretDependency{},
		&models.MachineIdentity{},
		&models.MachineIdentityCredential{},
		&models.MachineIdentityRole{},
		&models.MachineIdentityOIDCBinding{},
		&models.WebAuthnCredential{},
		&models.WebAuthnSession{},
		&models.LegalHold{},
		&models.AccessReviewCampaign{},
		&models.AccessReviewItem{},
		&models.BreakGlassActivation{},
		&models.RiskException{},
		&models.SoDPolicy{},
		&models.ConnectRefGrant{},
		&models.AnomalyAlert{},
		&models.AccessRequest{},
		&models.AccessRequestApproval{},
		&models.SSOLoginState{},
		&models.SchedulerLockLease{},
		&models.SecretACL{},
		&models.AnomalyConfigRecord{},
		&models.StatsSnapshot{},
		&models.DeploymentStatsSnapshot{},
		// compliance posture trending — CompliancePostureSnapshot is written by
		// GetCompliancePosture on every call and read for trend computation.
		&models.CompliancePostureSnapshot{},
	)
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active "+
		"ON legal_holds (released) WHERE released = false").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user "+
		"ON break_glass_activations (project_id, user_id) WHERE state = 'active'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''").Error)
	ls := store.NewLocalStorage(db)
	return complianceTrendSetup{core: core.NewKeyorixCore(ls), storage: ls}
}

// TestGetCompliancePosture_HasTrendField verifies that an authenticated admin
// receives a 200 response with a data.trend object containing a direction field.
func TestGetCompliancePosture_HasTrendField(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	setup := newComplianceTrendCore(t)
	token := createTestToken(t, setup.core)
	router, err := NewRouter(&config.Config{}, setup.core)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/compliance/posture", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response body must have a data object")
	assert.Contains(t, data, "trend")
	trend, ok := data["trend"].(map[string]any)
	require.True(t, ok, "data.trend must be an object")
	assert.Contains(t, trend, "direction")
}

// TestGetCompliancePosture_TrendNoData_FirstCall verifies that the very first call
// returns direction == "no_data" because no previous snapshot exists yet.
func TestGetCompliancePosture_TrendNoData_FirstCall(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	setup := newComplianceTrendCore(t)
	token := createTestToken(t, setup.core)
	router, err := NewRouter(&config.Config{}, setup.core)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/compliance/posture", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response body must have a data object")
	trend, ok := data["trend"].(map[string]any)
	require.True(t, ok, "data.trend must be an object")
	assert.Equal(t, "no_data", trend["direction"], "first call must report no_data — no previous snapshot exists")
}

// TestGetCompliancePosture_Unauthenticated verifies that a request without a Bearer
// token is rejected with 401 Unauthorized.
func TestGetCompliancePosture_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	setup := newComplianceTrendCore(t)
	router, err := NewRouter(&config.Config{}, setup.core)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/compliance/posture")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestGetCompliancePosture_TrendDirection_AfterTwoCalls verifies that after a
// prior-day snapshot is seeded, a call to the endpoint returns a trend direction
// that is not "no_data".
//
// GetPreviousCompliancePostureSnapshot intentionally queries for snapshots with
// snapshot_date strictly before today's UTC midnight (to avoid same-day
// self-comparison). Two HTTP calls on the same calendar day both write to the
// same "today" slot and neither sees the other as "previous". To test that the
// trend logic activates correctly we seed one snapshot dated yesterday directly
// through the storage layer, then confirm the endpoint returns a real direction.
func TestGetCompliancePosture_TrendDirection_AfterTwoCalls(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	setup := newComplianceTrendCore(t)
	token := createTestToken(t, setup.core)
	router, err := NewRouter(&config.Config{}, setup.core)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	// Seed a snapshot dated yesterday so GetPreviousCompliancePostureSnapshot
	// finds it. We use yesterday's UTC midnight directly.
	ctx := context.Background()
	now := time.Now().UTC()
	yesterday := time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, time.UTC)
	prevSnap := &models.CompliancePostureSnapshot{
		TotalControls:  10,
		PassedControls: 8,
		FailedControls: 2,
		SnapshotDate:   yesterday,
	}
	require.NoError(t, setup.storage.SaveCompliancePostureSnapshot(ctx, prevSnap))

	// Call the endpoint — a previous snapshot now exists, so direction must not be "no_data".
	req, err := http.NewRequest("GET", srv.URL+"/api/v1/compliance/posture", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response body must have a data object")
	trend, ok := data["trend"].(map[string]any)
	require.True(t, ok, "data.trend must be an object")
	direction, _ := trend["direction"].(string)
	assert.NotEqual(t, "no_data", direction, "a previous snapshot exists — direction must be a real value, not no_data")
}
