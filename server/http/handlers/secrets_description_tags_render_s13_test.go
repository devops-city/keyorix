// secrets_description_tags_render_s13_test.go — coverage sweep for the
// remaining branches in secrets_description.go not yet covered by s14:
//
//   - DescribeSecret: "exceeds" error branch → 400
//   - DescribeSecret: "permission"/"not authorized" error branch → 403
//
// All other branches in secrets_description.go, secrets_tags.go, and
// secrets_render.go are covered by handlers_s14_test.go.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// freshDescribeFixtureS13 opens a uniquely-named in-memory SQLite DB, migrates
// all required models, seeds two users (1 = owner, 2 = non-owner), a project, an
// environment, and one secret owned by user 1. Returns the handler and the secret ID.
func freshDescribeFixtureS13(t *testing.T) (*SecretHandler, uint) {
	t.Helper()

	cfg := &config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}
	require.NoError(t, i18n.Initialize(cfg))

	db := sqlitetest.Open(t, "kxhandlers_s13d_")

	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.Tag{}, &models.SecretTag{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.AnomalyAlert{}, &models.RotationPolicy{}, &models.Notification{},
		&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.LoginAttempt{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
		&models.WebAuthnCredential{}, &models.WebAuthnSession{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.ConnectRefGrant{}, &models.Session{}, &models.SetupToken{},
		&models.MFAChallenge{}, &models.SSOLoginState{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
		&models.SecretDependency{}, &models.RiskException{},
		&models.MFASecret{}, &models.MFARecoveryCode{},
		&models.IdentityProvider{}, &models.ExternalIdentity{},
		&models.LegalHold{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
	))

	// User 1 = owner of the secret; User 2 = someone with no access.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner_s13d", Email: "owner_s13d@test.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "other_s13d", Email: "other_s13d@test.com"}).Error)

	st := store.NewLocalStorage(db)
	cs := core.NewKeyorixCore(st)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "proj-s13d"})
	require.NoError(t, err)
	// User 1 must be a project member so CheckSecretPermission's IsProjectMember gate passes.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: proj.ID}).Error)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "env-s13d", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name:          "describe-target-s13d",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Type:          "static",
		OwnerID:       1,
		IsSecret:      true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)

	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h, secret.ID
}

// withUserCtxIDAndName injects a specific user ID into the request context.
func withUserCtxIDAndName(r *http.Request, userID uint, username string) *http.Request {
	uctx := &customMiddleware.UserContext{UserID: userID, Username: username, Email: username + "@test.com"}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), uctx))
}

// ── DescribeSecret: "exceeds" branch → 400 ───────────────────────────────────

// TestDescribeSecret_DescriptionExceeds_S13 sends a description longer than
// maxSecretDescriptionLen (1024) on an owned secret. Core returns an error
// containing "exceeds" → handler maps it to 400.
func TestDescribeSecret_DescriptionExceeds_S13(t *testing.T) {
	h, id := freshDescribeFixtureS13(t)

	// Description with 1025 characters — one over the 1024-char limit.
	longDesc := strings.Repeat("x", 1025)
	body, _ := json.Marshal(map[string]string{"description": longDesc})

	req := withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	)
	req = withUserCtxIDAndName(req, 1, "owner_s13d")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Error")
}

// ── DescribeSecret: "permission"/"not authorized" branch → 403 ───────────────

// TestDescribeSecret_PermissionDenied_S13 calls DescribeSecret as user 2, who
// does not own the secret and has no share. Core returns "not authorized" → 403.
func TestDescribeSecret_PermissionDenied_S13(t *testing.T) {
	h, id := freshDescribeFixtureS13(t)

	body, _ := json.Marshal(map[string]string{"description": "unauthorized note"})

	req := withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	)
	// User 2 has no access to the secret (owned by user 1, no share).
	req = withUserCtxIDAndName(req, 2, "other_s13d")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}
