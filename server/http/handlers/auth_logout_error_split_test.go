// auth_logout_error_split_test.go is the end-to-end HTTP-level proof for item 3 of the
// UX-fixes batch: POST /auth/logout must return 401 for an ordinary not-found/already-
// invalidated session (unchanged from #2337), and 500 -- not a silent 401 -- for a real
// storage failure during the session lookup. internal/core/auth_logout_error_split_test.go
// covers the same split at the core.Logout level directly; this file confirms the status
// code actually reaching the HTTP response, driven through the real handler.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failGetSessionStorageWrapper fails GetSession for exactly failToken with a plain error —
// NOT storage.ErrSessionNotFound — simulating a real retrieval failure distinct from an
// ordinary not-found/already-invalidated session. failToken is set AFTER bootstrap/login
// (which themselves exercise session lookups that must still succeed normally).
type failGetSessionStorageWrapper struct {
	storage.Storage
	failToken string
}

func (s *failGetSessionStorageWrapper) GetSession(ctx context.Context, token string) (*models.Session, error) {
	if token == s.failToken {
		return nil, errors.New("injected fault: simulated DB connection lost")
	}
	return s.Storage.GetSession(ctx, token)
}

// freshCoreWithFailingLogoutSession builds a fresh bootstrapped core (same shape as
// freshCoreS8) whose storage fails GetSession for exactly one token, for driving Logout's
// real-storage-failure path through the actual HTTP handler.
func freshCoreWithFailingLogoutSession(t *testing.T) (*core.KeyorixCore, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxlogouterrsplit_")
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.RotationPolicy{}, &models.Notification{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
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
		&models.LegalHold{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
	))

	base := store.NewLocalStorage(db)
	wrapped := &failGetSessionStorageWrapper{Storage: base}
	cs := core.NewKeyorixCore(wrapped)
	cs.SetDynamicAllowPrivateTargets(true)
	cs.SetDynamicEngineFactory(func(bt string) (dynamic.CredentialEngine, error) { return dynamic.New(bt, true, false) })

	const bootToken = "logout-err-split-boot"
	cs.SetBootstrapToken(bootToken)
	ctx := context.Background()
	_, err := cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "logouterrsplit", Email: "logouterrsplit@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw", Token: bootToken,
	})
	require.NoError(t, err)
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: "logouterrsplit", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	// Arm the fault only now — bootstrap/login must complete against the real storage first.
	wrapped.failToken = session.SessionToken
	return cs, session.SessionToken
}

func TestLogout_StorageFailure_Returns500NotSilent401(t *testing.T) {
	cs, sessionToken := freshCoreWithFailingLogoutSession(t)
	h := NewAuthHandler(cs, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w := httptest.NewRecorder()
	h.Logout(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"a real storage failure during the session lookup must surface as 500, not a silent 401")
}

func TestLogout_NotFoundSession_Returns401Unchanged(t *testing.T) {
	// #2337's own externally-visible behavior, byte-for-byte: still 401 for an ordinary
	// not-found/already-invalidated token.
	h := newAuthHandlerS8(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer notarealsessiontoken")
	w := httptest.NewRecorder()
	h.Logout(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
