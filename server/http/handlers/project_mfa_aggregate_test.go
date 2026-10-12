// project_mfa_aggregate_test.go — #G17 regression tests (HTTP side): the
// GET /rotation-plan, GET /shares, and GET /shared-secrets handlers are gated
// only by a global RequirePermission check, which never applies the
// per-project MFA policy (ADR-037) regardless of which specific projects the
// response discloses. Mirrors server/grpc/services/project_mfa_aggregate_test.go.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// httpMFAAggregateTestRig mirrors mfaAggregateTestRig (gRPC side): two
// projects — "guarded" (RequireMFA) and "open" — each with an overdue secret
// (so both appear in the deployment rotation plan) and a share (so both
// appear in the shares/shared-secrets listings).
type httpMFAAggregateTestRig struct {
	secretH *SecretHandler
	shareH  *ShareHandler
}

func newHTTPMFAAggregateTestRig(t *testing.T) *httpMFAAggregateTestRig {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
		&models.SecretDependency{}, &models.ShareRecord{}, &models.User{},
		&models.Group{}, &models.UserGroup{},
	))

	now := time.Now()
	daysAgo := func(d int) *time.Time { tt := now.Add(-time.Duration(d) * 24 * time.Hour); return &tt }

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "guarded", RequireMFA: true}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "guarded-90d", Scope: "project", ProjectID: uintPtr(1), IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "guarded-secret", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		OwnerID: 1, LastRotatedAt: daysAgo(200),
	}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "open"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "env2"}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "open-90d", Scope: "project", ProjectID: uintPtr(2), IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 2, Name: "open-secret", ProjectID: 2, EnvironmentID: 2, IsSecret: true, Status: "active",
		OwnerID: 1, LastRotatedAt: daysAgo(200),
	}).Error)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "auditor", Email: "auditor@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "recipient", Email: "recipient@example.com"}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: 2, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	secretH, err := NewSecretHandler(coreService)
	require.NoError(t, err)
	shareH, err := NewShareHandler(coreService)
	require.NoError(t, err)
	return &httpMFAAggregateTestRig{secretH: secretH, shareH: shareH}
}

func uintPtr(v uint) *uint { return &v }

// sessionReq builds a GET request carrying an interactive session UserContext,
// as the auth middleware would populate it after validating a session token.
func sessionReq(userID uint, mfaEnabled bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	uc := &middleware.UserContext{UserID: userID, Username: "auditor", SessionAuth: true, MFAEnabled: mfaEnabled}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// TestGetDeploymentRotationPlan_DeniesGlobalScopeMFABypass is #G17: the route
// is gated only by global secrets.read (RequirePermission), which never
// applies ProjectMFABlocked — a project-scoped call to the same underlying
// data (GetProjectRotationPlan) would deny a no-MFA session, but the
// deployment-wide roll-up did not.
func TestGetDeploymentRotationPlan_DeniesGlobalScopeMFABypass(t *testing.T) {
	r := newHTTPMFAAggregateTestRig(t)

	w := httptest.NewRecorder()
	r.secretH.GetDeploymentRotationPlan(w, sessionReq(1, false))
	require.Equal(t, http.StatusForbidden, w.Code, "an MFA-required project's data must not leak through the deployment-wide roll-up")

	w2 := httptest.NewRecorder()
	r.secretH.GetDeploymentRotationPlan(w2, sessionReq(1, true))
	require.Equal(t, http.StatusOK, w2.Code, "a session with MFA is allowed")
}

// TestListSharedSecrets_DeniesGlobalScopeMFABypass is #G17's ListSharedSecrets
// HTTP member.
func TestListSharedSecrets_DeniesGlobalScopeMFABypass(t *testing.T) {
	r := newHTTPMFAAggregateTestRig(t)

	w := httptest.NewRecorder()
	r.shareH.ListSharedSecrets(w, sessionReq(2, false))
	require.Equal(t, http.StatusForbidden, w.Code, "a shared secret from an MFA-required project must not leak through this global-scope list")

	w2 := httptest.NewRecorder()
	r.shareH.ListSharedSecrets(w2, sessionReq(2, true))
	require.Equal(t, http.StatusOK, w2.Code, "a session with MFA is allowed")
}

// TestListShares_DeniesGlobalScopeMFABypass is #G17's ListShares (ListUserShares
// gRPC equivalent) HTTP member — ShareView only carries SecretID, so the fix
// must resolve each share's owning project via a batched lookup.
func TestListShares_DeniesGlobalScopeMFABypass(t *testing.T) {
	r := newHTTPMFAAggregateTestRig(t)

	w := httptest.NewRecorder()
	r.shareH.ListShares(w, sessionReq(1, false))
	require.Equal(t, http.StatusForbidden, w.Code, "a share on an MFA-required project's secret must not leak through this global-scope list")

	w2 := httptest.NewRecorder()
	r.shareH.ListShares(w2, sessionReq(1, true))
	require.Equal(t, http.StatusOK, w2.Code, "a session with MFA is allowed")
}

// memberOfEveryProjectStorage makes IsProjectMember true, so the owner-scoped list's
// membership filter keeps the owner's shares and the aggregate MFA check is what
// decides.
type memberOfEveryProjectStorage struct {
	corestorage.Storage
}

func (memberOfEveryProjectStorage) IsProjectMember(context.Context, uint, uint) (bool, error) {
	return true, nil
}

// TestListOwnedShares_DeniesNoMFASessionOnMFARequiredProject: GET /shares/owned is
// gated by the any-scope secrets.read check, which never applies a project's MFA
// policy, so the handler must (shareViewsMFAAllowed). A session without MFA that owns a
// share on an MFA-required project gets 403 ProjectMFARequired and no share data; a
// session with MFA gets the list.
func TestListOwnedShares_DeniesNoMFASessionOnMFARequiredProject(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.ShareRecord{}, &models.User{}, &models.Group{}, &models.UserGroup{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "guarded", RequireMFA: true}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "guarded-secret", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "auditor", Email: "auditor@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "recipient", Email: "recipient@example.com"}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}).Error)
	shareH, err := NewShareHandler(core.NewKeyorixCore(memberOfEveryProjectStorage{store.NewLocalStorage(db)}))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	shareH.ListOwnedShares(w, sessionReq(1, false))
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "ProjectMFARequired")
	require.NotContains(t, w.Body.String(), `"secretId"`, "no share data may accompany the MFA refusal")

	w2 := httptest.NewRecorder()
	shareH.ListOwnedShares(w2, sessionReq(1, true))
	require.Equal(t, http.StatusOK, w2.Code, "a session with MFA is allowed: %s", w2.Body.String())
	require.Contains(t, w2.Body.String(), `"secretId":1`)
}

// TestShareLists_OverCapIsTyped422: a share list over the 10000-share cap is refused
// with a typed 422 (ShareListOverCap) and no share data, on both GET /shares/owned and
// GET /shares, not a 500. Real pagination is a parked follow-up.
func TestShareLists_OverCapIsTyped422(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.ShareRecord{}, &models.User{}, &models.Group{}, &models.UserGroup{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "s", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@example.com"}).Error)
	const overCap = 10001 // core.maxShareViewBatchSize + 1
	rows := make([]models.ShareRecord, overCap)
	for i := range rows {
		rows[i] = models.ShareRecord{SecretID: 1, OwnerID: 1, RecipientID: uint(i + 2), Permission: "read"}
	}
	require.NoError(t, db.CreateInBatches(rows, 500).Error)
	shareH, err := NewShareHandler(core.NewKeyorixCore(memberOfEveryProjectStorage{store.NewLocalStorage(db)}))
	require.NoError(t, err)

	for name, list := range map[string]func(http.ResponseWriter, *http.Request){
		"owned": shareH.ListOwnedShares,
		"all":   shareH.ListShares,
	} {
		w := httptest.NewRecorder()
		list(w, sessionReq(1, true))
		require.Equal(t, http.StatusUnprocessableEntity, w.Code, "%s: %s", name, w.Body.String())
		require.Contains(t, w.Body.String(), "ShareListOverCap", name)
		require.NotContains(t, w.Body.String(), `"secretId"`, "%s: no share data on a refusal", name)
	}
}

// erroringSecretsByIDsStorage makes the batched secret lookup fail (a transient
// storage error), which is the only source of the project ids the share lists'
// aggregate MFA check sees.
type erroringSecretsByIDsStorage struct {
	corestorage.Storage
}

func (erroringSecretsByIDsStorage) GetSecretsByIDs(context.Context, []uint) ([]*models.SecretNode, error) {
	return nil, errors.New("connection reset by peer")
}

// TestListShares_MFACheckFailsClosedOnLookupError: shareViewProjectIDs used to log a
// failed project lookup and return no project ids, so ProjectsMFABlocked had nothing
// to check and a no-MFA session got the shares on an MFA-required project back
// (review of #3018, note 3; GET /shares/owned shares the helper). A lookup error
// must deny, never answer 200.
func TestListShares_MFACheckFailsClosedOnLookupError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.ShareRecord{}, &models.User{}, &models.Group{}, &models.UserGroup{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "guarded", RequireMFA: true}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "guarded-secret", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "auditor", Email: "auditor@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "recipient", Email: "recipient@example.com"}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}).Error)
	shareH, err := NewShareHandler(core.NewKeyorixCore(erroringSecretsByIDsStorage{store.NewLocalStorage(db)}))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	shareH.ListShares(w, sessionReq(1, false))
	require.Equal(t, http.StatusInternalServerError, w.Code, "an unverifiable MFA policy must not let the shares through: %s", w.Body.String())
	require.NotContains(t, w.Body.String(), `"secretId"`)
}
