package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
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

func setupSCIMTest(t *testing.T) (*SCIMHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		// PersonalAccessToken is migrated because SCIM DELETE now revokes PATs in
		// the same transaction as the session sweep (#2855) — without the table
		// the whole deprovision transaction aborts, which is exactly what this
		// fixture gap surfaced.
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Session{}, &models.PersonalAccessToken{}, &models.AuditEvent{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)
	return NewSCIMHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

// withID attaches a chi route param so chi.URLParam("id") resolves in the handler.
func withID(req *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func decodeSCIM(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &m))
	return m
}

func TestSCIM_ProvisionGetListDeactivateDelete(t *testing.T) {
	h, db := setupSCIMTest(t)

	// Create: an email-style userName derives an alphanumeric username and echoes externalId.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@corp.com","externalId":"okta-123","displayName":"Alice","active":true}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	created := decodeSCIM(t, w)
	assert.Equal(t, "alice@corp.com", created["userName"])
	assert.Equal(t, "okta-123", created["externalId"])
	assert.Equal(t, true, created["active"])
	id, _ := created["id"].(string)
	require.NotEmpty(t, id)

	// The stored user has a derived alphanumeric username and pending_first_login state.
	var u models.User
	require.NoError(t, db.Where("external_id = ?", "okta-123").First(&u).Error)
	assert.Equal(t, "alice", u.Username)
	assert.Equal(t, core.AccountPendingFirstLogin, u.AccountState)
	assert.NotEmpty(t, u.PasswordHash, "a random (unusable) password is set")

	// Get.
	w = httptest.NewRecorder()
	h.GetUser(w, withID(httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+id, nil), id))
	require.Equal(t, http.StatusOK, w.Code)

	// List with a userName filter returns exactly the one match.
	w = httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "alice@corp.com"`), nil))
	require.Equal(t, http.StatusOK, w.Code)
	list := decodeSCIM(t, w)
	assert.Equal(t, float64(1), list["totalResults"])

	// PATCH active=false deactivates the account. IsActive=false blocks login; the
	// existing pending_first_login (restricted) state is PRESERVED, not overwritten to
	// deprovisioned, so a later reactivation can restore it rather than silently
	// clearing the first-login requirement. Only an already-'active' account moves to
	// the deprovisioned state.
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	w = httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+id, bytes.NewReader([]byte(patch))), id))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, false, decodeSCIM(t, w)["active"])

	var suspended models.User
	require.NoError(t, db.Where("external_id = ?", "okta-123").First(&suspended).Error)
	assert.Equal(t, core.AccountPendingFirstLogin, suspended.AccountState, "a restricted state is preserved across SCIM deactivation")
	assert.False(t, suspended.IsActive, "deactivation blocks login via IsActive")

	// DELETE → 204 and the user is soft-deleted.
	w = httptest.NewRecorder()
	h.DeleteUser(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+id, nil), id))
	require.Equal(t, http.StatusNoContent, w.Code)
	var count int64
	require.NoError(t, db.Model(&models.User{}).Where("external_id = ?", "okta-123").Count(&count).Error)
	assert.Equal(t, int64(0), count, "soft-deleted (excluded from default scope)")
}

func TestSCIM_CreateRequiresUserName(t *testing.T) {
	h, _ := setupSCIMTest(t)
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(`{"displayName":"x"}`))))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_DuplicateConflict(t *testing.T) {
	h, _ := setupSCIMTest(t)
	body := `{"userName":"bob@corp.com","externalId":"e1"}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code)
	w = httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	assert.Equal(t, http.StatusConflict, w.Code)
}

// TestSCIM_CannotRewriteNativeAdminEmail pins #120: a SCIM PUT (ReplaceUser) took an
// arbitrary numeric id straight off the URL with no check that SCIM actually
// provisioned it, so a valid (e.g. provisioning-only) SCIM bearer token could rewrite
// a NATIVE admin's email to a fresh attacker-controlled address — the existing
// same-email-collision guard only blocks an address already in use — and then claim
// the account via SSO/SAML email-fallback resolution. The fix refuses ReplaceUser/
// PatchUser/DeleteUser on any id that isn't SCIM-managed (no stored externalId).
func TestSCIM_CannotRewriteNativeAdminEmail(t *testing.T) {
	h, db := setupSCIMTest(t)
	// A native admin: created directly (no externalId), exactly like the classic
	// bootstrap/admin-console account this attack targets.
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "admin", Email: "admin@corp.com", DisplayName: "Admin",
		IsActive: true, AccountState: core.AccountActive,
	}).Error)

	body := `{"userName":"attacker@evil.com","emails":[{"value":"attacker@evil.com","primary":true}]}`
	w := httptest.NewRecorder()
	h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/1", bytes.NewReader([]byte(body))), "1"))
	assert.Equal(t, http.StatusNotFound, w.Code, "PUT on a non-SCIM-managed id must be refused")

	// The admin's email must be untouched.
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, "admin@corp.com", u.Email, "a native account's email must survive an attempted SCIM rewrite")

	// PATCH and DELETE on the same non-SCIM-managed id must likewise be refused.
	w = httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/1", bytes.NewReader([]byte(`{"Operations":[{"op":"replace","path":"active","value":false}]}`))), "1"))
	assert.Equal(t, http.StatusNotFound, w.Code, "PATCH on a non-SCIM-managed id must be refused")

	w = httptest.NewRecorder()
	h.DeleteUser(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/1", nil), "1"))
	assert.Equal(t, http.StatusNotFound, w.Code, "DELETE on a non-SCIM-managed id must be refused")

	require.NoError(t, db.First(&u, 1).Error)
	assert.True(t, u.IsActive, "the native admin must remain untouched by every SCIM mutation attempt")
}

// TestSCIM_ReplaceUserAllowsGenuinelyManagedAccount is the positive control: the
// normal SCIM lifecycle (an account SCIM itself provisioned) is unaffected.
func TestSCIM_ReplaceUserAllowsGenuinelyManagedAccount(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "bob", Email: "bob@corp.com", DisplayName: "Bob",
		IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|bob",
	}).Error)

	body := `{"userName":"bob@corp.com","displayName":"Bob Updated","emails":[{"value":"bob@corp.com","primary":true}]}`
	w := httptest.NewRecorder()
	h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/1", bytes.NewReader([]byte(body))), "1"))
	require.Equal(t, http.StatusOK, w.Code)

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, "Bob Updated", u.DisplayName)
}

// TestSCIM_ReplaceUser_OmittedDisplayNamePreservesExisting is the scim-07 regression:
// ReplaceUser always passed a non-nil *string to UpdateSCIMUser even when the PUT body
// omitted both displayName and name.formatted (p.displayName() then returns ""), and
// scimUpdateUserTx applied it unconditionally — unlike the email field two lines below
// it, which explicitly skips an empty value. Any PUT lacking displayName (e.g. a
// minimal/misconfigured IdP payload) silently blanked the stored value on every sync.
// The fix mirrors the email guard: an empty displayName must leave the existing value
// untouched.
func TestSCIM_ReplaceUser_OmittedDisplayNamePreservesExisting(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "bob", Email: "bob@corp.com", DisplayName: "Bob Existing",
		IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|bob",
	}).Error)

	// No displayName and no name.formatted in the payload.
	body := `{"userName":"bob@corp.com","emails":[{"value":"bob@corp.com","primary":true}]}`
	w := httptest.NewRecorder()
	h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/1", bytes.NewReader([]byte(body))), "1"))
	require.Equal(t, http.StatusOK, w.Code)

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, "Bob Existing", u.DisplayName, "a PUT that omits displayName must not blank the existing value")
}

// TestSCIM_ReplaceUser_SuppliedDisplayNameStillUpdates is the positive control for the
// scim-07 fix: a PUT that DOES supply a displayName must still update it, confirming the
// empty-value guard didn't turn into a blanket refusal to ever update the field (mirrors
// TestSCIM_ReplaceUserAllowsGenuinelyManagedAccount above).
func TestSCIM_ReplaceUser_SuppliedDisplayNameStillUpdates(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "bob", Email: "bob@corp.com", DisplayName: "Bob Existing",
		IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|bob",
	}).Error)

	body := `{"userName":"bob@corp.com","displayName":"Bob New","emails":[{"value":"bob@corp.com","primary":true}]}`
	w := httptest.NewRecorder()
	h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/1", bytes.NewReader([]byte(body))), "1"))
	require.Equal(t, http.StatusOK, w.Code)

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, "Bob New", u.DisplayName, "a PUT that supplies displayName must still update it")
}

// #3418: an SSO-claimed native account (external_id "sso:<provider>:<sub>") is not
// SCIM-owned, so the userName filter must not surface it or its numeric id, and
// GET/PATCH/DELETE on it answer like any non-SCIM account.
func TestSCIM_SSOClaimedAccountIsInvisibleAndImmutable(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Create(&models.User{
		ID: 7, Username: "alice", UsernameFolded: "alice", Email: "alice@corp.com", EmailFolded: "alice@corp.com",
		IsActive: true, AccountState: core.AccountActive, ExternalID: "sso:corp:sub-alice",
	}).Error)

	w := httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, `/scim/v2/Users?filter=userName+eq+"alice@corp.com"`, nil))
	require.Equal(t, http.StatusOK, w.Code)
	resources, _ := decodeSCIM(t, w)["Resources"].([]any)
	assert.Empty(t, resources)

	w = httptest.NewRecorder()
	h.GetUser(w, withID(httptest.NewRequest(http.MethodGet, "/scim/v2/Users/7", nil), "7"))
	assert.Equal(t, http.StatusNotFound, w.Code)

	w = httptest.NewRecorder()
	h.DeleteUser(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/7", nil), "7"))
	assert.Equal(t, http.StatusNotFound, w.Code)

	var u models.User
	require.NoError(t, db.First(&u, 7).Error)
	assert.True(t, u.IsActive)
}

// TestSCIM_ListFilterDoesNotLeakNativeAccount pins the "List adoption" half of
// #120: a userName-filter query (the IdP's reconciliation lookup) must not surface a
// NATIVE account by email match — doing so would leak its numeric SCIM resource id
// to any SCIM client, the ID a follow-up PUT/DELETE would otherwise need to target.
func TestSCIM_ListFilterDoesNotLeakNativeAccount(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "admin", Email: "admin@corp.com", DisplayName: "Admin",
		IsActive: true, AccountState: core.AccountActive,
	}).Error)

	req := httptest.NewRequest(http.MethodGet, `/scim/v2/Users?filter=userName+eq+"admin@corp.com"`, nil)
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeSCIM(t, w)
	resources, _ := resp["Resources"].([]any)
	assert.Empty(t, resources, "a filter match against a native (non-SCIM-managed) account must not be returned")
}

// TestSCIM_ListUsersOnlyReturnsSCIMManaged pins the "GET /scim/v2/Users" half of
// #G85: ListSCIMUsersPage previously queried storage.ListUsers with no scimManaged
// filter at all, so the unfiltered SCIM directory listing enumerated EVERY user
// account — native, non-SCIM-managed accounts included, not just the ones actually
// under SCIM control. Seeds one SCIM-managed user (via the normal CreateUser flow)
// and one native account (created directly, no externalId — same shape as the
// classic bootstrap admin), then asserts the unfiltered list surfaces only the
// SCIM-managed one, and that totalResults/itemsPerPage reflect that filtered count,
// not the full 2-user directory.
func TestSCIM_ListUsersOnlyReturnsSCIMManaged(t *testing.T) {
	h, db := setupSCIMTest(t)
	managedID := provisionUser(t, h, "managed@corp.com")
	require.NoError(t, db.Create(&models.User{
		ID: 999, Username: "native", Email: "native@corp.com", DisplayName: "Native Admin",
		IsActive: true, AccountState: core.AccountActive,
	}).Error)

	w := httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil))
	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeSCIM(t, w)

	assert.Equal(t, float64(1), resp["totalResults"], "totalResults must reflect only the SCIM-managed user, not the full 2-user directory")
	assert.Equal(t, float64(1), resp["itemsPerPage"])

	resources, _ := resp["Resources"].([]any)
	require.Len(t, resources, 1, "only the SCIM-managed account may be listed")
	only, _ := resources[0].(map[string]any)
	assert.Equal(t, managedID, only["id"], "the returned resource must be the SCIM-managed user, not the native one")
	assert.NotEqual(t, "native@corp.com", only["userName"], "a native (non-SCIM-managed) account must never appear in a SCIM listing")
}

// TestSCIM_GetUserRefusesNativeAccount pins the "GET /scim/v2/Users/{id}" half of
// #G85: GetUser previously called the generic core.GetUser with no scimManaged
// check at all, so any valid numeric id — including a NATIVE admin account SCIM
// never provisioned — would be disclosed. A native id must now come back as a
// generic SCIM 404, the same response a genuinely nonexistent id gets, so the
// response never confirms whether an out-of-scope resource exists, and must not
// leak any of the native account's fields along the way.
func TestSCIM_GetUserRefusesNativeAccount(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Create(&models.User{
		ID: 42, Username: "native", Email: "native@corp.com", DisplayName: "Native Admin",
		IsActive: true, AccountState: core.AccountActive,
	}).Error)

	w := httptest.NewRecorder()
	h.GetUser(w, withID(httptest.NewRequest(http.MethodGet, "/scim/v2/Users/42", nil), "42"))
	assert.Equal(t, http.StatusNotFound, w.Code, "GET on a non-SCIM-managed id must be refused, not disclosed")

	resp := decodeSCIM(t, w)
	assert.Equal(t, "user not found", resp["detail"], "the refusal must be the same generic message a nonexistent id gets")
	body := w.Body.String()
	assert.NotContains(t, body, "native@corp.com", "the native account's email must not leak in the refusal response")
	assert.NotContains(t, body, "Native Admin", "the native account's display name must not leak in the refusal response")
}

func TestSCIM_ServiceProviderConfig(t *testing.T) {
	h, _ := setupSCIMTest(t)
	w := httptest.NewRecorder()
	h.GetServiceProviderConfig(w, httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "scim+json")
	cfg := decodeSCIM(t, w)
	assert.NotNil(t, cfg["patch"])
}

// assertSCIMNoRawDBLeak is the SCIM-response counterpart of assertNoRawDBLeak
// (mfa_test.go): SCIM errors carry their message in the RFC 7644 "detail"
// field, not {message}, so this checks that key instead. Both halves of the
// G50 fix still apply: no raw driver text in the response, but the original
// error still reaches the server-side log for operators.
func assertSCIMNoRawDBLeak(t *testing.T, w *httptest.ResponseRecorder, logBuf *bytes.Buffer, droppedTable string) {
	t.Helper()
	body := w.Body.String()
	assert.NotContains(t, body, "no such table")
	assert.NotContains(t, body, droppedTable)

	resp := decodeSCIM(t, w)
	detail, _ := resp["detail"].(string)
	assert.NotEmpty(t, detail)
	assert.NotContains(t, detail, "no such table")
	assert.NotContains(t, detail, droppedTable)

	assert.Contains(t, logBuf.String(), "no such table",
		"the raw driver error must still be logged server-side for operators to debug")
}

// TestSCIM_CreateUser_DBErrorSanitized drops the users table so
// ProvisionSCIMUser's dedup check (FindSCIMUser → GetUserByEmail) fails with
// a raw SQLite driver error, wrapped as "failed to check for an existing
// user: %w" — proving CreateUser's default/fallback branch sanitizes it
// instead of echoing err.Error() straight into the SCIM "detail" field.
func TestSCIM_CreateUser_DBErrorSanitized(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Migrator().DropTable(&models.User{}))

	logBuf := captureLogBuf(t)
	body := `{"userName":"alice@corp.com"}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertSCIMNoRawDBLeak(t, w, logBuf, "users")
}

// TestSCIM_ReplaceUser_DBErrorSanitized provisions a real SCIM-managed user,
// then drops the users table so UpdateSCIMUser's locked read
// (scimUpdateUserTx → LockUserForUpdate) fails with a raw SQLite driver
// error that UpdateSCIMUser wraps as "storage failed: %w" — proving
// ReplaceUser sanitizes it instead of forwarding err.Error() raw.
func TestSCIM_ReplaceUser_DBErrorSanitized(t *testing.T) {
	h, db := setupSCIMTest(t)
	id := provisionUser(t, h, "carol@corp.com")
	require.NoError(t, db.Migrator().DropTable(&models.User{}))

	logBuf := captureLogBuf(t)
	body := `{"displayName":"Carol Updated"}`
	w := httptest.NewRecorder()
	h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/"+id, bytes.NewReader([]byte(body))), id))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertSCIMNoRawDBLeak(t, w, logBuf, "users")
}

// TestSCIM_PatchUser_DBErrorSanitized is PatchUser's counterpart to
// TestSCIM_ReplaceUser_DBErrorSanitized — same underlying UpdateSCIMUser call,
// reached via PATCH instead of PUT.
func TestSCIM_PatchUser_DBErrorSanitized(t *testing.T) {
	h, db := setupSCIMTest(t)
	id := provisionUser(t, h, "dave@corp.com")
	require.NoError(t, db.Migrator().DropTable(&models.User{}))

	logBuf := captureLogBuf(t)
	patch := `{"Operations":[{"op":"replace","path":"displayName","value":"Dave Updated"}]}`
	w := httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+id, bytes.NewReader([]byte(patch))), id))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertSCIMNoRawDBLeak(t, w, logBuf, "users")
}

// TestSCIM_DeleteUser_DBErrorSanitized provisions a real SCIM-managed user,
// then drops the users table so DeprovisionSCIMUser's initial GetUser read
// fails with a raw SQLite driver error (wrapped as "user not found: %w",
// which despite its name embeds the RAW underlying error text) — proving
// DeleteUser sanitizes it instead of forwarding err.Error() raw.
func TestSCIM_DeleteUser_DBErrorSanitized(t *testing.T) {
	h, db := setupSCIMTest(t)
	id := provisionUser(t, h, "erin@corp.com")
	require.NoError(t, db.Migrator().DropTable(&models.User{}))

	logBuf := captureLogBuf(t)
	w := httptest.NewRecorder()
	h.DeleteUser(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+id, nil), id))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertSCIMNoRawDBLeak(t, w, logBuf, "users")
}
