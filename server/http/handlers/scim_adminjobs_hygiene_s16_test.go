// scim_adminjobs_hygiene_s16_test.go — coverage sweep targeting uncovered branches in:
//   - scim.go:       bad-id param, invalid filter, bad body, scimPaging edge cases,
//     displayName/primaryEmail helpers, parseSCIMUserPatchOp paths,
//     GetUser/PatchUser/DeleteUser not-found
//   - scim_groups.go: bad-id param, invalid filter, bad body, too-many-members,
//     too-many-ops, not-found (replace/patch/delete), pageSlice edges,
//     conflict on duplicate create, replace-all members path
//   - admin_jobs.go: RunExpiryReminders default/invalid lead_days, RunComplianceDigest happy
//   - deployment_hygiene.go: unauthenticated, authenticated with query params
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// ── local setup helpers ───────────────────────────────────────────────────────

func setupSCIMTestS16(t *testing.T) *SCIMHandler {
	t.Helper()
	h, _ := setupSCIMTest(t)
	return h
}

// newSecretHandlerS16 creates a SecretHandler backed by a minimal in-memory core.
func newSecretHandlerS16(t *testing.T) *SecretHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s16_")
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
		&models.LegalHold{}, &models.ShareRecord{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
		&models.SecretVersion{},
	))
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h
}

// ── scim.go — bad id param ────────────────────────────────────────────────────

func TestSCIM_GetUser_BadID_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.GetUser(w, withID(httptest.NewRequest(http.MethodGet, "/scim/v2/Users/not-a-number", nil), "not-a-number"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_ReplaceUser_BadID_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	body := `{"userName":"x@x.com"}`
	h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/bad", bytes.NewReader([]byte(body))), "bad"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_PatchUser_BadID_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/xyz", bytes.NewReader([]byte(`{"Operations":[]}`))), "xyz"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_DeleteUser_BadID_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.DeleteUser(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/bad", nil), "bad"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── scim.go — invalid body ────────────────────────────────────────────────────

func TestSCIM_CreateUser_InvalidBody_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte("not json {"))))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_ReplaceUser_InvalidBody_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	uid := provisionUser(t, h, "replbad_s16@corp.com")
	w := httptest.NewRecorder()
	h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/"+uid, bytes.NewReader([]byte("{bad}"))), uid))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_PatchUser_InvalidBody_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	uid := provisionUser(t, h, "patchbad_s16@corp.com")
	w := httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+uid, bytes.NewReader([]byte("{bad}"))), uid))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── scim.go — ListUsers invalid filter ───────────────────────────────────────

func TestSCIM_ListUsers_UnsupportedFilter_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Users?filter=email+eq+%22x%22", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── scim.go — scimPaging edge cases ──────────────────────────────────────────

func TestSCIM_ListUsers_PagingParams_S16(t *testing.T) {
	h := setupSCIMTestS16(t)

	// startIndex out-of-range (larger than total) — should still return OK.
	w := httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=9999&count=10", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeSCIM(t, w)
	assert.Equal(t, float64(0), resp["totalResults"])

	// count=0 → itemsPerPage=0
	w = httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Users?count=0", nil))
	assert.Equal(t, http.StatusOK, w.Code)

	// count oversized → clamps to SCIMMaxPageSize
	w = httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/scim/v2/Users?count=%d", core.SCIMMaxPageSize+100), nil))
	assert.Equal(t, http.StatusOK, w.Code)

	// invalid startIndex value — ignored, defaults to 1
	w = httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=abc", nil))
	assert.Equal(t, http.StatusOK, w.Code)

	// invalid count value — ignored, defaults to SCIMMaxPageSize
	w = httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Users?count=xyz", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── scim.go — displayName / primaryEmail helper edge paths ───────────────────

func TestSCIM_CreateUser_DisplayNameFromNameFormatted_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	// displayName absent but name.formatted present — should use name.formatted.
	body := `{"userName":"nametest_s16@corp.com","externalId":"idp-nametest_s16","name":{"formatted":"Test Name S16"}}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	resp := decodeSCIM(t, w)
	assert.Equal(t, "Test Name S16", resp["displayName"])
}

func TestSCIM_CreateUser_PrimaryEmailFallback_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	// Non-primary email with no primary flag — should fall back to first email.
	body := `{"userName":"emailfb_s16@corp.com","externalId":"idp-emailfb_s16","emails":[{"value":"emailfb_s16@corp.com","primary":false}]}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	resp := decodeSCIM(t, w)
	assert.Equal(t, "emailfb_s16@corp.com", resp["userName"])
}

// ── scim.go — parseSCIMUserPatchOp paths ─────────────────────────────────────

func TestSCIM_PatchUser_DisplayNameOp_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	uid := provisionUser(t, h, "dispname_s16@corp.com")
	patch := `{"Operations":[{"op":"replace","path":"displayName","value":"New Name S16"}]}`
	w := httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+uid, bytes.NewReader([]byte(patch))), uid))
	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeSCIM(t, w)
	assert.Equal(t, "New Name S16", resp["displayName"])
}

func TestSCIM_PatchUser_NoPathObjectValue_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	uid := provisionUser(t, h, "nopathobj_s16@corp.com")
	// op with no path and an object value — covers the "" (empty path) case in parseSCIMUserPatchOp.
	patch := `{"Operations":[{"op":"replace","value":{"active":true,"displayName":"FromObj"}}]}`
	w := httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+uid, bytes.NewReader([]byte(patch))), uid))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestSCIM_PatchUser_UnknownOpIgnored_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	uid := provisionUser(t, h, "unknownop_s16@corp.com")
	// "remove" op on an unknown path should be a no-op (skipped, not error).
	patch := `{"Operations":[{"op":"remove","path":"phoneNumbers","value":"555"}]}`
	w := httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+uid, bytes.NewReader([]byte(patch))), uid))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestSCIM_PatchUser_NotFound_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	patch := `{"Operations":[{"op":"replace","path":"active","value":false}]}`
	w := httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/99999", bytes.NewReader([]byte(patch))), "99999"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_DeleteUser_NotFound_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.DeleteUser(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/99999", nil), "99999"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_GetUser_NotFound_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.GetUser(w, withID(httptest.NewRequest(http.MethodGet, "/scim/v2/Users/99999", nil), "99999"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── scim_groups.go — bad id / bad body / not-found ───────────────────────────

func TestSCIMGroups_GetGroup_BadID_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.GetGroup(w, withID(httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/abc", nil), "abc"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMGroups_GetGroup_NotFound_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.GetGroup(w, withID(httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/99999", nil), "99999"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIMGroups_CreateGroup_InvalidBody_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte("{bad}"))))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMGroups_CreateGroup_TooManyMembers_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	// Build a members array that exceeds scimMaxMembersPerRequest (5000).
	var sb strings.Builder
	sb.WriteString(`{"displayName":"BigGroup_S16","members":[`)
	for i := 0; i <= scimMaxMembersPerRequest; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"value":"%d"}`, i+1)
	}
	sb.WriteString(`]}`)
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(sb.String()))))
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestSCIMGroups_ReplaceGroup_BadID_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	body := `{"displayName":"X","members":[]}`
	h.ReplaceGroup(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Groups/bad", bytes.NewReader([]byte(body))), "bad"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMGroups_ReplaceGroup_InvalidBody_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.ReplaceGroup(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Groups/1", bytes.NewReader([]byte("{bad}"))), "1"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMGroups_ReplaceGroup_TooManyMembers_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	var sb strings.Builder
	sb.WriteString(`{"displayName":"Big_S16","members":[`)
	for i := 0; i <= scimMaxMembersPerRequest; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"value":"%d"}`, i+1)
	}
	sb.WriteString(`]}`)
	w := httptest.NewRecorder()
	h.ReplaceGroup(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Groups/1", bytes.NewReader([]byte(sb.String()))), "1"))
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestSCIMGroups_ReplaceGroup_NotFound_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	body := `{"displayName":"NotExist_S16","members":[]}`
	w := httptest.NewRecorder()
	h.ReplaceGroup(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Groups/99999", bytes.NewReader([]byte(body))), "99999"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIMGroups_PatchGroup_BadID_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/bad", bytes.NewReader([]byte(`{"Operations":[]}`))), "bad"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMGroups_PatchGroup_InvalidBody_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/1", bytes.NewReader([]byte("{bad}"))), "1"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMGroups_PatchGroup_TooManyOps_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	// Build an Operations array exceeding scimMaxPatchOps (1000).
	ops := make([]map[string]any, scimMaxPatchOps+1)
	for i := range ops {
		ops[i] = map[string]any{"op": "add", "path": "members", "value": []map[string]string{{"value": "1"}}}
	}
	b, err := json.Marshal(map[string]any{"Operations": ops})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/1", bytes.NewReader(b)), "1"))
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestSCIMGroups_PatchGroup_NotFound_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	patch := `{"Operations":[{"op":"replace","path":"displayName","value":"NewName"}]}`
	w := httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/99999", bytes.NewReader([]byte(patch))), "99999"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIMGroups_DeleteGroup_BadID_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.DeleteGroup(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/bad", nil), "bad"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMGroups_DeleteGroup_NotFound_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.DeleteGroup(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/99999", nil), "99999"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── scim_groups.go — ListGroups invalid filter ───────────────────────────────

func TestSCIMGroups_ListGroups_UnsupportedFilter_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	w := httptest.NewRecorder()
	h.ListGroups(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Groups?filter=members+eq+%221%22", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMGroups_ListGroups_ByDisplayName_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	// Create a group so the filtered list path can find it.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"TargetGroup_S16","members":[]}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	w = httptest.NewRecorder()
	h.ListGroups(w, httptest.NewRequest(http.MethodGet, `/scim/v2/Groups?filter=displayName+eq+"TargetGroup_S16"`, nil))
	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeSCIM(t, w)
	assert.Equal(t, float64(1), resp["totalResults"])

	// Non-matching name returns empty list.
	w = httptest.NewRecorder()
	h.ListGroups(w, httptest.NewRequest(http.MethodGet, `/scim/v2/Groups?filter=displayName+eq+"DoesNotExist"`, nil))
	require.Equal(t, http.StatusOK, w.Code)
	resp = decodeSCIM(t, w)
	assert.Equal(t, float64(0), resp["totalResults"])
}

// ── scim_groups.go — pageSlice edge cases (unit-tested directly) ─────────────

func TestSCIMGroups_PageSlice_S16(t *testing.T) {
	// startIndex beyond end → nil.
	got := pageSlice([]string{"a", "b"}, 10, 5)
	assert.Nil(t, got)

	// count=0 → nil.
	got = pageSlice([]string{"a", "b"}, 1, 0)
	assert.Nil(t, got)

	// normal window
	got = pageSlice([]string{"a", "b", "c"}, 2, 2)
	assert.Equal(t, []string{"b", "c"}, got)

	// window extends past end → clamps
	got = pageSlice([]string{"a", "b", "c"}, 2, 100)
	assert.Equal(t, []string{"b", "c"}, got)

	// startIndex=0 treated as lo=-1 → clamped to 0
	got = pageSlice([]string{"a", "b"}, 0, 1)
	assert.Equal(t, []string{"a"}, got)
}

// ── scim_groups.go — CreateGroup success path ────────────────────────────────

func TestSCIMGroups_CreateGroup_Success_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	body := `{"displayName":"NewGroup_S16","members":[]}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	resp := decodeSCIM(t, w)
	assert.Equal(t, "NewGroup_S16", resp["displayName"])
	assert.NotEmpty(t, resp["id"])
}

// ── scim_groups.go — PatchGroup replace-all path (op=replace path=members) ───

func TestSCIMGroups_PatchGroup_ReplaceAllMembers_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	u1 := provisionUser(t, h, "ra1_s16@corp.com")
	u2 := provisionUser(t, h, "ra2_s16@corp.com")

	body := `{"displayName":"ReplaceAll_S16","members":[{"value":"` + u1 + `"}]}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	gid, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, gid)

	// PATCH with op=replace path=members → replaceAll path, member list becomes {u2}.
	patch := `{"Operations":[{"op":"replace","path":"members","value":[{"value":"` + u2 + `"}]}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(patch))), gid))
	require.Equal(t, http.StatusOK, w.Code)
	assert.ElementsMatch(t, []string{u2}, groupMemberValues(decodeSCIM(t, w)))
}

// ── scim_groups.go — PatchGroup too-many accumulated member IDs ───────────────

func TestSCIMGroups_PatchGroup_TooManyAccumulatedMembers_S16(t *testing.T) {
	h := setupSCIMTestS16(t)
	body := `{"displayName":"AccumGroup_S16","members":[]}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	gid, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, gid)

	vals := make([]map[string]string, scimMaxMembersPerRequest+1)
	for i := range vals {
		vals[i] = map[string]string{"value": fmt.Sprintf("%d", i+1)}
	}
	b, err := json.Marshal(map[string]any{
		"Operations": []map[string]any{
			{"op": "add", "path": "members", "value": vals},
		},
	})
	require.NoError(t, err)
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader(b)), gid))
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// ── admin_jobs.go — RunExpiryReminders branch coverage ───────────────────────

func TestAdminJobs_RunExpiryReminders_DefaultLeadDays_S16(t *testing.T) {
	h := newAdminJobsHandler(t)
	// Omit lead_days entirely → leadDays stays 0, core applies its own default.
	w := postJob(h.RunExpiryReminders, "/api/v1/admin/jobs/expiry-reminders", true)
	require.Equal(t, http.StatusOK, w.Code)
	assert.EqualValues(t, 0, decodeData(t, w)["sent"])
}

func TestAdminJobs_RunExpiryReminders_InvalidLeadDays_S16(t *testing.T) {
	h := newAdminJobsHandler(t)
	// Non-numeric lead_days — parse fails, leadDays stays 0.
	w := postJob(h.RunExpiryReminders, "/api/v1/admin/jobs/expiry-reminders?lead_days=notanumber", true)
	require.Equal(t, http.StatusOK, w.Code)
	assert.EqualValues(t, 0, decodeData(t, w)["sent"])
}

// ── admin_jobs.go — RunComplianceDigest happy path ───────────────────────────

func TestAdminJobs_RunComplianceDigest_HappyPath_S16(t *testing.T) {
	h := newAdminJobsHandler(t)
	w := postJob(h.RunComplianceDigest, "/api/v1/admin/jobs/compliance-digest", true)
	require.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	_, hasSent := data["sent"]
	assert.True(t, hasSent, "response should include 'sent' field")
}

// ── deployment_hygiene.go ─────────────────────────────────────────────────────

func TestDeploymentHygiene_Unauthorized_S16(t *testing.T) {
	h := newSecretHandlerS16(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hygiene", nil)
	w := httptest.NewRecorder()
	h.DeploymentHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeploymentHygiene_AuthenticatedEmptyState_S16(t *testing.T) {
	h := newSecretHandlerS16(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/hygiene", nil))
	w := httptest.NewRecorder()
	h.DeploymentHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeploymentHygiene_QueryParams_S16(t *testing.T) {
	h := newSecretHandlerS16(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/hygiene?unused_days=30&expiring_days=14&stale_days=60", nil))
	w := httptest.NewRecorder()
	h.DeploymentHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeploymentHygiene_InvalidQueryParams_S16(t *testing.T) {
	h := newSecretHandlerS16(t)
	// Non-numeric values are silently ignored (qint falls back to 0).
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/hygiene?unused_days=abc&expiring_days=xyz", nil))
	w := httptest.NewRecorder()
	h.DeploymentHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
