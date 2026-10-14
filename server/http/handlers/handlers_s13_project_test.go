// handlers_s13_project_test.go — sprint-13 coverage sweep targeting:
//   - project_members.go: ListProjectMembers, GetProjectAccessReview,
//     UpdateProjectMember (no-user-ctx / happy-path branches not yet covered)
//   - project_memberships.go: ListProjectMemberships, InviteMember,
//     TransitionMembership, membershipActionState
//   - project_memberships_proxy.go: CreateMembershipProxy, GetMembershipProxy,
//     ListMembershipsProxy, GetActiveMembershipProxy,
//     ListStaleInvitedMembershipsProxy, ListUserMembershipsProxy,
//     CountMembershipsByUsersProxy (missing error/validation branches)
//   - project_catalog_proxy.go: ListProjectsProxy, ListProjectsWithCountsProxy,
//     GetProjectProxy, DeleteProjectProxy,
//     DeleteProjectIfEmptyProxy, ListProjectMembersProxy
//   - project_hygiene.go: ProjectHygiene (bad-param / no-auth)
//   - projects_suspend.go: SuspendProjectSecrets, ResumeProjectSecrets
//     (bad-param / no-auth error paths)
package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// newSecretHandlerProjS13 wraps freshCoreS12 in a SecretHandler (no admin seeded).
func newSecretHandlerProjS13(t *testing.T) *SecretHandler {
	t.Helper()
	h, err := NewSecretHandler(freshCoreS12(t))
	require.NoError(t, err)
	return h
}

// newCatalogHandlerProjS13 wraps freshCoreS12 in a CatalogHandler (no admin seeded).
func newCatalogHandlerProjS13(t *testing.T) *CatalogHandler {
	t.Helper()
	return NewCatalogHandler(freshCoreS12(t))
}

// ── project_members.go — branches NOT already in invitations_project_members_s13_test.go ──

// TestListProjectMembers_HappyPath_S13 — valid project ID → 200.
func TestListProjectMembers_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13listmembers", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ListProjectMembers(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetProjectAccessReview_HappyPath_S13 — valid project ID → 200.
func TestGetProjectAccessReview_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13accessreview", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.GetProjectAccessReview(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRevokeProjectAccessReview_NoUserCtx_S13 — no user context → 401.
func TestRevokeProjectAccessReview_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"source":"manual","principal_type":"user","principal_id":1,"role_id":1}`
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	// no user context injected
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestAttestProjectAccessReview_StorageError_S13 — G50: a raw storage/DB
// error surfacing from verifyAccessReviewGrantExists (e.g. a broken
// user_roles table) must not leak internal detail (table/column names) to
// the client; AttestProjectAccessReview must sanitize it via clientSafe,
// matching RevokeProjectAccessReview's sibling pattern in this file.
func TestAttestProjectAccessReview_StorageError_S13(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13attest-storageerr", "")
	require.NoError(t, err)

	// Break the table verifyAccessReviewGrantExists queries for a "role"
	// source decision, forcing a raw driver error out of core.
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS user_roles").Error)

	// principal_id deliberately != the acting user's ID (1, per withUserCtx) —
	// otherwise #G52's new self-review independence check refuses the request
	// before it ever reaches the broken table this test exists to exercise.
	body := `{"source":"role","principal_type":"user","principal_id":999,"role_id":1}`
	r := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)),
		"id", fmt.Sprintf("%d", proj.ID),
	))
	w := httptest.NewRecorder()
	h.AttestProjectAccessReview(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "user_roles")
	assert.NotContains(t, w.Body.String(), "no such table")
	assert.Contains(t, w.Body.String(), "an internal error occurred")
}

// TestUpdateProjectMember_NoUserCtx_S13 — no user context → 401.
func TestUpdateProjectMember_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"role":"viewer"}`
	r := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "1", "userId": "2"})
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUpdateProjectMember_BadJSON_S13 — malformed JSON body → 400.
func TestUpdateProjectMember_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParams(withUserCtx(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad"))),
		map[string]string{"id": "1", "userId": "2"})
	r.ContentLength = 4
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRemoveProjectMember_NoUserCtx_S13 — no user context → 401.
func TestRemoveProjectMember_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "userId": "2"})
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── project_memberships.go ───────────────────────────────────────────────────

// TestListProjectMemberships_BadID_S13 — non-numeric project ID → 400.
func TestListProjectMemberships_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notnum")
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListProjectMemberships_HappyPath_S13 — valid project ID, no stale filter → 200.
func TestListProjectMemberships_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13listmemships", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListProjectMemberships_Stale_S13 — ?stale=true path, empty result is fine → 200.
func TestListProjectMemberships_Stale_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13listmemships-stale", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/?stale=true", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestInviteMember_BadID_S13 — non-numeric project ID → 400.
func TestInviteMember_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"user_id":1,"role":"viewer"}`
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "notnum")
	w := httptest.NewRecorder()
	h.InviteMember(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestInviteMember_NoUserCtx_S13 — no actor context → 401.
func TestInviteMember_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"user_id":1,"role":"viewer"}`
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.InviteMember(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestInviteMember_BadJSON_S13 — malformed JSON → 400.
func TestInviteMember_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))), "id", "1")
	r.ContentLength = 4
	w := httptest.NewRecorder()
	h.InviteMember(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestInviteMember_MissingFields_S13 — missing user_id/role → 400.
func TestInviteMember_MissingFields_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"user_id":0,"role":""}`
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))), "id", "1")
	w := httptest.NewRecorder()
	h.InviteMember(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestInviteMember_IDPResolved_ClientCannotBypassVerification_S13 — PM-008
// regression: InviteMember's HTTP body no longer has an idp_resolved field, so
// a legacy client that still sends `"idp_resolved":true` must have it silently
// ignored (unknown JSON field), not smuggled through to core.InviteMember. In
// ValidationModeIDP that field controls whether a new membership starts at
// `provisioned` (skipping invited/identity_verified) — only the real
// SSO/JIT-provisioning path may assert that, never a client-supplied bool on
// this general-purpose, roles.assign-gated endpoint. Assert the resulting
// membership lands at `invited`, exactly as an untrusted invite should.
func TestInviteMember_IDPResolved_ClientCannotBypassVerification_S13(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS12WithAdmin(t)
	cs.SetMembershipValidationMode(core.ValidationModeIDP)
	h := NewCatalogHandler(cs)

	role := &models.Role{Name: "pm008-viewer-s13", Description: "viewer"}
	require.NoError(t, db.Create(role).Error)
	targetUser := &models.User{Username: "pm008target_s13", Email: "pm008target_s13@example.com", AccountState: "active"}
	require.NoError(t, db.Create(targetUser).Error)

	proj, err := cs.CreateProject(context.Background(), "pm008-idp-trust-s13", "")
	require.NoError(t, err)

	body := fmt.Sprintf(`{"user_id":%d,"role":"pm008-viewer-s13","idp_resolved":true}`, targetUser.ID)
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))),
		"id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.InviteMember(w, r)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	memberships, err := cs.ListProjectMemberships(context.Background(), proj.ID)
	require.NoError(t, err)
	require.Len(t, memberships, 1)
	assert.Equal(t, core.MembershipInvited, memberships[0].State,
		"a client-supplied idp_resolved must not bypass invited/identity_verified in idp mode")
}

// TestTransitionMembership_BadProjectID_S13 — non-numeric project ID → 400.
func TestTransitionMembership_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"action":"activate"}`
	r := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "notnum", "membershipId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransitionMembership_BadMembershipID_S13 — non-numeric membershipId → 400.
func TestTransitionMembership_BadMembershipID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"action":"activate"}`
	r := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "1", "membershipId": "notnum"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransitionMembership_NoUserCtx_S13 — no actor context → 401.
func TestTransitionMembership_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"action":"activate"}`
	r := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "1", "membershipId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestTransitionMembership_BadJSON_S13 — malformed JSON → 400.
func TestTransitionMembership_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParams(withUserCtx(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad"))),
		map[string]string{"id": "1", "membershipId": "1"})
	r.ContentLength = 4
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransitionMembership_InvalidAction_S13 — unknown action → 400.
func TestTransitionMembership_InvalidAction_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"action":"teleport"}`
	r := withChiParams(withUserCtx(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))),
		map[string]string{"id": "1", "membershipId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestMembershipActionState_AllActions_S13 — unit-test the action→state mapper.
func TestMembershipActionState_AllActions_S13(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		action string
		want   string
		ok     bool
	}{
		{"verify", "identity_verified", true},
		{"provision", "provisioned", true},
		{"activate", "active", true},
		{"revoke", "revoked", true},
		{"unknown", "", false},
		{"", "", false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			t.Parallel()
			got, ok := membershipActionState(tc.action)
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// ── project_memberships_proxy.go ─────────────────────────────────────────────

// TestCreateMembershipProxy_BadJSON_S13 — malformed JSON body → 400.

// TestCreateMembershipProxy_MissingFields_S13 — zero project_id/user_id → 400.

// TestGetMembershipProxy_BadID_S13 — non-numeric membership ID → 400.

// TestGetActiveMembershipProxy_MissingParams_S13 — no project_id / user_id → 400.

// TestGetActiveMembershipProxy_BadProjectID_S13 — invalid project_id → 400.

// TestGetActiveMembershipProxy_BadUserID_S13 — invalid user_id → 400.

// TestGetActiveMembershipProxy_NotFound_S13 — valid IDs but no membership → 404.

// TestListStaleInvitedMembershipsProxy_MissingBefore_S13 — no before param → 400.

// TestListStaleInvitedMembershipsProxy_BadBefore_S13 — invalid timestamp → 400.

// TestListUserMembershipsProxy_BadUserID_S13 — non-numeric userID → 400.

// TestCountMembershipsByUsersProxy_MissingParam_S13 — no user_ids → 400.

// TestCountMembershipsByUsersProxy_BadUserIDs_S13 — non-numeric value in list → 400.

// TestCountMembershipsByUsersProxy_HappyPath_S13 — valid user_ids → 200.

// ── project_catalog_proxy.go ─────────────────────────────────────────────────

// TestListProjectsProxy_HappyPath_S13 — empty DB → 200 with empty list.

// TestListProjectsWithCountsProxy_HappyPath_S13 — no include_deleted → 200.

// TestListProjectsWithCountsProxy_IncludeDeleted_S13 — include_deleted=true → 200.

// TestGetProjectProxy_BadID_S13 — non-numeric id → 400.

// TestGetProjectProxy_NotFound_S13 — non-existent id → 404.

// TestGetProjectProxy_HappyPath_S13 — existing project → 200.

// TestDeleteProjectProxy_BadID_S13 — non-numeric id → 400.

// TestDeleteProjectProxy_NotFound_S13 — non-existent id → 404.

// TestDeleteProjectProxy_HappyPath_S13 — existing project → 200.

// TestDeleteProjectIfEmptyProxy_BadID_S13 — non-numeric id → 400.

// TestDeleteProjectIfEmptyProxy_NotFound_S13 — non-existent id → 404.

// TestDeleteProjectIfEmptyProxy_HappyPath_S13 — empty project → 200.

// TestListProjectMembersProxy_BadID_S13 — non-numeric id → 400.

// TestListProjectMembersProxy_HappyPath_S13 — valid project → 200.

// ── project_hygiene.go ───────────────────────────────────────────────────────

// TestProjectHygiene_NoUserCtx_S13 — no user context → 401.
func TestProjectHygiene_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestProjectHygiene_BadID_S13 — non-numeric project ID → 400.
func TestProjectHygiene_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)), "id", "notnum")
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestProjectHygiene_HappyPath_S13 — valid project with optional query params → 200.
func TestProjectHygiene_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	proj, err := cs.CreateProject(context.Background(), "s13hygiene", "")
	require.NoError(t, err)

	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/?unused_days=30&expiring_days=7&stale_days=90", nil)),
		"id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── projects_suspend.go ──────────────────────────────────────────────────────

// TestSuspendProjectSecrets_NoUserCtx_S13 — no user context → 401.
func TestSuspendProjectSecrets_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSuspendProjectSecrets_BadID_S13 — non-numeric project ID → 400.
func TestSuspendProjectSecrets_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`))), "id", "notnum")
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSuspendProjectSecrets_HappyPath_S13 — valid project ID → 200.
func TestSuspendProjectSecrets_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	proj, err := cs.CreateProject(context.Background(), "s13suspend", "")
	require.NoError(t, err)

	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"reason":"incident"}`))),
		"id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestResumeProjectSecrets_NoUserCtx_S13 — no user context → 401.
func TestResumeProjectSecrets_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestResumeProjectSecrets_BadID_S13 — non-numeric project ID → 400.
func TestResumeProjectSecrets_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)), "id", "notnum")
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestResumeProjectSecrets_HappyPath_S13 — valid project ID → 200.
func TestResumeProjectSecrets_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	proj, err := cs.CreateProject(context.Background(), "s13resume", "")
	require.NoError(t, err)

	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)),
		"id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}
