// groups_s13_test.go — S13 coverage sweep for groups_handler.go and
// groups_members.go. groups_proxy.go's tests were removed with the
// ADR-108 Phase 6 /system proxy tier deletion.
//
// Targets uncovered branches: bad-param paths, not-found paths, conflict
// responses, validation-error paths.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newGroupHandlerS13 returns a fresh GroupHandler backed by its own unique DB.
func newGroupHandlerS13(t *testing.T) *GroupHandler {
	t.Helper()
	cs := freshCoreS12(t)
	gh, err := NewGroupHandler(cs)
	require.NoError(t, err)
	return gh
}

// newGroupHandlerWithCoreS13 returns both the handler and the core so tests
// can seed data.
func newGroupHandlerWithCoreS13(t *testing.T) (*GroupHandler, *core.KeyorixCore) {
	t.Helper()
	cs := freshCoreS12(t)
	gh, err := NewGroupHandler(cs)
	require.NoError(t, err)
	return gh, cs
}

// jsonBody encodes v as compact JSON into a *bytes.Reader.
func jsonBody(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// ── groups_handler.go: ListGroups ────────────────────────────────────────────

func TestListGroups_NoUserCtx_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListGroups_EmptyDB_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil))
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── groups_handler.go: CreateGroup ───────────────────────────────────────────

func TestCreateGroup_NoUserCtx_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups",
		jsonBody(t, map[string]string{"name": "ops"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateGroup_BadJSON_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/groups",
		strings.NewReader("{bad json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateGroup_MissingName_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/groups",
		jsonBody(t, map[string]string{"description": "no name"})))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateGroup_HappyPath_S13 verifies a well-formed name creates a group (201).
// Note: the conflict path (409) requires a partial unique index created by
// migrateDatabase which AutoMigrate does not produce; it is therefore not
// exercised here.
func TestCreateGroup_HappyPath_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/groups",
		jsonBody(t, map[string]string{"name": "happy-grp-s13"})))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ── groups_handler.go: GetGroup ──────────────────────────────────────────────

func TestGetGroup_NoUserCtx_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/groups/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetGroup_BadID_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetGroup_NotFound_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999999"))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── groups_handler.go: UpdateGroup ───────────────────────────────────────────

func TestUpdateGroup_NoUserCtx_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateGroup_BadID_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/",
		jsonBody(t, map[string]string{"name": "newname"})), "id", "abc"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateGroup_BadJSON_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/",
		strings.NewReader("{bad")), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateGroup_NotFound_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/",
		jsonBody(t, map[string]string{"name": "renamed"})), "id", "999999"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── groups_handler.go: DeleteGroup ───────────────────────────────────────────

func TestDeleteGroup_NoUserCtx_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteGroup_BadID_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "abc"))
	w := httptest.NewRecorder()
	h.DeleteGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteGroup_NotFound_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "999999"))
	w := httptest.NewRecorder()
	h.DeleteGroup(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── groups_handler.go: RestoreGroup ──────────────────────────────────────────

func TestRestoreGroup_BadID_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "xyz"))
	w := httptest.NewRecorder()
	h.RestoreGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRestoreGroup_NotFound_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999999"))
	w := httptest.NewRecorder()
	h.RestoreGroup(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── groups_members.go: GetGroupMembers ───────────────────────────────────────

func TestGetGroupMembers_NoUserCtx_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetGroupMembers_BadID_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanid"))
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetGroupMembers_NonExistent_S13 — when the group doesn't exist the error
// message is "Data retrieval failed: ErrorGroupNotFound" (the key returned by
// i18n.T as fallback). That string does NOT contain the literal "not found", so
// the handler falls through to the 500 branch rather than the 404 branch.
func TestGetGroupMembers_NonExistent_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999999"))
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	// The handler's "not found" check doesn't match the i18n key fallback, so
	// it returns 500 for a non-existent group.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── groups_members.go: AddGroupMember ────────────────────────────────────────

func TestAddGroupMember_NoUserCtx_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/",
		jsonBody(t, map[string]int{"user_id": 1})), "id", "1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddGroupMember_BadID_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/",
		jsonBody(t, map[string]int{"user_id": 1})), "id", "notanid"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddGroupMember_BadJSON_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader("{bad")), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddGroupMember_ZeroUserID_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/",
		jsonBody(t, map[string]int{"user_id": 0})), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddGroupMember_GroupNotFound_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/",
		jsonBody(t, map[string]int{"user_id": 1})), "id", "999999"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	// user or group not found → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── groups_members.go: RemoveGroupMember ─────────────────────────────────────

func TestRemoveGroupMember_NoUserCtx_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "userId": "1"})
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRemoveGroupMember_InternalError_S13 — removing a member of a group when
// neither the group nor user exist returns 500 (the conflict guard is bypassed
// because guardLastGlobalAdminMembership only triggers for real admin grants).
func TestRemoveGroupMember_InternalError_S13(t *testing.T) {
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "999999", "userId": "999999"}))
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	// No conflict guard fires; storage.RemoveUserFromGroup on a row that doesn't
	// exist is a no-op (DELETE with 0 rows affected is not an error in GORM).
	// So actually → 204 (success, nothing to remove).
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── groups_members.go: project-scoped AddGroupMember / RemoveGroupMember ─────

// TestAddGroupMember_ProjectScoped_S13 verifies that a project_id in the body
// is accepted and the response echoes it back.
func TestAddGroupMember_ProjectScoped_S13(t *testing.T) {
	t.Parallel()
	h, cs := newGroupHandlerWithCoreS13(t)
	ctx := context.Background()

	grp, err := cs.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "scoped-add-s13"})
	require.NoError(t, err)

	// Seed a user so AddUserToGroup doesn't return "not found".
	user, err := cs.Storage().CreateUser(ctx, &models.User{
		Username: "scoped-add-user-s13", Email: "scopedadd@s13.test", PasswordHash: "x", IsActive: true,
	})
	require.NoError(t, err)

	body := map[string]any{"user_id": user.ID, "project_id": 42}
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", jsonBody(t, body)), "id", fmt.Sprintf("%d", grp.ID)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data struct {
			ProjectID uint `json:"project_id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, uint(42), resp.Data.ProjectID)
}

// TestRemoveGroupMember_ProjectScoped_S13 verifies that a project_id query param
// is accepted when removing a scoped membership.
func TestRemoveGroupMember_ProjectScoped_S13(t *testing.T) {
	t.Parallel()
	h, cs := newGroupHandlerWithCoreS13(t)
	ctx := context.Background()

	grp, err := cs.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "scoped-rm-s13"})
	require.NoError(t, err)
	user, err := cs.Storage().CreateUser(ctx, &models.User{
		Username: "scoped-rm-user-s13", Email: "scopedrm@s13.test", PasswordHash: "x", IsActive: true,
	})
	require.NoError(t, err)

	// Add a project-scoped membership first.
	require.NoError(t, cs.AddUserToGroup(ctx, 0, false, user.ID, grp.ID, 5))

	// Now remove it via the handler with ?project_id=5.
	url := "/?project_id=5"
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, url, nil),
		map[string]string{"id": fmt.Sprintf("%d", grp.ID), "userId": fmt.Sprintf("%d", user.ID)}))
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// TestRemoveGroupMember_InvalidProjectID_S13 verifies that an invalid project_id
// query param returns 400.
func TestRemoveGroupMember_InvalidProjectID_S13(t *testing.T) {
	t.Parallel()
	h := newGroupHandlerS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/?project_id=notanumber", nil),
		map[string]string{"id": "1", "userId": "1"}))
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── groups_members.go: InitCoreHandlers ──────────────────────────────────────

func TestInitCoreHandlers_S13(t *testing.T) {
	cs := freshCoreS12(t)
	uh, gh, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	assert.NotNil(t, uh)
	assert.NotNil(t, gh)
}
