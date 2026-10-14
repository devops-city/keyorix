package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// provisionUser creates a SCIM user (with a real externalId, so it's SCIM-managed
// per #167/#120's convention — scimManaged only looks at a stored ExternalID, which
// ProvisionSCIMUser only sets from the payload's own externalId field) and returns
// its SCIM id.
func provisionUser(t *testing.T, h *SCIMHandler, userName string) string {
	t.Helper()
	body := `{"userName":"` + userName + `","externalId":"idp-` + userName + `"}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	id, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, id)
	return id
}

func groupMemberValues(g map[string]any) []string {
	var out []string
	members, _ := g["members"].([]any)
	for _, m := range members {
		if mm, ok := m.(map[string]any); ok {
			if v, ok := mm["value"].(string); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func TestSCIM_GroupsCreateReplacePatchDelete(t *testing.T) {
	h, _ := setupSCIMTest(t)
	u1 := provisionUser(t, h, "alice@corp.com")
	u2 := provisionUser(t, h, "bob@corp.com")

	// Create a group with alice as the initial member.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineers","members":[{"value":"` + u1 + `"}]}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	created := decodeSCIM(t, w)
	assert.Equal(t, "Engineers", created["displayName"])
	assert.ElementsMatch(t, []string{u1}, groupMemberValues(created))
	gid, _ := created["id"].(string)
	require.NotEmpty(t, gid)

	// PUT replaces the full member set: alice → bob.
	put := `{"displayName":"Engineers","members":[{"value":"` + u2 + `"}]}`
	w = httptest.NewRecorder()
	h.ReplaceGroup(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(put))), gid))
	require.Equal(t, http.StatusOK, w.Code)
	assert.ElementsMatch(t, []string{u2}, groupMemberValues(decodeSCIM(t, w)))

	// PATCH add alice back → both members.
	addPatch := `{"Operations":[{"op":"add","path":"members","value":[{"value":"` + u1 + `"}]}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(addPatch))), gid))
	require.Equal(t, http.StatusOK, w.Code)
	assert.ElementsMatch(t, []string{u1, u2}, groupMemberValues(decodeSCIM(t, w)))

	// PATCH remove bob via the filtered path syntax → alice only.
	rmPatch := `{"Operations":[{"op":"remove","path":"members[value eq \"` + u2 + `\"]"}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(rmPatch))), gid))
	require.Equal(t, http.StatusOK, w.Code)
	assert.ElementsMatch(t, []string{u1}, groupMemberValues(decodeSCIM(t, w)))

	// PATCH rename.
	renamePatch := `{"Operations":[{"op":"replace","path":"displayName","value":"Platform"}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(renamePatch))), gid))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "Platform", decodeSCIM(t, w)["displayName"])

	// List returns the one group.
	w = httptest.NewRecorder()
	h.ListGroups(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Groups", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, float64(1), decodeSCIM(t, w)["totalResults"])

	// DELETE → 204.
	w = httptest.NewRecorder()
	h.DeleteGroup(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/"+gid, nil), gid))
	require.Equal(t, http.StatusNoContent, w.Code)
}

// TestSCIM_PatchGroupFilteredPathHonorsOp is a regression test for #226: the
// members[value eq "X"] filtered path previously ignored op.Op and always
// removed the matched member, even for "add"/"replace" operations.
func TestSCIM_PatchGroupFilteredPathHonorsOp(t *testing.T) {
	h, _ := setupSCIMTest(t)
	u1 := provisionUser(t, h, "carol@corp.com")
	u2 := provisionUser(t, h, "dave@corp.com")

	// Create a group with only carol as a member.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Filtered","members":[{"value":"` + u1 + `"}]}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	gid, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, gid)

	// PATCH add via the filtered path syntax must ADD dave, not remove carol.
	addPatch := `{"Operations":[{"op":"add","path":"members[value eq \"` + u2 + `\"]"}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(addPatch))), gid))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.ElementsMatch(t, []string{u1, u2}, groupMemberValues(decodeSCIM(t, w)))

	// PATCH replace via the filtered path syntax must also ensure the member is
	// present (not remove it): re-"replace" dave, who is already a member.
	replacePatch := `{"Operations":[{"op":"replace","path":"members[value eq \"` + u2 + `\"]"}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(replacePatch))), gid))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.ElementsMatch(t, []string{u1, u2}, groupMemberValues(decodeSCIM(t, w)))

	// PATCH remove via the filtered path syntax must still remove the matched
	// member (the pre-existing, correct behavior).
	rmPatch := `{"Operations":[{"op":"remove","path":"members[value eq \"` + u2 + `\"]"}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(rmPatch))), gid))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.ElementsMatch(t, []string{u1}, groupMemberValues(decodeSCIM(t, w)))
}

func TestSCIM_CreateGroupRequiresDisplayName(t *testing.T) {
	h, _ := setupSCIMTest(t)
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(`{"members":[]}`))))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── G50 regression coverage: SCIM group handlers must never forward a raw
// backend/driver error to the client. Mirrors scim_test.go's convention: drop
// the groups table so the underlying core call fails with a genuine SQLite
// driver error, and assert that text never reaches the SCIM "detail" field
// while it still lands in the server-side log.

// TestSCIM_CreateGroup_DBErrorSanitized drops the groups table so
// ProvisionSCIMGroup's storage.CreateGroup insert fails with a raw SQLite
// driver error, returned bare — proving CreateGroup's default/fallback
// branch sanitizes it instead of echoing err.Error() straight through.
func TestSCIM_CreateGroup_DBErrorSanitized(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Migrator().DropTable(&models.Group{}))

	logBuf := captureLogBuf(t)
	body := `{"displayName":"Engineers"}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertSCIMNoRawDBLeak(t, w, logBuf, "groups")
}

// TestSCIM_ReplaceGroup_DBErrorSanitized provisions a real group, then drops
// the groups table so ReplaceSCIMGroup's initial GetGroup read fails with a
// raw SQLite driver error wrapped as "not found: %w" — proving ReplaceGroup
// sanitizes it instead of forwarding err.Error() raw.
func TestSCIM_ReplaceGroup_DBErrorSanitized(t *testing.T) {
	h, db := setupSCIMTest(t)
	body := `{"displayName":"Engineers"}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	gid, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, gid)

	require.NoError(t, db.Migrator().DropTable(&models.Group{}))

	logBuf := captureLogBuf(t)
	put := `{"displayName":"Engineers Updated"}`
	w = httptest.NewRecorder()
	h.ReplaceGroup(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(put))), gid))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertSCIMNoRawDBLeak(t, w, logBuf, "groups")
}

// TestSCIM_PatchGroup_DBErrorSanitized is PatchGroup's counterpart to
// TestSCIM_ReplaceGroup_DBErrorSanitized — same underlying GetGroup read,
// reached via PATCH instead of PUT.
func TestSCIM_PatchGroup_DBErrorSanitized(t *testing.T) {
	h, db := setupSCIMTest(t)
	body := `{"displayName":"Engineers"}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	gid, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, gid)

	require.NoError(t, db.Migrator().DropTable(&models.Group{}))

	logBuf := captureLogBuf(t)
	patch := `{"Operations":[{"op":"replace","path":"displayName","value":"Renamed"}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(patch))), gid))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertSCIMNoRawDBLeak(t, w, logBuf, "groups")
}

// TestSCIM_DeleteGroup_DBErrorSanitized provisions a real group, then drops
// the groups table so DeprovisionSCIMGroup's storage.DeleteGroup fails with a
// raw SQLite driver error, returned bare — proving DeleteGroup sanitizes it
// instead of forwarding err.Error() raw.
func TestSCIM_DeleteGroup_DBErrorSanitized(t *testing.T) {
	h, db := setupSCIMTest(t)
	body := `{"displayName":"Engineers"}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	gid, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, gid)

	require.NoError(t, db.Migrator().DropTable(&models.Group{}))

	logBuf := captureLogBuf(t)
	w = httptest.NewRecorder()
	h.DeleteGroup(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/"+gid, nil), gid))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertSCIMNoRawDBLeak(t, w, logBuf, "groups")
}

// TestSCIM_ListGroups_DBErrorSanitized drops the groups table so
// ListSCIMGroupsPage's read fails with a raw SQLite driver error — proving
// the unfiltered ListGroups path (already using clientSafe before this G50
// pass, kept here as a regression pin) still sanitizes it.
func TestSCIM_ListGroups_DBErrorSanitized(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Migrator().DropTable(&models.Group{}))

	logBuf := captureLogBuf(t)
	w := httptest.NewRecorder()
	h.ListGroups(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Groups", nil))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assertSCIMNoRawDBLeak(t, w, logBuf, "groups")
}
