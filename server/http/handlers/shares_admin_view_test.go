// shares_admin_view_test.go — HTTP-layer coverage for
// GET /api/v1/users/{id}/shared-secrets (ListSharedSecretsForUser), the
// admin-scoped counterpart to GET /api/v1/shared-secrets added to close the
// CLI-split inventory §6 secondary gap (`keyorix share shared-secrets
// --user-id N` had no REST route for a target other than the caller). Reuses
// freshCoreS12WithAdmin/seedUsersWriteOnlyActor/seedOrdinaryUser from
// handlers_s12_test.go / users_admin_rank_ceiling_test.go.
package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// seedShareForRecipient creates a secret owned by a throwaway owner and
// shares it directly with recipientID, returning the secret's ID.
func seedShareForRecipient(t *testing.T, db *gorm.DB, recipientID uint) uint {
	t.Helper()
	secret := &models.SecretNode{Name: "db-pass", ProjectID: 1, EnvironmentID: 1, OwnerID: 999, Status: "active", Type: "password"}
	require.NoError(t, db.Create(secret).Error)
	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: secret.ID, OwnerID: 999, RecipientID: recipientID, IsGroup: false, Permission: "read",
	}).Error)
	return secret.ID
}

func requestSharedSecretsForUser(cs *core.KeyorixCore, callerID, targetID uint, username string) *httptest.ResponseRecorder {
	h, err := NewShareHandler(cs)
	if err != nil {
		panic(err)
	}
	req := withChiParams(httptest.NewRequest("GET", "/", nil), map[string]string{"id": machineUintToStr(targetID)})
	uc := &middleware.UserContext{UserID: callerID, Username: username, ActorType: core.ActorTypeUser}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.ListSharedSecretsForUser(w, req)
	return w
}

// TestListSharedSecretsForUser_HandlerSelfView_HappyPath: a caller viewing
// their own shared secrets gets 200 with the expected secret.
func TestListSharedSecretsForUser_HandlerSelfView_HappyPath(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	targetID := seedOrdinaryUser(t, db, "s6_self_view")
	secretID := seedShareForRecipient(t, db, targetID)

	w := requestSharedSecretsForUser(cs, targetID, targetID, "s6_self_view")
	require.Equal(t, 200, w.Code, w.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data := body["data"].(map[string]any)
	secrets := data["secrets"].([]any)
	require.Len(t, secrets, 1)
	assert.Equal(t, float64(secretID), secrets[0].(map[string]any)["id"])
}

// TestListSharedSecretsForUser_HandlerAdminViewsLowerRankedUser_NoSecretValueLeak:
// an admin viewing an ordinary target's shares gets 200 with the target's
// share data, and the response never carries a secret VALUE — only the same
// metadata fields as the caller's own /api/v1/shared-secrets route.
func TestListSharedSecretsForUser_HandlerAdminViewsLowerRankedUser_NoSecretValueLeak(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	admin, err := cs.GetUserByUsername(t.Context(), "testuser_s12")
	require.NoError(t, err)
	targetID := seedOrdinaryUser(t, db, "s6_lower_target")
	secretID := seedShareForRecipient(t, db, targetID)

	w := requestSharedSecretsForUser(cs, admin.ID, targetID, "testuser_s12")
	require.Equal(t, 200, w.Code, w.Body.String())

	respBody := w.Body.String()
	assert.NotContains(t, strings.ToLower(respBody), `"value"`, "the response must never carry a secret VALUE, only metadata")

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data := body["data"].(map[string]any)
	secrets := data["secrets"].([]any)
	require.Len(t, secrets, 1)
	assert.Equal(t, float64(secretID), secrets[0].(map[string]any)["id"])

	var event models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", string(core.ShareAuditEventSharedSecretsAdminViewed)).First(&event).Error)
	require.NotNil(t, event.UserID)
	assert.Equal(t, admin.ID, *event.UserID)
}

// TestListSharedSecretsForUser_HandlerRefusesOrdinaryUserAgainstSameRankPeer:
// secrets.read alone (even bundled with users.read, the exact project_viewer
// permission pair) is not an admin permission -- an actor holding only that
// pair must be refused viewing a same-rank peer's shares, since the S1
// ceiling alone never refuses a peer holding no MORE than the actor.
func TestListSharedSecretsForUser_HandlerRefusesOrdinaryUserAgainstSameRankPeer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	actorID := seedUsersWriteOnlyActor(t, db, "s6_ordinary_actor", "secrets.read", "users.read")
	peerID := seedUsersWriteOnlyActor(t, db, "s6_ordinary_peer", "secrets.read", "users.read")
	seedShareForRecipient(t, db, peerID)

	w := requestSharedSecretsForUser(cs, actorID, peerID, "s6_ordinary_actor")
	assert.Equal(t, 403, w.Code, w.Body.String())
}

// TestListSharedSecretsForUser_HandlerRefusesLowerRankActorAgainstHigherTarget:
// a users.write-only actor (not global admin) attempting to view the
// install's real admin's shares is refused with a generic 403 that does not
// leak the specific permission name.
func TestListSharedSecretsForUser_HandlerRefusesLowerRankActorAgainstHigherTarget(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	admin, err := cs.GetUserByUsername(t.Context(), "testuser_s12")
	require.NoError(t, err)
	seedShareForRecipient(t, db, admin.ID)
	attackerID := seedUsersWriteOnlyActor(t, db, "s6_weak_attacker", "users.write", "roles.read")

	w := requestSharedSecretsForUser(cs, attackerID, admin.ID, "s6_weak_attacker")
	assert.Equal(t, 403, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "roles.assign", "the refusal must not leak the specific permission name to the client")
}

// TestListSharedSecretsForUser_HandlerUnknownTarget_SameResponseShapeAsForbidden:
// the SAME weak actor targeting a user ID that does not exist must get a
// response indistinguishable from the real-refusal case above -- same status
// code, same body -- so the route cannot be used to probe which numeric user
// IDs exist.
func TestListSharedSecretsForUser_HandlerUnknownTarget_SameResponseShapeAsForbidden(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	admin, err := cs.GetUserByUsername(t.Context(), "testuser_s12")
	require.NoError(t, err)
	seedShareForRecipient(t, db, admin.ID)
	attackerID := seedUsersWriteOnlyActor(t, db, "s6_probe_attacker", "users.write", "roles.read")

	forbiddenResp := requestSharedSecretsForUser(cs, attackerID, admin.ID, "s6_probe_attacker")
	const nonexistentTargetID = uint(999999)
	unknownResp := requestSharedSecretsForUser(cs, attackerID, nonexistentTargetID, "s6_probe_attacker")

	require.Equal(t, 403, forbiddenResp.Code)
	assert.Equal(t, forbiddenResp.Code, unknownResp.Code, "an unknown target must return the SAME status code as a real refusal")
	assert.JSONEq(t, forbiddenResp.Body.String(), unknownResp.Body.String(), "an unknown target must return the SAME body as a real refusal -- no existence oracle")
}

// TestListSharedSecretsForUser_HandlerInvalidUserIDParam: a non-numeric id
// path param is a 400, not a 403/404/500.
func TestListSharedSecretsForUser_HandlerInvalidUserIDParam(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withChiParams(httptest.NewRequest("GET", "/", nil), map[string]string{"id": "not-a-number"})
	uc := &middleware.UserContext{UserID: 1, Username: "testuser_s12", ActorType: core.ActorTypeUser}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.ListSharedSecretsForUser(w, req)

	assert.Equal(t, 400, w.Code)
}

// TestListSharedSecretsForUser_HandlerUnauthenticated: no user context at all
// is a 401, matching every other ShareHandler route.
func TestListSharedSecretsForUser_HandlerUnauthenticated(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withChiParams(httptest.NewRequest("GET", "/", nil), map[string]string{"id": "1"})
	w := httptest.NewRecorder()
	h.ListSharedSecretsForUser(w, req)

	assert.Equal(t, 401, w.Code)
}
