// users_admin_rank_ceiling_test.go — S1 (CLI-split inventory #2012): the
// human-facing PUT /api/v1/users/{id} route (and its siblings that mutate
// ANOTHER user's account) never enforced the admin-rank ceiling
// (RequireEqualOrGreaterAdminAuthority) its already-fixed /system sibling
// (UpdateUserIfActiveStateMatchesProxy, F5) required. A principal holding
// only users.write -- not global admin -- could rewrite a HIGHER-privileged
// user's identity fields (or suspend/delete/restore/revoke-sessions/
// resend-setup-link them) with no ceiling beyond the flat permission the
// router already required.
//
// seedUsersWriteOnlyActor below seeds a role bundling ONLY users.write/
// users.delete (never system_admin's BypassesPermissionChecks) -- the exact
// attacker shape the finding describes -- and assigns it at global scope.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// seedUsersWriteOnlyActor creates a new user holding ONLY the named
// permissions (global scope, no admin-bypass role) and returns its ID. Used
// to build the attacker shape S1 describes: users.write (and, where needed,
// users.delete) but NOT global admin.
func seedUsersWriteOnlyActor(t *testing.T, db *gorm.DB, username string, permissionNames ...string) uint {
	t.Helper()
	role := &models.Role{Name: username + "_role", NameFolded: username + "_role"}
	require.NoError(t, db.Create(role).Error)
	for _, name := range permissionNames {
		perm := &models.Permission{}
		err := db.Where("name = ?", name).First(perm).Error
		if err != nil {
			perm = &models.Permission{Name: name}
			require.NoError(t, db.Create(perm).Error)
		}
		require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	}
	actor := &models.User{
		Username: username, UsernameFolded: username,
		Email: username + "@example.com", EmailFolded: username + "@example.com",
		AccountState: "active", IsActive: true,
	}
	require.NoError(t, db.Create(actor).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: actor.ID, RoleID: role.ID}).Error)
	return actor.ID
}

// seedOrdinaryUser creates a user with no role grants at all -- the "lower or
// equal privilege" control target.
func seedOrdinaryUser(t *testing.T, db *gorm.DB, username string) uint {
	t.Helper()
	u := &models.User{
		Username: username, UsernameFolded: username,
		Email: username + "@example.com", EmailFolded: username + "@example.com",
		AccountState: "active", IsActive: true,
	}
	require.NoError(t, db.Create(u).Error)
	return u.ID
}

// ── PUT /api/v1/users/{id} (UpdateUser) ─────────────────────────────────────

// TestUpdateUser_UsersWriteHolderCannotRewriteHigherPrivilegedTarget_RealServer
// is the RED test: a principal holding only users.write (not global admin)
// attempts to rewrite the install's global-admin target's email through the
// PRIMARY human-facing route. Before the S1 fix this returned 200 and
// persisted the new email (the attack); after the fix it must be refused
// (403) with the email unchanged.
func TestUpdateUser_UsersWriteHolderCannotRewriteHigherPrivilegedTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	originalEmail := admin.Email

	attackerID := seedUsersWriteOnlyActor(t, db, "s1_attacker_update", "users.write")

	body, err := json.Marshal(map[string]any{"email": "attacker-owned@evil.example"})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(admin.ID)})
	uc := &middleware.UserContext{UserID: attackerID, Username: "s1_attacker_update", ActorType: core.ActorTypeUser}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.UpdateUser(w, req)

	assert.Equal(t, 403, w.Code, "a users.write-only holder must be refused when rewriting a higher-privileged target: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), "roles.assign", "the refusal must not leak the specific permission name to the client")

	reloaded, err := cs.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	assert.Equal(t, originalEmail, reloaded.Email, "the admin's email must be UNCHANGED -- this is the attack this test exists to catch")
}

// TestUpdateUser_UsersWriteHolderCanUpdateOrdinaryTarget_RealServer is the
// control case: the SAME users.write-only actor updating an ORDINARY
// (unprivileged) user must still succeed -- the ceiling must not become an
// unconditional refusal.
func TestUpdateUser_UsersWriteHolderCanUpdateOrdinaryTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	targetID := seedOrdinaryUser(t, db, "s1_ordinary_target")
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_actor_ordinary_ok", "users.write")

	body, err := json.Marshal(map[string]any{"display_name": "Updated Name"})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(targetID)})
	uc := &middleware.UserContext{UserID: attackerID, Username: "s1_actor_ordinary_ok", ActorType: core.ActorTypeUser}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.UpdateUser(w, req)

	require.Equal(t, 200, w.Code, "updating an ordinary, unprivileged target must still succeed: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, targetID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", reloaded.DisplayName)
}

// TestUpdateUser_EqualPrivilegeTargetAllowed_RealServer: an actor with the
// SAME permission the target holds (equal rank, not greater) must be
// allowed -- the ceiling is "equal or greater," not "strictly greater."
func TestUpdateUser_EqualPrivilegeTargetAllowed_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	targetID := seedUsersWriteOnlyActor(t, db, "s1_equal_target", "users.write")
	actorID := seedUsersWriteOnlyActor(t, db, "s1_equal_actor", "users.write")

	body, err := json.Marshal(map[string]any{"display_name": "Equal Rank Update"})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(targetID)})
	uc := &middleware.UserContext{UserID: actorID, Username: "s1_equal_actor", ActorType: core.ActorTypeUser}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.UpdateUser(w, req)

	require.Equal(t, 200, w.Code, "an actor holding the SAME permission as the target must be allowed: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, targetID)
	require.NoError(t, err)
	assert.Equal(t, "Equal Rank Update", reloaded.DisplayName)
}

// TestUpdateUser_SelfUpdateAllowedEvenAgainstHigherRankCheck_RealServer:
// self-update must keep working regardless of the ceiling -- you always have
// equal authority to yourself.
func TestUpdateUser_SelfUpdateAllowedEvenAgainstHigherRankCheck_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	actorID := seedUsersWriteOnlyActor(t, db, "s1_self_update", "users.write")

	body, err := json.Marshal(map[string]any{"display_name": "Self Updated"})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(actorID)})
	uc := &middleware.UserContext{UserID: actorID, Username: "s1_self_update", ActorType: core.ActorTypeUser}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.UpdateUser(w, req)

	require.Equal(t, 200, w.Code, "self-update must keep working: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, actorID)
	require.NoError(t, err)
	assert.Equal(t, "Self Updated", reloaded.DisplayName)
}

// TestUpdateUser_SelfDeactivationRefused_RealServer: S1b -- UpdateUser had no
// self-action guard at all, unlike DeleteUser/accountStateAction/
// RevokeUserSessions. A self-targeted `active: false` must now be refused.
func TestUpdateUser_SelfDeactivationRefused_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	actorID := seedUsersWriteOnlyActor(t, db, "s1_self_deactivate", "users.write")

	active := false
	body, err := json.Marshal(map[string]any{"active": active})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(actorID)})
	uc := &middleware.UserContext{UserID: actorID, Username: "s1_self_deactivate", ActorType: core.ActorTypeUser}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.UpdateUser(w, req)

	assert.Equal(t, 400, w.Code, "self-deactivation via PUT must be refused: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, actorID)
	require.NoError(t, err)
	assert.True(t, reloaded.IsActive, "the actor must still be active -- the self-deactivation must not have persisted")
}

// TestUpdateUser_PivotDemonstration_ResendSetupLinkNowRefusedToo_RealServer
// shows the S1 finding's own "pivot" claim end to end: even with the
// UpdateUser gap closed, resend-setup-link was ALSO unguarded and, in
// out-of-band delivery mode (this test harness's default -- no
// credentialDelivery channel configured), hands the raw setup token straight
// back to the API caller via ProvisionSetupResult.LinkForAdmin. Before the S1
// fix this succeeded for a users.write-only actor targeting the global admin,
// which is a COMPLETE account-takeover primitive on its own (no email
// rewrite needed at all). After the fix both routes refuse.
func TestUpdateUser_PivotDemonstration_ResendSetupLinkNowRefusedToo_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	uh, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)

	attackerID := seedUsersWriteOnlyActor(t, db, "s1_pivot_attacker", "users.write")

	// Step 1: UpdateUser refuses the identity rewrite (already covered above,
	// re-asserted here as the setup for the pivot).
	body, err := json.Marshal(map[string]any{"email": "attacker-owned-pivot@evil.example"})
	require.NoError(t, err)
	updateReq := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(admin.ID)})
	uc := &middleware.UserContext{UserID: attackerID, Username: "s1_pivot_attacker", ActorType: core.ActorTypeUser}
	updateReq = updateReq.WithContext(context.WithValue(updateReq.Context(), middleware.GetUserContextKey(), uc))
	w1 := httptest.NewRecorder()
	uh.UpdateUser(w1, updateReq)
	require.Equal(t, 403, w1.Code, "setup: the email-rewrite half of the pivot must already be refused")

	// Step 2: the SHARPER pivot -- resend-setup-link needs no prior email
	// rewrite at all. A successful call here would hand the attacker a raw,
	// usable setup token for the admin account.
	resendReq := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(admin.ID)})
	resendReq = resendReq.WithContext(context.WithValue(resendReq.Context(), middleware.GetUserContextKey(), uc))
	w2 := httptest.NewRecorder()
	uh.ResendSetupLink(w2, resendReq)
	assert.Equal(t, 403, w2.Code, "resend-setup-link must ALSO refuse a users.write-only holder targeting the admin -- this is the sharper half of the S1 pivot: %s", w2.Body.String())
	assert.NotContains(t, w2.Body.String(), "link_for_admin", "no setup link/token may leak to a refused caller")
}
