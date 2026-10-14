// users_update_lastadmin_test.go — the last-install-admin refusal at the HTTP
// boundary, retargeted onto the route where it is actually reachable (#2496).
//
// HISTORY, because this file's subject moved and the reason matters
// -----------------------------------------------------------------
// ADR-108 PR 6 added TestUpdateUser_RefusesLastAdminDeactivation_RealServer:
// UserHandler.UpdateUser's error switch had no case for
// guardLastAdminDeactivation's refusal, so deactivating the install's sole admin
// via PUT /api/v1/users/{id} returned a bare 500 instead of the readable 409 its
// DeleteUser sibling already produced.
//
// Reaching that guard without self-action needed an actor who passed
// requireAdminRankCeilingForTarget WITHOUT being counted as an admin by
// guardLastAdminDeactivation's resolveGlobalAdminHolders — and that test's own
// doc comment named how: "these use two different definitions of 'admin' (any
// role with BypassesPermissionChecks=true, vs. the fixed installAdminRoleNames
// list)". It built an actor holding a bypass-flagged role named outside the
// fixed list, which the ceiling honoured and the holder count could not see.
//
// #2496 removed that divergence: both now resolve from the structural
// bypasses_permission_checks flag. The fixture's vehicle is gone, and with it
// the reachability of UpdateUser's own 409 case — see
// TestUpdateUser_CeilingAlreadyGuaranteesASurvivingAdminHolder below, which
// asserts the precondition that makes it unreachable rather than leaving that
// as a claim in a comment (#1494's precedent: guard the condition, not the
// conclusion).
//
// The old test is NOT simply deleted, and its assertion was NOT loosened to
// match the new behaviour. What it actually protected — "an operator who tries
// to deactivate the install's last administrator gets a readable refusal, not a
// bare 500" — is preserved, moved to the route where the guard genuinely fires:
// POST /api/v1/users/{id}/suspend, which runs through accountStateAction and
// applies NO admin-rank ceiling (only a self-action check). That route was
// missing the 409 mapping entirely, so it had the exact defect ADR-108 PR 6
// fixed for UpdateUser; this change adds it and tests it.
//
// Why the 200 on the old fixture is correct, not a regression
// -----------------------------------------------------------
// In that fixture the acting user holds a bypass-flagged role at GLOBAL scope.
// Under ADR-084 the bypass applies at whatever scope the role is held, so that
// actor can exercise any permission install-wide — they ARE an install
// administrator, and the install retains one after the target is deactivated.
// TestUpdateUser_DeactivatingAnAdminIsSafeWhileAnotherAdminSurvives below does
// not take that on trust: it authorizes the survivor for users.write /
// roles.assign / system.write and then has them actually create a user. The old
// 409 was the over-refusal direction #2496's PR documents — the guard refusing
// because the name list could not see a real administrator.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// seedGlobalBypassActor creates an active user holding a freshly-created
// bypass-flagged role at GLOBAL scope — i.e. a genuine install administrator
// under ADR-084, whose role name is deliberately outside the canonical set so
// the fixture cannot accidentally depend on name-based resolution.
func seedGlobalBypassActor(t *testing.T, db *gorm.DB, roleName, username string, actorID uint) uint {
	t.Helper()
	require.NoError(t, db.Create(&models.Role{Name: roleName, BypassesPermissionChecks: true}).Error)
	var role models.Role
	require.NoError(t, db.Where("name = ?", roleName).First(&role).Error)
	require.NoError(t, db.Create(&models.User{
		ID: actorID, Username: username, UsernameFolded: username,
		Email: username + "@example.com", EmailFolded: username + "@example.com",
		DisplayName: "Bypass Actor", IsActive: true,
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: actorID, RoleID: role.ID}).Error)
	return role.ID
}

// TestUpdateUser_DeactivatingAnAdminIsSafeWhileAnotherAdminSurvives is the old
// test's fixture with the correct expectation and, more importantly, the
// invariant that actually matters asserted directly: the install is never left
// without a working administrator.
//
// It deliberately proves capability rather than membership. "Another row exists
// in user_roles" is what the old name-based count checked and is exactly the
// kind of claim that can be true while the install is still bricked (#G03's
// lesson: a surviving grant row is not a surviving administrator). So this
// authorizes the survivor on three install-wide permissions and then makes them
// perform a real admin action.
func TestUpdateUser_DeactivatingAnAdminIsSafeWhileAnotherAdminSurvives(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	target, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	require.True(t, target.IsActive)

	const actorID = uint(9001)
	seedGlobalBypassActor(t, db, "custom_bypass_role", "bypassactor", actorID)

	body, err := json.Marshal(map[string]any{"active": false})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(target.ID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(actorID, "bypassactor")))
	w := httptest.NewRecorder()
	h.UpdateUser(w, req)

	require.Equal(t, http.StatusOK, w.Code,
		"the acting user holds a bypass-flagged role at global scope, so they are themselves an install "+
			"administrator and the install is not left without one: %s", w.Body.String())

	// The invariant: a live, CAPABLE administrator remains.
	for _, perm := range []string{"users.write", "roles.assign", "system.write"} {
		allowed, aerr := cs.Authorize(ctx, actorID, perm, core.Scope{})
		require.NoError(t, aerr)
		assert.True(t, allowed,
			"the surviving administrator must still be authorized install-wide for %q — otherwise the "+
				"deactivation DID strand the install and the refusal was right after all", perm)
	}
	created, cerr := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "post-deactivation-user", Email: "post-deactivation-user@example.com",
		DisplayName: "Proof", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, cerr, "the surviving administrator must be able to perform a real admin action — "+
		"authorization returning true is necessary but not sufficient evidence the install is governable")
	require.NotNil(t, created)
}

// TestUpdateUser_CeilingAlreadyGuaranteesASurvivingAdminHolder is the
// precondition tripwire. It asserts WHY UpdateUser's last-admin 409 case cannot
// fire, so that the day the premise changes this goes red and whoever changed
// it has to restore end-to-end coverage there, instead of discovering a silently
// unreachable branch years later.
//
// The premise, in two halves, both checked below:
//
//  1. requireAdminRankCeilingForTarget refuses any non-self actor that does NOT
//     bypass at every scope where the target bypasses. The seeded admin bypasses
//     at global scope, so an actor without a global bypass is refused with
//     ErrInsufficientAdminAuthority (403) BEFORE the guard is ever consulted.
//  2. An actor that DOES bypass at global scope is, by #2496's single authority,
//     exactly what resolveGlobalAdminHolders counts as a global-admin holder —
//     so it survives the target's deactivation and the guard finds a holder.
//
// Together: no actor can both reach UpdateUser's guard and leave zero holders.
// The 409 case is kept in the handler regardless (it costs nothing and becomes
// live again if either half changes), but the REACHABLE route's coverage lives
// in TestSuspendUser_RefusesLastAdminDeactivation_RealServer below.
func TestUpdateUser_CeilingAlreadyGuaranteesASurvivingAdminHolder(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	target, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	targetIsAdmin, err := cs.IsGlobalAdmin(ctx, target.ID)
	require.NoError(t, err)
	require.True(t, targetIsAdmin, "fixture precondition: the target must be a global admin, or neither half "+
		"of this test's premise is being exercised")

	deactivate := func(actorID uint, username string) *httptest.ResponseRecorder {
		body, merr := json.Marshal(map[string]any{"active": false})
		require.NoError(t, merr)
		req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(target.ID)})
		req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(actorID, username)))
		rec := httptest.NewRecorder()
		h.UpdateUser(rec, req)
		return rec
	}

	// Half 1: an actor holding users.write but NO global bypass is stopped by the
	// ceiling, not by the last-admin guard.
	const weakActorID = uint(9100)
	usersWrite, err := cs.Storage().GetRoleByName(ctx, "user_manager_for_ceiling_test")
	if err != nil {
		var role models.Role
		require.NoError(t, db.Create(&models.Role{Name: "user_manager_for_ceiling_test"}).Error)
		require.NoError(t, db.Where("name = ?", "user_manager_for_ceiling_test").First(&role).Error)
		usersWrite = &role
	}
	require.NoError(t, db.Create(&models.User{
		ID: weakActorID, Username: "weakactor", UsernameFolded: "weakactor",
		Email: "weakactor@example.com", EmailFolded: "weakactor@example.com",
		DisplayName: "Weak Actor", IsActive: true,
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: weakActorID, RoleID: usersWrite.ID}).Error)

	weakIsAdmin, err := cs.IsGlobalAdmin(ctx, weakActorID)
	require.NoError(t, err)
	require.False(t, weakIsAdmin, "fixture precondition: this actor must NOT be a global admin")

	w := deactivate(weakActorID, "weakactor")
	assert.Equal(t, http.StatusForbidden, w.Code,
		"an actor who is not a global admin must be refused by requireAdminRankCeilingForTarget (403) "+
			"before the last-admin guard is reached: %s", w.Body.String())
	reloaded, err := cs.Storage().GetUser(ctx, target.ID)
	require.NoError(t, err)
	assert.True(t, reloaded.IsActive, "the ceiling refusal must not have deactivated anyone")

	// Half 2: an actor who DOES pass the ceiling is necessarily a global-admin
	// holder, so the guard finds a survivor and the deactivation proceeds.
	const strongActorID = uint(9101)
	seedGlobalBypassActor(t, db, "another_bypass_role", "strongactor", strongActorID)
	strongIsAdmin, err := cs.IsGlobalAdmin(ctx, strongActorID)
	require.NoError(t, err)
	require.True(t, strongIsAdmin,
		"THE PREMISE: anything that can pass the ceiling for a global-admin target bypasses at global "+
			"scope, which under #2496's single authority IS what resolveGlobalAdminHolders counts. If this "+
			"ever becomes false, UpdateUser's last-admin 409 case is reachable again and this file must "+
			"regain an end-to-end test for it")

	w = deactivate(strongActorID, "strongactor")
	assert.Equal(t, http.StatusOK, w.Code,
		"the ceiling passed and the actor is itself a surviving global-admin holder, so there is no "+
			"last-admin condition to refuse: %s", w.Body.String())
}

// TestSuspendUser_RefusesLastAdminDeactivation_RealServer is where the original
// test's subject lives now: a readable refusal rather than a bare 500 when an
// operator tries to lock the install out of administration.
//
// POST /api/v1/users/{id}/suspend goes through accountStateAction, which applies
// NO admin-rank ceiling — only a self-action check — so core.SuspendUser's
// guardLastAdminDeactivation genuinely fires here for an actor holding
// users.write but no admin role. That makes this the route where the refusal is
// reachable, and (before this change) the only one of the three guard routes
// whose switch had no 409 case, so the refusal arrived as a bare 500.
func TestSuspendUser_RefusesLastAdminDeactivation_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	target, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	targetIsAdmin, err := cs.IsGlobalAdmin(ctx, target.ID)
	require.NoError(t, err)
	require.True(t, targetIsAdmin, "fixture precondition: the target must be the install's only global admin")

	// An actor with no admin role at all: the suspend route's gate is the
	// router's users.write, which this unit test bypasses by injecting the actor
	// context directly — exactly the shape accountStateAction sees in production
	// once the route gate has passed.
	const actorID = uint(9200)
	require.NoError(t, db.Create(&models.User{
		ID: actorID, Username: "suspender", UsernameFolded: "suspender",
		Email: "suspender@example.com", EmailFolded: "suspender@example.com",
		DisplayName: "Suspender", IsActive: true,
	}).Error)

	req := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(target.ID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(actorID, "suspender")))
	w := httptest.NewRecorder()
	h.SuspendUser(w, req)

	assert.Equal(t, http.StatusConflict, w.Code,
		"suspending the install's last administrator must be a readable 409 refusal, not a bare 500 — "+
			"the same mapping UpdateUser and DeleteUser already had: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "last install administrator",
		"the real refusal reason must reach the client")

	reloaded, err := cs.Storage().GetUser(ctx, target.ID)
	require.NoError(t, err)
	assert.Equal(t, core.AccountActive, core.NormalizeAccountState(reloaded.AccountState),
		"the refused suspension must not have persisted")
}
