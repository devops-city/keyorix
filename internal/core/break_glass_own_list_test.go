// break_glass_own_list_test.go — ListBreakGlassActivationsForCaller's edges
// (BREAKGLASS-OWN-1). The transports' behaviour (member A vs B, cross-project,
// revoked/expired, machines, PATs, MFA) is driven end to end in
// server/http/break_glass_own_list_test.go and the gRPC twin; these pin the
// decisions only a fake store can reach.
package core

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func bgOwnRows() []*models.BreakGlassActivation {
	return []*models.BreakGlassActivation{
		{ID: 1, ProjectID: 2, UserID: 10, State: BreakGlassActive},
		{ID: 2, ProjectID: 2, UserID: 11, State: BreakGlassActive},
		{ID: 3, ProjectID: 2, UserID: 10, State: BreakGlassRevoked},
		{ID: 4, ProjectID: 2, UserID: 12, State: BreakGlassExpired},
	}
}

// bgOwnCore stubs the role reads MockStorage composes ResolveUserPermissionAt from:
// roleIDs are the caller's roles at project 2, hasRolesRead whether they grant
// roles.read, roleErr a failure of the first read.
func bgOwnCore(t *testing.T, roleIDs []uint, hasRolesRead bool, roleErr error) (*KeyorixCore, *MockStorage) {
	t.Helper()
	m := new(MockStorage)
	m.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, storage.Scope{ProjectID: 2}).Return(roleIDs, roleErr).Maybe()
	m.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, storage.Scope{ProjectID: 2}).Return([]uint(nil), nil).Maybe()
	m.On("RoleSetBypassesPermissionChecks", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	m.On("RoleSetHasPermission", mock.Anything, mock.Anything, permRolesRead).Return(hasRolesRead, nil).Maybe()
	m.On("ListBreakGlassActivations", mock.Anything, uint(2)).Return(bgOwnRows(), nil).Maybe()
	m.On("IsProjectMember", mock.Anything, uint(10), uint(2)).Return(true, nil).Maybe()
	return &KeyorixCore{storage: m}, m
}

func TestListBreakGlassActivationsForCaller_OwnRowsOnly(t *testing.T) {
	c, _ := bgOwnCore(t, []uint{4}, false, nil)
	rows, scope, err := c.ListBreakGlassActivationsForCaller(context.Background(), ActorTypeUser, 10, 10, 2)
	require.NoError(t, err)
	assert.Equal(t, BreakGlassListScopeOwn, scope)
	require.Len(t, rows, 2)
	for _, r := range rows {
		assert.Equal(t, uint(10), r.UserID)
	}
}

func TestListBreakGlassActivationsForCaller_RolesReadSeesAll(t *testing.T) {
	c, _ := bgOwnCore(t, []uint{5}, true, nil)
	rows, scope, err := c.ListBreakGlassActivationsForCaller(context.Background(), ActorTypeUser, 10, 10, 2)
	require.NoError(t, err)
	assert.Equal(t, BreakGlassListScopeProject, scope)
	assert.Len(t, rows, 4)
}

// A failed authorization read is a refusal, never a quiet fall-back to the own view.
func TestListBreakGlassActivationsForCaller_AuthzErrorFailsClosed(t *testing.T) {
	c, m := bgOwnCore(t, nil, false, errors.New("connection reset by peer"))
	rows, _, err := c.ListBreakGlassActivationsForCaller(context.Background(), ActorTypeUser, 10, 10, 2)
	require.ErrorIs(t, err, ErrBreakGlassListForbidden)
	assert.Nil(t, rows)
	m.AssertNotCalled(t, "ListBreakGlassActivations", mock.Anything, mock.Anything)
}

// The own filter is keyed on the authenticated user, and only when the principal IS
// that user: a context whose actor kind and principal disagree is refused.
func TestListBreakGlassActivationsForCaller_RefusesWithoutAUserPrincipal(t *testing.T) {
	for name, tc := range map[string]struct {
		actor               string
		principalID, userID uint
	}{
		"principal_is_not_the_user": {ActorTypeUser, 11, 10},
		"user_id_zero":              {ActorTypeUser, 0, 0},
		"unknown_actor_type":        {"system", 10, 10},
	} {
		t.Run(name, func(t *testing.T) {
			c, m := bgOwnCore(t, []uint{4}, false, nil)
			rows, _, err := c.ListBreakGlassActivationsForCaller(context.Background(), tc.actor, tc.principalID, tc.userID, 2)
			require.ErrorIs(t, err, ErrBreakGlassListForbidden)
			assert.Nil(t, rows)
			m.AssertNotCalled(t, "ListBreakGlassActivations", mock.Anything, mock.Anything)
		})
	}
}

func TestListBreakGlassActivationsForCaller_MachineWithoutRolesReadRefused(t *testing.T) {
	m := new(MockStorage)
	m.On("GetMachineRoleIDsAt", mock.Anything, uint(10), storage.Scope{ProjectID: 2}).Return([]uint{4}, nil)
	m.On("RoleSetHasPermission", mock.Anything, []uint{4}, permRolesRead).Return(false, nil)
	c := &KeyorixCore{storage: m}
	_, _, err := c.ListBreakGlassActivationsForCaller(context.Background(), ActorTypeMachine, 10, 0, 2)
	require.ErrorIs(t, err, ErrBreakGlassListForbidden)
	m.AssertNotCalled(t, "ListBreakGlassActivations", mock.Anything, mock.Anything)
}

// A restricted PAT the restriction keeps out of roles.read at the project gets no own
// view either; one confined to the project does.
func TestListBreakGlassActivationsForCaller_PATRestriction(t *testing.T) {
	c, _ := bgOwnCore(t, []uint{4}, false, nil)
	elsewhere := WithPATRestriction(context.Background(), &PATRestriction{ProjectID: 3})
	_, _, err := c.ListBreakGlassActivationsForCaller(elsewhere, ActorTypeUser, 10, 10, 2)
	require.ErrorIs(t, err, ErrBreakGlassListForbidden)

	secretsOnly := WithPATRestriction(context.Background(), &PATRestriction{Permissions: []string{permSecretsRead}})
	_, _, err = c.ListBreakGlassActivationsForCaller(secretsOnly, ActorTypeUser, 10, 10, 2)
	require.ErrorIs(t, err, ErrBreakGlassListForbidden)

	here := WithPATRestriction(context.Background(), &PATRestriction{ProjectID: 2})
	rows, scope, err := c.ListBreakGlassActivationsForCaller(here, ActorTypeUser, 10, 10, 2)
	require.NoError(t, err)
	assert.Equal(t, BreakGlassListScopeOwn, scope)
	assert.Len(t, rows, 2)
}

// The own view is for current members only; a failed membership read fails closed.
func TestListBreakGlassActivationsForCaller_NonMemberRefused(t *testing.T) {
	for name, member := range map[string]struct {
		ok  bool
		err error
	}{
		"not_a_member":     {false, nil},
		"membership_error": {false, errors.New("connection reset by peer")},
	} {
		t.Run(name, func(t *testing.T) {
			m := new(MockStorage)
			m.On("GetUserRoleIDsAt", mock.Anything, uint(10), storage.Scope{ProjectID: 2}).Return([]uint(nil), nil)
			m.On("GetUserGroupRoleIDsAt", mock.Anything, uint(10), storage.Scope{ProjectID: 2}).Return([]uint(nil), nil)
			m.On("IsProjectMember", mock.Anything, uint(10), uint(2)).Return(member.ok, member.err)
			c := &KeyorixCore{storage: m}
			rows, _, err := c.ListBreakGlassActivationsForCaller(context.Background(), ActorTypeUser, 10, 10, 2)
			require.ErrorIs(t, err, ErrBreakGlassListForbidden)
			assert.Nil(t, rows)
			m.AssertNotCalled(t, "ListBreakGlassActivations", mock.Anything, mock.Anything)
		})
	}
}

func TestListBreakGlassActivationsForCaller_ProjectRequired(t *testing.T) {
	c := &KeyorixCore{storage: new(MockStorage)}
	_, _, err := c.ListBreakGlassActivationsForCaller(context.Background(), ActorTypeUser, 10, 10, 0)
	require.ErrorIs(t, err, ErrBreakGlassInvalidRequest)
}

// bgFullRow is a reviewed AND revoked activation of user 10 with every admin-side
// field set.
func bgFullRow() *models.BreakGlassActivation {
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	return &models.BreakGlassActivation{
		ID: 7, ProjectID: 2, UserID: 10, RoleID: 4, RoleName: "admin", Justification: "incident 42 outage",
		State: BreakGlassRevoked, ExpiresAt: &exp, CreatedAt: now,
		RevokedBy: 99, RevokedByMachineIdentityID: 98, RevokedAt: &now,
		ReviewedBy: 97, ReviewedAt: &now, ReviewNote: "confidential reviewer note",
	}
}

// The own view of a reviewed + revoked activation drops the note and both
// identities but still says it was reviewed and revoked; the project view
// (roles.read) is unchanged; the storage row is never mutated.
func TestListBreakGlassActivationsForCaller_OwnViewRedactsAdminFields(t *testing.T) {
	full := bgFullRow()
	for _, tc := range []struct {
		name         string
		hasRolesRead bool
	}{{"own", false}, {"project", true}} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := bgOwnCore(t, []uint{4}, tc.hasRolesRead, nil)
			m.ExpectedCalls = nil
			m.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, storage.Scope{ProjectID: 2}).Return([]uint{4}, nil)
			m.On("GetUserGroupRoleIDsAt", mock.Anything, mock.Anything, storage.Scope{ProjectID: 2}).Return([]uint(nil), nil)
			m.On("RoleSetBypassesPermissionChecks", mock.Anything, mock.Anything).Return(false, nil)
			m.On("RoleSetHasPermission", mock.Anything, mock.Anything, permRolesRead).Return(tc.hasRolesRead, nil)
			m.On("IsProjectMember", mock.Anything, uint(10), uint(2)).Return(true, nil)
			m.On("ListBreakGlassActivations", mock.Anything, uint(2)).Return([]*models.BreakGlassActivation{full}, nil)

			rows, scope, err := c.ListBreakGlassActivationsForCaller(context.Background(), ActorTypeUser, 10, 10, 2)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			r := rows[0]
			assert.Equal(t, BreakGlassRevoked, r.State)
			assert.NotNil(t, r.RevokedAt)
			assert.NotNil(t, r.ReviewedAt)
			assert.Equal(t, "incident 42 outage", r.Justification)
			assert.NotNil(t, r.ExpiresAt)
			if tc.hasRolesRead {
				assert.Equal(t, BreakGlassListScopeProject, scope)
				assert.Equal(t, "confidential reviewer note", r.ReviewNote)
				assert.Equal(t, uint(97), r.ReviewedBy)
				assert.Equal(t, uint(99), r.RevokedBy)
				assert.Equal(t, uint(98), r.RevokedByMachineIdentityID)
				return
			}
			assert.Equal(t, BreakGlassListScopeOwn, scope)
			assert.Empty(t, r.ReviewNote)
			assert.Zero(t, r.ReviewedBy)
			assert.Zero(t, r.RevokedBy)
			assert.Zero(t, r.RevokedByMachineIdentityID)
			// the stored row is untouched
			assert.Equal(t, "confidential reviewer note", full.ReviewNote)
			assert.Equal(t, uint(99), full.RevokedBy)
		})
	}
}

// Guard for the class: every BreakGlassActivation field must be either listed as
// safe for the own view or cleared by redactBreakGlassForOwnView. A new field
// (say a second reviewer id) fails here until someone classifies it.
func TestBreakGlassOwnView_RedactsEveryAdminField(t *testing.T) {
	safe := map[string]bool{
		"ID": true, "ProjectID": true, "UserID": true, "RoleID": true, "RoleName": true,
		"Justification": true, "State": true, "ExpiresAt": true, "CreatedAt": true,
		"RevokedAt": true, "ReviewedAt": true,
	}
	filled := reflect.New(reflect.TypeFor[models.BreakGlassActivation]()).Elem()
	now := time.Now()
	for i := 0; i < filled.NumField(); i++ {
		f := filled.Field(i)
		switch f.Kind() {
		case reflect.Uint:
			f.SetUint(5)
		case reflect.String:
			f.SetString("x")
		case reflect.Pointer:
			f.Set(reflect.ValueOf(&now))
		case reflect.Struct:
			f.Set(reflect.ValueOf(now))
		default:
			t.Fatalf("unclassified field kind %s on %s", f.Kind(), filled.Type().Field(i).Name)
		}
	}
	in := filled.Addr().Interface().(*models.BreakGlassActivation)
	out := reflect.ValueOf(redactBreakGlassForOwnView(in)).Elem()
	for i := 0; i < out.NumField(); i++ {
		name := out.Type().Field(i).Name
		if safe[name] {
			assert.False(t, out.Field(i).IsZero(), "%s is declared own-view-safe but was cleared", name)
		} else {
			assert.True(t, out.Field(i).IsZero(), "%s is not own-view-safe: redactBreakGlassForOwnView must clear it", name)
		}
	}
}
