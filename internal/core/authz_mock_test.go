package core

import (
	"errors"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
)

// stubAuthorizedPrincipal wires MockStorage so AuthorizePrincipal/Authorize grants
// actorID perm at scope via a plain (non-admin) RBAC role — the standard shape used
// across this package's MockStorage-based tests (see authz_pat_test.go). Matches ctx
// loosely (mock.Anything) since callers rarely thread the exact same context.Context
// value through to the assertion.
func stubAuthorizedPrincipal(ms *MockStorage, actorID uint, scope Scope, perm string) {
	const roleID = uint(10)
	ms.On("GetUserRoleIDsAt", mock.Anything, actorID, scope).Return([]uint{roleID}, nil).Maybe()
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, actorID, scope).Return([]uint{}, nil).Maybe()
	// ADR-084: roleSetContainsAdmin resolves the admin-tier bypass by structural
	// flag now, one query over the caller's whole role-ID set, not four separate
	// by-name lookups. This stub means "none of the caller's roles carry the
	// bypass flag" — a real error case (storage down) is a different stub.
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	ms.On("RoleSetHasPermission", mock.Anything, []uint{roleID}, perm).Return(true, nil).Maybe()
}

// stubUnauthorizedPrincipal wires MockStorage so AuthorizePrincipal/Authorize denies
// actorID at scope — no roles at all, so Authorize short-circuits before ever reaching
// the admin-name/permission lookups.
//
// It also wires "no shares on any secret" (stubNoShares): since #2941 a per-secret
// decision the role denied consults the share term next, and a principal this helper
// describes holds none.
func stubUnauthorizedPrincipal(ms *MockStorage, actorID uint, scope Scope) {
	ms.On("GetUserRoleIDsAt", mock.Anything, actorID, scope).Return([]uint{}, nil).Maybe()
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, actorID, scope).Return([]uint{}, nil).Maybe()
	stubNoShares(ms, actorID)
}

// stubNoShares wires MockStorage so the share term (sharePermissionFor) finds no share
// granting actorID anything: no share rows, no group memberships.
func stubNoShares(ms *MockStorage, actorID uint) {
	ms.On("ListSharesBySecret", mock.Anything, mock.Anything).Return([]*models.ShareRecord{}, nil).Maybe()
	ms.On("GetUserGroupsAt", mock.Anything, actorID, mock.Anything).Return([]*models.Group{}, nil).Maybe()
}

// stubAuthorizedSecretPrincipal wires MockStorage so AuthorizeSecretPrincipal/
// AuthorizeSecret grants actorID perm on secretID at scope, via the RBAC fallback (no
// SecretACL grant, no folder-ancestor inheritance) — the standard shape for a test that
// isn't itself about ACL/inheritance behavior.
func stubAuthorizedSecretPrincipal(ms *MockStorage, actorID, secretID uint, scope Scope, perm string) {
	ms.On("GetSecretACL", mock.Anything, secretID, actorID).Return(nil, errors.New("record not found")).Maybe()
	ms.On("GetSecretAncestors", mock.Anything, secretID).Return([]uint{}, nil).Maybe()
	stubAuthorizedPrincipal(ms, actorID, scope, perm)
}
