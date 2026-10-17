package storage

import "context"

// UserRoleGrant is one live role grant of a user (SHARES-BATCH-AUTHZ-1): ProjectID and
// EnvironmentID are the grant's own scope (0 = global), the project and environment
// rows it names are live (a missing row counts as live, as in the one-statement
// query), and an expired grant or a grant through a deleted group is not listed.
// ViaGroup grants also carry MemberProjectID, the project the user's membership of the
// group is scoped to (0 = global). Bypass is the role's ADR-084 flag.
type UserRoleGrant struct {
	RoleID          uint
	ProjectID       uint
	EnvironmentID   uint
	ViaGroup        bool
	MemberProjectID uint
	Bypass          bool
}

// AppliesAt reports whether the grant is part of the role set at scope: the same
// WHERE clauses as ResolveUserPermissionAt's two subqueries, minus the liveness and
// expiry tests the listing already applied.
func (g UserRoleGrant) AppliesAt(scope Scope) bool {
	if g.ProjectID != 0 && g.ProjectID != scope.ProjectID {
		return false
	}
	if g.EnvironmentID != 0 && g.EnvironmentID != scope.EnvironmentID {
		return false
	}
	if g.ViaGroup && g.MemberProjectID != 0 && g.MemberProjectID != scope.ProjectID {
		return false
	}
	return true
}

// UserGroupMembershipAt is one membership of a user in a live group; ProjectID is the
// project the membership is scoped to (0 = global).
type UserGroupMembershipAt struct {
	GroupID   uint
	ProjectID uint
}

// UserRoleReads is the subset of Storage that ComposeUserPermissionAt reads.
type UserRoleReads interface {
	GetUserRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	RoleSetBypassesPermissionChecks(ctx context.Context, roleIDs []uint) (bool, error)
	RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error)
}

// MachineRoleReads is the subset of Storage that ComposeMachinePermissionAt reads.
type MachineRoleReads interface {
	GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope Scope) ([]uint, error)
	RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error)
}

// ComposeUserPermissionAt answers ResolveUserPermissionAt from the
// per-statement methods, in the order core.Authorize called them before
// PERF-FIX-6: direct role ids, group role ids (union, de-duplicated), the
// bypass flag when the set is non-empty, and RoleSetHasPermission when it does
// not bypass. Any read's error is returned (fail closed).
//
// It is the reference the one-statement implementation is tested against, the
// LocalStorage fallback when that statement fails, and what a Storage wrapper
// that overrides one of these reads (a test injecting a fault) forwards
// ResolveUserPermissionAt to, so the override still reaches the decision.
func ComposeUserPermissionAt(ctx context.Context, s UserRoleReads, userID uint, scope Scope, permission string) (*PrincipalPermission, error) {
	direct, err := s.GetUserRoleIDsAt(ctx, userID, scope)
	if err != nil {
		return nil, err
	}
	viaGroups, err := s.GetUserGroupRoleIDsAt(ctx, userID, scope)
	if err != nil {
		return nil, err
	}
	out := &PrincipalPermission{}
	seen := make(map[uint]struct{}, len(direct)+len(viaGroups))
	for _, id := range append(append([]uint(nil), direct...), viaGroups...) {
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			out.RoleIDs = append(out.RoleIDs, id)
		}
	}
	if len(out.RoleIDs) == 0 {
		return out, nil
	}
	if out.BypassesPermissionChecks, err = s.RoleSetBypassesPermissionChecks(ctx, out.RoleIDs); err != nil {
		return nil, err
	}
	if out.BypassesPermissionChecks {
		return out, nil
	}
	if out.HasPermission, err = s.RoleSetHasPermission(ctx, out.RoleIDs, permission); err != nil {
		return nil, err
	}
	return out, nil
}

// ComposeMachinePermissionAt is ComposeUserPermissionAt for a machine
// principal: GetMachineRoleIDsAt, then RoleSetHasPermission when non-empty.
// Never reads the bypass flag (a machine never bypasses).
func ComposeMachinePermissionAt(ctx context.Context, s MachineRoleReads, machineID uint, scope Scope, permission string) (*PrincipalPermission, error) {
	ids, err := s.GetMachineRoleIDsAt(ctx, machineID, scope)
	if err != nil {
		return nil, err
	}
	out := &PrincipalPermission{RoleIDs: ids}
	if len(ids) == 0 {
		return out, nil
	}
	if out.HasPermission, err = s.RoleSetHasPermission(ctx, ids, permission); err != nil {
		return nil, err
	}
	return out, nil
}
