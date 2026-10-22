// role_scope_guard.go — GROUP-ROLE-SCOPE-1 (#3546): a role grant's scope must be
// one the role is meaningful at.
//
// ADR-021 splits the built-in roles into two tiers by WHERE they are assigned:
// system_* at the global scope (project 0), project_* at a project scope. The
// split had no enforcement: a grant of project_developer with no project_id
// landed at {0, 0}, and storage's authorization queries treat a global grant as
// applying in EVERY project — so "give alice project_developer" from a form that
// forgot the project silently made alice a developer of every project
// (DEMO-WALK-4). requireGranterHoldsRolePermissions cannot catch it: it bounds
// the GRANTER's authority, and an install admin passes it for any role.
//
// This file is that missing check. It runs in internal/core, not in a
// transport, so every grant path is covered — see
// TestEveryRoleGrantWriteChecksRoleScope (role_scope_guard_registry_test.go)
// for the AST-derived proof that every storage grant write in this package is
// either guarded or exempt for a stated reason.
package core

import (
	"context"
	"errors"
	"fmt"
)

// ErrRoleScopeInvalid is the sentinel every role-scope refusal wraps
// (errors.Is). Transports map it to HTTP 400 / gRPC InvalidArgument.
var ErrRoleScopeInvalid = errors.New("invalid scope for role")

// RoleScopeError is a role-scope refusal. ClientMessage is a fixed,
// application-generated sentence (a built-in role name and the fix) that is
// safe to send to a client verbatim.
type RoleScopeError struct {
	ClientMessage string
}

func (e *RoleScopeError) Error() string { return ErrRoleScopeInvalid.Error() + ": " + e.ClientMessage }

// Is makes errors.Is(err, ErrRoleScopeInvalid) true for a *RoleScopeError.
func (e *RoleScopeError) Is(target error) bool { return target == ErrRoleScopeInvalid }

// RoleScopeClientMessage returns the client-safe message of a role-scope
// refusal anywhere in err's chain, and false when err is not one.
func RoleScopeClientMessage(err error) (string, bool) {
	if rse, ok := errors.AsType[*RoleScopeError](err); ok {
		return rse.ClientMessage, true
	}
	return "", false
}

// projectTierRoleNames are the ADR-021 project-tier built-in roles, matched by
// EXACT name. Deliberately not a "project_" prefix: a custom role an operator
// happened to name project_* must not change behaviour in a patch release
// (custom roles get an explicit assignable scope in Phase 2, not a naming
// convention). Role names are immutable (TestUpdateRoleRequest_CarriesNoNameField)
// and unique, so a custom role cannot take one of these names.
var projectTierRoleNames = map[string]bool{
	"project_admin":     true,
	"project_developer": true,
	"project_viewer":    true,
	"project_auditor":   true,
}

// IsProjectTierRole reports whether name is an ADR-021 project-tier built-in
// role, which is only meaningful at a project scope.
func IsProjectTierRole(name string) bool { return projectTierRoleNames[name] }

// validateRoleScope is the pure part of the check: an environment scope needs
// its project, and a project-tier role needs a project.
func validateRoleScope(roleName string, scope Scope) error {
	if scope.ProjectID == 0 && scope.EnvironmentID != 0 {
		return &RoleScopeError{ClientMessage: "environment_id requires project_id: specify the project the environment belongs to"}
	}
	if scope.ProjectID == 0 && IsProjectTierRole(roleName) {
		return &RoleScopeError{ClientMessage: fmt.Sprintf(
			"role %s is project-scoped; specify a project_id (and optionally environment_id)", roleName)}
	}
	return nil
}

// requireScopeValidForRole refuses a grant of roleID at scope when the scope is
// not valid for the role: an environment without its project, an environment
// of a different project, or a project-tier role at the global scope. Read-only;
// call it before any write.
func (c *KeyorixCore) requireScopeValidForRole(ctx context.Context, roleID uint, scope Scope) error {
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to resolve role %d for its scope check: %w", roleID, err)
	}
	return c.requireScopeValidForRoleName(ctx, role.Name, scope)
}

// requireScopeValidForRoleName is requireScopeValidForRole for a caller that
// already resolved the role.
func (c *KeyorixCore) requireScopeValidForRoleName(ctx context.Context, roleName string, scope Scope) error {
	if err := validateRoleScope(roleName, scope); err != nil {
		return err
	}
	if scope.EnvironmentID == 0 {
		return nil
	}
	env, err := c.storage.GetEnvironment(ctx, scope.EnvironmentID)
	if err != nil {
		if !isEnvironmentNotFoundErr(err) {
			// Unknown, not refused: a failing read must not turn into a 400.
			return fmt.Errorf("failed to verify environment %d for the role scope check: %w", scope.EnvironmentID, err)
		}
		return &RoleScopeError{ClientMessage: "environment_id does not name an existing environment"}
	}
	if env.ProjectID != scope.ProjectID {
		return &RoleScopeError{ClientMessage: "environment_id must name an environment of project_id"}
	}
	return nil
}
