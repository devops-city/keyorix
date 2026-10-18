// authz_any_scope_fail_closed_test.go — HoldsPermissionInAnyScope must fail closed:
// an error while enumerating the principal's scopes, or while authorizing at one of
// them, is returned as (false, err), never skipped into a pass or a quiet false.
package core

import (
	"context"
	"errors"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// machineAnyScopeStub drives the machine path of HoldsPermissionInAnyScope: the
// global scope resolves to no roles (a clean "no"), the principal has one project
// scope, and resolving roles at that project scope fails.
type machineAnyScopeStub struct {
	corestorage.Storage
	scopes     []corestorage.Scope
	scopesErr  error
	projectErr error
}

func (s *machineAnyScopeStub) GetMachineRoleScopes(_ context.Context, _ uint) ([]corestorage.Scope, error) {
	return s.scopes, s.scopesErr
}

func (s *machineAnyScopeStub) GetMachineRoleIDsAt(_ context.Context, _ uint, scope corestorage.Scope) ([]uint, error) {
	if scope.ProjectID != 0 {
		return nil, s.projectErr
	}
	return nil, nil
}

// ResolveMachinePermissionAt (PERF-FIX-6) reads through this stub's own
// GetMachineRoleIDsAt, so AuthorizePrincipal still meets the project-scope error.
func (s *machineAnyScopeStub) ResolveMachinePermissionAt(ctx context.Context, machineID uint, scope corestorage.Scope, permission string) (*corestorage.PrincipalPermission, error) {
	return corestorage.ComposeMachinePermissionAt(ctx, s, machineID, scope, permission)
}

func TestHoldsPermissionInAnyScope_UserScopeEnumerationErrorFailsClosed(t *testing.T) {
	t.Parallel()
	c, _ := newACLCore(t)
	wantErr := errors.New("scopes db failure")
	c2 := newACLCoreWithStorage(c, userRoleScopesStub(c.storage, nil, wantErr))

	ok, err := c2.HoldsPermissionInAnyScope(context.Background(), ActorTypeUser, 1, "secrets.read")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	assert.False(t, ok)
}

func TestHoldsPermissionInAnyScope_MachineScopeEnumerationErrorFailsClosed(t *testing.T) {
	t.Parallel()
	c, _ := newACLCore(t)
	wantErr := errors.New("machine scopes db failure")
	c2 := newACLCoreWithStorage(c, &machineAnyScopeStub{Storage: c.storage, scopesErr: wantErr})

	ok, err := c2.HoldsPermissionInAnyScope(context.Background(), ActorTypeMachine, 1, "secrets.read")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	assert.False(t, ok)
}

func TestHoldsPermissionInAnyScope_AuthorizeErrorAtProjectScopeFailsClosed(t *testing.T) {
	t.Parallel()
	c, _ := newACLCore(t)
	wantErr := errors.New("role lookup failure at project scope")
	c2 := newACLCoreWithStorage(c, &machineAnyScopeStub{
		Storage:    c.storage,
		scopes:     []corestorage.Scope{{ProjectID: 1}},
		projectErr: wantErr,
	})

	ok, err := c2.HoldsPermissionInAnyScope(context.Background(), ActorTypeMachine, 1, "secrets.read")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	assert.False(t, ok)
}

// Control: with no failure and no role at any scope the answer is a plain
// (false, nil), so the three tests above are asserting the error path and not a
// function that always errors.
func TestHoldsPermissionInAnyScope_NoRoleIsFalseWithoutError(t *testing.T) {
	t.Parallel()
	c, _ := newACLCore(t)
	c2 := newACLCoreWithStorage(c, &machineAnyScopeStub{
		Storage: c.storage,
		scopes:  []corestorage.Scope{{ProjectID: 1}},
	})

	ok, err := c2.HoldsPermissionInAnyScope(context.Background(), ActorTypeMachine, 1, "secrets.read")
	require.NoError(t, err)
	assert.False(t, ok)
}
