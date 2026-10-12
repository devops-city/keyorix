package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ResolveUserPermissionAt / ResolveMachinePermissionAt (PERF-FIX-6) are
// composed from the mock's own role methods (storage.Compose*PermissionAt, in
// the order core.Authorize used to call them), so a test that stubs those
// (On("GetUserRoleIDsAt"), On("RoleSetBypassesPermissionChecks"),
// On("RoleSetHasPermission"), ...) drives the combined read unchanged, errors
// included.
func (m *MockStorage) ResolveUserPermissionAt(ctx context.Context, userID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error) {
	return storage.ComposeUserPermissionAt(ctx, m, userID, scope, permission)
}

func (m *MockStorage) ResolveMachinePermissionAt(ctx context.Context, machineID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error) {
	return storage.ComposeMachinePermissionAt(ctx, m, machineID, scope, permission)
}
