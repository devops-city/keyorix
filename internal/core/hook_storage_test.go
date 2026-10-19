package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// hookStore is THE storage.Storage test double for this package's tests.
//
// Why it exists (CORE-MOCKS-SLIM-1, reports/SESSION-CACHE-SHAPE-1.md): storage.Storage
// has ~1,090 methods, and Go emits a value+pointer wrapper for every promoted method
// of every struct that embeds it, whether or not a test ever calls it. 123 per-test
// `struct{ storage.Storage; ... }` doubles produced ~120,000 wrappers and a 326-434 MB
// [internal/core.test] archive (the cost is ~2.6 MB per embedding type, regardless of
// how many methods it overrides). Embedding ONCE, here, keeps that cost to one type.
//
// DO NOT add another type that embeds storage.Storage, *store.LocalStorage, hookStore
// or any other whole-Storage implementation in an internal/core test file:
// TestNoWholeStorageEmbeddingInCoreTests fails on it. Build a double with hooked()
// and a storeHooks literal instead.
//
// Semantics, chosen so a converted double behaves exactly like the struct it replaced:
//
//   - A hooked method runs its hook. The hook gets `next`, the store this hookStore
//     wraps, and may delegate to it (`return next.GetUser(ctx, id)`).
//   - An un-hooked method delegates to the inner store, like a promoted method did.
//     With a nil inner store (a pure spy) it dereferences nil and panics, which is
//     the loud failure the old spies relied on: a test can never silently reach an
//     un-faked method.
//   - WithTransaction hands the callback the inner store's raw transaction handle, as a
//     promoted method did (the "tx blind spot": a hook does NOT fire inside the
//     transaction). storeHooks.WrapTx re-wraps the handle with the SAME hooks so a
//     fault fires inside the transaction too (the failOnce*/atomicity idiom), and
//     storeHooks.WithTransaction overrides it outright.
//
// The per-method plumbing lives in hook_storage_methods_test.go. It was derived
// mechanically from storage.Storage and is plain code: to hook one more method add a
// field to storeHooks and a method to hookStore following the pattern there. A
// signature that drifts from the interface stops hookStore satisfying it, which is a
// compile error.
type hookStore struct {
	storage.Storage
	h *storeHooks
}

// hooked wraps inner (may be nil for a pure spy) with the given overrides.
func hooked(inner storage.Storage, h *storeHooks) *hookStore {
	return &hookStore{Storage: inner, h: h}
}

// WithTransaction implements storage.Storage; see the hookStore doc comment.
func (hs *hookStore) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	if hk := hs.h.WithTransaction; hk != nil {
		return hk(hs.Storage, ctx, fn)
	}
	if !hs.h.WrapTx {
		return hs.Storage.WithTransaction(ctx, fn)
	}
	return hs.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&hookStore{Storage: tx, h: hs.h})
	})
}

// The three combined reads below are hand-written, not plain hook-or-delegate. Each
// is served by the store in ONE statement that never calls the per-statement reads a
// test usually overrides, so a hook on one of those would be bypassed silently
// (PERF-FIX-6 role reads, PERF-FIX-7 session cache hit: see
// role_read_wrapper_forwarding_guard_test.go and
// session_auth_read_wrapper_forwarding_guard_test.go). When any feeding read is
// hooked, the combined read is composed over the hookStore itself so the hook is met;
// otherwise it delegates to the inner store. A hook on the combined read itself wins.

// ResolveUserPermissionAt implements storage.Storage; see the comment above.
func (hs *hookStore) ResolveUserPermissionAt(ctx context.Context, userID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error) {
	if hk := hs.h.ResolveUserPermissionAt; hk != nil {
		return hk(hs.Storage, ctx, userID, scope, permission)
	}
	if hs.h.GetUserRoleIDsAt != nil || hs.h.GetUserGroupRoleIDsAt != nil ||
		hs.h.RoleSetBypassesPermissionChecks != nil || hs.h.RoleSetHasPermission != nil {
		return storage.ComposeUserPermissionAt(ctx, hs, userID, scope, permission)
	}
	return hs.Storage.ResolveUserPermissionAt(ctx, userID, scope, permission)
}

// ResolveMachinePermissionAt implements storage.Storage; see the comment above.
func (hs *hookStore) ResolveMachinePermissionAt(ctx context.Context, machineID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error) {
	if hk := hs.h.ResolveMachinePermissionAt; hk != nil {
		return hk(hs.Storage, ctx, machineID, scope, permission)
	}
	if hs.h.GetMachineRoleIDsAt != nil || hs.h.RoleSetHasPermission != nil {
		return storage.ComposeMachinePermissionAt(ctx, hs, machineID, scope, permission)
	}
	return hs.Storage.ResolveMachinePermissionAt(ctx, machineID, scope, permission)
}

// GetSessionAuthLiveness implements storage.Storage; see the comment above.
func (hs *hookStore) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	if hk := hs.h.GetSessionAuthLiveness; hk != nil {
		return hk(hs.Storage, ctx, userID, sessionID)
	}
	if hs.h.GetUser != nil || hs.h.GetSessionByID != nil {
		return storage.ComposeSessionAuthLiveness(ctx, hs, userID, sessionID), nil
	}
	return hs.Storage.GetSessionAuthLiveness(ctx, userID, sessionID)
}
