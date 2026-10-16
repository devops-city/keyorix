// rbac_roles.go — role DEFINITION CRUD (CreateRole, UpdateRole), distinct from
// assigning a role to a principal (rbac_management.go/rbac.go).
//
// #1660: server/http/handlers/rbac.go's RBACHandler and server/grpc/services/
// role_service.go's RoleGRPCService both used to call storage.Storage.CreateRole/
// UpdateRole directly, bypassing internal/core entirely — the only two transports
// that create/update roles had no shared validation layer, unlike every other
// resource (users, groups, secrets, projects), each of which routes through a
// core-layer function. #1642's identity.FoldedName constructor closed the
// worst of this as a side effect (charset/length validation on the name), but
// that was incidental to a different fix, not a deliberate one for this shape,
// and left the reserved-builtin-name check and audit logging duplicated
// per-transport rather than defined once. This file is that single definition;
// both transports now call CreateRole/UpdateRole here instead of the storage
// layer directly.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrRoleValidation marks a CreateRole failure as an application-generated
// validation error (name length, folded-name charset/bidi rejection) rather
// than a storage/driver failure, so a caller like mapRoleError
// (server/grpc/services/role_service.go) can confirm via errors.Is that the
// failure is safe to classify as InvalidArgument instead of guessing from
// its text.
//
// FIX-4 (adversarial review run 2), restored 2026-09-03: this sentinel was
// introduced by #1668 (e78bab59) and reverted 22 hours later by #1669, as a
// side effect of resolving a merge conflict while ALSO fixing a genuinely
// real, separate problem (see mapRoleError's comment) — #1669's commit
// message says so explicitly: "the sentinel machinery was removed... this
// fixed-message approach is simpler." That conflation is exactly the gap:
// #1669's message-safety fix (never pass err.Error() to status.Error,
// required by the keyorix-raw-error-to-client Semgrep gate) is correct and
// stays; #1669's classification regression (back to strings.Contains(msg,
// "validation"), the imprecise substring match #1668 existed specifically
// to close) does not need to accompany it — the two are independent, and
// restoring the sentinel here does not require echoing its content anywhere.
var ErrRoleValidation = errors.New("role validation")

// roleValidationError tags err as matching ErrRoleValidation for errors.Is,
// without ErrRoleValidation's own text ever appearing in Error() -- the
// displayed message stays exactly err's, unchanged from before this marker
// existed.
type roleValidationError struct{ err error }

func (e *roleValidationError) Error() string        { return e.err.Error() }
func (e *roleValidationError) Unwrap() error        { return e.err }
func (e *roleValidationError) Is(target error) bool { return target == ErrRoleValidation }

// WrapRoleValidation marks err as an ErrRoleValidation match for errors.Is,
// without altering its Error() text.
func WrapRoleValidation(err error) error { return &roleValidationError{err: err} }

// Role Name/Description length bounds — the single source of truth both
// transports' own early-reject validation (server/http/handlers/rbac.go's
// CreateRoleRequest/UpdateRoleRequest struct tags, server/grpc/services/
// role_service.go's validateRoleName/validateRoleDescription) must mirror,
// closing the #191/#1660 duplication where gRPC previously defined its own
// copy of these numbers with no shared layer to inherit them from. Roles get
// their own bounds rather than reusing the generic validateNameLength/
// validateDescription (maxResourceNameLen=255, maxSecretDescriptionLen=1024,
// neither with a minimum) — tighter and minimum-enforcing on purpose, since a
// role name is a short, human-typed identifier, not free text.
const (
	RoleNameMinLen        = 3
	RoleNameMaxLen        = 50
	RoleDescriptionMinLen = 1
	RoleDescriptionMaxLen = 200
)

func validateRoleNameLength(name string) error {
	if len(name) < RoleNameMinLen || len(name) > RoleNameMaxLen {
		return fmt.Errorf("role name must be between %d and %d characters", RoleNameMinLen, RoleNameMaxLen)
	}
	return nil
}

// CreateRole creates a new role definition and, when permissionIDs is
// non-empty, bundles that permission set onto it — atomically: the role row
// and every permission assignment run inside one storage.WithTransaction, so
// a failure partway through can never leave a role created with only SOME of
// its intended permissions while still reporting overall success. Both
// REST (server/http/handlers/rbac.go) and gRPC
// (server/grpc/services/role_service.go) used to run these as two separately-
// sequenced steps, each discarding (REST: logged and swallowed) or
// independently handling (gRPC: propagated) an AssignPermissionToRole
// failure after the role row had already committed — the REST side is F3's
// exact sibling shape (see docs/findings/2026-09-21-FINDING-role-update-permission-replace-swallows-storage-errors.md),
// found live by FuzzStorageFaultOperations on this call site directly, not
// assumed from the UpdateRole fix.
//
// name is the raw, caller-supplied role name — this is the ONLY point that
// constructs the identity.FoldedName storage.CreateRole requires, so no
// future call site can reach storage with an unfolded/unvalidated name
// (mirrors CreateGroup's identical treatment, groups.go). Rejects reserved
// built-in role names (#294) before ever writing anything: roleSetContainsAdmin
// (authz.go) grants a full admin bypass by name match alone, so a
// caller-created row named e.g. "super_admin" would function as a complete
// admin-bypass switch the moment it's assigned, even with zero permissions of
// its own. actorID is the admin performing the create (0 = no authenticated
// principal).
func (c *KeyorixCore) CreateRole(ctx context.Context, actorID uint, name, description string, permissionIDs []uint) (*models.Role, []*models.Permission, error) {
	if err := validateRoleNameLength(name); err != nil {
		return nil, nil, WrapRoleValidation(fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err))
	}
	foldedName, ferr := identity.NewFoldedName(name)
	if ferr != nil {
		return nil, nil, WrapRoleValidation(fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr))
	}
	if IsBuiltinRole(foldedName.Folded()) {
		return nil, nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "this role name is reserved and cannot be created")
	}

	var role *models.Role
	var assignedPermissionIDs []uint
	var assignedPermissions []*models.Permission
	txErr := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var err error
		role, err = tx.CreateRole(ctx, foldedName, description)
		if err != nil {
			return err
		}
		for _, id := range permissionIDs {
			if err := tx.AssignPermissionToRole(ctx, role.ID, id); err != nil {
				return err
			}
			assignedPermissionIDs = append(assignedPermissionIDs, id)
		}
		// Read the final permission set to return to the caller INSIDE the
		// same transaction, not after it commits (F3d — see UpdateRole's own
		// comment for the fault-injection finding this exact shape produced):
		// a failure here must roll back the whole create, not report an
		// error against an already-committed role.
		assignedPermissions, err = tx.GetRolePermissions(ctx, role.ID)
		if err != nil {
			return err
		}
		// AUDIT-TX-2: the audit rows are the LAST statements of the create's own
		// transaction (mutation_audit_tx.go), so they commit or roll back with it
		// — no phantom row on a rolled-back create (F3b), and no committed role
		// without its rows.
		c.logRoleDefinitionChangeOn(ctx, tgt, EventRoleCreated, "created", actorID, role.ID, role.Name)
		builtinTarget := IsBuiltinRole(role.Name) // always false here (guarded above); kept symmetric with AssignPermissionToRole's own logging
		for _, id := range assignedPermissionIDs {
			c.logPermissionAssignedOn(ctx, tgt, actorID, role.ID, id, builtinTarget)
		}
		return nil
	})
	if txErr != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), txErr)
	}

	return role, assignedPermissions, nil
}

// UpdateRole updates an existing role's description (role names are immutable —
// #1494's closure rests on this: neither transport's UpdateRoleRequest carries
// a field mapping to models.Role.Name, verified by AST inspection in
// server/http/role_rename_unreachable_guard_test.go's
// TestUpdateRoleRequest_CarriesNoNameField, so there is no rename call site
// here to guard) and, when newPermissionIDs is non-nil, replaces the role's
// entire permission set to match it (nil = leave permissions untouched; an
// empty non-nil slice clears every permission). Rejects mutating a built-in
// role (mirrors CreateRole's reserved-name guard — an admin/system_admin
// role's permission set must not be alterable through this path), including a
// permissions-only update: the guard runs before either phase, unconditionally.
//
// Both the role-row update and the permission replacement run inside ONE
// storage.WithTransaction, and every audit event this call writes is written
// as the last statements of that same transaction (AUDIT-TX-2; before it, they
// were written after the commit) — fixing two real fault-injection
// findings from the same defect (docs/findings/2026-09-21-FINDING-role-update-permission-replace-swallows-storage-errors.md):
// F3a (a storage error partway through the old two-phase, non-transactional
// sequence was silently swallowed by the caller and reported as success) and
// F3b (a panic partway through was correctly turned into an error response,
// but the role-update phase's own audit write — which used to happen before
// permission replacement even started — had already committed and survived
// the panic). Both callers (server/http/handlers/rbac.go,
// server/grpc/services/role_service.go) now call this single function instead
// of each independently sequencing AssignPermissionToRole/RemovePermissionFromRole
// around a bare role-row update.
func (c *KeyorixCore) UpdateRole(ctx context.Context, actorID uint, role *models.Role, newPermissionIDs *[]uint) (*models.Role, []*models.Permission, error) {
	if IsBuiltinRole(role.Name) {
		c.LogRoleUpdateDenied(ctx, actorID, role.ID, role.Name, "target is a built-in role")
		return nil, nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "cannot update built-in role: "+role.Name)
	}

	var updated *models.Role
	var removedPermissionIDs, assignedPermissionIDs []uint
	var finalPermissions []*models.Permission
	txErr := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var err error
		updated, finalPermissions, removedPermissionIDs, assignedPermissionIDs, err = updateRoleTx(ctx, tx, role, newPermissionIDs)
		if err != nil {
			return err
		}
		// AUDIT-TX-2: every audit row is written as the LAST statements of this
		// transaction, through tx (mutation_audit_tx.go), so it commits or rolls
		// back with the update (no phantom row on rollback: F3b).
		c.logRoleDefinitionChangeOn(ctx, tgt, EventRoleUpdated, "updated", actorID, updated.ID, updated.Name)
		builtinTarget := IsBuiltinRole(updated.Name) // always false here (guarded above); kept symmetric with Assign/RemovePermissionFromRole's own logging for a future caller of those directly
		for _, id := range removedPermissionIDs {
			c.logPermissionRemovedOn(ctx, tgt, actorID, role.ID, id, builtinTarget)
		}
		for _, id := range assignedPermissionIDs {
			c.logPermissionAssignedOn(ctx, tgt, actorID, role.ID, id, builtinTarget)
		}
		return nil
	})
	if txErr != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), txErr)
	}

	return updated, finalPermissions, nil
}

// updateRoleTx is UpdateRole's storage work inside its transaction: the
// role-row update, the permission-set replacement, and the final read of the
// permission set (F3d: read INSIDE the transaction, so a failure there rolls
// the whole update back instead of reporting an error for a committed change).
// It returns which permissions it removed and assigned, for the audit rows.
func updateRoleTx(ctx context.Context, tx storage.Storage, role *models.Role, newPermissionIDs *[]uint) (updated *models.Role, final []*models.Permission, removed, assigned []uint, err error) {
	if updated, err = tx.UpdateRole(ctx, role); err != nil {
		return nil, nil, nil, nil, err
	}
	if newPermissionIDs != nil {
		existing, err := tx.GetRolePermissions(ctx, role.ID)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		want := make(map[uint]bool, len(*newPermissionIDs))
		for _, id := range *newPermissionIDs {
			want[id] = true
		}
		have := make(map[uint]bool, len(existing))
		for _, ep := range existing {
			have[ep.ID] = true
			if want[ep.ID] {
				continue // already assigned, nothing to do
			}
			if err := tx.RemovePermissionFromRole(ctx, role.ID, ep.ID); err != nil {
				return nil, nil, nil, nil, err
			}
			removed = append(removed, ep.ID)
		}
		for _, id := range *newPermissionIDs {
			if have[id] {
				continue // already assigned, nothing to do
			}
			if err := tx.AssignPermissionToRole(ctx, role.ID, id); err != nil {
				return nil, nil, nil, nil, err
			}
			assigned = append(assigned, id)
		}
	}
	if final, err = tx.GetRolePermissions(ctx, role.ID); err != nil {
		return nil, nil, nil, nil, err
	}
	return updated, final, removed, assigned, nil
}

// DeleteRole deletes a role definition by id. Rejects deleting a built-in
// role (mirrors CreateRole/UpdateRole's reserved-name guard — deleting
// e.g. admin/super_admin would invalidate every live assignment of it and
// can lock every administrator out).
//
// #1660 sibling sweep (Part 2 regression audit continuation): both
// transports' DeleteRole handlers used to call storage.Storage.DeleteRole
// directly, the SAME direct-to-storage shape #1665 fixed for CreateRole/
// UpdateRole, recurring exactly as that issue's own "worthwhile follow-up"
// predicted. Unlike the original pre-#1665 CreateRole gap, this one was
// NOT a live, exploitable hole — both transports had already, deliberately,
// kept an inline IsBuiltinRole check and audit call in sync (the gRPC side's
// own comment: "the guard is bypassable by switching transport" shows the
// duplication was intentional and watched, not accidental) — but the
// architectural risk (duplicated logic that could silently drift) is the
// same one #1665 closed for the other two operations. Consolidating here
// for the same reason, not because a gap was found live.
// A residual check-then-act race is left deliberately unguarded (PR #2357
// review, non-blocking): an AssignRole or AssignMachineRole whose GetRole
// existence check reads before this function's DeleteRole commits, but whose
// own insert lands after, can still leave an orphan UserRole/GroupRole/
// MachineIdentityRole row pointing at the just-deleted role ID -- the same
// check-then-act shape as DeleteEnvironment's F6 race, but inert for the
// same reason the cascade's own orphans were inert before this PR: role-ID
// reuse is impossible, and every authorization query joins against the live
// roles table, so the orphan row never grants anything. Not worth a named
// lock for an inert outcome.
func (c *KeyorixCore) DeleteRole(ctx context.Context, actorID, id uint) error {
	role, err := c.storage.GetRole(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if IsBuiltinRole(role.Name) {
		c.LogRoleDeleteDenied(ctx, actorID, role.ID, role.Name, "target is a built-in role")
		return fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "cannot delete built-in role: "+role.Name)
	}
	counts, err := c.storage.DeleteRole(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogRoleDeleted(ctx, actorID, role.ID, role.Name, counts)
	return nil
}
