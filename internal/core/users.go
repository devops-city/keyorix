// users.go — User CRUD, list, and validation.
//
// CreateUser, GetUser, UpdateUser, DeleteUser, RestoreUser, ListUsers, GetUserByEmail.
// For group operations see groups.go. Types are in users_types.go.
package core

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// emailRegex/usernameMinLen/usernameMaxLen/displayNameMinLen/displayNameMaxLen
// mirror the exact format rules server/http/handlers' request-body `validate`
// struct tags enforce for username/email/display_name (users_handler.go,
// users_crud.go) — NOT internal/core/users_types.go's CreateUserRequest.validate
// tags, which are unread dead documentation (no validator library in this
// codebase resolves them) and, for Username, actually claim a stricter
// `alphanum` rule the live HTTP path never enforces. Duplicated here rather
// than imported from server/validation (which internal/core does not, and per
// this repo's layering should not, depend on) so gRPC and CLI embedded-mode —
// which construct a CreateUserRequest/UpdateUserRequest directly and never
// route through the HTTP JSON decoder's validator — get the identical format
// guarantee the HTTP path already has (G38).
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

const (
	usernameMinLen    = 3
	usernameMaxLen    = 50
	displayNameMinLen = 1
	displayNameMaxLen = 100
)

func validateUsernameFormat(username string) error {
	if len(username) < usernameMinLen || len(username) > usernameMaxLen {
		return fmt.Errorf("%s: username must be between %d and %d characters", i18n.T("ErrorValidation", nil), usernameMinLen, usernameMaxLen)
	}
	return nil
}

func validateEmailFormat(email string) error {
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelEmail", nil))
	}
	return nil
}

func validateDisplayNameFormat(displayName string) error {
	if len(displayName) < displayNameMinLen || len(displayName) > displayNameMaxLen {
		return fmt.Errorf("%s: display name must be between %d and %d characters", i18n.T("ErrorValidation", nil), displayNameMinLen, displayNameMaxLen)
	}
	return nil
}

// ProjectAssignment grants Role to the new user at a project's scope, applied
// atomically with the user create (ADR-028).
type ProjectAssignment struct {
	ProjectID uint
	Role      string
}

// buildUserForCreate validates the request and constructs the (unsaved) user
// record plus its bcrypt hash. Shared by CreateUser and CreateUserWithAssignments.
func (c *KeyorixCore) buildUserForCreate(ctx context.Context, req *CreateUserRequest) (*models.User, string, error) {
	if err := c.validateCreateUserRequest(req); err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// #1642: fold once here, use everywhere below — the constructor is the
	// single point every username/email must pass through before it can reach
	// a comparison or a write, so a raw string can never bypass normalization.
	foldedUsername, err := identity.NewFoldedName(req.Username)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	foldedEmail, err := identity.NewFoldedName(req.Email)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	// Enforce the configured password policy on the admin-supplied password — the same
	// policy BootstrapSystem and ChangePassword apply. Without this, the admin "classic"
	// create path (the one path where a human picks the credential) silently accepted a
	// weak password, which is then exposed to online guessing. The policy's user context
	// also catches username/email-in-password. ADR-025.
	policyUser := &models.User{Username: req.Username, Email: req.Email, DisplayName: displayName}
	if err := c.passwordPolicy.Validate(req.Password, policyUser); err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), int(bcryptCost.Load()))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
		return nil, "", fmt.Errorf("%w: username already exists", ErrUserAlreadyExists)
	} else if !storage.IsUserNotFound(err) {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	existing, err := c.storage.GetUserByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return nil, "", fmt.Errorf("%w: user with email already exists", ErrUserAlreadyExists)
	}
	if err != nil && !storage.IsUserNotFound(err) {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	now := c.now()
	active := true
	if req.IsActive != nil {
		active = *req.IsActive
	}
	user := &models.User{
		Username:          req.Username,
		UsernameFolded:    foldedUsername.Folded(),
		Email:             req.Email,
		EmailFolded:       foldedEmail.Folded(),
		DisplayName:       displayName,
		PasswordHash:      string(hash),
		IsActive:          active,
		AccountState:      NormalizeAccountState(req.AccountState), // empty → active (ADR-025)
		PasswordChangedAt: &now,                                    // baseline for max-age expiry (ADR-025)
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	return user, string(hash), nil
}

// EventUserCreated/EventUserUpdated are audited on every user create/update,
// REST and gRPC alike (F2, audit-completeness campaign) — previously CreateUser/
// CreateUserWithAssignments/UpdateUser wrote no audit event of their own at all,
// despite EventUserDeleted/EventUserRestored below already following this
// exact convention for delete/restore.
//
// CreateUser itself takes no actorID (many callers construct it directly with
// no caller identity in scope, e.g. BootstrapSystem's first-admin create, the
// self-service invite-consumption path) — same reasoning LogRoleCreated/
// LogRoleUpdated/LogRoleDeleted are standalone methods rather than parameters
// baked into CreateRole/UpdateRole/DeleteRole's own signatures. Every REST/gRPC
// path that reaches a user create/update calls LogUserCreated/LogUserUpdated
// explicitly once it knows the real actor — see auth_bootstrap.go,
// setup_consume.go, setup_delivery.go (both wrappers), users_crud.go, and
// CreateUserWithAssignments/UpdateUser below (which already had an actorID
// parameter and so call it directly rather than needing an external call site).
const (
	EventUserCreated = "user.created"
	EventUserUpdated = "user.updated"
)

// LogUserCreated records a user creation. actorID is the creating admin (0 =
// none, e.g. BootstrapSystem's first-admin create or self-service invite
// consumption). See the EventUserCreated doc comment above for why this is a
// standalone method rather than a CreateUser parameter.
func (c *KeyorixCore) LogUserCreated(ctx context.Context, actorID, userID uint, username string) {
	c.writeAuditEvent(ctx, EventUserCreated, actorPtr(actorID), nil,
		fmt.Sprintf("created user %d (%s)", userID, username))
}

// CreateUser creates a new user with business logic validation. It auto-assigns
// the system_viewer baseline role (best-effort). For atomic create-with-role and
// project assignments see CreateUserWithAssignments. Callers must call
// LogUserCreated once they know the real actor — see that method's doc comment.
func (c *KeyorixCore) CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
	user, hash, err := c.buildUserForCreate(ctx, req)
	if err != nil {
		return nil, err
	}

	// req.Password is forwarded as the optional plaintext argument (#499): LocalStorage
	// ignores it (a no-op — it already has the hash above). RemoteStorage (since
	// deleted, #2162) used to forward it over the wire so the upstream handler could
	// hash its own copy. This covers
	// every core.CreateUser caller uniformly (the admin classic path, CreateUserWithSetupLink,
	// and CreateUserWithOneTimePassword all populate req.Password with a real, hashable
	// string before reaching here — see buildUserForCreate above and setup_delivery.go),
	// and it is never logged.
	// fix/create-ops-atomicity: the user row and its baseline system_viewer role
	// grant now share ONE storage.WithTransaction, closing the same mixed-state gap
	// as CreateProject/CreateSecret above — a fault on the CreateUser write itself
	// rolls back cleanly instead of leaving a user row with an ambiguous role state.
	// The role-assignment step stays non-fatal INSIDE the transaction (its own
	// failure/panic must not roll back the user row — same accepted tradeoff as
	// before, just tx-scoped now), so only a CreateUser failure can trigger rollback.
	var createdUser *models.User
	err = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var txErr error
		createdUser, txErr = tx.CreateUser(ctx, user, req.Password)
		if txErr != nil {
			return txErr
		}
		// Auto-assign the system_viewer role (ADR-021): a minimal install-wide
		// baseline. Non-fatal (found by fuzz-injecting an AssignRole failure, same
		// class as CreateProjectWithEnvs's CreateEnvironment fix above): the user
		// row itself already committed, and both failure modes — a returned error
		// AND a panic (found separately, by fuzz-injecting a panic on the same
		// call) — must be OBSERVABLE, not swallowed, even though the user is
		// still created regardless.
		//
		// Runs in its own nested tx.WithTransaction (a SAVEPOINT on PostgreSQL):
		// on PostgreSQL a failed statement aborts the enclosing transaction at
		// the protocol level, so an unguarded AssignRole failure would silently
		// fail the whole CreateUser call, not just the non-fatal role grant —
		// unlike SQLite, which has no equivalent transaction-abort behavior.
		// Found reviewing PR #1996 before merge.
		besteffort.Run(ctx, "users.CreateUser.AssignBaselineRole", func() error {
			return tx.WithTransaction(ctx, func(savepoint storage.Storage) error {
				role, err := savepoint.GetRoleByName(ctx, "system_viewer")
				if err != nil {
					return err
				}
				return savepoint.AssignRole(ctx, createdUser.ID, role.ID, Scope{})
			})
		})
		return nil
	})
	if err != nil {
		// #117: the pre-check above (GetUserByEmail) is a check-then-act read that races
		// with a concurrent create for the identical email — both can pass it before
		// either commits. The DB-level partial unique index (uniq_users_email_active)
		// catches the loser here and CreateUser wraps it in ErrDuplicateEmail; surface the
		// same clean "email already in use" error the winner's sequential check would have
		// produced, instead of a raw constraint-violation message or an ambiguous
		// duplicate-email row.
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("%w: user with email already exists", ErrUserAlreadyExists)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Seed password history with the initial password so the no-reuse rule
	// (ADR-025) counts it. Best-effort — user creation has already succeeded.
	// A panic here is recovered too (found live by FuzzStorageFaultOperations,
	// server/faultops, on the sibling AssignRole step below): without it, a
	// panic propagates straight through CreateUser and out to the real
	// Recovery middleware, misreporting an already-committed user creation as
	// a failed request (oracle (a) — see
	// docs/findings/2026-09-22-FINDING-secret-delete-restore-dependency-emission-panic-masks-success.md
	// for the identical shape found first on DeleteSecret/RestoreSecret).
	if c.passwordPolicy.HistoryCount > 0 {
		besteffort.Run(ctx, "users.CreateUser.AddPasswordHistory", func() error {
			return c.storage.AddPasswordHistory(ctx, createdUser.ID, hash, c.now())
		})
	}
	// Role assignment (system_viewer) now happens INSIDE the WithTransaction above,
	// alongside the CreateUser write — see the fix/create-ops-atomicity comment there.

	return createdUser, nil
}

// maxUserCreateAssignments bounds how many project-scoped role assignments a
// single CreateUserWithAssignments call may carry. Each entry costs at least
// one GetRole/rolePermissionNameSet round trip via
// requireGrantSetNoSoDViolation's SoD evaluation below; an unbounded
// assignments list submitted in one request is a per-request
// resource-exhaustion vector, the same class of bug as
// maxBulkAccessRequestBatchSize (internal/core/bulk_access_requests.go).
const maxUserCreateAssignments = 500

// CreateUserWithAssignments creates a user and grants a system role plus a set of
// project-scoped roles in one transaction (ADR-028 atomic provisioning). All role
// names and project IDs are resolved and validated up front, so an invalid input
// fails before anything is written; a storage failure mid-way rolls everything
// back. systemRole defaults to system_viewer when empty.
//
// #480: this is InviteGlobal's sibling — both mint a system role plus a set of
// project assignments in one call, and both need the identical escalation-by-proxy
// ceiling (requireAuthorityForRole): the generic roles.assign permission that gates
// the HTTP/gRPC entry points is a plain, non-admin-gated permission grantable to
// any custom role, so without this check a non-admin roles.assign holder could
// mint a brand-new super_admin account directly — no invite/accept step an admin
// could notice or revoke in between, unlike InviteGlobal.
func (c *KeyorixCore) CreateUserWithAssignments(ctx context.Context, req *CreateUserRequest, systemRole string, assignments []ProjectAssignment, actorID uint, actorIsMachine bool) (*models.User, error) {
	if len(assignments) > maxUserCreateAssignments {
		return nil, fmt.Errorf("assignments exceeds the maximum batch size of %d", maxUserCreateAssignments)
	}
	user, hash, err := c.buildUserForCreate(ctx, req)
	if err != nil {
		return nil, err
	}

	// Resolve every grant before touching the database. Dedup by role+project so a
	// repeated assignment can't trip the unique constraint inside the transaction.
	grants := make([]storage.RoleGrant, 0, len(assignments)+1)
	seen := map[[2]uint]bool{}

	sysRole := systemRole
	if sysRole == "" {
		sysRole = "system_viewer"
	}
	sr, err := c.storage.GetRoleByName(ctx, sysRole)
	if err != nil {
		return nil, fmt.Errorf("%s: unknown role %q (system)", i18n.T("ErrorValidation", nil), sysRole)
	}
	// Escalation-by-proxy guard (#480), mirroring InviteGlobal (#231): a global
	// system role is the most powerful grant this flow can mint, so it needs the
	// same ceiling check requireGranterHoldsRolePermissions applies everywhere
	// else — the actor's real bundled permissions, not just the role's name —
	// at global scope (projectID 0).
	//
	// F6 sweep (2026-09-22): requireGranterHoldsRolePermissions's roles.assign
	// BASELINE deliberately does not apply when systemRole was left empty (the
	// caller never asked for a specific system role -- sysRole defaulted to
	// system_viewer above). That mandatory, non-discretionary default mirrors
	// plain CreateUser's own unconditional auto-assign (users.go): "create a
	// plain user" has always been gated by users.write alone. Only an
	// EXPLICITLY requested system role represents a real discretionary grant
	// the actor is choosing to make, so only that case needs roles.assign.
	if systemRole == "" {
		if err := c.requireGranterHoldsRolePermissionsNoBaseline(ctx, actorID, sr.ID, Scope{}, actorIsMachine); err != nil {
			return nil, err
		}
	} else if err := c.requireGranterHoldsRolePermissions(ctx, actorID, sr.ID, Scope{}, actorIsMachine); err != nil {
		return nil, err
	}
	addRoleGrant(&grants, seen, sr.ID, 0)

	for _, a := range assignments {
		g, err := c.resolveProjectRoleGrant(ctx, actorID, actorIsMachine, a)
		if err != nil {
			return nil, err
		}
		addRoleGrant(&grants, seen, g.RoleID, g.Scope.ProjectID)
	}

	// #419: the separation-of-duties preventive gate. A brand-new user has no
	// prior grants to check against (requireNoSoDViolation needs a user ID that
	// doesn't exist yet), so requireGrantSetNoSoDViolation instead evaluates
	// whether the FULL set of role grants landing atomically below would together
	// complete a policy — the same evasion this closes for an existing user's
	// individual grants, applied to "many roles minted for one brand-new user in
	// one call" instead.
	roleIDs := make([]uint, 0, len(grants))
	for _, g := range grants {
		roleIDs = append(roleIDs, g.RoleID)
	}
	if err := c.requireGrantSetNoSoDViolation(ctx, roleIDs); err != nil {
		return nil, err
	}

	created, err := c.storage.CreateUserWithRoleGrants(ctx, user, grants)
	if err != nil {
		// #117: same race/translation as CreateUser above — see its comment.
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("%w: user with email already exists", ErrUserAlreadyExists)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Best-effort password-history seed, after the atomic create (ADR-025).
	// Through besteffort.Run, exactly like CreateUser above: a bare `_ =`
	// discards the error but not a PANIC, which escaped past the committed
	// CreateUserWithRoleGrants and reported a created user as a failed request
	// (FuzzStorageFaultOperations: GRPC UserService.CreateUser,
	// AddPasswordHistory#1/panic, oracle (a), [User UserRole]).
	if c.passwordPolicy.HistoryCount > 0 {
		besteffort.Run(ctx, "users.CreateUserWithAssignments.AddPasswordHistory", func() error {
			return c.storage.AddPasswordHistory(ctx, created.ID, hash, c.now())
		})
	}

	c.LogUserCreated(ctx, actorID, created.ID, created.Username)
	return created, nil
}

// addRoleGrant deduplicates and appends a role grant. It is a package-level helper
// rather than a closure so it does not increase cognitive complexity of callers.
func addRoleGrant(grants *[]storage.RoleGrant, seen map[[2]uint]bool, roleID, projectID uint) {
	key := [2]uint{roleID, projectID}
	if seen[key] {
		return
	}
	seen[key] = true
	*grants = append(*grants, storage.RoleGrant{RoleID: roleID, Scope: storage.Scope{ProjectID: projectID}})
}

// resolveProjectRoleGrant validates and resolves a single ProjectAssignment into a
// storage.RoleGrant, enforcing the same authority-ceiling check as InviteGlobal.
func (c *KeyorixCore) resolveProjectRoleGrant(ctx context.Context, actorID uint, actorIsMachine bool, a ProjectAssignment) (storage.RoleGrant, error) {
	if a.ProjectID == 0 || a.Role == "" {
		return storage.RoleGrant{}, fmt.Errorf("%s: each project assignment needs a project_id and a role", i18n.T("ErrorValidation", nil))
	}
	if _, err := c.storage.GetProject(ctx, a.ProjectID); err != nil {
		return storage.RoleGrant{}, fmt.Errorf("%s: unknown project %d", i18n.T("ErrorValidation", nil), a.ProjectID)
	}
	r, err := c.storage.GetRoleByName(ctx, a.Role)
	if err != nil {
		return storage.RoleGrant{}, fmt.Errorf("%s: unknown role %q", i18n.T("ErrorValidation", nil), a.Role)
	}
	if err := c.requireGranterHoldsRolePermissions(ctx, actorID, r.ID, Scope{ProjectID: a.ProjectID}, actorIsMachine); err != nil {
		return storage.RoleGrant{}, err
	}
	return storage.RoleGrant{RoleID: r.ID, Scope: storage.Scope{ProjectID: a.ProjectID}}, nil
}

// ValidateRoleGrantAuthority checks that actorID has the authority to grant
// every role in grants and that the resulting grant set as a whole would not
// itself complete a separation-of-duties violation — the same two guards
// (requireAuthorityForRole per grant, requireGrantSetNoSoDViolation over the
// full set) CreateUserWithAssignments above applies to a human-supplied
// []ProjectAssignment. Was exposed for a caller that already had a resolved
// []storage.RoleGrant instead of role names — CreateUserWithRoleGrantsProxy,
// deleted along with the rest of the RemoteStorage-sync proxy tree (ADR-108
// Phase 6, #2162/#2171). No production caller currently reaches this method.
func (c *KeyorixCore) ValidateRoleGrantAuthority(ctx context.Context, actorID uint, actorIsMachine bool, grants []storage.RoleGrant) error {
	if len(grants) > maxUserCreateAssignments {
		return fmt.Errorf("%s: grants exceeds the maximum batch size of %d", i18n.T("ErrorValidation", nil), maxUserCreateAssignments)
	}
	// Baseline (F6 sweep, 2026-09-22): the loop below only ever calls
	// requireGranterHoldsRolePermissions for a grant that's actually IN the
	// list -- an empty grants slice (a legal request: "create this user,
	// no role grants yet") is zero iterations, so this function returned nil
	// unconditionally regardless of the caller's standing. This function's
	// one real caller (CreateUserWithRoleGrantsProxy) mints a brand-new,
	// fully-active user account -- the same authority the human-facing
	// POST /users route requires (users.write) unconditionally, independent
	// of how many grants (if any) accompany the create. Machine-actor
	// resolution mirrors requireGranterHoldsRolePermissions/
	// checkGranterHoldsPermission exactly: CreateUserWithRoleGrantsProxy
	// never tags ctx via WithSelfMachineGranter, so a machine caller here
	// fails closed, same as it always has for the per-grant loop below.
	selfMachineID, isSelfMachineGrant := uint(0), false
	if actorIsMachine {
		selfMachineID, isSelfMachineGrant = selfMachineGranterFromContext(ctx)
	}
	if ok, aerr := checkGranterHoldsPermission(ctx, c, actorID, "users.write", Scope{}, actorIsMachine, isSelfMachineGrant, selfMachineID); aerr != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", aerr)
	} else if !ok {
		return fmt.Errorf("creating a user with role grants requires the users.write permission")
	}
	roleIDs := make([]uint, 0, len(grants))
	for _, g := range grants {
		if _, err := c.storage.GetRole(ctx, g.RoleID); err != nil {
			return fmt.Errorf("%s: unknown role id %d", i18n.T("ErrorValidation", nil), g.RoleID)
		}
		if err := c.requireGranterHoldsRolePermissions(ctx, actorID, g.RoleID, Scope{ProjectID: g.Scope.ProjectID, EnvironmentID: g.Scope.EnvironmentID}, actorIsMachine); err != nil {
			return err
		}
		roleIDs = append(roleIDs, g.RoleID)
	}
	return c.requireGrantSetNoSoDViolation(ctx, roleIDs)
}

// GetUser retrieves a user by ID.
func (c *KeyorixCore) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// UpdateUser updates an existing user.
//
// req.ActorID is the caller making the change. A self-update (ActorID ==
// req.ID) may not deactivate its own account (ErrCannotActOnSelf) — mirrors
// DeleteUser/accountStateAction/RevokeUserSessions's existing self-action
// guards, which UpdateUser alone lacked (S1b, CLI-split inventory #2012) —
// but every other field remains self-updatable exactly as before. A
// different-target update is refused (ErrInsufficientAdminAuthority) unless
// the actor holds, at every scope, every permission the target already
// holds — see requireAdminRankCeilingForTarget's own doc for the exemptions
// (system/background callers, ActorID 0) and why. Before this, a principal
// holding only users.write (not global admin) could rewrite a
// HIGHER-privileged target's email/username or flip `active`, then pivot
// via password-reset/setup-token completion — the exact escalation the
// already-fixed /system sibling (UpdateUserIfActiveStateMatchesProxy) closed
// for its own callers but this, the primary human-facing route, never did
// (S1, CLI-split inventory #2012).
func (c *KeyorixCore) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*models.User, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	if err := c.validateUpdateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	if req.ActorID == req.ID && req.IsActive != nil && !*req.IsActive {
		return nil, ErrCannotActOnSelf
	}
	if req.ActorID != req.ID {
		if err := c.requireAdminRankCeilingForTarget(ctx, req.ActorID, req.ID, "modify"); err != nil {
			return nil, err
		}
	}
	user, err := c.storage.GetUser(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if req.Username != "" && req.Username != user.Username {
		foldedUsername, ferr := identity.NewFoldedName(req.Username)
		if ferr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
		}
		// #1642: a rename that only changes display form/case (folds to the
		// SAME identity the row already has, e.g. "Bob" -> "bob") must be a
		// no-op for the uniqueness check -- otherwise GetUserByUsername would
		// find this exact row under its own about-to-be-replaced folded value
		// and reject the rename as "already exists" against itself. Only a
		// genuine identity change needs the collision check.
		if foldedUsername.Folded() != user.UsernameFolded {
			if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
				return nil, fmt.Errorf("%w: username already exists", ErrUserAlreadyExists)
			} else if !storage.IsUserNotFound(err) {
				return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
			}
		}
		user.Username = req.Username
		user.UsernameFolded = foldedUsername.Folded()
	}
	if req.Email != "" && req.Email != user.Email {
		foldedEmail, ferr := identity.NewFoldedName(req.Email)
		if ferr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
		}
		if foldedEmail.Folded() != user.EmailFolded {
			existing, err := c.storage.GetUserByEmail(ctx, req.Email)
			if err == nil && existing != nil && existing.ID != user.ID {
				return nil, fmt.Errorf("%w: user with email already exists", ErrUserAlreadyExists)
			}
			if err != nil && !storage.IsUserNotFound(err) {
				return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
			}
		}
		user.Email = req.Email
		user.EmailFolded = foldedEmail.Folded()
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	wasActive := user.IsActive
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	deactivating := wasActive && !user.IsActive
	user.UpdatedAt = c.now()

	var sessionHashes []string
	if deactivating {
		// Collect session hashes before the write so we can evict the auth cache
		// after commit. The HTTP auth middleware caches validated tokens for up to
		// validTokenTTL (30s); without eviction a just-deactivated user's session
		// keeps passing auth for that window — same race SetAccountState already
		// handles on suspend/deactivate via the account-state path (#r124).
		sessionHashes, _ = c.storage.ListSessionTokenHashesForUser(ctx, req.ID)
	}

	var patHashes []string
	var updated *models.User
	switch {
	case deactivating:
		// req.IsActive != nil is implied here (deactivating can only be true if
		// the request actually mutated user.IsActive from wasActive), so the
		// final persist must go through the conditional write — a plain
		// c.storage.UpdateUser here would silently clobber (or be clobbered by)
		// a concurrent IsActive flip on the same user with no error to either
		// caller (see UpdateUserIfActiveStateMatches's doc, storage/interface.go).
		//
		// #1646: the last-admin guard check (moved here, from before this switch)
		// and the deactivating write below must be serialized under the SAME lock
		// acquisition, across every replica of an HA deployment — two concurrent
		// UpdateUser deactivations of two DIFFERENT admins could otherwise each
		// observe "another admin survives" and both proceed, jointly stranding the
		// install with zero admins. See lastAdminGuardLockKey's doc comment
		// (account_state.go).
		err = c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
			if err := c.guardLastAdminDeactivation(ctx, req.ID); err != nil {
				return err
			}
			return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
				matched, terr := tx.UpdateUserIfActiveStateMatches(ctx, user, wasActive)
				if terr != nil {
					return terr
				}
				if !matched {
					return fmt.Errorf("user %d: %w", req.ID, ErrUserActiveStateConflict)
				}
				updated = user
				var patErr, sessionErr error
				var hashes []string
				hashes, patErr = tx.RevokeAllPersonalAccessTokensForUser(ctx, req.ID)
				if patErr == nil {
					patHashes = hashes
				}
				sessionErr = tx.DeleteSessionsForUserExcept(ctx, req.ID, 0)
				// Best-effort, not fatal: the conditional write this switch case
				// exists for (UpdateUserIfActiveStateMatches) has ALREADY matched
				// and applied by this point -- the deactivation itself durably
				// succeeded. Letting a revocation failure here fail the whole
				// WithTransaction call would report total failure for an
				// operation that, from the target user's perspective, already
				// happened. This matters most over storage.type: remote, where
				// WithTransaction provides NO real atomicity at all (each
				// sub-call is its own independent HTTP round-trip -- see
				// remote_transaction.go) -- treating this as fatal there could
				// never have rolled the deactivation back anyway, only hidden
				// that it succeeded behind a misleading error.
				//
				// Safe specifically because a failed revocation does NOT leave a
				// working credential: ValidateSessionToken (auth.go) and
				// ValidatePATToken (pat.go) BOTH independently re-check the live
				// user.IsActive/AccountLoginBlocked state on every single use of
				// a session or PAT, cold path AND the 30s warm auth-cache path
				// (via AccountStillUsable, server/middleware/auth.go's
				// serveAuthCacheHit) -- already-committed IsActive=false alone
				// blocks the credential regardless of whether its row was ever
				// deleted. There is no session-expiry sweeper in this codebase
				// (CleanupExpiredSessions is implemented but never scheduled), so
				// a row a failed revocation leaves behind lingers indefinitely --
				// but inertly: it authorizes nothing. The residual cost is
				// orphaned-row hygiene and forensic noise, not a live credential,
				// which is why this is audited (right below) rather than merely
				// swallowed.
				if patErr != nil || sessionErr != nil {
					// nil actor: UpdateUser (unlike DeleteUser/SetAccountState) takes
					// no actorID parameter at all -- a pre-existing gap in this
					// function's own signature, not something this fix should
					// silently paper over with a fabricated attribution.
					c.writeAuditEventFailed(ctx, EventUserDeactivationCleanupFailed, nil, nil, "",
						fmt.Sprintf("user %d deactivated, but credential cleanup was incomplete (pat_error=%v, session_error=%v) -- "+
							"the account is already login-blocked regardless, but a stale row may remain until its own expiry",
							req.ID, patErr, sessionErr))
				}
				return nil
			})
		})
	case req.IsActive != nil:
		// Not deactivating (either re-activating, or a redundant "set to the same
		// value" call) but the request still explicitly asserts IsActive — same
		// TOCTOU exposure as the deactivating branch above, just without the
		// session/PAT revocation side effects.
		var matched bool
		matched, err = c.storage.UpdateUserIfActiveStateMatches(ctx, user, wasActive)
		if err == nil {
			if !matched {
				err = fmt.Errorf("user %d: %w", req.ID, ErrUserActiveStateConflict)
			} else {
				updated = user
			}
		}
	default:
		// No active-state assertion in this request, but a plain c.storage.UpdateUser
		// (unconditional Save) is still a check-then-act race against any concurrent
		// IsActive flip observed between the GetUser above and this write — same
		// TOCTOU shape as the two branches above, just asserting the unchanged
		// wasActive value as the precondition instead of a new one.
		var matched bool
		matched, err = c.storage.UpdateUserIfActiveStateMatches(ctx, user, wasActive)
		if err == nil {
			if !matched {
				err = fmt.Errorf("user %d: %w", req.ID, ErrUserActiveStateConflict)
			} else {
				updated = user
			}
		}
	}
	if err != nil {
		if errors.Is(err, ErrUserActiveStateConflict) {
			return nil, err
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if deactivating {
		c.invalidateTokenCache(sessionHashes...)
		c.invalidateTokenCache(patHashes...)
	}
	c.writeAuditEvent(ctx, EventUserUpdated, actorPtr(req.ActorID), nil,
		fmt.Sprintf("updated user %d (%s)", updated.ID, updated.Username))
	return updated, nil
}

// EventUserDeleted/EventUserRestored are audited on the admin delete/restore path
// (distinct from SCIM's own scim.user_deprovisioned/scim.user_reactivated events).
const (
	EventUserDeleted  = "user.deleted"
	EventUserRestored = "user.restored"
)

// EventAdminRankCeilingRefused is audited (Success=false) whenever
// requireAdminRankCeilingForTarget refuses a caller — the detection signal
// ADR-102's "alerting on the audit stream for anomalous activity" position
// depends on: a refusal here means someone holding users.write (or the
// operation's equivalent gate) but not global admin just attempted to modify,
// deactivate, delete, restore, or revoke credentials for a HIGHER-privileged
// account. S1, CLI-split inventory #2012.
const EventAdminRankCeilingRefused = "user.admin_rank_ceiling_refused"

// EventUserDeactivationCleanupFailed is audited (Success=false) when
// UpdateUser's deactivating branch's PAT/session revocation is incomplete —
// see that branch's own comment for why this is best-effort rather than
// fatal to the deactivation itself, and why a failure here doesn't leave a
// working credential (ValidateSessionToken/ValidatePATToken's live
// user.IsActive/AccountLoginBlocked re-check already blocks it). This event
// exists purely for discoverability: with no session-expiry sweeper in this
// codebase, a row a failed revocation leaves behind is inert but otherwise
// invisible until an operator goes looking for it.
const EventUserDeactivationCleanupFailed = "user.deactivation_cleanup_failed"

// RevokeUserCredentialsForDeactivation performs the SAME mandatory PAT/session
// revocation UpdateUser's own local deactivating branch applies inline
// against storage directly (see that branch's comment) — a MANDATORY,
// already-decided consequence of a deactivation that has ALREADY been
// committed by the caller, not an independent action a caller is choosing to
// take on its own (that case is RevokeAllPersonalAccessTokensForUser/
// DeleteSessionsForUserExcept above, which correctly gate on
// requireUserCredentialsRevokeAuthority because there the revocation IS the
// whole ask). #1572: the /system UpdateUserIfActiveStateMatchesProxy handler
// used to call THOSE ceiling-gated wrappers for its own post-deactivation
// cleanup — any caller reaching that route without users.write (the route's
// own gate is the broader, non-project-scoped system.write every /system
// proxy accepts, not users.write specifically) would have the deactivation
// itself succeed while this cleanup silently failed the ceiling check and
// was swallowed as "best-effort." Calling storage directly here, exactly as
// UpdateUser's local branch does, removes the inappropriate re-authorization
// instead of threading it through — the deactivation decision was already
// authorized (or not) upstream of this call by whatever decided to persist
// IsActive=false; revocation is not a second decision.
//
// Session-cache eviction is unconditional: sessionHashes is collected BEFORE
// the revocation attempt (mirroring UpdateUser exactly) so the up-to-30s
// warm-auth-cache window (server/middleware/auth.go's serveAuthCacheHit)
// closes immediately regardless of whether the row deletion itself
// succeeds — a session already blocked by IsActive=false at the DB layer
// could otherwise still authenticate against a stale cache entry for that
// window. PAT-hash eviction remains conditional on the revoke call
// succeeding (it needs the returned hashes to know what to evict), matching
// UpdateUser's identical asymmetry — a row a failed revocation leaves behind
// is inert regardless (ValidatePATToken's live IsActive re-check blocks it),
// only the up-to-30s cache window differs, same tradeoff UpdateUser already
// accepts. Fire-and-forget: audits on failure, returns nothing, exactly like
// the code path it mirrors.
func (c *KeyorixCore) RevokeUserCredentialsForDeactivation(ctx context.Context, userID uint) {
	sessionHashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, userID)
	patHashes, patErr := c.storage.RevokeAllPersonalAccessTokensForUser(ctx, userID)
	sessionErr := c.storage.DeleteSessionsForUserExcept(ctx, userID, 0)
	c.invalidateTokenCache(sessionHashes...)
	if patErr == nil {
		c.invalidateTokenCache(patHashes...)
	}
	if patErr != nil || sessionErr != nil {
		c.writeAuditEventFailed(ctx, EventUserDeactivationCleanupFailed, nil, nil, "",
			fmt.Sprintf("user %d deactivated, but credential cleanup was incomplete (pat_error=%v, session_error=%v) — "+
				"the account is already login-blocked regardless, but a stale row may remain until its own expiry",
				userID, patErr, sessionErr))
	}
}

// DeleteUser deprovisions and soft-deletes a user by ID: blocks login
// (AccountDeprovisioned, mirroring DeprovisionSCIMUser), terminates every session,
// revokes every personal access token, and evicts them from the auth cache — then
// soft-deletes the record. Before this, only the row was soft-deleted: IsActive and
// AccountState were untouched and no session/PAT was revoked, leaving live
// credentials usable for up to the auth-cache TTL and, since nothing was actually
// revoked, indefinitely if the account was later restored (see RestoreUser).
// Refuses to deprovision the install's last global administrator
// (guardLastAdminDeactivation), same as SCIM DELETE. actorID is the acting admin
// (for the audit trail; 0 = no actor known, e.g. an unauthenticated internal caller
// — the audit event's UserID is then left nil rather than pointing at a nonexistent
// actor). A non-zero, non-self actorID must also hold the admin-rank ceiling
// requireAdminRankCeilingForTarget enforces — before this (S1 sweep, CLI-split
// inventory #2012) a users.delete holder with no other elevated authority could
// deprovision a HIGHER-privileged account with no check beyond the flat
// permission the HTTP router already required.
func (c *KeyorixCore) DeleteUser(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if actorID != id {
		if err := c.requireAdminRankCeilingForTarget(ctx, actorID, id, "delete"); err != nil {
			return err
		}
	}
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	// #1646: guardLastAdminDeactivation's read and the deactivating write below
	// must be serialized under the SAME lock acquisition, across every replica of
	// an HA deployment, not just within this process — previously
	// accountStateMu (an in-process sync.Mutex) alone let two concurrent DeleteUser
	// calls for two different admins each observe "not the last admin" and both
	// proceed on two different replicas, jointly stranding the install with zero
	// admins. See lastAdminGuardLockKey's doc comment (account_state.go).
	return c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
		if err := c.guardLastAdminDeactivation(ctx, id); err != nil {
			return err
		}
		user.IsActive = false
		if NormalizeAccountState(user.AccountState) != AccountSuspended {
			user.AccountState = AccountDeprovisioned
		}
		user.UpdatedAt = c.now()
		sessionHashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, id)
		var patHashes []string
		if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			if _, err := tx.UpdateUser(ctx, user); err != nil {
				return err
			}
			if err := tx.DeleteSessionsForUserExcept(ctx, id, 0); err != nil {
				return err
			}
			hashes, err := tx.RevokeAllPersonalAccessTokensForUser(ctx, id)
			if err != nil {
				return err
			}
			patHashes = hashes
			return tx.DeleteUser(ctx, id)
		}); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		c.invalidateTokenCache(sessionHashes...)
		c.invalidateTokenCache(patHashes...)
		c.writeAuditEvent(ctx, EventUserDeleted, actorPtr(actorID), nil,
			fmt.Sprintf("deleted user %d (%s)", id, user.Username))
		return nil
	})
}

// EventUserCredentialsRevoked is audited when an admin-driven bulk PAT/session
// revocation runs against a target user via RevokeAllPersonalAccessTokensForUser
// or DeleteSessionsForUserExcept below (the /system proxy layer's direct-caller
// path — server/http/handlers/users_credentials_proxy.go). #1530: for a
// node-credential caller these primitives are still reached via the raw
// storage passthrough with no audit event at all (the same node-relay
// actor-attribution gap #1530 tracks for the sibling /system proxies) — this
// event only covers the direct-caller half fixed here.
const EventUserCredentialsRevoked = "user.credentials_revoked"

// requireUserCredentialsRevokeAuthority is the shared ceiling for
// RevokeAllPersonalAccessTokensForUser/DeleteSessionsForUserExcept below.
//
// Derived, not chosen: core.UpdateUser and core.DeleteUser perform NO
// caller-authority check of their own on a deactivating transition (only
// guardLastAdminDeactivation, a target-state invariant with no actor
// parameter — see its doc in scim.go) — authority is enforced entirely by the
// HTTP layer, at RequirePermission(permUsersWrite) on PUT /api/v1/users/{id}
// (server/http/router.go) and identically on POST /api/v1/users/{id}/suspend.
// "users.write" at GLOBAL scope is therefore the actual ceiling that governs
// "who may deactivate a user" today. Revoking a user's live PATs/sessions is a
// sub-operation of that same action (core.UpdateUser's own deactivating
// branch already does both under a real local transaction — see
// UpdateUser/DeleteUser above), so it inherits that SAME ceiling here rather
// than the broader, differently-scoped system.write the /system route group
// otherwise blanket-gates on: looser would reopen exactly the bypass shape
// #1552 was filed for; stricter would refuse a caller the operation it
// belongs to already permits.
func (c *KeyorixCore) requireUserCredentialsRevokeAuthority(ctx context.Context, actorType string, actorID uint) error {
	allowed, err := c.AuthorizePrincipal(ctx, actorType, actorID, permUsersWrite, Scope{})
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !allowed {
		return fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "revoking a user's credentials requires users.write authority")
	}
	return nil
}

// RequireUsersWriteAuthority was the /system-proxy-layer export of
// requireUserCredentialsRevokeAuthority's exact ceiling, for a caller outside
// internal/core (server/http/handlers) that needed to re-derive the SAME
// "users.write at global scope" authority the human-facing PUT
// /api/v1/users/{id} route already requires before relaying a user-row
// mutation. Zero callers remain today: #F5's UpdateUserIfActiveStateMatchesProxy
// (users_active_transition_proxy.go), the /system active-transition proxy
// backing the now-deleted RemoteStorage's UpdateUserIfActiveStateMatches, is
// itself deleted along with the rest of that proxy tree (ADR-108 Phase 6) —
// another follow-up cleanup candidate, not removed here. It used to accept any
// caller holding only the /system route group's own blanket system.write
// gate, with no per-target authority check at all, letting a system.write-only
// principal rewrite ANY user's username/email/display_name/active state,
// including a global admin's. core.UpdateUser itself performs no
// caller-authority check either (see requireUserCredentialsRevokeAuthority's
// own doc) — "users.write" at global scope, enforced at the HTTP layer, is
// the real authority path this reuses, mirroring the same fix already applied
// to RevokeAllPersonalAccessTokensForUser/DeleteSessionsForUserExcept below.
func (c *KeyorixCore) RequireUsersWriteAuthority(ctx context.Context, actorType string, actorID uint) error {
	return c.requireUserCredentialsRevokeAuthority(ctx, actorType, actorID)
}

// RequireRolesAssignAuthority is the /system-proxy-layer export of a plain
// "does actorType/actorID hold roles.assign at scope" check, for a caller
// outside internal/core that needs to re-derive the SAME roles.assign
// authority a human-facing route already requires via RequirePermission(
// permRolesAssign) (global scope, e.g. POST /groups/{id}/restore) or
// RequireScopedPermission(permRolesAssign, projectScope) (project scope,
// e.g. POST /projects/{id}/break-glass/{id}/revoke, the access-review
// campaign/item routes, POST /projects/{id}/invitations/{id} revoke).
// Pass Scope{} for the global-scope form.
func (c *KeyorixCore) RequireRolesAssignAuthority(ctx context.Context, actorType string, actorID uint, scope Scope) error {
	allowed, err := c.AuthorizePrincipal(ctx, actorType, actorID, permRolesAssign, scope)
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !allowed {
		return fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "this operation requires roles.assign authority")
	}
	return nil
}

// RequireEqualOrGreaterAdminAuthority is the /system-proxy-layer export of
// requireEqualOrGreaterAdminAuthority (authz.go) — the admin-rank ceiling
// impersonation already uses, for a caller outside internal/core that needs
// the SAME ceiling on an action targeting another user's own account state
// (e.g. UpdateWebAuthnCredentialProxy disabling another user's passkey): a
// lower-privileged actor must not be able to touch a target who holds, at
// any scope, a permission the actor does not also hold.
func (c *KeyorixCore) RequireEqualOrGreaterAdminAuthority(ctx context.Context, actorID, targetID uint, action string) error {
	return c.requireEqualOrGreaterAdminAuthority(ctx, actorID, targetID, action)
}

// RevokeAllPersonalAccessTokensForUser authorizes, performs, and audits an
// admin-driven bulk PAT revocation for targetUserID — the /system proxy
// layer's direct-caller entry point (RevokeAllPersonalAccessTokensForUserProxy).
// See requireUserCredentialsRevokeAuthority for the ceiling this enforces.
func (c *KeyorixCore) RevokeAllPersonalAccessTokensForUser(ctx context.Context, actorType string, actorID, targetUserID uint) ([]string, error) {
	if err := c.requireUserCredentialsRevokeAuthority(ctx, actorType, actorID); err != nil {
		return nil, err
	}
	hashes, err := c.storage.RevokeAllPersonalAccessTokensForUser(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	c.invalidateTokenCache(hashes...)
	c.writeAuditEvent(ctx, EventUserCredentialsRevoked, actorPtr(actorID), nil,
		fmt.Sprintf("revoked all personal access tokens for %s", c.auditRef(ctx, c.storage, auditKindUser, targetUserID)))
	return hashes, nil
}

// DeleteSessionsForUserExcept authorizes, performs, and audits an admin-driven
// session termination for targetUserID (keeping exceptSessionID, if nonzero) —
// the /system proxy layer's direct-caller entry point
// (DeleteSessionsForUserExceptProxy). See requireUserCredentialsRevokeAuthority
// for the ceiling this enforces.
func (c *KeyorixCore) DeleteSessionsForUserExcept(ctx context.Context, actorType string, actorID, targetUserID, exceptSessionID uint) error {
	if err := c.requireUserCredentialsRevokeAuthority(ctx, actorType, actorID); err != nil {
		return err
	}
	sessionHashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, targetUserID)
	if err := c.storage.DeleteSessionsForUserExcept(ctx, targetUserID, exceptSessionID); err != nil {
		return err
	}
	c.invalidateTokenCache(sessionHashes...)
	c.writeAuditEvent(ctx, EventUserCredentialsRevoked, actorPtr(actorID), nil,
		fmt.Sprintf("deleted sessions for %s", c.auditRef(ctx, c.storage, auditKindUser, targetUserID)))
	return nil
}

// RestoreUser clears the deleted_at timestamp on a soft-deleted user and forces
// re-credentialing: the account comes back requiring a password reset rather than
// silently reactivating, since DeleteUser's revoked sessions/PATs are gone for good
// (hard-deleted/permanently revoked, not merely soft-deleted) and the old password
// may be stale after an offboarding. actorID is the acting admin (audit trail);
// a non-zero, non-self actorID must also hold the admin-rank ceiling
// requireAdminRankCeilingForTarget enforces (S1 sweep, CLI-split inventory
// #2012) -- restoring reinstates whatever role grants the account held at
// deletion, so this is exactly the same "reinstate a HIGHER-privileged
// account" shape UpdateUser/DeleteUser close. Checked against the target's
// CURRENT role grants (GetUserRoleScopes, via the ceiling helper), which
// exist independently of the user row's own soft-delete flag.
func (c *KeyorixCore) RestoreUser(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if actorID != id {
		if err := c.requireAdminRankCeilingForTarget(ctx, actorID, id, "restore"); err != nil {
			return err
		}
	}
	// RestoreUser (clears deleted_at) and the follow-up UpdateUser (sets IsActive/
	// AccountState) run in one transaction: previously sequential, a failure on the
	// second call left the user undeleted (visible in listings again) but in a
	// stale/inconsistent state — the caller sees an error and assumes nothing
	// happened, when in fact the undelete already landed.
	var user *models.User
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if terr := tx.RestoreUser(ctx, id); terr != nil {
			return terr
		}
		var gerr error
		user, gerr = tx.GetUser(ctx, id)
		if gerr != nil {
			return gerr
		}
		user.IsActive = true
		user.AccountState = AccountPasswordResetRequired
		user.UpdatedAt = c.now()
		_, uerr := tx.UpdateUser(ctx, user)
		return uerr
	})
	if err != nil {
		if storage.IsUserNotFound(err) {
			return fmt.Errorf("%s: user not found or not deleted", i18n.T("ErrorUserNotFound", nil))
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventUserRestored, actorPtr(actorID), nil,
		fmt.Sprintf("restored user %d (%s); password reset required", id, user.Username))
	return nil
}

// ListUsers lists users with filtering and pagination.
func (c *KeyorixCore) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	if filter == nil {
		filter = &storage.UserFilter{}
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.PageSize > 100 {
		filter.PageSize = 100
	}
	users, total, err := c.storage.ListUsers(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, total, nil
}

// GetUserByEmail retrieves a user by email address.
func (c *KeyorixCore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "email is required")
	}
	user, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username. Backs the GET
// /api/v1/users/by-username HTTP route (#505).
func (c *KeyorixCore) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if username == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "username is required")
	}
	user, err := c.storage.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// GetUserByExternalID retrieves a user by the IdP-assigned external id. Backs the
// GET /api/v1/users/by-external-id HTTP route (#505), for SSO/SCIM identity
// resolution.
func (c *KeyorixCore) GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error) {
	if externalID == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "external_id is required")
	}
	user, err := c.storage.GetUserByExternalID(ctx, externalID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// ── Validation ────────────────────────────────────────────────────────────────

func (c *KeyorixCore) validateCreateUserRequest(req *CreateUserRequest) error {
	if req.Username == "" {
		return fmt.Errorf("%s", i18n.T("LabelUsername", nil))
	}
	if err := validateUsernameFormat(req.Username); err != nil {
		return err
	}
	if req.Email == "" {
		return fmt.Errorf("%s", i18n.T("LabelEmail", nil))
	}
	if err := validateEmailFormat(req.Email); err != nil {
		return err
	}
	// DisplayName is optional at this layer (buildUserForCreate defaults it to
	// Username when blank) — only format-check it when the caller actually
	// supplied one, matching the HTTP path's required-at-the-request-body-level
	// semantics without re-imposing that requirement here.
	if req.DisplayName != "" {
		if err := validateDisplayNameFormat(req.DisplayName); err != nil {
			return err
		}
	}
	if req.Password == "" {
		return fmt.Errorf("%s", i18n.T("LabelPassword", nil))
	}
	return nil
}

func (c *KeyorixCore) validateUpdateUserRequest(req *UpdateUserRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("user ID is required")
	}
	// Username/Email/DisplayName are partial-update fields (UpdateUser only
	// applies a non-empty value; see the req.Username != "" / req.Email != "" /
	// req.DisplayName != "" guards below in UpdateUser) — an empty string means
	// "leave unchanged," not "clear the field," so only format-check a value
	// the caller actually supplied (G38: gRPC/CLI-embedded previously skipped
	// this check entirely, unlike the HTTP path's `omitempty,...` request-body
	// validate tags).
	if req.Username != "" {
		if err := validateUsernameFormat(req.Username); err != nil {
			return err
		}
	}
	if req.Email != "" {
		if err := validateEmailFormat(req.Email); err != nil {
			return err
		}
	}
	if req.DisplayName != "" {
		if err := validateDisplayNameFormat(req.DisplayName); err != nil {
			return err
		}
	}
	return nil
}
