// scim.go — SCIM 2.0 user provisioning (RFC 7644). An IdP (Okta/Entra) provisions,
// updates, deactivates, and deletes Keyorix users over /scim/v2 (see the SCIM
// handler + the static-token middleware). A SCIM userName is typically an email/UPN,
// which Keyorix usernames (alphanumeric) cannot hold verbatim, so a compliant
// username is DERIVED from the userName and the IdP's stable externalId is stored
// for reconciliation. Provisioned users have no usable password (a random,
// discarded one) — they authenticate via SSO or set a password out-of-band — and
// start in pending_first_login (or suspended when provisioned inactive).
package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	EventSCIMUserProvisioned   = "scim.user_provisioned"
	EventSCIMUserUpdated       = "scim.user_updated"
	EventSCIMUserDeprovisioned = "scim.user_deprovisioned"
)

var scimNonAlphanum = regexp.MustCompile(`[^a-z0-9]`)

// deriveSCIMUsername builds a unique alphanumeric username from a SCIM userName
// (typically an email/UPN): its local-part, lowercased and stripped to [a-z0-9],
// padded to the 3-char minimum, with a numeric suffix on collision.
func (c *KeyorixCore) deriveSCIMUsername(ctx context.Context, userName string) (string, error) {
	base := userName
	if i := strings.IndexByte(base, '@'); i > 0 {
		base = base[:i]
	}
	base = scimNonAlphanum.ReplaceAllString(strings.ToLower(base), "")
	if len(base) < 3 {
		base += "usr"
	}
	if len(base) > 40 {
		base = base[:40]
	}
	for i := range 1000 {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s%d", base, i)
		}
		_, err := c.storage.GetUserByUsername(ctx, candidate)
		if err == nil {
			continue // taken — try the next suffix
		}
		if storage.IsUserNotFound(err) {
			return candidate, nil // available
		}
		return "", err // a real lookup error
	}
	return "", fmt.Errorf("could not derive a unique username from %q", userName)
}

// randomPasswordHash mints a bcrypt hash of a random, discarded password so a
// provisioned account has no usable password until the user sets one.
func randomPasswordHash() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(b)), int(bcryptCost.Load()))
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// FindSCIMUser resolves a provisioned user by externalId first, then by email
// (SCIM userName). Returns (nil, nil) when neither matches — used by the handler to
// implement userName-filter reconciliation.
func (c *KeyorixCore) FindSCIMUser(ctx context.Context, externalID, email string) (*models.User, error) {
	if externalID != "" {
		if u, err := c.storage.GetUserByExternalID(ctx, externalID); err == nil {
			return u, nil
		} else if !storage.IsUserNotFound(err) {
			return nil, err
		}
	}
	if email != "" {
		if u, err := c.storage.GetUserByEmail(ctx, email); err == nil {
			return u, nil
		} else if !storage.IsUserNotFound(err) {
			return nil, err
		}
	}
	return nil, nil
}

// ProvisionSCIMUser creates a Keyorix user from a SCIM Create request. actorID is
// the SCIM principal (0 for the provisioner). It refuses a duplicate externalId or
// email.
func (c *KeyorixCore) ProvisionSCIMUser(ctx context.Context, actorID uint, userName, displayName, email, externalID string, active bool) (*models.User, error) {
	if userName == "" {
		return nil, fmt.Errorf("userName is required")
	}
	if email == "" {
		email = userName // SCIM userName is conventionally the email
	}
	// #3418: the sso: scheme is reserved for SSO identity bindings (ssoExternalID). A
	// SCIM-supplied one would mint an account scimOwned rejects (SCIM could never
	// deactivate or delete it again) and pre-bind an SSO identity. Refused before the
	// dedup lookup, so the answer does not depend on whether that binding exists.
	if strings.HasPrefix(externalID, ssoExternalIDScheme) {
		return nil, fmt.Errorf("externalId must not use the reserved %q scheme", ssoExternalIDScheme)
	}
	// ADR-022: the domain allowlist is an install-wide boundary on who may hold an
	// account at all, not just an invite-flow check — a SCIM directory sync from an
	// unapproved domain (e.g. a misconfigured/multi-tenant IdP) must not silently
	// mint an account either.
	if !c.domainAllowed(email) {
		return nil, fmt.Errorf("email domain is not on the allowlist")
	}
	// Fail CLOSED on a lookup error: swallowing it would let a transient DB error during
	// the dedup check fall through to CreateUser and mint a SECOND identity with the same
	// email (there is no DB-level email uniqueness), and SSO/SCIM resolve email via
	// first-match — so which physical account a login binds to would become ambiguous.
	existing, ferr := c.FindSCIMUser(ctx, externalID, email)
	if ferr != nil {
		return nil, fmt.Errorf("failed to check for an existing user: %w", ferr)
	}
	if existing != nil {
		return nil, fmt.Errorf("a user already exists for this externalId/email")
	}
	username, err := c.deriveSCIMUsername(ctx, userName)
	if err != nil {
		return nil, err
	}
	if displayName == "" {
		displayName = userName
	}
	hash, err := randomPasswordHash()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	now := c.now()
	state := AccountPendingFirstLogin
	if !active {
		state = AccountDeprovisioned
	}
	// #1642: SCIM-provisioned usernames/emails come from an external IdP and
	// bypass buildUserForCreate entirely, so they need their own fold here —
	// otherwise an IdP-asserted "Admin"/non-ASCII identity could collide with
	// (or duplicate) an existing account in a way neither uniqueness check
	// below would catch.
	foldedUsername, ferr := identity.NewFoldedName(username)
	if ferr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
	}
	foldedEmail, ferr := identity.NewFoldedName(email)
	if ferr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
	}
	// The user row and its baseline role grant run in one transaction — the same
	// "user created, then role assign fails, leaves a user with zero roles" bootstrap
	// shape #2295 fixes for first-boot; best-effort here meant a SCIM-provisioned user
	// could end up with no role at all, unable to do anything until an admin noticed
	// and manually granted one.
	var created *models.User
	err = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var cerr error
		created, cerr = tx.CreateUser(ctx, &models.User{
			Username: username, UsernameFolded: foldedUsername.Folded(),
			Email: email, EmailFolded: foldedEmail.Folded(), DisplayName: displayName,
			PasswordHash: hash, IsActive: active, AccountState: state, ExternalID: externalID,
			PasswordChangedAt: &now, CreatedAt: now, UpdatedAt: now,
		})
		if cerr != nil {
			return cerr
		}
		role, rerr := tx.GetRoleByName(ctx, "system_viewer")
		if rerr != nil {
			return fmt.Errorf("failed to resolve baseline role: %w", rerr)
		}
		return tx.AssignRole(ctx, created.ID, role.ID, Scope{})
	})
	if err != nil {
		// #117: the FindSCIMUser dedup check above races with a concurrent provision call
		// for the identical email — both can pass it before either commits. The DB-level
		// partial unique index catches the loser here and CreateUser wraps it in
		// ErrDuplicateEmail; surface the same clean error the dedup check above already
		// returns for the sequential case, instead of a raw constraint-violation message.
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("a user already exists for this externalId/email")
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventSCIMUserProvisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM provisioned user %d (username=%s, externalId=%q, active=%t)", created.ID, username, externalID, active))
	return created, nil
}

// scimOwned reports whether user is an account SCIM owns: it carries a stored
// externalId that SCIM set (ProvisionSCIMUser), as opposed to a native/local account
// (empty) or one the SSO sign-in path claimed (the "sso:<provider>:<sub>" scheme,
// ssoExternalIDScheme, written by resolveSSOUser/JIT provisioning). SCIM and SSO share
// the external_id column, so an ExternalID != "" test alone treated a native admin who
// merely signed in through SSO once as SCIM-managed (#3418). This is the ONLY
// definition of SCIM ownership; every SCIM entry point (read, list, update, delete,
// group membership) goes through it.
//
// UpdateSCIMUser and DeprovisionSCIMUser refuse to operate on an id that isn't
// SCIM-owned: the SCIM PUT/PATCH/DELETE endpoints take an arbitrary numeric id straight
// off the URL path with no check that it belongs to an account SCIM actually owns,
// so a valid (e.g. provisioning-only) SCIM bearer token could otherwise rewrite a
// NATIVE admin's email to a fresh attacker-controlled address (the existing
// same-email-collision guard only blocks an address already in use) and then claim
// the account via SSO/SAML email-fallback resolution — an account takeover reachable
// with no admin-console access at all (#120).
//
// Consequence, deliberate and conservative: an account the IdP JIT-provisioned through
// SSO carries the SSO scheme too, so SCIM does not manage it either. Accounts SCIM
// created keep their bare externalId and are unaffected.
func scimOwned(user *models.User) bool {
	return user.ExternalID != "" && !strings.HasPrefix(user.ExternalID, ssoExternalIDScheme)
}

// IsSCIMManaged is scimOwned for callers outside this package (the SCIM HTTP handler's
// userName-filter path).
func IsSCIMManaged(user *models.User) bool {
	return scimOwned(user)
}

// UpdateSCIMUser applies a SCIM Replace/PATCH to a user: displayName, email, and the
// active flag. Deactivation marks the account deprovisioned (blocks login, terminates
// sessions); activation clears only a prior SCIM deactivation. An admin security
// suspension is sticky and survives IdP sync — only an admin can clear it
// (ReactivateUser), so routine SCIM traffic can't undo an incident-response lockout.
// nil fields are left unchanged. Refuses a target that isn't SCIM-managed
// (scimOwned) — checked against the fresh, lock-guarded read inside the
// transaction below, not a pre-fetch, so a TOCTOU can't let a target's SCIM
// management status change between the check and the write (#120).
//
// #344: the account_state/is_active mutation below races with setAccountState's (the
// admin SuspendUser/ReactivateUser/RequirePasswordReset actions) — a routine SCIM/IdP
// resync's read of the row can land before an admin's incident-response suspend
// commits, and this function's Save would otherwise silently overwrite it back with no
// error to either caller. It is serialized against setAccountState the same way
// setAccountState is: accountStateMu (whole read-modify-write, in-process) + a fresh
// LockUserForUpdate row lock (across replicas, Postgres only). See accountStateMu's doc
// comment in service.go and setAccountState in account_state.go.
func (c *KeyorixCore) UpdateSCIMUser(ctx context.Context, actorID, id uint, displayName, email *string, active *bool) (*models.User, error) {
	// #G14: the SCIM-ownership check runs FIRST, before checkSCIMEmailCollision
	// below — otherwise a SCIM token holder could supply an arbitrary id it has
	// no rights to touch (e.g. a native admin's) together with a probe email,
	// and learn from "email already in use" whether that email is registered to
	// a DIFFERENT account, without ever needing a target id it can legitimately
	// act on. This is a best-effort pre-check (matching DeprovisionSCIMUser's
	// own GetUser+scimOwned pattern) — scimUpdateUserTx below still re-checks
	// scimOwned against the fresh, lock-guarded read for the authoritative,
	// race-free decision.
	target, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if !scimOwned(target) {
		return nil, fmt.Errorf("%s: not a SCIM-managed account", i18n.T("ErrorUserNotFound", nil))
	}
	// Refuse an email that collides with a DIFFERENT user (#336). Checked up front
	// (against id, not a pre-fetched struct) since it targets a DIFFERENT user's row
	// and doesn't need the account-state lock below. The DB partial unique index
	// (uniq_users_email_active, #117) is the backstop against the residual race.
	if err := c.checkSCIMEmailCollision(ctx, id, email); err != nil {
		return nil, err
	}
	// #G03: guardLastAdminDeactivation's read and this function's write must be
	// serialized under the SAME lock acquisition — checked BEFORE accountStateMu.Lock()
	// (as it used to be), two concurrent deactivations of two different admins could
	// each observe "not the last admin" (the other hasn't been deactivated yet) and
	// both proceed, jointly stranding the install with zero admins. Locking first
	// makes the check-then-act atomic against every other accountStateMu-guarded path
	// (SuspendUser, DeleteUser, DeprovisionSCIMUser).
	//
	// GUARD-2: accountStateMu alone only ever serialized this against the OTHER
	// paths within the SAME process — cross-replica-unsafe the moment an HA
	// deployment routes two concurrent SCIM deactivations of two different admins
	// to two different replicas (scim.go's own prior header comment named this
	// exact gap as deliberately deferred). storage.WithNamedLock(lastAdminGuardLockKey)
	// is the SAME Postgres advisory lock SuspendUser/UpdateUser/DeleteUser already
	// take for this guard (account_state.go, users.go) — wrapping accountStateMu's
	// critical section in it (nested, same composition order SuspendUser already
	// uses via setAccountState) closes the cross-replica gap without touching the
	// in-process #344 clobber-protection accountStateMu still provides.
	var deactivated bool
	var updated *models.User
	var patHashes []string // PATs revoked by a deactivation; evicted from the auth cache after commit
	var guardErr error     // guardLastAdminDeactivation's own error, returned verbatim below — never wrapped as a storage failure
	lockErr := c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
		c.accountStateMu.Lock()
		defer c.accountStateMu.Unlock()
		if active != nil && !*active {
			// Don't let a routine (or hostile) SCIM sync deactivate the only admin.
			if err := c.guardLastAdminDeactivation(ctx, id); err != nil {
				guardErr = err
				return err
			}
		}
		// A fresh, lock-guarded read inside the transaction: never reuse a struct fetched
		// before the lock above was taken — a concurrent setAccountState commit between
		// that read and this write would be silently clobbered (the exact #344 race).
		return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			var err error
			updated, deactivated, patHashes, err = c.scimUpdateUserTx(ctx, tx, id, displayName, email, active)
			return err
		})
	})
	if guardErr != nil {
		return nil, guardErr
	}
	if lockErr != nil {
		if errors.Is(lockErr, storage.ErrUserNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), lockErr)
		}
		// #120/#218: email-uniqueness check races with a concurrent update — DB partial
		// unique index catches the loser and wraps it in ErrDuplicateEmail.
		if errors.Is(lockErr, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("%s: email already in use by another user", i18n.T("ErrorValidation", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), lockErr)
	}
	if deactivated {
		// Suspension must be effective immediately — terminate sessions AND evict from
		// auth cache so an offboarded user doesn't keep access for the cache TTL.
		_ = c.deleteSessionsForUserAndEvict(ctx, id, 0, "")
		purgeStepUpGrants(ctx, c.storage, id)
		c.invalidateTokenCache(patHashes...)
	}
	c.writeAuditEvent(ctx, EventSCIMUserUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM updated user %d", id))
	return updated, nil
}

// checkSCIMEmailCollision refuses an email that is already in use by a DIFFERENT user.
// #336: distinguishes "email unused" from "DB failure" — fail CLOSED on any error
// that is not the not-found sentinel, rather than silently proceeding.
func (c *KeyorixCore) checkSCIMEmailCollision(ctx context.Context, id uint, email *string) error {
	if email == nil || *email == "" {
		return nil
	}
	existing, eerr := c.storage.GetUserByEmail(ctx, *email)
	switch {
	case eerr == nil:
		if existing != nil && existing.ID != id {
			return fmt.Errorf("%s: email already in use by another user", i18n.T("ErrorValidation", nil))
		}
	case storage.IsUserNotFound(eerr):
		// Genuinely unused — proceed.
	default:
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), eerr)
	}
	return nil
}

// scimUpdateUserTx executes the locked read-modify-write inside the transaction.
// Returns (updated user, whether the user was deactivated, error).
func (c *KeyorixCore) scimUpdateUserTx(ctx context.Context, tx storage.Storage, id uint, displayName, email *string, active *bool) (*models.User, bool, []string, error) {
	user, err := tx.LockUserForUpdate(ctx, id)
	if err != nil {
		return nil, false, nil, err
	}
	if !scimOwned(user) {
		return nil, false, nil, storage.ErrUserNotFound
	}
	// Captured before mutation so we only call SetAccountState when the state actually
	// changes (#454), avoiding an unnecessary write for a plain name/email PATCH that
	// never touches lifecycle state.
	origState := user.AccountState
	wasActive := user.IsActive
	if displayName != nil && *displayName != "" {
		user.DisplayName = *displayName
	}
	if email != nil && *email != "" {
		// #1642: keep EmailFolded in lockstep with Email on every write path,
		// not just core.UpdateUser's -- a stale EmailFolded here would make
		// GetUserByEmail keep resolving to the user's OLD address forever.
		folded, ferr := identity.NewFoldedName(*email)
		if ferr != nil {
			return nil, false, nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
		}
		user.Email = *email
		user.EmailFolded = folded.Folded()
	}
	deactivated := false
	applySCIMActiveState(user, active, &deactivated)
	if user.AccountState != origState {
		// #454: persist the state transition FIRST and abort if the backend can't —
		// prevents a false "success" that leaves login-blocking state silently unchanged.
		// C-RACE-FIX-B2: conditional on origState, the value applySCIMActiveState
		// derived the new state from. UpdateUserIfActiveStateMatches below writes
		// only the profile columns (#2653/#2654), so this is the ONLY write of
		// account_state here, and a blind one would revert a SuspendUser that
		// committed after the read above in the #G42 window (or anywhere the row
		// lock is not held): a reactivation would turn that suspension into active.
		matched, err := tx.SetAccountStateIfMatches(ctx, id, origState, user.AccountState, c.now())
		if err != nil {
			return nil, false, nil, err
		}
		if !matched {
			return nil, false, nil, fmt.Errorf("user %d: %w", id, ErrUserAccountStateConflict)
		}
	}
	user.UpdatedAt = c.now()
	// #G42: LockUserForUpdate above only takes a real row lock on Postgres: on
	// SQLite (this codebase's default embedded deployment) a deferred
	// transaction doesn't acquire its exclusive write lock until the FIRST
	// write statement, leaving a window between this read and that first
	// write where a concurrent, un-transacted core.UpdateUser call can commit
	// its own IsActive flip via UpdateUserIfActiveStateMatches. A blind
	// tx.UpdateUser here would silently revert that flip using the
	// now-stale in-memory user struct. Route through the same
	// state-conditional write core.UpdateUser itself uses instead.
	matched, err := tx.UpdateUserIfActiveStateMatches(ctx, user, wasActive)
	if err != nil {
		return nil, false, nil, err
	}
	if !matched {
		return nil, false, nil, fmt.Errorf("user %d: %w", id, ErrUserActiveStateConflict)
	}
	// #3419: a deactivation revokes the user's PATs in this same transaction, as
	// DeprovisionSCIMUser does (#2855). A surviving PAT is inert while the account is
	// deactivated, but ReactivateUser and an IdP active=true revoke nothing, so an
	// unrevoked row would authenticate again on re-enable. The hashes go back to the
	// caller for the post-commit auth-cache eviction.
	var patHashes []string
	if deactivated {
		patHashes, err = tx.RevokeAllPersonalAccessTokensForUser(ctx, id)
		if err != nil {
			return nil, false, nil, err
		}
	}
	return user, deactivated, patHashes, nil
}

// applySCIMActiveState applies an IdP active=true/false directive to the user model,
// preserving any admin-set state (suspension, password-reset-required, etc.) through
// the deactivate→reactivate cycle.
func applySCIMActiveState(user *models.User, active *bool, deactivated *bool) {
	if active == nil {
		return
	}
	user.IsActive = *active
	if *active {
		// Reactivation clears only a SCIM/IdP deactivation (AccountDeprovisioned).
		// An admin security suspension (AccountSuspended) is sticky: routine IdP sync
		// re-sends active=true for every active user and must not undo an
		// incident-response lockout — only an admin clears that via ReactivateUser.
		if NormalizeAccountState(user.AccountState) == AccountDeprovisioned {
			user.AccountState = AccountActive
		}
	} else {
		// Mark the SCIM/IdP deactivation distinctly so a later reactivation can tell
		// it from an admin-set state. Only an 'active' account moves to deprovisioned:
		// admin-set states (suspended, password_reset_required, pending_first_login)
		// are preserved so a routine deactivate→reactivate can't silently clear them.
		// Login is blocked immediately by IsActive=false regardless of which state is
		// retained.
		if NormalizeAccountState(user.AccountState) == AccountActive {
			user.AccountState = AccountDeprovisioned
		}
		*deactivated = true
	}
}

// guardLastAdminDeactivation refuses an operation that would deactivate/deprovision the
// only remaining install administrator, so a routine or hostile SCIM push — or an admin
// DeleteUser call (core.DeleteUser shares this guard) — can't lock everyone out.
//
// Uses resolveGlobalAdminHolders (the same group-membership-aware resolver
// guardLastGlobalAdminGroupDelete/guardLastGlobalAdminMembership use), excluding
// targetID both as a direct grant holder and as a group member — NOT the previous
// per-assignment scan, which treated ANY admin-conferring group assignment as
// "another admin survives" without checking whether targetID was that group's only
// member. A target whose sole route to admin authority is membership in a
// single-member admin group was therefore never recognized as the last admin.
//
// #1646 SCOPE NOTE: SuspendUser, UpdateUser, and DeleteUser (the direct
// user-facing API) now wrap their call to this guard, plus the deactivating
// write that follows it, in storage.WithNamedLock(lastAdminGuardLockKey, ...) --
// a Postgres advisory lock that serializes the check-then-act sequence across
// every replica of an HA deployment, not just within one process. The three
// SCIM callers below (UpdateSCIMUser, the deactivate helper at line ~460, and
// DeprovisionSCIMUser) still rely on accountStateMu ALONE -- an in-process
// mutex, cross-replica-safe only if a real multi-instance-Postgres deployment
// never routes two concurrent SCIM syncs for two different admins to two
// different replicas. That gap was deliberately left open in this pass (their
// larger, more deeply nested transaction bodies made a safe mechanical
// WithNamedLock wrap higher-risk to land alongside the direct-API fix within
// the same change) -- filed as an explicit follow-up, not silently carried
// forward as already covered.
func (c *KeyorixCore) guardLastAdminDeactivation(ctx context.Context, targetID uint) error {
	// targetHasGlobalAdminRole, not IsGlobalAdmin: this asks whether targetID
	// is an admin, not whether the acting caller is — see targetHasGlobalAdminRole's
	// doc comment (internal/core/authz.go) for the confused-deputy this avoids.
	isAdmin, err := c.targetHasGlobalAdminRole(ctx, targetID)
	if err != nil {
		// #337: "can't tell" is NOT the same as "confirmed not an admin". The previous
		// code treated an IsGlobalAdmin lookup error identically to a confirmed non-admin
		// (both fell through to `return nil`, permitting the deactivation/deprovision),
		// silently disabling the last-admin lockout guard on exactly the failure mode (a
		// DB hiccup, or connection-pool exhaustion an attacker could induce) it exists to
		// protect against — the opposite of the fail-safe behaviour this guard is meant to
		// provide. Fail CLOSED: refuse the operation rather than risk stranding the
		// install with zero admins.
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if !isAdmin {
		return nil // confirmed not an admin — not the last-admin case
	}
	adminIDs, err := c.adminBypassRoleIDSet(ctx)
	if err != nil {
		// #2496, same stance as the targetHasGlobalAdminRole error above: "can't
		// tell which roles are admin-conferring" must not silently become "there
		// are none", which would disable this guard entirely.
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, adminIDs, assignments,
		func(a storage.RoleAssignment) bool { return a.PrincipalType == "user" && a.PrincipalID == targetID },
		func(_, userID uint) bool { return userID == targetID },
	)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if len(holders) == 0 {
		return fmt.Errorf("refusing to deactivate the last install administrator")
	}
	return nil
}

// GuardLastAdminDeactivation is guardLastAdminDeactivation, exported for
// UpdateUserIfActiveStateMatchesProxy (server/http/handlers/users_active_transition_proxy.go,
// deleted along with the rest of the /system tier, ADR-108, and with it this
// method's only caller -- zero production callers remain today, another
// follow-up cleanup candidate, not removed here) -- the raw-storage /system
// proxy behind UpdateUserIfActiveStateMatches never called this guard at all
// before the G80 overnight campaign's Tier 1 Group A fix #3, meaning a caller
// could deactivate the install's last global admin through that route with no
// lockout protection. The guard depended only on targetID (this function
// takes no actor parameter, by design -- it's a target-state invariant, not a
// caller-authority check), so it needed no RemoteStorage wire-protocol change
// to close.
func (c *KeyorixCore) GuardLastAdminDeactivation(ctx context.Context, targetID uint) error {
	return c.guardLastAdminDeactivation(ctx, targetID)
}

// DeprovisionSCIMUser handles a SCIM DELETE: it deprovisions the user (blocks login,
// terminates sessions) and soft-deletes the record, so the account is recoverable
// within the retention window rather than hard-destroyed. Refuses a target that
// isn't SCIM-managed (scimOwned) — a valid SCIM token must not be able to
// deprovision an arbitrary native account it never provisioned.
func (c *KeyorixCore) DeprovisionSCIMUser(ctx context.Context, actorID, id uint) error {
	// Best-effort pre-check only (matching UpdateSCIMUser's identical pre-fetch, #120):
	// the authoritative scimOwned decision is re-made below against the fresh,
	// lock-guarded read inside the transaction, not this struct.
	precheck, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if !scimOwned(precheck) {
		return fmt.Errorf("%s: not a SCIM-managed account", i18n.T("ErrorUserNotFound", nil))
	}
	// #G03: guardLastAdminDeactivation's read is serialized against every other
	// accountStateMu-guarded admin-deactivation path (UpdateSCIMUser, DeleteUser,
	// SuspendUser) — see UpdateSCIMUser's identical comment above. Previously this
	// function held no lock at all, so it raced not just with itself but with every
	// sibling path too.
	//
	// GUARD-2: as in UpdateSCIMUser above, accountStateMu alone is cross-replica-unsafe
	// — wrap it in storage.WithNamedLock(lastAdminGuardLockKey), the same lock
	// SuspendUser/UpdateUser/DeleteUser already take for this exact guard.
	var sessionHashes []string
	var username string
	var guardErr error
	lockErr := c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
		c.accountStateMu.Lock()
		defer c.accountStateMu.Unlock()
		// Don't let a SCIM DELETE deprovision the only admin and lock the install out.
		if err := c.guardLastAdminDeactivation(ctx, id); err != nil {
			guardErr = err
			return err
		}
		// Capture the user's session-token hashes BEFORE the transaction so they can be
		// evicted from the auth cache after commit (the stored token is the SHA-256 cache key).
		sessionHashes, _ = c.storage.ListSessionTokenHashesForUser(ctx, id)
		// Suspend + terminate sessions + soft-delete atomically: a SCIM DELETE either fully
		// deprovisions or leaves the account untouched, so a mid-way storage failure can't
		// leave it half-deprovisioned (suspended but not deleted), which would make retries
		// non-idempotent.
		return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			// Re-read the row via a locked read INSIDE the transaction, immediately before
			// the write, instead of reusing the struct captured by the unlocked GetUser
			// above — a concurrent state-changing write (e.g. SuspendUser, or another
			// accountStateMu-guarded action that landed between that read and here) would
			// otherwise be silently clobbered by a blind write of the stale struct.
			// Mirrors scimUpdateUserTx/setAccountState's locked-read-then-selective-write
			// pattern (both in this package) rather than scimUpdateUserTx's own #G42
			// caveat: everything from here to the write below runs while accountStateMu is
			// still held, so this fresh read can't itself go stale before it's persisted.
			user, err := tx.LockUserForUpdate(ctx, id)
			if err != nil {
				return err
			}
			if !scimOwned(user) {
				return storage.ErrUserNotFound
			}
			username = user.Username
			origState := user.AccountState
			wasActive := user.IsActive
			user.IsActive = false
			// Mark as SCIM-deprovisioned rather than admin-suspended, but never downgrade an
			// existing admin security suspension — evaluated against the FRESH state so a
			// suspension that committed after the pre-check above isn't lost. The user is
			// soft-deleted below regardless, so this only affects the state on the
			// recoverable record.
			if NormalizeAccountState(user.AccountState) != AccountSuspended {
				user.AccountState = AccountDeprovisioned
			}
			user.UpdatedAt = c.now()
			if user.AccountState != origState {
				// #454: persist the state transition via the narrow column-only write (not
				// folded into the profile-column write below, which never writes
				// account_state, #2653/#2654). C-RACE-FIX-B2: conditional on origState —
				// the value the "never downgrade a suspension" check above was evaluated
				// against — so a suspension that commits after that read is refused here
				// rather than overwritten with deprovisioned.
				matched, err := tx.SetAccountStateIfMatches(ctx, id, origState, user.AccountState, user.UpdatedAt)
				if err != nil {
					return err
				}
				if !matched {
					return fmt.Errorf("user %d: %w", id, ErrUserAccountStateConflict)
				}
			}
			// Persist IsActive (and the other profile columns) via the same conditional
			// write every other IsActive-flipping path in this package uses, rather than a
			// blind tx.UpdateUser: succeeds only if the row's current is_active still
			// matches wasActive, which — since user was just read under LockUserForUpdate
			// while accountStateMu is held — should always hold true here; a false match
			// means a non-accountStateMu-guarded write raced in, and must surface as a
			// conflict rather than being silently overwritten or retried.
			matched, err := tx.UpdateUserIfActiveStateMatches(ctx, user, wasActive)
			if err != nil {
				return err
			}
			if !matched {
				return fmt.Errorf("user %d: %w", id, ErrUserActiveStateConflict)
			}
			if err := tx.DeleteSessionsForUserExcept(ctx, id, 0); err != nil {
				return err
			}
			// #2855: revoke the user's PATs too. This path swept sessions only,
			// unlike every other deprovisioning path (setAccountState's
			// blocked-state branch, DeleteUser, RevokeUserCredentialsForDeactivation),
			// all of which revoke both. A surviving PAT is inert while the account
			// is deprovisioned — ValidatePATToken re-checks is_active and the
			// account state — but nothing on the way back revokes it:
			// ReactivateUser and RestoreUser deliberately revoke nothing, on the
			// assumption the deprovision already did. So an IdP offboard followed
			// by a restore handed every PAT back, possibly with no expiry, after an
			// audit trail that recorded a completed deprovision.
			//
			// In the same transaction as the rest, so a SCIM DELETE stays
			// all-or-nothing (see this function's own doc comment); the hashes are
			// folded into sessionHashes for the post-commit cache eviction below,
			// so a cached PAT stops authenticating immediately rather than
			// lingering for the auth-cache TTL.
			patHashes, err := tx.RevokeAllPersonalAccessTokensForUser(ctx, id)
			if err != nil {
				return err
			}
			sessionHashes = append(sessionHashes, patHashes...)
			return tx.DeleteUser(ctx, id)
		})
	})
	if guardErr != nil {
		return guardErr
	}
	if lockErr != nil {
		if errors.Is(lockErr, storage.ErrUserNotFound) {
			return fmt.Errorf("%s: not a SCIM-managed account", i18n.T("ErrorUserNotFound", nil))
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), lockErr)
	}
	// Evict the terminated sessions from the auth cache AFTER commit, so a deprovisioned
	// (offboarded) user's live session stops authenticating immediately instead of
	// lingering for the cache TTL.
	c.invalidateTokenCache(sessionHashes...)
	purgeStepUpGrants(ctx, c.storage, id)
	c.writeAuditEvent(ctx, EventSCIMUserDeprovisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM deprovisioned user %d (%s)", id, username))
	return nil
}

// GetSCIMUser retrieves a user by ID for a SCIM GET, refusing (as the not-found
// sentinel) a target that isn't SCIM-managed (scimOwned) — closing the read-path
// half of the boundary UpdateSCIMUser/DeprovisionSCIMUser already enforce on write
// (#120). Before this, GET /scim/v2/Users/{id} called the generic core.GetUser (also
// used by the admin console and self-profile lookups) with no scimOwned check at
// all, so a valid SCIM bearer token could disclose ANY native (non-SCIM-managed)
// account's userName/email/displayName just by guessing/enumerating numeric ids
// (#G85). The handler maps this error to a generic SCIM 404 either way — same as a
// truly nonexistent id — so the response never confirms whether an out-of-scope id
// exists at all, matching SCIM convention for a resource outside the client's scope.
func (c *KeyorixCore) GetSCIMUser(ctx context.Context, id uint) (*models.User, error) {
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if !scimOwned(user) {
		return nil, fmt.Errorf("%s: not a SCIM-managed account", i18n.T("ErrorUserNotFound", nil))
	}
	return user, nil
}

// SCIMMaxPageSize bounds how many resources a single SCIM list page returns — the
// value advertised in ServiceProviderConfig (filter.maxResults). A larger requested
// count is clamped to it so an unfiltered list can't drain the whole directory into one
// response (memory + DB amplification).
const SCIMMaxPageSize = 200

// ListSCIMUsersPage returns one page of SCIM-managed users for a SCIM list, and the
// SCIM-managed total (not the full directory size). startIndex is 1-based (SCIM
// convention); count is clamped to [0, SCIMMaxPageSize] (count==0 returns no
// resources, just the total).
//
// Filtered to scimOwned (#G85): GET /scim/v2/Users previously enumerated the
// ENTIRE user directory — native, non-SCIM-managed accounts included — because
// storage.ListUsers/UserFilter has no externalId-presence filter and this method
// never applied one of its own, unlike UpdateSCIMUser/DeprovisionSCIMUser which
// already refuse a non-SCIM-managed target (#120). A leaked totalResults count was
// itself a smaller instance of the same disclosure, so it's fixed here too.
//
// Rather than add a filter to storage.UserFilter, this loads the full user list via
// ListSCIMUsers and filters/pages it in Go. That's the same "load once, filter/slice
// in memory" shape ListGroups' filtered path already uses for groups
// (scim_groups.go), at the cost of an O(directory size) scan per page instead of a
// DB-level LIMIT/OFFSET.
func (c *KeyorixCore) ListSCIMUsersPage(ctx context.Context, startIndex, count int) ([]*models.User, int, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 0
	}
	if count > SCIMMaxPageSize {
		count = SCIMMaxPageSize
	}
	allUsers, err := c.ListSCIMUsers(ctx)
	if err != nil {
		return nil, 0, err
	}
	managed := make([]*models.User, 0, len(allUsers))
	for _, u := range allUsers {
		if scimOwned(u) {
			managed = append(managed, u)
		}
	}
	total := len(managed)
	if count == 0 || startIndex > total {
		// SCIM count=0 (or a startIndex past the end) → return totalResults only.
		return []*models.User{}, total, nil
	}
	lo := startIndex - 1
	hi := min(lo+count, total)
	return managed[lo:hi], total, nil
}

// ListSCIMUsers returns users for a SCIM list, paging through all of them.
func (c *KeyorixCore) ListSCIMUsers(ctx context.Context) ([]*models.User, error) {
	const pageSize = 200
	var out []*models.User
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: pageSize})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		out = append(out, users...)
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}
	return out, nil
}
