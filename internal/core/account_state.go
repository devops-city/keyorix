// account_state.go — user account lifecycle state machine (ADR-025).
//
// States:
//
//	active                    — normal; full access.
//	pending_first_login       — provisioned by an admin; must set a password
//	                            before doing anything else (restricted session).
//	password_reset_required   — admin forced a reset; restricted until changed.
//	suspended                 — login is refused entirely (admin security action).
//	deprovisioned             — login is refused; set by SCIM/IdP deactivation. Kept
//	                            distinct from `suspended` so an IdP reactivation clears
//	                            only its own deactivation and can never undo an admin's
//	                            security suspension (incident response wins).
//
// A "restricted" session (pending_first_login / password_reset_required)
// authenticates but the auth middleware blocks every endpoint except the
// password-change / profile allowlist, returning 403 so the client redirects to
// change-password. Completing a password change clears the restriction back to
// active. Admin transitions are audited.
package core

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Account states.
const (
	AccountActive                = "active"
	AccountPendingFirstLogin     = "pending_first_login"
	AccountPasswordResetRequired = "password_reset_required"
	AccountSuspended             = "suspended"
	// AccountDeprovisioned is set by SCIM/IdP deactivation. It blocks login exactly
	// like AccountSuspended, but is a separate value so SCIM reactivation can clear it
	// without clearing an admin's (stronger, sticky) AccountSuspended. See UpdateSCIMUser.
	AccountDeprovisioned = "deprovisioned"
)

// NormalizeAccountState maps the empty legacy value to active.
func NormalizeAccountState(state string) string {
	if state == "" {
		return AccountActive
	}
	return state
}

// validAccountStates is the canonical ADR-025 set a caller may explicitly write.
// The empty string is separately accepted by IsValidAccountState — it is legacy
// shorthand for "unset", normalized to active by NormalizeAccountState — but is
// deliberately not in this map so callers that want the exact persisted set can
// use it directly.
var validAccountStates = map[string]bool{
	AccountActive:                true,
	AccountPendingFirstLogin:     true,
	AccountPasswordResetRequired: true,
	AccountSuspended:             true,
	AccountDeprovisioned:         true,
}

// IsValidAccountState reports whether state is the empty string (legacy "unset",
// normalized to active) or one of the ADR-025 canonical lifecycle values. Any other
// string (a typo, wrong casing, or arbitrary garbage) is not a value any code path
// in this codebase ever writes itself. #334 originally used this to validate gRPC
// CreateUser's account_state field before persisting it; #135 replaced that with
// ignoring the field entirely (mirroring the HTTP CreateUser handler, which never
// exposed it), so this validator no longer has a caller-controlled write path — kept
// for any future internal caller that needs to check a state before writing it.
func IsValidAccountState(state string) bool {
	return state == "" || validAccountStates[state]
}

// AccountRestricted reports whether a state forces a password change before the
// user may use any non-allowlisted endpoint.
//
// Fail-CLOSED default: an unrecognized state (default case below) is treated as
// restricted, not as active/unrestricted. This is the defense-in-depth backstop
// for #334 — IsValidAccountState now rejects a bad value at the one caller-
// controlled write path, but this function must still cope with an unrecognized
// value already sitting in the database (e.g. written before this fix shipped, or
// by a future path that forgets to validate). Restricting is a safe default here
// specifically because it is *not* a lockout: a restricted session still
// authenticates (see AccountLoginBlocked) and self-heals the moment the user next
// changes their password (clearRestrictionOnPasswordChange resets a restricted
// state to active), so the failure mode of a garbage value is "forced through the
// password-change flow", never "silently full access" and never "permanently
// locked out with no recovery path".
func AccountRestricted(state string) bool {
	switch NormalizeAccountState(state) {
	case AccountActive, AccountSuspended, AccountDeprovisioned:
		// Suspended/deprovisioned are already refused outright by
		// AccountLoginBlocked, so "restricted" is moot for them either way.
		return false
	case AccountPendingFirstLogin, AccountPasswordResetRequired:
		return true
	default:
		return true
	}
}

// AccountLoginBlocked reports whether a state refuses login outright. Both an admin
// suspension and a SCIM/IdP deactivation block login; every login/session/token path
// funnels through here, so a deprovisioned account is refused everywhere a suspended
// one is, with no per-path change.
//
// Fails CLOSED on blank, whitespace-only, and any other unrecognized value — this is
// a change from this function's original design, which deliberately chose fail-OPEN
// here (see git history for the prior reasoning: blocking login outright has no
// self-healing path, so failing closed on a merely malformed value risked permanently
// locking out an already-legitimate user with no recovery short of direct DB/admin
// intervention).
//
// That reasoning was correct in general — it is exactly why AccountRestricted (a
// state that still authenticates but forces a password change) keeps a fail-closed
// default while THIS function, which refuses login outright, did not. But it weighed
// wrongful-lockout and wrongful-access as comparable costs, and at this specific
// call site they are not. For a secrets-management platform: a lockout is
// admin-recoverable in minutes and loudly visible (ReactivateUser, an audited action,
// with the operator informed exactly why via the log line and metric below); an
// authentication bypass through this exact gate is how a suspended/deprovisioned
// account got fully reactivated for login in a real, confirmed incident (a full-row
// storage overwrite silently blanked account_state, which this function's old
// fail-open default then read as "not blocked") — unrecoverable once exploited, and
// may never be detected. At an authentication boundary specifically, the integrity
// argument wins. This does NOT generalize to the rest of the codebase; it is a
// property of this one call site, which is why AccountRestricted's own default is
// untouched.
//
// Four things make failing closed here safe rather than a new blast radius:
//  1. internal/storage/account_state_backfill.go's guardAccountStateValid adds a
//     Postgres CHECK constraint restricting account_state to exactly the ADR-025
//     canonical set — no other value can be newly WRITTEN, on that backend. (This
//     function is still the one enforcement this constraint doesn't reach: it's a
//     pure function over a string, not a query result. A User struct can carry an
//     arbitrary value from a session-cache entry, an API request body deserialized
//     before any write, a test fixture, or a non-Postgres backend the constraint was
//     never applied to at all — SQLite has no equivalent, by design; see that
//     function's doc. The constraint is defense-in-depth for one backend, not a
//     substitute for the check below.)
//  2. TestAccountLoginBlocked_ExhaustsStateRegistry (account_state_exhaustiveness_
//     guard_test.go) statically asserts every AccountXxx constant declared in this
//     file is explicitly listed in this switch's case clauses — adding a new account
//     state without handling it here fails CI, which is what makes "a future state
//     not yet in this switch" (the original comment's main scenario) impossible to
//     ship silently.
//  3. Every existing blank row was backfilled to an explicit "active" before this
//     change shipped (internal/storage/account_state_backfill.go's
//     backfillBlankAccountState, proven idempotent and correct for every blank shape
//     — empty, NULL, whitespace-only — by its own test suite), so this flip does not
//     retroactively lock out any account that was blank for a benign reason.
//  4. The failure is LOUD, never silent: every fail-closed hit below logs the exact
//     value and the affected user ID at security level and increments
//     accountStateUnrecognizedTotal (account_state_metrics.go), so a lockout this
//     causes is immediately diagnosable from a single log line and alertable via the
//     metric — never a mysterious, undiagnosable "why can't I log in".
//
// Release ordering: the backfill (item 3) is backward-compatible — old code reads
// the explicit "active" value exactly the same as it read blank — so it can ship in
// a release ahead of this fail-closed change without any coordination requirement
// beyond "the backfill's release is deployed first". See ADR-025 for the account of
// why a live-database confirmation gate was replaced with these four self-certifiable
// preconditions.
func AccountLoginBlocked(userID uint, state string) bool {
	switch strings.TrimSpace(state) {
	case AccountActive, AccountPendingFirstLogin, AccountPasswordResetRequired:
		return false
	case AccountSuspended, AccountDeprovisioned:
		return true
	default:
		accountStateUnrecognizedTotal.Inc()
		log.Printf("SECURITY: user %d has a blank or unrecognized account_state %q -- failing closed "+
			"(login blocked). Recovery: an administrator must explicitly reactivate this account "+
			"(ReactivateUser) to set it to a valid state.", userID, state)
		return true
	}
}

// StaleAccounts returns users that have sat in the given account_state longer
// than olderThan — by default pending_first_login accounts an admin provisioned
// but the user never completed (ADR-025 stale-account warnings; surfaced at >7
// days). Oldest first.
func (c *KeyorixCore) StaleAccounts(ctx context.Context, state string, olderThan time.Duration) ([]*models.User, error) {
	if state == "" {
		state = AccountPendingFirstLogin
	}
	before := c.now().Add(-olderThan)
	return c.storage.ListUsersInStateBefore(ctx, state, before)
}

// SuspendUser blocks a user's login. Admin action; audited. Refuses to suspend
// the install's last global administrator (guardLastAdminDeactivation, #G02)
// — the same lockout DeleteUser and SCIM deactivation already refuse.
//
// #1646: the guard check and setAccountState's write must be serialized under
// the SAME lock acquisition, and that serialization must hold across every
// replica of an HA deployment -- two concurrent SuspendUser calls for two
// DIFFERENT admins could each observe "another admin survives" (the other
// hasn't been deactivated yet) and both proceed, jointly stranding the install
// with zero admins. lastAdminGuardLockKey is a single global key (matching
// accountStateMu's own single-mutex, not-sharded-per-user design): this
// operation is rare (admin actions, not steady-state traffic), and the
// invariant itself is install-wide, not per-target-user.
func (c *KeyorixCore) SuspendUser(ctx context.Context, adminID, userID uint) error {
	return c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
		if err := c.guardLastAdminDeactivation(ctx, userID); err != nil {
			return err
		}
		return c.setAccountState(ctx, adminID, userID, AccountSuspended, "account.suspended")
	})
}

// lastAdminGuardLockKey is the WithNamedLock key for guardLastAdminDeactivation's
// check-then-act sequence (#1646), used by every deactivation path
// (SuspendUser, UpdateUser, DeleteUser, and the SCIM update/deactivate/deprovision
// paths in scim.go).
const lastAdminGuardLockKey = "last-admin-guard"

// ReactivateUser returns a suspended (or otherwise non-active) user to active.
func (c *KeyorixCore) ReactivateUser(ctx context.Context, adminID, userID uint) error {
	return c.setAccountState(ctx, adminID, userID, AccountActive, "account.reactivated")
}

// RequirePasswordReset forces the user into a restricted session until they
// change their password. Admin action; audited.
func (c *KeyorixCore) RequirePasswordReset(ctx context.Context, adminID, userID uint) error {
	return c.setAccountState(ctx, adminID, userID, AccountPasswordResetRequired, "account.password_reset_required")
}

// setAccountState persists a new account state and writes an audit event.
//
// #344: this read-modify-write races with UpdateSCIMUser's — a routine SCIM/IdP
// resync's GetUser can read the row before an admin's SuspendUser here commits, and
// whichever caller's full-row Save lands last would otherwise win outright, silently
// reverting the other's change with no error to either side. accountStateMu (held for
// the whole read-modify-write, not just the DB write) serializes this against
// UpdateSCIMUser in-process, and LockUserForUpdate's row lock (Postgres: SELECT ...
// FOR UPDATE) does the same across replicas — the identical pattern recordFailedLogin
// uses for the login-lockout counter (see login_lockout.go).
//
// #454: persists via SetAccountState, not the generic UpdateUser — an admin
// suspend/reactivate is an explicit security directive, so a backend that cannot
// actually persist account_state must fail this call outright rather than silently
// succeed while the account stays unchanged. See SetAccountState's doc comment on
// storage.Storage.
func (c *KeyorixCore) setAccountState(ctx context.Context, adminID, userID uint, state, eventType string) error {
	if userID == 0 {
		return fmt.Errorf("user ID is required")
	}
	// S1 sweep (CLI-split inventory #2012): a non-zero, non-self adminID must
	// hold the same admin-rank ceiling UpdateUser/DeleteUser/RestoreUser now
	// enforce -- suspending, reactivating, or forcing a password reset on a
	// HIGHER-privileged account is the same shape of attack (a users.write
	// holder acting on a target they don't outrank), just against account
	// state instead of identity fields. adminID == 0 stays exempt: the
	// inactivity-suspend sweep (inactivity_suspend.go) calls SuspendUser with
	// adminID 0 as an explicit system/background caller, and already excludes
	// global admins itself before reaching this point -- see
	// requireAdminRankCeilingForTarget's own doc for why 0 means "not a human
	// decision" rather than "unauthenticated human."
	if adminID != userID {
		if err := c.requireAdminRankCeilingForTarget(ctx, adminID, userID, "change the account state of"); err != nil {
			return err
		}
	}
	c.accountStateMu.Lock()
	defer c.accountStateMu.Unlock()

	// The proactive cache-eviction sweep below is needed only when the TARGET state is
	// more restrictive than plain active — i.e. it blocks login (AccountLoginBlocked) or
	// imposes a restriction (AccountRestricted, e.g. password_reset_required). Both
	// predicates fail closed to true for every state except AccountActive, so this is
	// exactly "skip the TOMBSTONING sweep only when the account is becoming fully
	// unrestricted." Moving TOWARD active never needs a proactive TOMBSTONE for
	// correctness: any EXISTING positive cache entry already gets its
	// AccountState/Restricted refreshed on every hit by serveAuthCacheHit's own re-check
	// (server/middleware/auth.go), independent of this sweep. See
	// TestReactivateUser_DoesNotTombstoneNeverCachedPAT (server/http) for the bug this
	// guard closes: FuzzAuthCacheDifferential (G5) found that reactivating an account (or
	// any OTHER transition into active) unconditionally wrote a negative cache tombstone
	// (InvalidateTokenCacheByHash's own doc comment: "a short-lived tombstone...
	// negative-caches... for invalidTokenTTL") for every one of the user's PAT hashes,
	// including PATs that had NEVER been cached at all — e.g. a PAT created WHILE the
	// account was suspended, then hit by the reactivation's own sweep the moment the
	// account went back to active. The result: a brand-new, fully valid PAT was
	// spuriously rejected (401) for up to invalidTokenTTL, even though the account was
	// already active again and nothing about that credential was ever wrong.
	needsCacheEvictionSweep := accountStateNeedsEvictionSweep(userID, state)
	// G5 follow-up (#2402): skipping the sweep entirely on the "becoming active" branch
	// left a DIFFERENT, narrower bug open — an EXISTING negative cache entry, written
	// while the account WAS blocked/restricted (e.g. the very first use of a token
	// created during that window, which the sweep above correctly tombstones as
	// negative), now outlives the account becoming active again: nothing ever clears it,
	// so it keeps answering "denied" for up to invalidTokenTTL after the account is
	// already fine again. FuzzAuthCacheDifferential found this too — same mechanism,
	// opposite direction from the #2206 bug: both paths still deny (not an authz bypass,
	// since a stale negative can never grant more than a fresh check would), but the
	// cache's REASON disagrees with storage's (e.g. 401 "unauthenticated" from the stale
	// tombstone vs whatever status a fresh check now gives). Clearing via
	// clearCachedTokens (delete-ONLY-if-cached, never writes a new tombstone) is safe
	// here specifically because it cannot recreate the #2206 bug: a hash that was never
	// cached is simply not in the map to delete.
	needsCacheClearSweep := !needsCacheEvictionSweep

	var sessionHashes []string
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		hashes, serr := c.setAccountStateInTx(ctx, tx, userID, state)
		sessionHashes = hashes
		return serr
	})
	if err != nil {
		return fmt.Errorf("failed to update account state: %w", err)
	}
	// Evict the captured session/PAT-token hashes from the auth cache — AFTER commit,
	// so a rolled-back transaction never evicts a still-valid cache entry — so the new
	// state is reflected on the very next request, not after the cache TTL. A
	// blocked/restricted target TOMBSTONES (denies even a never-cached credential, since
	// the whole point is "deny effective immediately"); a target becoming active only
	// CLEARS an existing entry, never creates a new negative one (see needsCacheClearSweep's
	// doc comment above for why these need different primitives, not just a different
	// condition on the same one).
	if needsCacheEvictionSweep {
		c.invalidateTokenCache(sessionHashes...)
	} else if needsCacheClearSweep {
		c.clearCachedTokens(sessionHashes...)
	}
	aid := adminID
	c.writeAuditEventFull(ctx, eventType, &aid, nil, nil, "",
		fmt.Sprintf("%s account state set to %s", c.auditRef(ctx, c.storage, auditKindUser, userID), state))
	return nil
}

// accountStateNeedsEvictionSweep reports whether a transition to state needs the
// TOMBSTONING cache sweep (as opposed to the clear-only one). Extracted so
// setAccountState and setAccountStateInTx's callers cannot disagree about which
// primitive to use after commit — see setAccountState's own doc comment above
// for why the two directions need different primitives rather than one
// primitive under a different condition.
func accountStateNeedsEvictionSweep(userID uint, state string) bool {
	return AccountLoginBlocked(userID, state) || AccountRestricted(state)
}

// setAccountStateInTx is setAccountState's transaction body, extracted (#2867) so
// a caller that must commit an account-state change TOGETHER with another write
// can run both inside ONE WithTransaction. It returns the session/PAT token
// hashes the caller must evict from the auth cache AFTER commit.
//
// The caller owns, and must do in this order: the userID validation and the
// admin-rank ceiling check (BEFORE any write — an under-ranked actor must leave
// nothing committed), accountStateMu, the WithTransaction, then post-commit the
// cache sweep (pick the primitive with accountStateNeedsEvictionSweep) and the
// audit event. setAccountState immediately above is the single-write caller and
// is the reference for that ordering; MigrateUserToMachine
// (migrate_user_to_machine.go) is the multi-write one.
//
// Writing the hashes to the caller rather than evicting here is deliberate: the
// eviction must not happen until the transaction has actually committed, or a
// rolled-back change evicts a still-valid cache entry.
func (c *KeyorixCore) setAccountStateInTx(ctx context.Context, tx storage.Storage, userID uint, state string) ([]string, error) {
	needsCacheEvictionSweep := accountStateNeedsEvictionSweep(userID, state)
	needsCacheClearSweep := !needsCacheEvictionSweep
	var sessionHashes []string
	{
		// The lock-guarded read is still needed for serialization (row lock + existence
		// check) even though its returned user struct is no longer written back wholesale.
		if _, err := tx.LockUserForUpdate(ctx, userID); err != nil {
			return nil, err
		}
		if needsCacheEvictionSweep || needsCacheClearSweep {
			// Capture the user's current session-token HASHES BEFORE mutating so we can
			// evict their auth-cache entries after commit. The HTTP auth cache fast path
			// serves a frozen identity without re-reading the DB, so without eviction a
			// suspend/deactivate/restrict would not take effect until the positive-cache
			// TTL — a window where a blocked user keeps full access. The stored
			// session_token IS the SHA-256 hash, which is exactly the cache key.
			sessionHashes, _ = tx.ListSessionTokenHashesForUser(ctx, userID)
			// Also collect PAT hashes — for a transition INTO a blocked or restricted
			// state (e.g. password_reset_required), without this a cached PAT bypasses
			// the restriction for up to validTokenTTL (30 s): ValidatePATToken sees the
			// old identity from the cache and never re-checks the new account state
			// (#r125-H2). We evict here without revoking; revoking follows for blocked
			// states below. For a transition TOWARD active, this is what lets the clear
			// sweep below reach a stale negative PAT entry too, not just session ones.
			if pats, _ := tx.ListPersonalAccessTokensByUser(ctx, userID); len(pats) > 0 {
				sessionHashes = append(sessionHashes, activePATHashes(pats)...)
			}
		}

		if err := tx.SetAccountState(ctx, userID, state, c.now()); err != nil {
			return nil, err
		}
		// A state that blocks login must also terminate the user's existing sessions AND
		// PATs, so suspension is effective immediately instead of lingering until the
		// token expires. ValidateSessionToken/ValidatePATToken also reject blocked
		// accounts as a slow-path backstop, but the cache fast path bypasses it — so
		// evict here too. Revoked PAT hashes are folded into sessionHashes so they're
		// evicted from the auth cache alongside the session hashes after commit.
		if AccountLoginBlocked(userID, state) {
			_ = tx.DeleteSessionsForUserExcept(ctx, userID, 0)
			if hashes, herr := tx.RevokeAllPersonalAccessTokensForUser(ctx, userID); herr == nil {
				sessionHashes = append(sessionHashes, hashes...)
			}
		}
	}
	return sessionHashes, nil
}

// activePATHashes returns the token hashes of all non-revoked PATs that have a hash,
// used to evict them from the auth cache after an account-state transition.
func activePATHashes(pats []*models.PersonalAccessToken) []string {
	var hashes []string
	for _, p := range pats {
		if !p.Revoked && p.TokenHash != "" {
			hashes = append(hashes, p.TokenHash)
		}
	}
	return hashes
}

// clearRestrictionOnPasswordChange returns the account state a user should hold
// after a successful password change: a restricted state clears to active; any
// other state is left unchanged.
func clearRestrictionOnPasswordChange(state string) string {
	if AccountRestricted(state) {
		return AccountActive
	}
	return NormalizeAccountState(state)
}
