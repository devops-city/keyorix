// login_lockout.go — per-account login lockout (brute-force protection). After
// MaxAttempts failed password logins within Window, the account is locked for an
// exponentially-backing-off cooldown; a successful login or an admin unlock resets
// it. This is distinct from the per-IP rate limiter (ADR-040): lockout binds to a
// specific account, so an attacker cannot evade it by rotating source IPs, and it
// rejects even a correct password while the lock is active. State lives on the User
// (failed_login_attempts / last_failed_login_at / login_locked_until /
// login_lockout_count); the lock auto-expires on read — no sweeper needed.
package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// LoginLockoutPolicy is the resolved lockout configuration (built from
// config.LoginLockoutConfig at startup). The zero value is disabled.
type LoginLockoutPolicy struct {
	Enabled      bool
	MaxAttempts  int
	Window       time.Duration
	BaseCooldown time.Duration
	MaxCooldown  time.Duration
}

const (
	EventAccountLocked   = "account.locked"
	EventAccountUnlocked = "account.unlocked"
)

// loginFailureMuShards is the shard count for loginFailureMu (see service.go):
// enough to make same-shard collisions between two unrelated accounts rare under
// realistic concurrency, without the memory/complexity of a per-user sync.Map.
const loginFailureMuShards = 64

// loginFailureLock returns the shard of loginFailureMu serializing this user's
// failed-login accounting. Sharding by userID means a flood against one (even
// already-locked) account no longer blocks every other account's accounting
// behind a single process-wide lock.
func (c *KeyorixCore) loginFailureLock(userID uint) *sync.Mutex {
	return &c.loginFailureMu[userID%loginFailureMuShards]
}

// loginLocked reports whether the user is currently within an active lockout window.
func (c *KeyorixCore) loginLocked(user *models.User) bool {
	return c.loginLockout.Enabled && user.LoginLockedUntil != nil && c.now().Before(*user.LoginLockedUntil)
}

// cooldownFor returns the lock duration for the nth lockout (1-based): an
// exponential backoff BaseCooldown * 2^(n-1), capped at MaxCooldown.
func (p LoginLockoutPolicy) cooldownFor(lockoutCount int) time.Duration {
	cd := p.BaseCooldown
	for i := 1; i < lockoutCount && cd < p.MaxCooldown; i++ {
		cd *= 2
	}
	if cd > p.MaxCooldown {
		cd = p.MaxCooldown
	}
	return cd
}

// recordFailedLogin increments the user's failed-attempt counter (resetting it when
// the previous failure is older than the window) and locks the account once it
// reaches MaxAttempts. Best-effort persistence: a storage error must not change the
// "invalid credentials" outcome the caller returns.
//
// The read-increment-write runs inside a transaction over a freshly LockUserForUpdate'd
// row, under the user's loginFailureMu shard, so concurrent failures for the same
// account cannot lose an increment and let an attacker spend more than MaxAttempts
// guesses before the lock trips: the shard mutex serializes same-process callers for
// that account (and so the whole single-process SQLite case), and the FOR UPDATE row
// lock LockUserForUpdate takes on Postgres serializes across HA replicas. The
// passed-in user struct was loaded before the lock, so the authoritative current
// state is re-read inside the transaction.
func (c *KeyorixCore) recordFailedLogin(ctx context.Context, user *models.User) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	if !c.loginLockout.Enabled {
		return
	}
	uid := user.ID
	now := c.now()

	mu := c.loginFailureLock(uid)
	mu.Lock()
	defer mu.Unlock()

	var locked bool
	var lockedUntil time.Time
	var lockoutNum int

	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		u, err := tx.LockUserForUpdate(ctx, uid)
		if err != nil {
			return err
		}
		// Already within an active lockout: don't escalate. The Login gate refuses to
		// process a password while locked, so reaching here means this caller loaded the
		// user before the lock was set (a concurrent burst). Counting it would re-trip the
		// lock with exponential backoff and stretch a single burst into a much longer lock.
		if u.LoginLockedUntil != nil && now.Before(*u.LoginLockedUntil) {
			return nil
		}
		// A stale failure (older than the window) starts a fresh count.
		if u.LastFailedLoginAt != nil && now.Sub(*u.LastFailedLoginAt) > c.loginLockout.Window {
			u.FailedLoginAttempts = 0
		}
		u.FailedLoginAttempts++
		u.LastFailedLoginAt = &now

		tripped := u.FailedLoginAttempts >= c.loginLockout.MaxAttempts
		if tripped {
			u.LoginLockoutCount++
			until := now.Add(c.loginLockout.cooldownFor(u.LoginLockoutCount))
			u.LoginLockedUntil = &until
			u.FailedLoginAttempts = 0 // window counter resets; the lock now gates
		}
		// Persist via the narrow UpdateLoginLockoutState, not the generic UpdateUser —
		// this is the sole write path for the four lockout-accounting columns.
		if err := tx.UpdateLoginLockoutState(ctx, uid, u.FailedLoginAttempts, u.LastFailedLoginAt, u.LoginLockedUntil, u.LoginLockoutCount); err != nil {
			return err
		}
		// Reflect the persisted lockout fields back onto the caller's struct (it was
		// loaded before the lock), without clobbering preloaded associations. Only reached
		// when the write above actually committed, so a struct mutated in memory always
		// matches what was persisted.
		user.FailedLoginAttempts = u.FailedLoginAttempts
		user.LastFailedLoginAt = u.LastFailedLoginAt
		user.LoginLockedUntil = u.LoginLockedUntil
		user.LoginLockoutCount = u.LoginLockoutCount
		if tripped {
			locked, lockedUntil, lockoutNum = true, *u.LoginLockedUntil, u.LoginLockoutCount
		}
		return nil
	})
	if err != nil {
		return // best-effort: a storage error must not change the caller's outcome
	}

	// Emit the lock audit only after the transaction commits, so a rolled-back lock is
	// never logged.
	if locked {
		c.writeAuditEventFull(ctx, EventAccountLocked, &uid, nil, nil, "",
			fmt.Sprintf("account %d locked until %s after repeated failed logins (lockout #%d)",
				uid, lockedUntil.UTC().Format(time.RFC3339), lockoutNum))
	}
}

// recheckLoginLockFailClosed re-checks the account's lock state under the SAME
// serialization (the user's loginFailureMu shard, plus the Postgres FOR UPDATE
// row lock LockUserForUpdate takes) that recordFailedLogin uses. This closes the
// TOCTOU gap between a caller's pre-verification snapshot check (loginLocked,
// evaluated against a user row read before the slow credential check — bcrypt, a
// TOTP/recovery-code check, or a WebAuthn assertion) and minting a session:
// without re-checking here, a concurrent burst of failed attempts against the
// same account could trip the lock AFTER a request already passed the snapshot
// check but BEFORE it mints a session, letting that request's otherwise-valid
// credential succeed against an account that should already be locked.
//
// Returns an error (the same "account temporarily locked" message the snapshot
// check uses) when the account is found to be locked; the caller MUST refuse the
// login rather than mint a session. Also returns an error — failing closed — if
// the lock state cannot be verified (a storage error), rather than falling back
// to the caller's stale snapshot. Shared by every login path that reaches a
// session mint after passing the lockout gate: password (Login), TOTP/recovery
// (VerifyMFALogin), and WebAuthn (FinishWebAuthnLogin /
// FinishWebAuthnPasswordlessLogin) — recordFailedLogin feeds the same counter
// from all of them, so the recheck must cover all of them too.
//
// #2894: this function used to ALSO clear the accumulated failure state on its
// way past (it was called checkLockAndClearLoginFailures), which put the clear
// BEFORE every remaining fallible step of the login — mintSession, the
// password-expiry gate, the step-up-grant write, and the transport's own
// identity resolution. A storage fault in any of those denied the login with a
// response byte-identical to a wrong credential (#2888) while leaving the
// counter at 0, so a CORRECT guess was strictly cheaper lockout-wise than a
// wrong one: at threshold−1, a wrong password locks the account and a correct
// password plus an injected fault does not. The clear now happens only at each
// path's true completion point — see LoginCompletion.
func (c *KeyorixCore) recheckLoginLockFailClosed(ctx context.Context, user *models.User) error {
	if !c.loginLockout.Enabled {
		return nil
	}
	uid := user.ID

	mu := c.loginFailureLock(uid)
	mu.Lock()
	defer mu.Unlock()

	var lockErr error
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		u, err := tx.LockUserForUpdate(ctx, uid)
		if err != nil {
			return err
		}
		if u.LoginLockedUntil != nil && c.now().Before(*u.LoginLockedUntil) {
			// A concurrent burst tripped the lock after our caller's pre-verification
			// snapshot but before we reached here — reflect the authoritative state
			// back onto the caller's struct and refuse.
			user.LoginLockedUntil = u.LoginLockedUntil
			user.LoginLockoutCount = u.LoginLockoutCount
			lockErr = fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
			return nil
		}
		return nil
	})
	if err != nil {
		// Unable to verify the current lock state — fail closed. Silently falling
		// back to "not locked" here would reopen exactly the snapshot-trust gap
		// this function exists to close. Every caller has already matched the
		// credential, so this is a post-verdict fault: callers go through
		// recheckLockAfterCredentialMatched, which settles the lockout for it.
		return fmt.Errorf("%w: %w", errLoginLockRecheckUnavailable, err)
	}
	return lockErr
}

// errLoginLockRecheckUnavailable marks recheckLoginLockFailClosed's storage-fault
// branch, as distinct from its "the account is locked" refusal. Its text is the
// message that branch has always carried.
var errLoginLockRecheckUnavailable = errors.New("unable to verify account lock state, please try again")

// recheckLockAfterCredentialMatched is recheckLoginLockFailClosed for a caller
// whose credential has ALREADY matched, which is every caller today (#2894
// review). A storage fault in the recheck is then a post-verdict denial, and it
// must cost exactly what a wrong credential costs on the same path: counted
// when that path's wrong-credential branch counts (counted=true), left alone
// when it does not (passwordless, counted=false; see
// newLoginCompletionNotCounted). Before this, the fault returned a bare error
// nobody counted, so at threshold−1 a wrong credential locked the account and a
// correct one plus a LockUserForUpdate fault did not.
//
// The count runs here, after recheckLoginLockFailClosed has released the
// account's mutex shard (recordFailedLogin takes the same shard). The error is
// wrapped with ErrLoginPostVerdict so transports audit auth.login_error and
// answer exactly like a wrong credential. A recheck that SUCCEEDS and finds the
// account locked is a genuine refusal and is returned unchanged.
func (c *KeyorixCore) recheckLockAfterCredentialMatched(ctx context.Context, user *models.User, counted bool) error {
	err := c.recheckLoginLockFailClosed(ctx, user)
	if err == nil || !errors.Is(err, errLoginLockRecheckUnavailable) {
		return err
	}
	if counted {
		c.recordFailedLogin(ctx, user)
	}
	return fmt.Errorf("%w: %w", ErrLoginPostVerdict, err)
}

// LoginCompletion is the deferred half of a login's lockout accounting (#2894).
//
// A login is NOT finished when a core login function returns: the transport
// still has to resolve the identity payload (a storage read) and set the session
// cookies, and the identity read can fail — which denies the login with a
// response byte-identical to a wrong credential (#2888). Until then the
// account's failed-login counter is left exactly as the credential check found
// it, so the two cases cost an attacker the same lockout progress:
//
//	wrong credential:                  N−1 → recordFailedLogin → N  (locks at N)
//	correct credential, late fault:    N−1 → Failed()          → N  (locks at N)
//	correct credential, delivered:     N−1 → Succeeded()       → 0
//
// Counting the late failure WITHOUT also deferring the clear is not enough, and
// that is why this type exists rather than a bare recordFailedLogin call in each
// failure branch: clear-then-count leaves the account at 1, not N, so at
// threshold−1 a correct guess still buys the attacker N−1 extra attempts that a
// wrong guess does not. Both halves are required.
//
// Exactly one of Succeeded or Failed must be called, exactly once; both are
// no-ops afterwards, and both are nil-safe so a flow with no per-account
// lockout stake (the setup-token consume path, which authenticates a one-shot
// token rather than a guessable credential) can pass nil.
//
// Not safe for concurrent use: it belongs to one in-flight login.
type LoginCompletion struct {
	c    *KeyorixCore
	user *models.User
	done bool
	// countsFailures is false for a path whose own WRONG-credential branch does
	// not feed this counter either — see newLoginCompletionNotCounted.
	countsFailures bool
	// heldSlots are per-IP login-budget slots EARLIER requests of this login
	// flow reserved and kept (the password step's, bound to the MFA challenge;
	// a WebAuthn Begin's, bound to its ceremony session). Succeeded hands them
	// back; Failed keeps them counted (#2936 item 4).
	heldSlots []uint
}

// holdLoginSlots records the budget slots bound to the single-use challenge /
// ceremony rows this login just consumed. Because those rows are consumed
// atomically, at most one login ever holds a given slot, and Succeeded's
// done-guard releases it at most once.
func (lc *LoginCompletion) holdLoginSlots(ids ...*uint) {
	if lc == nil {
		return
	}
	for _, id := range ids {
		if id != nil && *id != 0 {
			lc.heldSlots = append(lc.heldSlots, *id)
		}
	}
}

// newLoginCompletion is called by a login path once the credential has been
// confirmed correct and the lock re-checked, but before any remaining fallible
// step. Use this for every path whose wrong-credential branch calls
// recordFailedLogin: password login, the TOTP second factor, the WebAuthn
// second factor, WebAuthn re-auth and TOTP step-up.
func (c *KeyorixCore) newLoginCompletion(user *models.User) *LoginCompletion {
	return &LoginCompletion{c: c, user: user, countsFailures: true}
}

// newLoginCompletionNotCounted is newLoginCompletion for a path whose own
// wrong-credential branch deliberately does NOT feed the per-account counter,
// so counting a post-verdict fault would make a CORRECT credential the more
// expensive one — the same oracle as #2894, just inverted.
//
// Today that is exactly one path: passwordless WebAuthn. A failed discoverable
// assertion never identifies a user at all (the user handle comes out of the
// assertion the authenticator signed), so there is nobody to charge the failure
// to, and charging one would let an attacker lock an arbitrary victim — see
// checkPasswordlessAccountState. The property still holds, with both sides at
// zero cost: a failed assertion leaves the counter alone, and so does a valid
// assertion whose mint faulted. What must NOT happen, and did before #2894, is
// the valid-assertion case CLEARING it — wiping a victim's accumulated lockout
// progress on the way to a denial.
func (c *KeyorixCore) newLoginCompletionNotCounted(user *models.User) *LoginCompletion {
	return &LoginCompletion{c: c, user: user, countsFailures: false}
}

// Succeeded records that the login reached the client, clearing the accumulated
// failure state. This is the ONLY place a successful login's counter is reset.
func (lc *LoginCompletion) Succeeded(ctx context.Context) {
	if lc == nil || lc.done {
		return
	}
	lc.done = true
	lc.c.clearLoginFailures(ctx, lc.user)
	// #2936 item 4: the flow delivered a session, so the slots its earlier
	// steps kept were not failures. Best-effort (ReleaseLoginAttempt): a
	// release that fails leaves the slot counted, the strict side.
	for _, id := range lc.heldSlots {
		lc.c.ReleaseLoginAttempt(ctx, id)
	}
}

// Failed records that the login was denied AFTER the credential had already
// matched — a storage fault, not a bad guess. It counts toward the lockout
// exactly as a wrong credential would, because the response the client gets is
// already identical to a wrong credential's (#2888) and the lockout state must
// not be the thing that tells them apart. The audit trail still distinguishes
// the two (auth.login_error vs auth.login_failed), which is where an operator —
// and only an operator — can see the difference.
func (lc *LoginCompletion) Failed(ctx context.Context) {
	if lc == nil || lc.done {
		return
	}
	lc.done = true
	if !lc.countsFailures {
		// This path's wrong-credential branch does not count either, so the
		// matching cost is zero — leaving the counter exactly as the credential
		// check found it. NOT clearing it is the whole fix here; see
		// newLoginCompletionNotCounted.
		return
	}
	lc.c.recordFailedLogin(ctx, lc.user)
}

// RecordPostVerdictLoginFailure counts a login denial that happened AFTER the
// credential was confirmed correct, for a step the TRANSPORT owns rather than
// core (#2894).
//
// There is exactly one such step: /auth/login issuing the MFA challenge for an
// account that has a second factor. Login returns ErrMFARequired there having
// deliberately NOT cleared the counter (a correct password alone is not full
// authentication for such an account), so the password step itself leaves the
// counter at whatever the failure history was — but if CreateMFAChallenge then
// fails, the handler answers with the same 401 a wrong password gets, and
// without this call the counter would stay one short of the threshold while a
// wrong password would have tripped it. "Does the account lock?" would answer
// "was the password right?".
//
// Not needed for the setup-token consume flow's equivalent branch: that path
// authenticates a one-shot token and never feeds this counter on any branch.
func (c *KeyorixCore) RecordPostVerdictLoginFailure(ctx context.Context, user *models.User) {
	if user == nil {
		return
	}
	c.recordFailedLogin(ctx, user)
}

// clearLoginFailures resets the lockout state after a successful authentication.
// It writes only when there is something to clear, so the happy path adds no extra
// write on every login. Persists via the narrow UpdateLoginLockoutState, not the
// generic UpdateUser.
func (c *KeyorixCore) clearLoginFailures(ctx context.Context, user *models.User) {
	if user.FailedLoginAttempts == 0 && user.LoginLockedUntil == nil && user.LoginLockoutCount == 0 {
		return
	}
	if err := c.storage.UpdateLoginLockoutState(ctx, user.ID, 0, nil, nil, 0); err != nil {
		return
	}
	user.FailedLoginAttempts = 0
	user.LastFailedLoginAt = nil
	user.LoginLockedUntil = nil
	user.LoginLockoutCount = 0
}

// UnlockUser clears a user's login-lockout state (admin action; audited). It does
// not change the account_state — a suspended account stays suspended.
//
// #484: persists via the same narrow UpdateLoginLockoutState primitive #454 already
// established for the automatic clear paths (clearLoginFailures, reached via
// LoginCompletion.Succeeded) — not the generic UpdateUser. UnlockUser clears the
// exact same four columns those callers do, just admin-triggered instead of triggered
// by a successful login.
// S1 sweep decision (CLI-split inventory #2012): deliberately NOT ceiling-gated
// like its siblings (UpdateUser, DeleteUser, RestoreUser, SuspendUser/
// ReactivateUser/RequirePasswordReset, RevokeUserSessions,
// ResendAccountSetupLink). Unlocking a login-lockout grants no new access and
// changes no identity or privilege field -- the target still needs their own
// real password (or second factor) to actually authenticate. A users.write
// holder clearing a HIGHER-privileged account's lockout counter early is, at
// worst, a minor UX favor to that account, not an escalation vector.
func (c *KeyorixCore) UnlockUser(ctx context.Context, adminID, userID uint) error {
	if userID == 0 {
		return fmt.Errorf("user ID is required")
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	if err := c.storage.UpdateLoginLockoutState(ctx, userID, 0, nil, nil, 0); err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}
	user.FailedLoginAttempts = 0
	user.LastFailedLoginAt = nil
	user.LoginLockedUntil = nil
	user.LoginLockoutCount = 0
	aid := adminID
	c.writeAuditEventFull(ctx, EventAccountUnlocked, &aid, nil, nil, "",
		fmt.Sprintf("user %d login lockout cleared by admin %d", userID, adminID))
	return nil
}
