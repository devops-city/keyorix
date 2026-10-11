// account.go — Self-service account operations for the authenticated user.
//
// These power the "My Account" page (ADR-021) and are deliberately scoped to the
// caller's own user ID: the HTTP layer never forwards a target user ID, role, or
// active flag from the request body. For admin user management see users.go.
package core

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// UpdateOwnProfile updates the caller's display name and email only. It delegates
// to UpdateUser (which enforces email uniqueness) but constructs the request from
// the authenticated userID, so a caller can never change username/is_active or
// target another user.
//
// An email change additionally requires the caller's current password, mirroring
// ChangePassword's re-authentication check. The email is often the recovery/identity
// anchor (password reset delivery, SSO account linking — see ADR-052/ADR-053 related
// fixes) so a hijacked session (stolen cookie/token, unattended device) must not be
// able to silently repoint it to an attacker-controlled address and ride the
// password-reset flow to full takeover. Display-name-only changes are unaffected and
// need no password. currentPassword is ignored when the email is not changing.
func (c *KeyorixCore) UpdateOwnProfile(ctx context.Context, userID uint, displayName, email, currentPassword string) (*models.User, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if email != "" {
		user, err := c.storage.GetUser(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
		}
		if email != user.Email {
			// For accounts with ANY second factor enrolled (TOTP or WebAuthn/passkey),
			// require a TOTP code or password via requireReauth (the same bar as
			// DisableMFA / DeleteWebAuthnCredential). The email is the password-reset
			// anchor and SSO linking key: redirecting it to an attacker-controlled
			// address with only a stolen session suffices for full account takeover.
			// Password-only re-auth is too weak when a second factor is enrolled.
			// Checking user.MFAEnabled alone (as this used to) let a WebAuthn-only
			// account (MFAEnabled=false, WebAuthnEnabled=true) fall through to the
			// bare bcrypt branch below, bypassing the second-factor requirement
			// requireReauth's own doc comment says is mandatory once any second
			// factor is enrolled. For accounts with no second factor at all, fall
			// back to the bcrypt password check.
			if user.MFAEnabled || user.WebAuthnEnabled {
				if err := c.requireReauth(ctx, user, currentPassword, "email_change"); err != nil {
					return nil, err
				}
			} else if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
				return nil, fmt.Errorf("%w: current password is incorrect", ErrIncorrectCurrentPassword)
			}
		}
	}
	return c.UpdateUser(ctx, &UpdateUserRequest{
		ID:          userID,
		ActorID:     userID,
		DisplayName: displayName,
		Email:       email,
	})
}

// ChangePassword verifies the caller's current password and sets a new one. On
// success it drops the caller's other sessions (keeping the one identified by
// keepSessionToken) so a credential change invalidates other devices. If the
// current session cannot be resolved from keepSessionToken (e.g. a PAT-authenticated
// request), all of the user's sessions are dropped.
func (c *KeyorixCore) ChangePassword(ctx context.Context, userID uint, current, newPassword, keepSessionToken string) error {
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)); err != nil {
		return fmt.Errorf("%w: current password is incorrect", ErrIncorrectCurrentPassword)
	}
	// Enforce policy + history after the current-password check so an attacker can't
	// probe the policy without already holding valid credentials (ADR-025).
	if err := c.validateNewPassword(ctx, user, newPassword); err != nil {
		return err
	}
	if err := c.applyNewPassword(ctx, user, newPassword); err != nil {
		return err
	}

	// Drop OTHER sessions and evict them from the auth cache, so a thief holding a
	// stolen session is locked out immediately on the next request — not after the
	// cache TTL. Best-effort: the password change itself has succeeded.
	keepID, keepHash := c.resolveKeepSession(ctx, userID, keepSessionToken, "change_password")
	_ = c.deleteSessionsForUserAndEvict(ctx, userID, keepID, keepHash)
	c.writeAuditEvent(ctx, "auth.password_changed", actorPtr(userID), nil,
		fmt.Sprintf("user %d changed their own password", userID))
	return nil
}

// SetTokenCacheInvalidator wires the HTTP auth-cache eviction function (by token hash)
// so core token-revocation paths can evict immediately. Called once at startup.
func (c *KeyorixCore) SetTokenCacheInvalidator(fn func(hash string)) {
	c.tokenCacheInvalidator = fn
}

// SetMachineTokenCacheFlusher wires the HTTP auth-cache's fail-closed, all-machine-tokens
// eviction function. Called once at startup, alongside SetTokenCacheInvalidator.
func (c *KeyorixCore) SetMachineTokenCacheFlusher(fn func()) {
	c.machineTokenCacheFlusher = fn
}

// SetTokenCacheClearer wires the HTTP auth-cache's delete-only-if-cached eviction
// function (middleware.ClearTokenCacheIfCached), for a core path that must clear a
// STALE existing cache entry without ever creating a new negative one for a
// never-cached credential. Called once at startup, alongside SetTokenCacheInvalidator.
func (c *KeyorixCore) SetTokenCacheClearer(fn func(hash string)) {
	c.tokenCacheClearer = fn
}

// invalidateTokenCache evicts the given token hashes from the auth cache when an
// invalidator is wired (a no-op otherwise — e.g. tests, where the cache doesn't exist).
func (c *KeyorixCore) invalidateTokenCache(hashes ...string) {
	if c.tokenCacheInvalidator == nil {
		return
	}
	for _, h := range hashes {
		if h != "" {
			c.tokenCacheInvalidator(h)
		}
	}
}

// clearCachedTokens deletes the given token hashes from the auth cache ONLY where an
// entry already exists (see tokenCacheClearer) — a no-op when the clearer is unwired
// (tests, remote mode), same as invalidateTokenCache.
func (c *KeyorixCore) clearCachedTokens(hashes ...string) {
	if c.tokenCacheClearer == nil {
		return
	}
	for _, h := range hashes {
		if h != "" {
			c.tokenCacheClearer(h)
		}
	}
}

// evictUserSessionCache evicts every one of the user's active sessions from the HTTP
// auth cache WITHOUT deleting the sessions themselves — unlike
// deleteSessionsForUserAndEvict, the user stays logged in. Used after a permission
// change (e.g. role removal) where the goal is only to force the NEXT request to
// re-resolve the user's permissions from storage instead of serving a stale,
// positively-cached authorization decision for up to validTokenTTL.
//
// Uses clearCachedTokens (delete-ONLY-if-already-cached), not invalidateTokenCache:
// the credential itself is still perfectly valid here — only its PRIVILEGES may have
// changed — so writing a new negative tombstone would be wrong, not just unnecessary.
// Found live by FuzzAuthCacheDifferential (G5, #2402): RemoveUserRole's own call to
// this function (via removeUserRoleUnguarded) could tombstone a session token that
// had NEVER been used/cached yet (e.g. login immediately followed by a role
// grant+removal, before the session's first authenticated request) — the next request
// hit the tombstone and got 401 from the cache while a cache-bypassed, fresh check of
// the SAME token got 403 (valid session, but the downstream authorization check
// denied for an unrelated reason). Same bug class PR #2206 fixed for setAccountState's
// own "becoming active" branch, reached through a different call site: any
// credential-lifecycle helper that only needs to force re-resolution (not revoke
// outright) must never use the tombstone-writing primitive.
//
// Every caller of this function calls it AFTER its own primary operation has
// already committed — the same "best-effort helper, primary effect already
// succeeded" shape emitAudit protects against (service.go). Found live by
// FuzzStorageFaultOperations during the break-glass revoke atomicity fix's own
// validation burst (docs/findings/2026-09-23-FINDING-breakglass-revoke-half-commit.md):
// a panic here, previously unrecovered, propagated past an ALREADY-COMMITTED
// role removal + activation-revoke, and (worse) past the point where the
// caller's own post-commit audit event gets written, reporting the whole
// operation as a failure while the state had, in fact, already changed —
// oracle (a). The recover here is this function's OWN choke point, closing it
// for the role-removal call sites in rbac_management.go too, not just the one
// the fuzzer happened to reach it through.
func (c *KeyorixCore) evictUserSessionCache(ctx context.Context, userID uint) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: evictUserSessionCache panicked for user %d (best-effort, primary operation already succeeded): %v", userID, r)
		}
	}()
	hashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, userID)
	c.clearCachedTokens(hashes...)
}

// EventSessionRevocationPanicked audits a panic recovered inside
// deleteSessionsForUserAndEvict. Every one of this function's 8 call sites
// (account.go, mfa.go x2, scim.go, setup_consume.go x2, webauthn.go x2)
// discards the returned error (`_ = c.deleteSessionsForUserAndEvict(...)`)
// because the primary operation (password change, MFA activate/disable, SCIM
// deprovision, setup-token consume, WebAuthn registration) has ALREADY
// committed by the time this runs -- the same "best-effort helper, primary
// effect already succeeded" shape evictUserSessionCache above and
// revokeProjectDynamicSecretLeases (catalog.go, #2325) already recover from.
// A panic here is security-relevant in a way a returned error is not: some of
// the user's sessions may be left un-revoked with no signal anywhere else
// that this happened, so it is both logged loudly and audited under the
// affected user's ID, not just swallowed.
const EventSessionRevocationPanicked = "auth.session_revocation_panicked" // #nosec G101 -- audit event type, not a credential

// EventSessionRevocationFailed audits deleteSessionsForUserAndEvict's own
// storage.DeleteSessionsForUserExcept call returning a plain (non-panic) error.
// #2835: previously this was indistinguishable from success to every caller --
// all 8 call sites discard the returned error (`_ = c.deleteSessionsForUserAndEvict(...)`)
// because, same as EventSessionRevocationPanicked's own rationale, the primary
// operation has already committed by the time this runs. A failed purge here means
// sessions that should have been revoked are left live with no signal anywhere else
// that happened, so — like the panic case — it is audited under the affected user's
// ID rather than only swallowed.
const EventSessionRevocationFailed = "auth.session_revocation_failed" // #nosec G101 -- audit event type, not a credential

// EventKeepSessionLookupFailed audits resolveKeepSession falling back to purging
// EVERY session (including the caller's own) because keepSessionToken was supplied
// but could not be resolved. #2835: ChangePassword, ActivateMFA, and DisableMFA all
// spare the calling session from their post-change session purge by resolving
// keepSessionToken via storage.GetSession; a storage-layer failure on that one
// lookup previously widened the purge silently -- the caller saw an unexplained
// logout with nothing in the audit trail distinguishing it from "no session to
// spare" (keepSessionToken == ""). The widened purge itself is NOT a bug -- it is
// the correct fail-closed fallback (we cannot prove which session is the caller's,
// so revoking all of them is safer than guessing) -- only its silence was.
const EventKeepSessionLookupFailed = "auth.keep_session_lookup_failed" // #nosec G101 -- audit event type, not a credential

// resolveKeepSession resolves keepSessionToken (when supplied) to the session ID and
// stored hash deleteSessionsForUserAndEvict should spare from its post-change purge.
// reason identifies the calling operation ("change_password", "activate_mfa",
// "disable_mfa") for the audit trail. If keepSessionToken is empty, there is no
// session to spare and this returns (0, "") -- a full purge -- exactly as before.
//
// #2835: if keepSessionToken is supplied but storage.GetSession fails, the purge
// still widens to include the caller's own session (keepID stays 0) -- that
// fallback is deliberately unchanged, see EventKeepSessionLookupFailed. What
// changes is that the widening is no longer silent.
func (c *KeyorixCore) resolveKeepSession(ctx context.Context, userID uint, keepSessionToken, reason string) (keepID uint, keepHash string) {
	if keepSessionToken == "" {
		return 0, ""
	}
	s, serr := c.getKeepSession(ctx, keepSessionToken)
	if serr != nil {
		log.Printf("SECURITY: %s: could not resolve the caller's own session (%v) -- purging ALL sessions for user %d instead of sparing the caller's", reason, serr, userID)
		c.writeAuditEventFull(ctx, EventKeepSessionLookupFailed, &userID, nil, nil, "",
			fmt.Sprintf("%s: the caller's own session could not be resolved (%v), so the session purge included it too instead of sparing it", reason, serr))
		return 0, ""
	}
	return s.ID, s.SessionToken
}

// getKeepSession is resolveKeepSession's lookup with a panic turned into an
// error, so it takes the same fail-closed full-purge fallback. Every caller runs
// it AFTER its change has committed (#2844 sweep, mfa/activate
// GetSession#1/panic): an escaping panic reported the committed MFA activation
// as failed AND skipped the session purge that must follow it, leaving every
// other session live after a security-factor change.
func (c *KeyorixCore) getKeepSession(ctx context.Context, token string) (s *models.Session, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = nil, fmt.Errorf("session lookup panicked: %v", r)
		}
	}()
	return c.storage.GetSession(ctx, token)
}

// deleteSessionsForUserAndEvict deletes all of the user's sessions except keepID and
// evicts the deleted sessions from the HTTP auth cache, so a revoked session stops
// authenticating on the very NEXT request rather than lingering for the positive-cache
// TTL. The stored session_token IS the SHA-256 cache key. keepHash (the kept session's
// stored hash, or "") is never evicted, so the caller's own session is not disturbed.
// Best-effort: the session deletion is the durable control; eviction is the immediacy.
//
// A panic anywhere in this function (listing hashes, the delete itself, or the
// cache-eviction loop) is recovered rather than left to propagate: see
// EventSessionRevocationPanicked's doc comment for why every call site needs this.
func (c *KeyorixCore) deleteSessionsForUserAndEvict(ctx context.Context, userID, keepID uint, keepHash string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.writeAuditEventFull(ctx, EventSessionRevocationPanicked, &userID, nil, nil, "",
				fmt.Sprintf("panic revoking sessions for user %d: %v — sessions may not have been fully revoked, review manually", userID, r))
			log.Printf("SECURITY: deleteSessionsForUserAndEvict panicked for user %d (best-effort, primary operation already succeeded): %v\n%s", userID, r, debug.Stack())
			err = nil
		}
	}()
	hashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, userID)
	err = c.storage.DeleteSessionsForUserExcept(ctx, userID, keepID)
	if err != nil {
		log.Printf("SECURITY: deleteSessionsForUserAndEvict failed to purge sessions for user %d (best-effort, primary operation already succeeded): %v", userID, err)
		c.writeAuditEventFull(ctx, EventSessionRevocationFailed, &userID, nil, nil, "",
			fmt.Sprintf("failed to purge sessions for user %d: %v — sessions may not have been fully revoked, review manually", userID, err))
	}
	for _, h := range hashes {
		if h != "" && h != keepHash {
			c.invalidateTokenCache(h)
		}
	}
	return err
}

// validateNewPassword checks a candidate password against the configured policy and
// the password-history rule, without mutating anything. Split from applyNewPassword
// so callers (e.g. the setup-token consume flow) can reject a weak password BEFORE
// spending a single-use token, rather than burning the link on a policy failure.
func (c *KeyorixCore) validateNewPassword(ctx context.Context, user *models.User, newPassword string) error {
	if err := c.passwordPolicy.Validate(newPassword, user); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	// Stateful history rule: forbid reuse of the last N passwords (ADR-025).
	if c.passwordReused(ctx, user, newPassword) {
		return fmt.Errorf("%s: password must not reuse a recent password", i18n.T("ErrorValidation", nil))
	}
	return nil
}

// applyNewPassword hashes newPassword, stamps it on the user (clearing a restricted
// account state back to active per ADR-025), persists the user, and records the hash
// in history. It assumes the password has already passed validateNewPassword. Shared
// by ChangePassword and the setup-token consume flow so password handling is uniform.
//
// #484: persists via the narrow SetPasswordHash (and, only when the account state
// actually needs to clear a restriction, SetAccountState) rather than the generic
// UpdateUser. Both writes run inside one transaction so a partial application (hash
// persisted but the state clear lost, or vice versa) can't happen.
func (c *KeyorixCore) applyNewPassword(ctx context.Context, user *models.User, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), int(bcryptCost.Load()))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	now := c.now()
	newState := clearRestrictionOnPasswordChange(user.AccountState)
	// Compare against the NORMALIZED current state, not the raw field: an unset legacy
	// AccountState ("") normalizes to AccountActive, exactly like newState does for a
	// non-restricted user, so a naive raw comparison would spuriously call
	// SetAccountState for every legacy-row password change even though nothing is
	// actually changing.
	stateChanged := newState != NormalizeAccountState(user.AccountState)

	err = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.SetPasswordHash(ctx, user.ID, string(hash), now); err != nil {
			return err
		}
		if stateChanged {
			if err := tx.SetAccountState(ctx, user.ID, newState, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	user.PasswordHash = string(hash)
	user.PasswordChangedAt = &now
	user.AccountState = newState
	user.UpdatedAt = now

	// Record the new hash in history and prune to the configured depth.
	// Best-effort: the password change itself has already succeeded. Through
	// besteffort.Run, not a bare `_ =`: a PANIC here used to escape, report the
	// committed password change as a 500, and skip the PAT and session
	// revocation below entirely (FuzzStorageFaultOperations: change-password,
	// PrunePasswordHistory#1/panic, oracle (a), [PasswordHistory]).
	if c.passwordPolicy.HistoryCount > 0 {
		besteffort.Run(ctx, "account.ChangePassword.AddPasswordHistory", func() error {
			return c.storage.AddPasswordHistory(ctx, user.ID, string(hash), now)
		})
		besteffort.Run(ctx, "account.ChangePassword.PrunePasswordHistory", func() error {
			return c.storage.PrunePasswordHistory(ctx, user.ID, c.passwordPolicy.HistoryCount)
		})
	}

	// Revoke the user's PATs too. A credential change must invalidate EVERY bearer class,
	// not just sessions — otherwise a thief who minted a (possibly non-expiring) PAT from a
	// stolen session survives the victim's reset. The password change itself has already
	// succeeded (unlike the hash/state pair above, this is not rolled back on failure —
	// the user must not be told their new password didn't take just because PAT cleanup
	// failed) but a failure here is loud, not silently swallowed: an old, un-revoked PAT
	// surviving a compromise-driven password reset is exactly the attack this step exists
	// to close, so it must be visible for operator follow-up, not indistinguishable from
	// "nothing to revoke."
	hashes, herr := c.storage.RevokeAllPersonalAccessTokensForUser(ctx, user.ID)
	if herr != nil {
		uid := user.ID
		c.writeAuditEventFailed(ctx, EventPasswordChangePATRevokeFailed, &uid, nil, "",
			fmt.Sprintf("password changed for user %d, but FAILED to revoke their personal access tokens: %v — any PAT minted from a compromised session remains live, investigate immediately", user.ID, herr))
	} else {
		c.invalidateTokenCache(hashes...)
	}
	return nil
}

// EventPasswordChangePATRevokeFailed fires when applyNewPassword's PAT
// revocation fails after the password hash/state change already committed.
// #nosec G101 -- audit event type, not a credential
const EventPasswordChangePATRevokeFailed = "user.password_change_pat_revoke_failed"

// passwordReused reports whether newPassword matches the user's current password
// or any of the most recent HistoryCount stored hashes (ADR-025 history_count).
// Returns false when the history rule is disabled.
func (c *KeyorixCore) passwordReused(ctx context.Context, user *models.User, newPassword string) bool {
	if c.passwordPolicy.HistoryCount <= 0 {
		return false
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(newPassword)) == nil {
		return true
	}
	hashes, err := c.storage.RecentPasswordHashes(ctx, user.ID, c.passwordPolicy.HistoryCount)
	if err != nil {
		return false // best-effort: a history lookup failure must not block a change
	}
	for _, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(newPassword)) == nil {
			return true
		}
	}
	return false
}

// PasswordExpired reports whether the user's password has exceeded the policy's
// max age (ADR-025 max_age_days). Returns false when expiry is disabled. For
// legacy rows with no PasswordChangedAt, the account creation time is used.
func (c *KeyorixCore) PasswordExpired(user *models.User) bool {
	if user == nil || c.passwordPolicy.MaxAgeDays <= 0 {
		return false
	}
	set := user.PasswordChangedAt
	if set == nil {
		if user.CreatedAt.IsZero() {
			return false
		}
		set = &user.CreatedAt
	}
	maxAge := time.Duration(c.passwordPolicy.MaxAgeDays) * 24 * time.Hour
	return c.now().Sub(*set) > maxAge
}

// enforcePasswordExpiryGate transitions an active user to password_reset_required
// when the configured max_age_days policy has elapsed (ADR-025). Called at
// session-mint time so every subsequent API request is hard-gated by
// EnforceAccountSetup, not just the client-side soft flag in the login
// response.
//
// Only transitions active → password_reset_required; other states (already
// restricted, suspended, deprovisioned) are left unchanged. Fails closed: a
// storage error is returned so an expired password cannot bypass the gate due
// to a transient write failure.
func (c *KeyorixCore) enforcePasswordExpiryGate(ctx context.Context, user *models.User) error {
	if !c.PasswordExpired(user) {
		return nil
	}
	if NormalizeAccountState(user.AccountState) != AccountActive {
		return nil
	}
	now := c.now()
	if err := c.storage.SetAccountState(ctx, user.ID, AccountPasswordResetRequired, now); err != nil {
		return fmt.Errorf("failed to enforce password expiry: %w", err)
	}
	user.AccountState = AccountPasswordResetRequired
	user.UpdatedAt = now
	return nil
}

// CurrentSessionID returns the session ID backing a session token, or 0 if the
// token is not a session (e.g. a PAT) or no longer exists. Used to flag the
// "current" row in the active-sessions list.
func (c *KeyorixCore) CurrentSessionID(ctx context.Context, token string) uint {
	if token == "" {
		return 0
	}
	s, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return 0
	}
	return s.ID
}

// ListOwnSessions returns the caller's active sessions.
func (c *KeyorixCore) ListOwnSessions(ctx context.Context, userID uint) ([]*models.Session, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.ListSessionsByUser(ctx, userID)
}

// RevokeOwnSession deletes one of the caller's sessions after verifying ownership.
// A session that exists but belongs to another user is reported as not found, so a
// caller cannot probe for or revoke other users' session IDs.
// EventSessionRevoked is audited when a user revokes one of their OWN sessions
// (F3, audit-completeness campaign) — distinct from EventUserSessionsRevoked
// (account_sessions.go), which covers an admin force-logging-out another user.
const EventSessionRevoked = "session.revoked"

func (c *KeyorixCore) RevokeOwnSession(ctx context.Context, userID, sessionID uint) error {
	if userID == 0 || sessionID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user and session IDs are required")
	}
	session, err := c.storage.GetSessionByID(ctx, sessionID)
	if err != nil || session.UserID != userID {
		return fmt.Errorf("%s: session not found", i18n.T("ErrorNotFound", nil))
	}
	if err := c.storage.DeleteSession(ctx, sessionID); err != nil {
		return err
	}
	// Evict the revoked session from the auth cache so the device is logged out on its
	// next request, not after the positive-cache TTL. session_token is the cache key.
	c.invalidateTokenCache(session.SessionToken)
	c.writeAuditEvent(ctx, EventSessionRevoked, actorPtr(userID), nil,
		fmt.Sprintf("user %d revoked their own session %d", userID, sessionID))
	return nil
}
