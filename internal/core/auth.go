// auth.go — Session authentication: Login, Logout, RefreshSession, ValidateSessionToken.
//
// For first-boot system bootstrap see auth_bootstrap.go.
package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// sessionTouchInterval throttles last_seen_at writes on the auth hot path.
const sessionTouchInterval = 30 * time.Second

// defaultSessionAccessTTL is the access-token lifetime when no session config is
// set. It matches the historic hard-coded value, so an install that does not
// configure a session block keeps the old 24h behaviour.
const defaultSessionAccessTTL = 24 * time.Hour

// accessTTL returns the configured access-token lifetime, or the 24h default.
func (c *KeyorixCore) accessTTL() time.Duration {
	if c.sessionAccessTTL > 0 {
		return c.sessionAccessTTL
	}
	return defaultSessionAccessTTL
}

// LoginRequest holds credentials for login. UserAgent/IPAddress are captured for
// the My Account "active sessions" view and are optional.
type LoginRequest struct {
	Username  string
	Password  string
	UserAgent string
	IPAddress string
}

// VerifyPasswordCredentials resolves "is this username/password combination
// valid", enforcing the per-account lockout gate and the account-active/
// account-state checks Login has always required — extracted out of Login
// (#506) as the single source of truth for the LOCAL bcrypt-backed check.
func (c *KeyorixCore) VerifyPasswordCredentials(ctx context.Context, username, password string) (*models.User, error) {
	user, err := c.storage.GetUserByUsername(ctx, username)
	if err != nil {
		// Spend an equivalent bcrypt comparison so a missing username doesn't return
		// faster than a wrong password (account-enumeration timing side-channel).
		_ = bcrypt.CompareHashAndPassword(*dummyBcryptHash.Load(), []byte(password))
		return nil, fmt.Errorf("invalid credentials")
	}
	// Per-account lockout gate: while locked, refuse regardless of the password, so
	// repeated guessing can't progress. Spend an equivalent bcrypt comparison first so the
	// locked path's latency matches the unknown-user and wrong-password paths — otherwise a
	// fast (no-bcrypt) response on a locked account is a username-existence oracle (the
	// attacker first forces the lockout, then probes by timing).
	if c.loginLocked(user) {
		_ = bcrypt.CompareHashAndPassword(*dummyBcryptHash.Load(), []byte(password))
		return nil, fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		c.recordFailedLogin(ctx, user) // increment + lock at the threshold
		return nil, fmt.Errorf("invalid credentials")
	}
	// Correct password — but this is only PARTIAL authentication when the account
	// has a second factor configured (MFAEnabled/WebAuthnEnabled): Login refuses to
	// mint a session at this point and instead returns ErrMFARequired, deferring to
	// CreateMFAChallenge -> VerifyMFALogin (or the WebAuthn assertion ceremony).
	// Deliberately do NOT clear the accumulated lockout state here: this function
	// has no visibility into whether a second factor is required (that gate lives
	// in the caller, Login), so clearing unconditionally would let an attacker who
	// merely knows the correct password — without ever passing MFA — repeatedly
	// reset the account's failed-login counter/lock, defeating the lockout as a
	// brute-force backstop and even undoing a defender-triggered lock. The
	// TOCTOU-safe recheck-and-clear (checkLockAndClearLoginFailures) instead
	// happens at the ACTUAL full-authentication point for each login path: Login
	// itself, immediately before mintSession, when no second factor is required;
	// VerifyMFALogin and the WebAuthn Finish* functions, immediately before their
	// own mintSession, when one is. Every login path ends up covered exactly once,
	// at the point it is truly done authenticating — never earlier.
	// A deactivated account (IsActive=false — e.g. admin deactivation via UpdateUser,
	// or a SCIM/IdP deactivation) is refused login regardless of account_state. The
	// state-based gate below does not cover this, so without it a deactivated user who
	// still knew their password could authenticate; it also lets SCIM deactivation
	// preserve a restricted account_state (forced reset) while still blocking login.
	if !user.IsActive {
		return nil, fmt.Errorf("account is not active")
	}
	// A suspended account is refused login outright (ADR-025). Restricted states
	// (pending_first_login / password_reset_required) still log in, but the auth
	// middleware confines the session to the password-change allowlist.
	if AccountLoginBlocked(user.ID, user.AccountState) {
		return nil, fmt.Errorf("account suspended")
	}
	return user, nil
}

// Login validates credentials, creates a session, and returns (session, user, error).
func (c *KeyorixCore) Login(ctx context.Context, req *LoginRequest) (*models.Session, *models.User, error) {
	user, err := c.authenticatePasswordLogin(ctx, req)
	if err != nil {
		return nil, user, err
	}
	// #3024: an account that owes both setup steps (restricted AND no second factor
	// under security.require_mfa) gets a setup-only session: short-lived, confined to
	// the setup steps, revoked once they are done (account_setup.go).
	created, err := c.mintSessionWith(ctx, user.ID, req.UserAgent, req.IPAddress, c.needsSetupSession(user))
	if err != nil {
		return nil, nil, err
	}
	return created, user, nil
}

// LoginWithIdentity is Login for a caller that also needs the response
// identity (roles and permissions). It resolves the identity BEFORE minting
// the session, the same ordering the MFA and WebAuthn logins use (#2841), so
// nothing fallible runs after the session is written and a login reported as
// failed never leaves one behind (#2844: the HTTP handler used to read the
// identity after Login returned, and a panic in that read left a live session
// the client never received).
func (c *KeyorixCore) LoginWithIdentity(ctx context.Context, req *LoginRequest) (*models.Session, *models.User, UserIdentity, error) {
	user, err := c.authenticatePasswordLogin(ctx, req)
	if err != nil {
		return nil, user, UserIdentity{}, err
	}
	identity, err := c.resolveLoginIdentityBeforeMint(ctx, user.ID)
	if err != nil {
		return nil, nil, UserIdentity{}, err
	}
	// #3024: an account that owes both setup steps (restricted AND no second factor
	// under security.require_mfa) gets a setup-only session: short-lived, confined to
	// the setup steps, revoked once they are done (account_setup.go).
	created, err := c.mintSessionWith(ctx, user.ID, req.UserAgent, req.IPAddress, c.needsSetupSession(user))
	if err != nil {
		return nil, nil, UserIdentity{}, err
	}
	return created, user, identity, nil
}

// authenticatePasswordLogin is everything Login does before the session is
// minted. On ErrMFARequired it returns the user alongside the error (the caller
// needs it to start the challenge); on any other error the user is nil.
func (c *KeyorixCore) authenticatePasswordLogin(ctx context.Context, req *LoginRequest) (*models.User, error) {
	user, err := c.VerifyPasswordCredentials(ctx, req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	// Enforce the password max-age policy: if the password has expired, gate the
	// account to password_reset_required NOW so the middleware blocks API access
	// on every subsequent request (ADR-025 hard gate). The soft flag in the login
	// response alone is not sufficient — a client that ignores it would retain
	// full API access indefinitely.
	if err := c.enforcePasswordExpiryGate(ctx, user); err != nil {
		return nil, err
	}
	// Accounts with any second factor (TOTP or a passkey) get no session from the
	// password step — the caller must complete it (CreateMFAChallenge →
	// VerifyMFALogin for TOTP, or the WebAuthn assertion ceremony for a passkey).
	// Critically, the lockout counter is NOT cleared on this branch: a correct
	// password alone is not full authentication for these accounts, so an
	// attacker who knows the password but lacks the second factor must not be
	// able to reset the account's brute-force lockout state (VerifyMFALogin /
	// the WebAuthn Finish* functions each do their own clear once the second
	// factor actually succeeds).
	if user.MFAEnabled || user.WebAuthnEnabled {
		return user, ErrMFARequired
	}
	// No second factor configured — the password step IS the full authentication.
	// Re-check the lock state under the same serialization recordFailedLogin uses
	// (the account's mutex shard + a Postgres row lock) before minting a session,
	// and only then clear any accumulated failure state: a concurrent burst of
	// failed attempts against this account may have tripped the lock between the
	// snapshot read inside VerifyPasswordCredentials and now (TOCTOU) — never
	// trust that stale snapshot alone.
	if err := c.checkLockAndClearLoginFailures(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// mintSession creates and persists a new session token for a user. The access
// window is the configured access TTL (default 24h); when an absolute ceiling is
// configured it is stamped once here and carried unchanged through every refresh,
// so total session lifetime is bounded regardless of how often the token rotates.
// Shared by Login and the setup-token consume flow (auto-login) so session
// issuance — token generation, expiry, and the captured device fields — stays uniform.
func (c *KeyorixCore) mintSession(ctx context.Context, userID uint, userAgent, ip string) (*models.Session, error) {
	return c.mintSessionWith(ctx, userID, userAgent, ip, false)
}

// mintSessionWith is mintSession with the setup-only flag (#3024): a setup-only
// session's whole life is capped at SetupSessionTTL from now, whatever the
// configured access/absolute TTLs, and the cap is carried through every refresh.
func (c *KeyorixCore) mintSessionWith(ctx context.Context, userID uint, userAgent, ip string, setupOnly bool) (*models.Session, error) {
	token, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}
	// FamilyID starts a new lineage at login and is carried unchanged through every
	// RefreshSession rotation, so a detected refresh-token reuse can revoke the whole
	// chain in one shot (#211).
	familyID, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session family id: %w", err)
	}
	now := c.now()
	expiresAt := now.Add(c.accessTTL())
	session := &models.Session{
		UserID:       userID,
		SessionToken: token,
		FamilyID:     familyID,
		UserAgent:    userAgent,
		IPAddress:    ip,
		LastSeenAt:   &now,
		ExpiresAt:    &expiresAt,
	}
	if c.sessionAbsoluteTTL > 0 {
		absolute := now.Add(c.sessionAbsoluteTTL)
		// A ceiling shorter than one access window is meaningless — never let the
		// first window already overrun the ceiling.
		if absolute.Before(expiresAt) {
			absolute = expiresAt
		}
		session.AbsoluteExpiresAt = &absolute
	}
	if setupOnly {
		capSetupSession(session, now)
	}
	// A failed insert may still have committed: createSession delivers the row
	// if it landed instead of reporting a failed login over a live session
	// (#2844). See session_undelivered.go.
	created, err := c.createSession(ctx, session, ip, "login")
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	// Bound concurrent sessions per user so unbounded logins can't grow the table or
	// enlarge the credential-theft blast radius. Best-effort — never fail a login on
	// it, including a panic here (found live by FuzzStorageFaultOperations,
	// server/faultops, docs/findings/2026-10-02-FINDING-mfa-verify-enforcesessionlimit-panic-masks-successful-login.md):
	// unrecovered, it would propagate past this line and out through the
	// transport's own panic-recovery wrapper as a 500 — misreporting an
	// already-committed session (and, for the MFA-verify caller, an already-
	// consumed TOTP step) as a failed login.
	besteffort.Run(ctx, "auth.mintSession.EnforceSessionLimit", func() error {
		return c.storage.EnforceSessionLimit(ctx, userID, maxSessionsPerUser)
	})
	return created, nil
}

// capSetupSession clamps a setup-only session's access window and absolute
// ceiling to SetupSessionTTL from now, never lengthening an earlier ceiling.
func capSetupSession(session *models.Session, now time.Time) {
	ceiling := now.Add(SetupSessionTTL)
	if session.AbsoluteExpiresAt == nil || session.AbsoluteExpiresAt.After(ceiling) {
		session.AbsoluteExpiresAt = &ceiling
	}
	if session.ExpiresAt == nil || session.ExpiresAt.After(*session.AbsoluteExpiresAt) {
		exp := *session.AbsoluteExpiresAt
		session.ExpiresAt = &exp
	}
	session.SetupOnly = true
}

// maxSessionsPerUser caps a user's concurrent sessions; the oldest beyond this are
// reaped on each new login (see EnforceSessionLimit).
const maxSessionsPerUser = 25

// RecordLogin stamps the user's last_login_at to the current time. Best-effort:
// the login handler calls this in a goroutine after a successful authentication,
// so a storage error here must never fail the login itself.
//
// G81: normalized to UTC here explicitly rather than via a models.User BeforeSave
// hook — UpdateLastLogin's sole write path (local_users.go, UpdateColumn) bypasses
// all model hooks, so a hook would be silently ineffective (see the doc comment on
// User.LastLoginAt). Mirrors local_mfa_stepup.go's explicit-normalization fix for
// MFAStepupToken's ON CONFLICT path, which has the same hook-bypass shape.
func (c *KeyorixCore) RecordLogin(ctx context.Context, userID uint) error {
	return c.storage.UpdateLastLogin(ctx, userID, c.now().UTC())
}

// ErrSessionNotFound means token names no live session -- either it was
// never valid, or (the case this exists to distinguish, #N5) a PRIOR logout
// (a genuine double-click, two tabs, or a client retry) already deleted it.
// Either way this is a caller-facing 401, never a 500: the token is not
// valid, which is an ordinary authentication outcome, not a server fault.
var ErrSessionNotFound = errors.New("session not found")

// Logout invalidates the session identified by token.
//
// #2337 fixed the double-logout case (a prior logout already deleted the session) by
// mapping it to ErrSessionNotFound -> 401, but did so by collapsing EVERY GetSession
// error into that same sentinel — a real storage failure (DB down, a timeout) got the
// identical 401 "session not found" as an ordinary already-logged-out token, silently
// swallowing a genuine server fault. storage.IsSessionNotFound (backed by
// storage.ErrSessionNotFound, which GetSession now wraps ONLY for a genuine
// gorm.ErrRecordNotFound — see local_auth.go's GetSession) distinguishes the two: a
// definitive "no such session" still maps to ErrSessionNotFound (401, unchanged
// caller-visible behavior), while any other error propagates as-is for the HTTP
// handler's existing non-ErrSessionNotFound branch (500) to report — that branch
// already existed and was already correct; it was simply unreachable for this
// specific failure before now.
func (c *KeyorixCore) Logout(ctx context.Context, token string) error {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		if storage.IsSessionNotFound(err) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("logout: session lookup failed: %w", err)
	}
	return c.storage.DeleteSession(ctx, session.ID)
}

// EventSessionReuseDetected audits a refresh attempt against an already-rotated
// session token (#211) — distinct from the generic "session not found" a caller
// sees, since a rotated-away token is either a genuine refresh-token-reuse replay
// (a standard OAuth compromise signal) or a benign concurrent-refresh race loser;
// the DB alone cannot tell those apart, so both are treated as suspicious and the
// whole session family is revoked.
const EventSessionReuseDetected = "auth.session_reuse_detected" // #nosec G101 -- audit event type, not a credential

// RefreshSession rotates an existing session to a new token with a fresh access
// window. The access window may have lapsed — that is the normal silent-refresh
// case — but refresh is refused once the session's absolute ceiling is reached, so
// rotating the token can never extend a session indefinitely. The ceiling is
// carried unchanged onto the new session, and the new access window is clamped so
// it never overruns that ceiling.
//
// Rotation is atomic (RotateSession is a single DB transaction with a CAS guard —
// #211): a replay of a token that has already been rotated away, or a race where
// two concurrent refreshes target the same not-yet-rotated token, both surface here
// as "lost the rotation" and are handled identically — audited distinctly from
// ordinary expiry and the whole session family (every session descended from the
// same login) is revoked, not just the one replayed row.
func (c *KeyorixCore) RefreshSession(ctx context.Context, token string) (*models.Session, error) {
	old, err := c.storage.GetSessionAny(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("session not found or expired")
	}
	now := c.now()
	if old.RotatedAt != nil {
		// The token maps to a session that was already rotated away by an earlier,
		// successful refresh — a reuse of a stale refresh token.
		c.handleSessionReuse(ctx, old)
		return nil, fmt.Errorf("session not found or expired")
	}
	if old.AbsoluteExpiresAt != nil {
		// #1653: refuse a now that looks earlier than one this process has
		// already legitimately observed for a session refresh -- see
		// checkSessionRefreshClockNotRegressed's doc comment for what this
		// defends against (a backward-stepped host clock letting the
		// absolute-ceiling recheck below pass for a session that has
		// actually exceeded its lifetime). Scoped to sessions that actually
		// HAVE an absolute ceiling -- a session with none has nothing here
		// for a clock regression to extend.
		if err := c.checkSessionRefreshClockNotRegressed(now); err != nil {
			return nil, err
		}
	}
	if old.AbsoluteExpiresAt != nil && !now.Before(*old.AbsoluteExpiresAt) {
		// Past the hard ceiling — re-authentication required, not another refresh.
		_ = c.storage.DeleteSession(ctx, old.ID)
		return nil, fmt.Errorf("session lifetime exceeded; re-authentication required")
	}
	// An impersonation session must not be refreshable. /auth/refresh is public (any
	// bearer token), and refresh rebuilds the session without the impersonation fields —
	// so refreshing an impersonation token would mint a fresh, full-TTL session for the
	// target with the impersonated_by attribution stripped, laundering a bounded, audited
	// support session into unbounded, unattributed account access. The admin keeps their
	// own session and swaps back via "Return to Admin".
	if old.ImpersonatedBy != nil {
		return nil, fmt.Errorf("impersonation sessions cannot be refreshed")
	}
	// Re-check account state before rotating the token. ValidateSessionToken applies
	// this gate on every request, but refresh is a distinct, unauthenticated-by-token
	// entry point: without re-checking here, an account deactivated (IsActive=false)
	// or suspended after issuance could keep minting fresh, self-renewing sessions
	// indefinitely. Mirror the gate and drop the now-invalid session.
	user, err := c.storage.GetUser(ctx, old.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
		_ = c.storage.DeleteSession(ctx, old.ID)
		return nil, fmt.Errorf("account is not active")
	}
	newToken, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	expiresAt := now.Add(c.accessTTL())
	if old.AbsoluteExpiresAt != nil && expiresAt.After(*old.AbsoluteExpiresAt) {
		expiresAt = *old.AbsoluteExpiresAt
	}
	familyID, err := ensureFamilyID(old.FamilyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	session := &models.Session{
		UserID:            old.UserID,
		SessionToken:      newToken,
		FamilyID:          familyID,
		UserAgent:         old.UserAgent,
		IPAddress:         old.IPAddress,
		LastSeenAt:        &now,
		ExpiresAt:         &expiresAt,
		AbsoluteExpiresAt: old.AbsoluteExpiresAt,
		// #3024: a setup-only session stays one through every rotation, or a refresh
		// would launder it into a full session. A session whose account has since come
		// to owe both setup steps (e.g. an admin forced a reset on a factor-less user
		// while it was live) becomes one here, capped from now — the setup gate sends
		// such a session through refresh/re-login instead of serving it.
		SetupOnly: old.SetupOnly || c.needsSetupSession(user),
	}
	if session.SetupOnly && !old.SetupOnly {
		capSetupSession(session, now)
	}
	created, won, err := c.storage.RotateSession(ctx, old.ID, session, now)
	if err != nil {
		// RotateSession is one transaction, so a rotation that committed despite
		// the error has both retired the old row and written the new one. Failing
		// it would leave the client holding a retired token while the new
		// session sits live and undelivered (#2844); deliver it instead.
		row := c.sessionWriteLanded(ctx, newToken, old.UserID, old.IPAddress, "session refresh", err)
		if row == nil {
			return nil, fmt.Errorf("failed to rotate session: %w", err)
		}
		session.ID, session.SessionToken = row.ID, newToken
		created, won = session, true
	}
	if !won {
		// Lost the CAS: a concurrent refresh of this exact token won first between
		// our read and our write. Same signal as an out-of-band replay.
		c.handleSessionReuse(ctx, old)
		return nil, fmt.Errorf("session not found or expired")
	}
	return created, nil
}

// sessionRefreshClockRegressionTolerance bounds how far now may read EARLIER
// than sessionRefreshWatermark before checkSessionRefreshClockNotRegressed
// refuses a session refresh. Same value and rationale as
// secretExpiryClockRegressionTolerance (versions.go, #1632): large enough not
// to false-positive on ordinary NTP slew, small enough to still catch a
// deliberate/NTP-less manual clock reset.
const sessionRefreshClockRegressionTolerance = 30 * time.Second

// checkSessionRefreshClockNotRegressed refuses to trust now for
// RefreshSession's absolute-ceiling recheck if it looks EARLIER than a time
// this process has already legitimately observed for a session refresh
// (#1653, follow-up to #1632). RefreshSession's `!now.Before(*old.AbsoluteExpiresAt)`
// comparison binds a fresh c.now() directly against a DB-loaded, non-renewable
// ceiling — a host clock stepped backward past that ceiling would let a
// session refresh past its true absolute lifetime. Reuses the exact same
// refusal text RefreshSession's own ceiling check already returns
// ("session lifetime exceeded; re-authentication required"), not a distinct
// message, so a caller cannot use it as an oracle confirming clock
// manipulation had an effect. On success, advances the watermark to now
// (never backward).
// .UTC() strips any monotonic clock reading now carries — see
// authEffectiveNow's doc comment (same file) for why an unstripped
// comparison here would never actually detect a backward wall-clock step.
func (c *KeyorixCore) checkSessionRefreshClockNotRegressed(now time.Time) error {
	now = now.UTC()
	c.sessionRefreshWatermarkMu.Lock()
	defer c.sessionRefreshWatermarkMu.Unlock()
	if !c.sessionRefreshWatermark.IsZero() && now.Before(c.sessionRefreshWatermark.Add(-sessionRefreshClockRegressionTolerance)) {
		return fmt.Errorf("session lifetime exceeded; re-authentication required")
	}
	if now.After(c.sessionRefreshWatermark) {
		c.sessionRefreshWatermark = now
	}
	return nil
}

// ensureFamilyID returns existing if non-empty, otherwise generates a new secure token.
// Legacy sessions pre-dating FamilyID have an empty field; we start a fresh lineage
// rather than leaving it empty to avoid grouping all legacy sessions under one family.
func ensureFamilyID(existing string) (string, error) {
	if existing != "" {
		return existing, nil
	}
	return generateSecureToken()
}

// EventSessionReuseFamilyRevokeFailed fires when handleSessionReuse's
// DeleteSessionsByFamily call itself fails: unlike the deactivation-cleanup
// case (RevokeUserCredentialsForDeactivation, UpdateUser), there is no
// independent gate protecting a live sibling session here — the account is
// still active, this function exists specifically because reuse of an
// already-rotated token was detected (a suspected-compromise signal) — so a
// failure to revoke the family leaves a live, unrevoked session for an
// attacker who is actively replaying a stale token. This must be loud, not
// swallowed. #nosec G101 -- audit event type, not a credential
const EventSessionReuseFamilyRevokeFailed = "auth.session_reuse_family_revoke_failed"

// handleSessionReuse responds to a refresh attempt that targeted an already-rotated
// session token (#211): audits it distinctly from ordinary "not found"/expiry, and
// revokes every session descended from the same login (FamilyID) — not just the one
// replayed row — mirroring standard OAuth refresh-token-family revocation. Each
// revoked session's token hash is evicted from the HTTP auth cache immediately, so
// the attacker's already-rotated descendant session (if any) stops authenticating on
// the very next request rather than lingering for the cache TTL.
func (c *KeyorixCore) handleSessionReuse(ctx context.Context, old *models.Session) {
	uid := old.UserID
	// Worded as a fact about what was DETECTED, not what the revoke below will
	// accomplish (txscan2/scratch/txscan2, Session O follow-up 2026-09-29): the
	// original "— revoking the session family" phrasing asserted an outcome
	// that hadn't happened yet at the point this event is written, and could
	// still fail (EventSessionReuseFamilyRevokeFailed below is the event that
	// actually reports whether it did). An operator reading only this event
	// must not conclude the family was revoked.
	c.writeAuditEventFull(ctx, EventSessionReuseDetected, &uid, nil, nil, old.IPAddress,
		fmt.Sprintf("refresh attempted with an already-rotated session token for user %d", old.UserID))
	if old.FamilyID == "" {
		// Legacy row predating FamilyID — fall back to revoking just this one row.
		if err := c.storage.DeleteSession(ctx, old.ID); err != nil {
			c.writeAuditEventFailed(ctx, EventSessionReuseFamilyRevokeFailed, &uid, nil, old.IPAddress,
				fmt.Sprintf("FAILED to revoke the reused session (legacy row, no family) for user %d: %v — the session may still be live, investigate immediately", old.UserID, err))
		}
		return
	}
	hashes, herr := c.storage.ListSessionTokenHashesByFamily(ctx, old.FamilyID)
	derr := c.storage.DeleteSessionsByFamily(ctx, old.FamilyID)
	if derr != nil {
		c.writeAuditEventFailed(ctx, EventSessionReuseFamilyRevokeFailed, &uid, nil, old.IPAddress,
			fmt.Sprintf("FAILED to revoke session family %q for user %d after reuse was detected: %v — the family may still be live, investigate immediately", old.FamilyID, old.UserID, derr))
	}
	if herr != nil {
		// The revocation above still ran (DeleteSessionsByFamily doesn't depend on
		// this list) — only the cache-eviction step below is degraded, leaving
		// revoked-but-still-cached tokens valid for up to the auth-cache TTL.
		c.writeAuditEventFailed(ctx, EventSessionReuseFamilyRevokeFailed, &uid, nil, old.IPAddress,
			fmt.Sprintf("failed to read session hashes for family %q (user %d) after reuse was detected: %v — DB rows were still revoked, but the auth cache could not be evicted and stale tokens may authenticate for up to the cache TTL", old.FamilyID, old.UserID, herr))
		return
	}
	for _, h := range hashes {
		if h != "" {
			c.invalidateTokenCache(h)
		}
	}
}

// authEffectiveNow returns a wall-clock reading that never regresses relative
// to what this process has already observed while validating a presented
// authentication credential's expiry (session/PAT/machine token/MFA step-up
// -- see authTokenClockWatermark's doc comment, service.go). CLAMPs rather
// than refuses: max(c.now(), authTokenClockWatermark), always advancing the
// watermark forward.
//
// .UTC() is not cosmetic here: it strips any monotonic clock reading Go
// attaches to a real time.Now() value (see time.Time's package doc). Two
// monotonic-carrying Time values compare using ONLY their monotonic delta,
// which never regresses even when the OS wall clock is stepped backward --
// so an unstripped watermark comparison would silently never detect the
// exact regression this mechanism exists to catch, matching #1635's own
// root-cause bug in checkSecretExpiryClockNotRegressed (fixed alongside this
// one, same root cause). rbacEffectiveNow (local_rbac.go, #1651) already
// gets this right by always being called with time.Now().UTC(); mirrored
// here explicitly rather than trusting every future caller of c.now() to
// remember to strip it themselves.
func (c *KeyorixCore) authEffectiveNow() time.Time {
	now := c.now().UTC()
	c.authTokenClockWatermarkMu.Lock()
	defer c.authTokenClockWatermarkMu.Unlock()
	if now.Before(c.authTokenClockWatermark) {
		return c.authTokenClockWatermark
	}
	c.authTokenClockWatermark = now
	return now
}

// ErrRoleResolutionUnavailable is returned by ValidateSessionToken,
// ValidatePATToken, ValidateMachineToken and ValidateOIDCToken when the
// credential itself checked out (found, unrevoked, unexpired, owning account
// active and not blocked / machine identity active) but the principal's role
// names could not be read from storage (#1944 for the two user-credential
// validators, #2748 for the two machine ones). It is deliberately distinct
// from every "invalid credential" error: the failure says nothing about the
// token, so callers must not treat it as a bad credential (no 401 / negative
// cache / brute-force strike) — the HTTP middleware answers 503 and the gRPC
// interceptor codes.Unavailable, so the client simply retries.
//
// Previously both validators soft-failed to an EMPTY role list with a nil
// error, handing back a half-built identity the HTTP middleware then
// positively cached (UserContext.Roles) for up to validTokenTTL — a snapshot
// that silently misreported the user's roles even after storage recovered.
// Not a privilege issue (zero roles only ever fails closed), but a wrong
// answer is worse than an honest retryable error. The underlying storage
// error is intentionally NOT wrapped in, so its detail never reaches an
// unauthenticated caller.
var ErrRoleResolutionUnavailable = errors.New("role resolution temporarily unavailable")

// ValidateSessionToken looks up a session token, checks expiry, and returns the user and
// their role names. Used by the auth middleware on every authenticated request.
// A storage failure while reading the user's roles returns
// ErrRoleResolutionUnavailable rather than an empty role list (#1944).
func (c *KeyorixCore) ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error) { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("session not found")
	}
	if session.ExpiresAt != nil && c.authEffectiveNow().After(*session.ExpiresAt) {
		return nil, nil, fmt.Errorf("session expired")
	}
	// Enforce the hard absolute-lifetime ceiling at the validation boundary, not only via
	// the clamp RefreshSession/mintSession apply to ExpiresAt. The clamp makes an expired
	// ceiling imply an expired access window in normal operation, but the ceiling must not
	// DEPEND on every issuer having clamped correctly — a session whose access window is
	// still open yet whose ceiling has passed (a future non-clamping path, or a tampered
	// row) is rejected here. Self-checking invariant.
	if session.AbsoluteExpiresAt != nil && c.authEffectiveNow().After(*session.AbsoluteExpiresAt) {
		return nil, nil, fmt.Errorf("session lifetime exceeded")
	}
	user, err := c.storage.GetUser(ctx, session.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}
	// Reject sessions whose account has since been deactivated or suspended, so an
	// admin's suspend/deactivate takes effect on already-issued tokens rather than
	// lingering until expiry. Mirrors the active-state check in ValidatePATToken.
	if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
		return nil, nil, fmt.Errorf("account is not active")
	}
	// For an impersonation session (acting AS session.UserID on behalf of an admin),
	// the impersonating admin's account must still be valid too — otherwise suspending
	// or deactivating the admin would not stop their in-flight impersonation, since the
	// session is keyed to the target's user_id and the gate above only checks the
	// target. Self-checking backstop alongside the session purge on state change.
	// MT-007/#G05: re-verify both the admin's active state and the ceiling (not
	// just the target's, checked above) so neither an elevation of the target's
	// roles NOR a demotion/suspension of the impersonating admin after
	// impersonation started silently persists for the rest of the session.
	// Cached (IMP-001) to avoid repeated DB queries on every session validation;
	// cache TTL is 2× the auth-cache window. See ReauthorizeImpersonation's doc
	// comment (impersonation.go) — StreamAuditLogs' dedicated re-auth ticker
	// (#108) runs the identical check for long-lived gRPC streams.
	if session.ImpersonatedBy != nil && *session.ImpersonatedBy != 0 {
		if err := c.ReauthorizeImpersonation(ctx, *session.ImpersonatedBy, session.UserID); err != nil {
			return nil, nil, err
		}
	}
	// Best-effort, throttled last-seen stamp for the My Account sessions view.
	// Only writes when the stored value is older than sessionTouchInterval, so the
	// auth hot path is not turned into a write per request. Never fails the request.
	// Stamped only AFTER the account-state gate, so a rejected request from a
	// suspended/deactivated account is not "used" — it must not refresh last-seen
	// (matching ValidatePATToken, which touches only after the same gate).
	_ = c.storage.TouchSession(ctx, session.ID, c.now(), sessionTouchInterval)
	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, nil, ErrRoleResolutionUnavailable
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return user, roleNames, nil
}

// SessionStillLive reports whether the session row sessionID is still the LIVE
// credential it was when it authenticated a long-lived gRPC stream (#G18).
// StreamAuditLogs' periodic reauthorizeAuditStream tick previously re-checked
// only the owning account's state (GetUser/IsActive/AccountLoginBlocked), never
// the SPECIFIC session that opened the stream — so an individually revoked
// session (e.g. "log out this device", or DeleteSessionsForUserExcept from a
// password change) kept receiving the live feed for the rest of the stream's
// lifetime, since account-level checks alone can't see that. Deliberately keyed
// by the session's numeric row id, not its raw token or hash: the token is
// validated once at stream-open and is not retained afterward (security
// hygiene — the gRPC auth interceptor tags UserContext.SessionID, a
// non-sensitive identifier, instead). Mirrors ValidateSessionToken's own
// liveness checks (row exists, not rotated away, within both the access-window
// and absolute-lifetime ceilings) without repeating its account-state gate —
// reauthorizeAuditStream already runs that check independently.
func (c *KeyorixCore) SessionStillLive(ctx context.Context, sessionID uint) (bool, error) {
	session, err := c.storage.GetSessionByID(ctx, sessionID)
	if err != nil {
		return false, err
	}
	if session.RotatedAt != nil {
		return false, nil
	}
	now := c.now()
	if session.ExpiresAt != nil && now.After(*session.ExpiresAt) {
		return false, nil
	}
	if session.AbsoluteExpiresAt != nil && now.After(*session.AbsoluteExpiresAt) {
		return false, nil
	}
	return true, nil
}

// hashSessionTokenForLookup mirrors internal/storage/store's own unexported
// hashSessionToken (SHA-256 hex) so SessionLiveForToken can compare against a
// session row's stored hash without exporting that helper across the storage
// boundary. Must stay byte-for-byte identical to the storage layer's version — a
// drift here would make every legitimate cache hit spuriously fail closed as a
// hash mismatch.
func hashSessionTokenForLookup(token string) string {
	// codeql[go/weak-sensitive-data-hashing] -- mirrors internal/storage/store's
	// hashSessionToken: token is a high-entropy random session token, not a
	// password, so a fast deterministic lookup hash is correct, not a slow KDF.
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SessionLiveForToken reports whether sessionID is still the SAME live session
// backing the presented token — the HTTP auth cache-hit path's (serveAuthCacheHit)
// session counterpart of CurrentPATRestriction/CurrentMachineTokenRestriction
// re-checking their own credential's live state on every cache hit, closing the
// gap AccountStillUsable alone leaves (a session revoked without touching the
// owning account's IsActive/AccountState — RevokeUserSessions, ChangePassword,
// MFA/WebAuthn enrollment changes, and others — was previously invisible to a
// cache hit for up to validTokenTTL; see docs/findings/2026-09-20-FINDING-
// session-revoke-cache-race.md).
//
// Distinct from SessionStillLive (the gRPC long-lived-stream re-auth path, #G18):
// SessionStillLive is deliberately keyed by row id ALONE — its caller does not
// retain the bearer token past the stream's opening request, by design, for
// credential-retention hygiene. serveAuthCacheHit, by contrast, already holds the
// token for THIS SAME request (the caller presented it moments ago), so comparing
// the row's own stored hash against it here adds a real invariant at no extra
// retention cost: sessionID must belong to the EXACT token presented, not merely
// be "some session that happens to still be live." Session rotation
// (RefreshSession/RotateSession, #211) creates a NEW row with a NEW hash and
// marks the OLD row's RotatedAt; it never rewrites an existing row's
// session_token in place, so a rotated-out old token's own sessionID already
// fails the RotatedAt check below without the hash comparison — but the hash
// comparison is what makes the check safe against ANY sessionID that doesn't
// actually belong to the presented token (a wiring bug, not rotation), not just
// that one case, and is what a rotation regression test asserts directly.
//
// Return contract (callers must not treat these the same):
//   - (false, nil): the session is DEFINITIVELY not live — row hard-deleted
//     (storage.ErrSessionNotFound / storage.IsSessionNotFound), hash mismatch,
//     rotated away, or expired. Callers must deny and evict, exactly like the
//     PAT/machine branches deny on ErrPATRevoked/ErrMachineTokenRevoked.
//   - (false, err) / (_, err) for any other error: the LOOKUP failed — a
//     transient storage error. Callers must fall back to the cached snapshot,
//     exactly like the PAT/machine branches do on any err besides the
//     specific revoked/expired sentinels — a DB blip must not lock out every
//     session holder. (GetSessionByID also has no RemoteStorage implementation,
//     which would hit this same branch, but that combination cannot occur in a
//     supported deployment: ADR-083 makes storage.type: remote a CLI/client
//     mode only, never wired into the server's own HTTP handlers — see
//     validateRemoteStorageNotServer — so this path is unreachable there, not
//     a deployment-relevant gap.)
func (c *KeyorixCore) SessionLiveForToken(ctx context.Context, sessionID uint, token string) (bool, error) {
	session, err := c.storage.GetSessionByID(ctx, sessionID)
	if err != nil {
		if storage.IsSessionNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if session.SessionToken != hashSessionTokenForLookup(token) {
		return false, nil
	}
	if session.RotatedAt != nil {
		return false, nil
	}
	now := c.now()
	if session.ExpiresAt != nil && now.After(*session.ExpiresAt) {
		return false, nil
	}
	if session.AbsoluteExpiresAt != nil && now.After(*session.AbsoluteExpiresAt) {
		return false, nil
	}
	return true, nil
}

// SessionAuthFacts is what a transport needs from the authenticating session's
// own row once ValidateSessionToken has accepted the token: which row it is (for
// the per-request liveness re-check, #G18), whether it is a setup-only session
// (#3024), who is impersonating through it, and when it expires (F-TOK-1).
type SessionAuthFacts struct {
	SessionID       uint
	SetupOnly       bool
	ImpersonatedBy  *uint
	EffectiveExpiry *time.Time
}

// EventSessionFactsUnavailable audits a request refused because its session row
// could not be re-read after the token validated (ResolveSessionAuthFacts).
const EventSessionFactsUnavailable = "auth.session_facts_unavailable" // #nosec G101 -- audit event type, not a credential

// ErrSessionFactsUnavailable is ResolveSessionAuthFacts' error: the transports
// refuse the request with their generic "temporarily unavailable" answer.
var ErrSessionFactsUnavailable = errors.New("session facts unavailable")

// ResolveSessionAuthFacts reads the session behind an already-validated session
// token ONCE and returns every per-session fact the HTTP middleware and the gRPC
// interceptor act on. An error is the fail-closed side: each of these facts
// restricts the caller (setup-only confinement, impersonation guards, the
// session-liveness re-check, the cache-lifetime clamp), so a request whose
// facts could not be read must be refused, never served with them defaulted to
// "no restriction" (#3041 review: a failed read used to leave SetupOnly false
// and cache it, so a setup-only session racing its own revocation got full
// access). The refusal is logged and audited under userID; transport names the
// caller ("http"/"grpc"). A revoked session (not found) takes this path too: the
// retry then fails validation with an ordinary 401.
func (c *KeyorixCore) ResolveSessionAuthFacts(ctx context.Context, userID uint, token, transport string) (*SessionAuthFacts, error) {
	session, err := c.getSessionRecovering(ctx, token)
	if err == nil && session == nil {
		err = errors.New("no session row")
	}
	if err == nil && session.UserID != userID {
		err = fmt.Errorf("session belongs to user %d", session.UserID)
	}
	if err != nil {
		log.Printf("SECURITY: %s request by user %d refused: its session could not be re-read after validation (%v)", transport, userID, err)
		c.writeAuditEventFull(ctx, EventSessionFactsUnavailable, &userID, nil, nil, "",
			fmt.Sprintf("a %s request by user %d was refused: its session could not be re-read after the token validated (%v), so its restrictions could not be applied", transport, userID, err))
		return nil, ErrSessionFactsUnavailable
	}
	facts := &SessionAuthFacts{SessionID: session.ID, SetupOnly: session.SetupOnly, ImpersonatedBy: session.ImpersonatedBy}
	for _, t := range []*time.Time{session.ExpiresAt, session.AbsoluteExpiresAt} {
		if t != nil && (facts.EffectiveExpiry == nil || t.Before(*facts.EffectiveExpiry)) {
			facts.EffectiveExpiry = t
		}
	}
	return facts, nil
}

// getSessionRecovering is storage.GetSession with a panic turned into an error,
// so ResolveSessionAuthFacts refuses rather than crashing the request.
func (c *KeyorixCore) getSessionRecovering(ctx context.Context, token string) (s *models.Session, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = nil, fmt.Errorf("session lookup panicked: %v", r)
		}
	}()
	return c.storage.GetSession(ctx, token)
}

// SessionEffectiveExpiry returns the earliest of a session's idle-expiry (ExpiresAt)
// and absolute-expiry (AbsoluteExpiresAt), or nil when the session has neither or
// cannot be resolved. The auth middleware calls this on the SLOW validation path only
// (once per token-cache fill) to CLAMP the positive cache entry's lifetime to the
// session's own — so an expired session cannot keep authenticating on a cache hit for
// the remainder of the cache's validTokenTTL window. Unlike PAT/machine tokens, whose
// expiry the middleware re-checks on every cache hit, the session cache-hit path only
// re-checks account state; clamping forces a slow-path re-validation (which DOES check
// session expiry) exactly at the session's expiry instead (F-TOK-1, 2026-09-14 review).
func (c *KeyorixCore) SessionEffectiveExpiry(ctx context.Context, token string) *time.Time {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil
	}
	var earliest *time.Time
	for _, t := range []*time.Time{session.ExpiresAt, session.AbsoluteExpiresAt} {
		if t == nil {
			continue
		}
		if earliest == nil || t.Before(*earliest) {
			earliest = t
		}
	}
	return earliest
}

// AccountStillUsable reports whether userID's account is still active and not
// login-blocked (ADR-025) — the same account-state gate ValidateSessionToken's
// slow path already applies, factored out so the auth middleware's cache-hit
// path (#G18) can re-check it on every request instead of only once per
// validTokenTTL. A user deactivated or suspended mid-window previously kept
// authenticating via the positive session cache for up to 30s after the
// slow-path re-validation would have rejected them outright.
func (c *KeyorixCore) AccountStillUsable(ctx context.Context, userID uint) (bool, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return false, err
	}
	return user.IsActive && !AccountLoginBlocked(user.ID, user.AccountState), nil
}

// AccountUsabilityAndState is AccountStillUsable's session-cache-hit sibling:
// the same GetUser read, but also returns the account's raw AccountState —
// needed to refresh UserContext.AccountState/Restricted on a cache hit, not
// just decide the outright-deny boolean. AccountStillUsable itself is left
// untouched (internal/cli/migrate/user_to_machine.go has its own, unrelated
// caller that only needs the boolean) — this is a second, additive method,
// not a signature change.
//
// The gap this closes: AccountLoginBlocked and AccountRestricted are NOT the
// same predicate (see AccountRestricted's own doc comment) —
// pending_first_login/password_reset_required are AccountRestricted but NOT
// AccountLoginBlocked. Before this, a cache hit's AccountStillUsable check
// passed (the account isn't blocked) but the CACHED UserContext's
// AccountState/Restricted — fixed at the slow path's last fill — stayed
// whatever it was then. A transition into a restricted-but-not-blocked state
// was invisible to EnforceAccountSetup on a cache hit until the entry's
// own eviction (whether via that state-change's own invalidateTokenCache call,
// or the TTL) actually landed — the same race SHAPE as the session-liveness
// bug this PR fixes elsewhere, not merely a bounded 30s lag: a request served
// from the cache in the window between the state committing and its own
// eviction reaching this process's cache still sees the pre-transition
// Restricted value. See serveAuthCacheHit's session branch.
func (c *KeyorixCore) AccountUsabilityAndState(ctx context.Context, userID uint) (usable bool, state string, err error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return false, "", err
	}
	return user.IsActive && !AccountLoginBlocked(user.ID, user.AccountState), user.AccountState, nil
}

// RequestPasswordReset issues a password-reset link for the given email and
// delivers it via the configured credential-delivery channel (ADR-028). The
// recipient consumes it at /auth/setup/{token} to set a new password
// (completePasswordSetup handles the password_reset_link purpose).
//
// Always returns nil: the outcome must not reveal whether the email maps to an
// account (enumeration-safe), so unknown addresses, suspended accounts, throttled
// repeats, and delivery/config failures are all swallowed. The attempt itself is
// audited inside provisionSetupLink.
//
// #117: the known-account path used to synchronously dial-and-send the email
// (SMTP delivery blocks on the real network round-trip) before returning, while
// an unknown/blocked/SSO-managed address returned after a single fast DB lookup
// — a measurable timing side-channel an attacker can use to enumerate valid
// accounts without ever seeing a different response body. The issue+deliver
// step now runs detached in the background (DetachedAuditContext, the same
// fire-and-forget pattern used elsewhere for post-response audit work) so this
// function returns at the same speed regardless of whether the email exists.
func (c *KeyorixCore) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil // Don't reveal whether the email exists.
	}
	// Never send a reset to a login-blocked (e.g. suspended) account.
	if AccountLoginBlocked(user.ID, user.AccountState) {
		return nil
	}
	// Refuse for externally-managed identities (SSO/SCIM): issuing a local password
	// would create a backdoor that authenticates at /auth/login and bypasses the IdP's
	// MFA / conditional access / deprovisioning. Swallowed to stay enumeration-safe.
	if user.ExternalID != "" {
		return nil
	}
	// Throttle abusive repeats to a victim address (same control as resend). A
	// throttled repeat returns an error here, swallowed below to stay enumeration-safe.
	// Detached from the request context: the HTTP handler returns immediately after
	// this call, which would cancel a request-scoped ctx before the SMTP send (or
	// even the throttle check) completes.
	detached := DetachedAuditContext(ctx)
	goSafe(func() {
		_, _ = c.provisionSetupLinkThrottled(detached, IssueSetupTokenRequest{
			Purpose:       SetupPurposePasswordResetLink,
			SubjectEmail:  user.Email,
			SubjectUserID: &user.ID,
			CreatedBy:     0, // self-service (no issuing admin)
		}, user.DisplayName, "")
	})
	return nil
}

// generateSecureToken creates a cryptographically random 32-byte hex token.
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
