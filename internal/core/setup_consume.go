// setup_consume.go — public consumption of credential-delivery setup tokens (ADR-028).
//
// These power the unauthenticated landing page a new principal reaches via their
// setup link: a GET that describes the token (no secrets) so the page can render the
// right form, and the consume that sets the password and lands the user logged in.
//
// The password-setting purposes (account_setup, password_reset_link) act on an
// existing account; invitation_accept lazily creates the invited account and
// materializes its project membership (ADR-024). Each is dispatched by purpose.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrInvalidSetupPassword wraps a password-policy rejection during setup-token
// consume. It is the ONLY consume failure whose reason is safe (and useful) to
// surface to the unauthenticated caller — the link stays live so they can retry.
// Every other failure (dead token, missing/duplicate account, internal error) is
// reported generically by the HTTP layer so the public endpoint is not an
// account-existence / error-string oracle.
var ErrInvalidSetupPassword = errors.New("invalid password")

// SetupTokenInfo is the non-sensitive description of a setup token returned to the
// landing page. It deliberately carries no token, no hash, and no secret material.
type SetupTokenInfo struct {
	Purpose     string `json:"purpose"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
}

// SetupConsumeResult is returned after a setup token is consumed: the freshly minted
// session (auto-login) plus the user it belongs to, so the HTTP layer can build a
// login-shaped response.
type SetupConsumeResult struct {
	Session *models.Session
	User    *models.User
}

// DescribeSetupToken validates a raw setup token (without consuming it) and returns
// a non-sensitive description for the landing page, or an error if the token is
// unknown, expired, or otherwise not active. It is the GET /auth/setup/{token} path.
func (c *KeyorixCore) DescribeSetupToken(ctx context.Context, raw string) (*SetupTokenInfo, error) {
	tok, err := c.inspectActiveSetupToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	info := &SetupTokenInfo{Purpose: tok.Purpose, Email: tok.SubjectEmail}
	// Resolve a friendly name when the account already exists (best-effort; never
	// leaks more than the display name the user set).
	if tok.SubjectUserID != nil {
		if u, uerr := c.storage.GetUser(ctx, *tok.SubjectUserID); uerr == nil {
			info.DisplayName = u.DisplayName
		}
	}
	return info, nil
}

// CompleteSetup consumes a setup token and materializes its effect. For the
// account_setup and password_reset_link purposes it: validates the new password
// BEFORE spending the token (a weak password must not burn the link), atomically
// consumes the token, sets the password (clearing the account back to active), and
// mints a login session so the user lands authenticated. The invitation_accept
// purpose is completed by the invitation producer, not here.
func (c *KeyorixCore) CompleteSetup(ctx context.Context, raw, newPassword, userAgent, ip string) (*SetupConsumeResult, error) {
	tok, err := c.inspectActiveSetupToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	return c.completeValidSetupToken(ctx, tok, newPassword, userAgent, ip)
}

// completeValidSetupToken is everything CompleteSetup does once the token is
// known to be valid. A PANIC anywhere in it comes back as an error (#3277
// follow-up), which the HTTP layer answers with its generic "could not be
// completed" 400, exactly as it answers this path's errors. A dead or forged
// token never gets here, so the Recovery 500 a panic used to reach told the
// caller the token was valid.
//
// Commit-aware the same way the error kinds are: a session written before the
// panic is deleted by createSession and its token never returned
// (mintLoginSession). Nothing that runs after the session is minted can panic
// out (deleteSessionsForUserAndEvict and the audit writes recover their own),
// so a recovered panic never follows a minted session. Whatever else committed
// before the panic (the consumed token, the new password) is what the same
// write's error leaves too.
func (c *KeyorixCore) completeValidSetupToken(ctx context.Context, tok *models.SetupToken, newPassword, userAgent, ip string) (result *SetupConsumeResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: setup token %d completion panicked after the token was validated; "+
				"refusing it like its error: %v\n%s", tok.ID, r, debug.Stack())
			result, err = nil, fmt.Errorf("%s: setup completion panicked: %v", i18n.T("ErrorStorageFailed", nil), r)
		}
	}()
	switch tok.Purpose {
	case SetupPurposeAccountSetup, SetupPurposePasswordResetLink:
		return c.completePasswordSetup(ctx, tok, newPassword, userAgent, ip)
	case SetupPurposeInvitationAccept:
		return c.completeInvitationAccept(ctx, tok, newPassword, userAgent, ip)
	default:
		return nil, fmt.Errorf("%s: setup token purpose %q is not completed at this endpoint", i18n.T("ErrorValidation", nil), tok.Purpose)
	}
}

// completePasswordSetup handles account_setup / password_reset_link: set the existing
// subject's password and auto-log them in.
func (c *KeyorixCore) completePasswordSetup(ctx context.Context, tok *models.SetupToken, newPassword, userAgent, ip string) (*SetupConsumeResult, error) {
	if tok.SubjectUserID == nil {
		return nil, fmt.Errorf("%s: setup token has no subject account", i18n.T("ErrorValidation", nil))
	}
	user, err := c.storage.GetUser(ctx, *tok.SubjectUserID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	// A suspended account cannot be activated via a setup link.
	if AccountLoginBlocked(user.ID, user.AccountState) {
		return nil, fmt.Errorf("account suspended")
	}
	// Externally-managed identities (SSO/SCIM) must not get a local password: it would
	// be a backdoor that authenticates at /auth/login and bypasses the IdP entirely.
	// This is the critical gate — even if a link was somehow issued, consuming it for a
	// federated account is refused.
	if user.ExternalID != "" {
		return nil, fmt.Errorf("%s: this account is managed by an external identity provider; set a password through your IdP", i18n.T("ErrorValidation", nil))
	}

	// Validate the password BEFORE consuming the token, so a policy rejection lets
	// the user retry with the same link instead of dead-ending on a spent token.
	if err := c.validateNewPassword(ctx, user, newPassword); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSetupPassword, err)
	}

	// Consume is single-use and atomic; from here the token is spent (fail-closed).
	// tok was already inspected by CompleteSetup, so consume it directly (no re-lookup).
	if err := c.consumeInspectedToken(ctx, tok, tok.Purpose); err != nil {
		return nil, err
	}
	if err := c.applyNewPassword(ctx, user, newPassword); err != nil {
		return nil, err
	}

	// Accounts with any second factor (TOTP or a passkey) enrolled must NOT get an
	// auto-login session from a password reset — that would silently bypass MFA for
	// this session, mirroring exactly the gate Login applies after the password step
	// (see ErrMFARequired in auth.go). Still evict every existing session (keepID=0,
	// i.e. keep none) so a stolen session is locked out immediately, same invariant as
	// the auto-login path below — the reset must not leave a thief's session alive
	// just because the new session isn't minted yet. The caller completes the second
	// factor via CreateMFAChallenge → VerifyMFALogin (or the WebAuthn ceremony) using
	// the password that was just accepted.
	if user.MFAEnabled || user.WebAuthnEnabled {
		_ = c.deleteSessionsForUserAndEvict(ctx, user.ID, 0, "")
		c.writeAuditEventFull(ctx, "account.setup_completed", &user.ID, nil, nil, ip,
			fmt.Sprintf("account setup completed via %s (MFA required before session)", tok.Purpose))
		return &SetupConsumeResult{User: user}, ErrMFARequired
	}

	// The token is spent: a panic in the insert is answered like its error
	// (#3277 follow-up, mintLoginSession), never the Recovery 500 a dead token
	// cannot get.
	session, err := c.mintLoginSession(ctx, user.ID, userAgent, ip, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Evict every other session for this account, keeping only the one just minted, and
	// drop those sessions from the auth cache so a stolen session is locked out on its
	// next request, not after the cache TTL. A self-service password reset must lock out
	// anyone holding a stolen session (and a re-provision must drop stale ones) — matching
	// ChangePassword's invalidate-other-devices invariant, which this path previously skipped.
	_ = c.deleteSessionsForUserAndEvict(ctx, user.ID, session.ID, session.SessionToken)

	c.writeAuditEventFull(ctx, "account.setup_completed", &user.ID, nil, nil, ip,
		fmt.Sprintf("account setup completed via %s", tok.Purpose))

	return &SetupConsumeResult{Session: session, User: user}, nil
}

// completeInvitationAccept handles invitation_accept: lazily create the invited
// account (ADR-024/ADR-028), accept the invitation, create a project membership
// honouring the validation mode snapshotted at invite time (which grants the role
// when the mode lands it active), and auto-log the user in.
func (c *KeyorixCore) completeInvitationAccept(ctx context.Context, tok *models.SetupToken, newPassword, userAgent, ip string) (*SetupConsumeResult, error) {
	if tok.InvitationID == nil {
		return nil, fmt.Errorf("%s: invitation token has no invitation", i18n.T("ErrorValidation", nil))
	}
	inv, err := c.storage.GetProjectInvitation(ctx, *tok.InvitationID)
	if err != nil {
		return nil, fmt.Errorf("%s: invitation not found", i18n.T("ErrorNotFound", nil))
	}
	// Lazy-expire an overdue invite, then require it still be pending. Best-effort:
	// if a concurrent revoke/accept already resolved this invitation, that
	// transition wins and the conditional write no-ops; the state check below
	// still refuses to proceed either way.
	c.expireInvitationIfOverdue(ctx, inv)
	if inv.State != InvitationPending {
		return nil, fmt.Errorf("%s: invitation is %s", i18n.T("ErrorValidation", nil), inv.State)
	}

	// SECURITY: if an account already exists for this email, the invite link must NOT
	// log them in — that would bypass their real password. Reject and route them to
	// the normal add-member flow. Fail CLOSED: a lookup error that is NOT a clean
	// "not found" must abort rather than be read as "no account" (which would let a
	// transient store error slip the guard and mint a duplicate identity). Email
	// matching is case-insensitive (see GetUserByEmail) so "Bob@x" cannot evade a
	// "bob@x" invite. The message is deliberately generic (the HTTP layer keeps this
	// endpoint from being an account-existence oracle).
	existing, eerr := c.storage.GetUserByEmail(ctx, inv.Email)
	if eerr == nil && existing != nil {
		return nil, fmt.Errorf("%s: an account already exists for this email; ask an admin to add you to the project directly", i18n.T("ErrorValidation", nil))
	}
	if eerr != nil && !isUserNotFound(eerr) {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), eerr)
	}

	// Validate the password before consuming (a weak password must not burn the link).
	// No account exists yet, so this is policy-only (no history to check).
	if err := c.passwordPolicy.Validate(newPassword, nil); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSetupPassword, err)
	}

	// Lazily create the account with the chosen password (active — they just set it).
	// SECURITY (#155): create the account BEFORE consuming the token, not after. If a
	// concurrent account-creation for the same email (e.g. another invite, an admin
	// directly adding the address) wins the race, CreateUser fails here and the token
	// is left untouched, so the legitimate holder can retry the SAME link — at which
	// point the GetUserByEmail guard above now sees the winning account and returns
	// the clean "account already exists" message instead of a dead "token already
	// used" error. Consuming up front (the previous order) permanently burned the
	// invite link for the loser of that race even though nothing unsafe happened.
	username, err := c.deriveUsername(ctx, inv.Email)
	if err != nil {
		return nil, err
	}
	user, err := c.CreateUser(ctx, &CreateUserRequest{
		Username:    username,
		Email:       inv.Email,
		DisplayName: displayNameFromEmail(inv.Email),
		Password:    newPassword,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogUserCreated(ctx, 0, user.ID, user.Username) // self-service: the invitee (not yet an account) is consuming their own invite link

	// Consume the token (single-use, atomic) now that the account exists. tok was
	// already inspected by CompleteSetup, so consume it directly (no re-lookup).
	if err := c.consumeInspectedToken(ctx, tok, SetupPurposeInvitationAccept); err != nil {
		return nil, err
	}

	// Materialize the invitation's grants under the invite-time validation mode. For a
	// project-scoped invite that's the single project role; for a global invite it's
	// the system role plus every project assignment (ADR-024). This grants project
	// roles immediately when the mode (e.g. open) lands them active; under allowlist a
	// membership starts in `invited` for an admin to advance. Done BEFORE flipping the
	// invitation to accepted: if any grant fails, the invitation stays pending
	// (resendable / revocable) rather than being falsely marked accepted with no
	// grants behind it.
	if err := c.applyInvitationGrants(ctx, inv, user.ID); err != nil {
		// Session O follow-up (2026-09-29, coordinator hand-found candidate): the
		// account just created above has zero grants and the setup token that led
		// here is already spent (single-use, by design) -- without reverting the
		// account, the invitee is stuck permanently: the SAME link can't be
		// replayed (token consumed), and a resent link (a fresh token for this
		// same still-pending invitation) hits the "account already exists" guard
		// above on the very next attempt, with no self-service way out. Soft-delete
		// the orphaned account so a resend starts clean — both the email and
		// username uniqueness indexes are partial (`WHERE deleted_at IS NULL`,
		// see models.User's own doc comments), so this is safe: a subsequent
		// CreateUser for the same address does not collide with the deleted row.
		if derr := c.storage.DeleteUser(ctx, user.ID); derr != nil {
			c.auditProjectScoped(ctx, "invitation.accept_orphaned_account_cleanup_failed", user.ID, inv.ProjectID,
				fmt.Sprintf("invitation %d: grants failed for %s (user %d): %v -- AND cleaning up the resulting ungranted account also failed: %v -- MANUAL CLEANUP REQUIRED (delete or complete this account by hand, or the invitee is stuck)", inv.ID, inv.Email, user.ID, err, derr))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Mark the invitation accepted (only now that account + membership both exist).
	// Conditional on the invitation still being pending (#412): the grants above
	// were already applied, so if an admin's RevokeInvitation won a concurrent race
	// and flipped the row to revoked in the window since the pending check at the
	// top of this function, this write must not silently re-establish "accepted"
	// over a revoke — and the grant that already landed must not survive it.
	now := c.now()
	inv.State = InvitationAccepted
	inv.AcceptedAt = &now
	ok, uerr := c.storage.UpdateProjectInvitation(ctx, inv)
	if uerr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), uerr)
	}
	if !ok {
		// Lost the race: the invitation was concurrently revoked (or lazily
		// expired) after the grants above were applied. Best-effort revoke the
		// membership/role(s) just granted so a revoked invitation can't leave a
		// live grant behind, then fail closed — no session is minted below.
		c.revokeInvitationGrants(ctx, inv, user.ID)
		c.auditProjectScoped(ctx, "invitation.accept_race_reverted", user.ID, inv.ProjectID,
			fmt.Sprintf("invitation %d was concurrently revoked/resolved while %s (user %d) was accepting it; reverted the grant(s) just made", inv.ID, inv.Email, user.ID))
		return nil, fmt.Errorf("%s: this invitation was revoked", i18n.T("ErrorValidation", nil))
	}

	c.auditProjectScoped(ctx, "invitation.accepted", user.ID, inv.ProjectID,
		fmt.Sprintf("invitation %d accepted by %s (user %d)", inv.ID, inv.Email, user.ID))

	// The token is spent: a panic in the insert is answered like its error
	// (#3277 follow-up, mintLoginSession), never the Recovery 500 a dead token
	// cannot get.
	session, err := c.mintLoginSession(ctx, user.ID, userAgent, ip, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return &SetupConsumeResult{Session: session, User: user}, nil
}

// expireInvitationIfOverdue lazily marks an invitation expired when it is still
// pending but past its deadline. Best-effort: a concurrent revoke/accept may
// have already transitioned the state, in which case the conditional write
// no-ops. The caller must re-check inv.State after this returns.
func (c *KeyorixCore) expireInvitationIfOverdue(ctx context.Context, inv *models.ProjectInvitation) {
	if inv.State == InvitationPending && inv.ExpiresAt != nil && c.now().After(*inv.ExpiresAt) {
		inv.State = InvitationExpired
		_, _ = c.storage.UpdateProjectInvitation(ctx, inv)
	}
}

// deriveUsername builds a unique, alphanumeric username from an email's local part,
// appending a numeric suffix on collision. Best-effort: CreateUser re-checks
// uniqueness, so a racy lookup at worst surfaces there.
func (c *KeyorixCore) deriveUsername(ctx context.Context, email string) (string, error) {
	base := sanitizeUsername(localPart(email))
	if len(base) < 3 {
		base += "user"
	}
	candidate := base
	for i := 1; i <= 1000; i++ {
		if _, err := c.storage.GetUserByUsername(ctx, candidate); err != nil {
			return candidate, nil // not found → available
		}
		candidate = fmt.Sprintf("%s%d", base, i)
	}
	return "", fmt.Errorf("%s: could not derive a unique username for %s", i18n.T("ErrorValidation", nil), email)
}

// localPart returns the part of an email before '@' (or the whole string if none).
func localPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

// sanitizeUsername lowercases and keeps only [a-z0-9].
func sanitizeUsername(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// displayNameFromEmail derives a human-facing default name from an email.
func displayNameFromEmail(email string) string {
	if lp := localPart(email); lp != "" {
		return lp
	}
	return email
}

// isUserNotFound reports whether err is the storage layer's "user not found"
// signal (#504) — LocalStorage's wrapped ErrUserNotFound sentinel. Used to fail
// closed on a real lookup error while treating a clean miss as "no existing
// account". See storage.IsUserNotFound.
func isUserNotFound(err error) bool {
	return storage.IsUserNotFound(err)
}
