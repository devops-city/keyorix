// reissue_otp.go — an administrator issues a NEW one-time password for an
// existing user (REISSUE-1). The existing-account counterpart of
// CreateUserWithOneTimePassword, for the user who lost or never used the
// first one (it expired, OTP-EXPIRY-1) or forgot the password they never
// got to change.
package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventUserOneTimePasswordReissued audits a successful reissue: actor = the
// administrator, subject = the user. The description never contains the password.
const EventUserOneTimePasswordReissued = "user.one_time_password_reissued" // #nosec G101 -- audit event type, not a credential

// EventUserOneTimePasswordReissueRestricted audits a reissue's first commit (the account
// restricted to a password change, every session ended): owed, so an audit outage never
// keeps a session alive. The new credential follows with EventUserOneTimePasswordReissued.
const EventUserOneTimePasswordReissueRestricted = "user.one_time_password_reissue_restricted" // #nosec G101 -- audit event type, not a credential

// Fixed client-facing texts of the two refusal sentinels below. The transports
// send these constants, never err.Error() (keyorix-raw-error-to-client).
const (
	ReissueExternalIdentityMessage = "this account is managed by an external identity provider; it has no local password to reissue"
	ReissueAccountBlockedMessage   = "account is suspended or inactive; reactivate it before reissuing a one-time password"
)

var (
	// ErrReissueExternalIdentity: the account is managed by an external identity
	// provider (SSO/SCIM). A local password would be a backdoor that bypasses the
	// IdP's MFA, conditional access and deprovisioning (same rule as
	// RequestPasswordReset and setup-link consume).
	ErrReissueExternalIdentity = errors.New(ReissueExternalIdentityMessage)

	// ErrReissueAccountBlocked: the account is suspended/deprovisioned/inactive.
	// Reissuing would put it into password_reset_required, which is a LOGIN-able
	// state, so it would silently reactivate the account. Reactivate it first,
	// deliberately.
	ErrReissueAccountBlocked = errors.New(ReissueAccountBlockedMessage)
)

// ReissueOneTimePassword issues a new server-generated one-time password for the
// existing user userID on behalf of administrator adminID, and returns it ONCE for
// the admin to relay out of band. The password is never stored in clear (only its
// bcrypt hash), never audited, never logged.
//
// In one transaction the account gets the new password hash, its OTP-EXPIRY-1
// expiry (the same TTL as an admin-created one-time-password user), the same
// restricted password_reset_required state CreateUserWithOneTimePassword puts a new
// user in (so the first login is confined to changing the password, and to MFA
// enrolment where security.require_mfa applies -- PendingAccountSetupSteps derives
// that from the account, nothing is stored here), a cleared login lockout, and
// every existing session of the user is deleted.
//
// PATs follow what the admin "require password reset" action already does
// (setAccountStateInTx): the account becomes restricted and every PAT is evicted from
// the auth cache so the restriction binds it immediately; the PATs are revoked when
// the user replaces the one-time password (applyNewPassword), like any credential
// change.
//
// An enrolled second factor is left alone: stripping it would let a users.write
// holder take over an MFA-protected account. (recover-admin clears MFA, but that is
// an offline, host-operator act.)
//
// Refused: the caller's own account (ErrCannotActOnSelf -- use recover-admin for
// that), an actor that does not meet the admin-rank ceiling of the target, an
// externally-managed (SSO/SCIM) account, and a suspended/inactive one (a reissue
// would otherwise reactivate it). Nothing is written on any refusal.
func (c *KeyorixCore) ReissueOneTimePassword(ctx context.Context, adminID, userID uint) (*OneTimePasswordResult, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: user ID is required", i18n.T("ErrorValidation", nil))
	}
	if adminID == 0 {
		// 0 is the "no human actor" / machine sentinel; a reissue is a human decision.
		return nil, fmt.Errorf("%w: a reissue needs an identified administrator", ErrInsufficientAdminAuthority)
	}
	if adminID == userID {
		return nil, fmt.Errorf("%w: use `keyorix-server admin recover-admin` to recover your own account", ErrCannotActOnSelf)
	}
	if err := c.requireAdminRankCeilingForTarget(ctx, adminID, userID, "reissue the one-time password of"); err != nil {
		return nil, err
	}

	otp, err := GenerateInitialCredential()
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(otp), PasswordHashCost())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	c.accountStateMu.Lock()
	defer c.accountStateMu.Unlock()

	now := c.now()
	expiresAt := now.Add(c.effectiveOneTimePasswordExpiry()).UTC()
	var target *models.User
	var evict []string
	// A reissue narrows access (the account is restricted to a password change and
	// every session ends) and widens it (a new credential, a cleared lockout): a mixed
	// request, so two commits (MERGE-FIX-3482G, audit_split.go). Commit 1, the
	// narrowing, is owed: an audit outage never keeps a session alive. Commit 2, the
	// credential, is fail closed: the reissue row commits with it or no password is
	// issued. Both validate on the row lock, not on an earlier read: the account may
	// have been suspended or linked to an IdP since.
	lockValid := func(tx storage.Storage) (*models.User, error) {
		locked, lerr := tx.LockUserForUpdate(ctx, userID)
		if lerr != nil {
			if errors.Is(lerr, storage.ErrUserNotFound) {
				return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), lerr)
			}
			// A storage fault is not a missing user: it surfaces as a server error
			// (500 / Internal), never as a 404 the admin would read as "no such user".
			return nil, lerr
		}
		if locked.ExternalID != "" {
			return nil, ErrReissueExternalIdentity
		}
		if !locked.IsActive || AccountLoginBlocked(locked.ID, locked.AccountState) {
			return nil, ErrReissueAccountBlocked
		}
		return locked, nil
	}
	aid := adminID
	settle, err := c.runOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		evict = nil // fn may run again (the owed fallback)
		locked, lerr := lockValid(tx)
		if lerr != nil {
			return lerr
		}
		target = locked
		// Restricts the account and collects the session + PAT hashes to evict.
		hashes, serr := c.setAccountStateInTx(ctx, tx, userID, AccountPasswordResetRequired)
		if serr != nil {
			return serr
		}
		evict = hashes
		if err := tx.DeleteSessionsForUserExcept(ctx, userID, 0); err != nil {
			return err
		}
		c.writeAuditEventFullOn(ctx, tgt, EventUserOneTimePasswordReissueRestricted, &aid, nil, nil, "",
			fmt.Sprintf("administrator %d is reissuing the one-time password of user %d (%s): account restricted to a password change, all existing sessions ended",
				adminID, target.ID, target.Username))
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrReissueExternalIdentity) || errors.Is(err, ErrReissueAccountBlocked) {
			return nil, err
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// After commit, so a rolled-back reissue never evicts a still-valid cache entry;
	// before the owed row and before commit 2, so the restriction binds at once.
	c.invalidateTokenCache(evict...)
	settle()

	if err := c.commitSplitRemainder(ctx, "account restriction and session end", "new one-time password", true, func(tx storage.Storage, tgt auditTarget) error {
		locked, lerr := lockValid(tx)
		if lerr != nil {
			return lerr
		}
		target = locked
		// SetPasswordHash clears any prior expiry; the new one is written in the same
		// transaction so the credential never exists without its expiry.
		if err := tx.SetPasswordHash(ctx, userID, string(hash), now); err != nil {
			return err
		}
		if err := tx.SetOneTimePasswordExpiry(ctx, userID, &expiresAt, now); err != nil {
			return err
		}
		if err := tx.UpdateLoginLockoutState(ctx, userID, 0, nil, nil, 0); err != nil {
			return err
		}
		c.writeAuditEventFullOn(ctx, tgt, EventUserOneTimePasswordReissued, &aid, nil, nil, "",
			fmt.Sprintf("administrator %d reissued the one-time password of user %d (%s): account restricted to a password change, all existing sessions ended, expires %s",
				adminID, target.ID, target.Username, expiresAt.Format(time.RFC3339)))
		return nil
	}); err != nil {
		return nil, err
	}

	// Best-effort, as in CreateUser: the reissue has already succeeded.
	besteffort.Run(ctx, "users.ReissueOneTimePassword.AddPasswordHistory", func() error {
		return c.storage.AddPasswordHistory(ctx, userID, string(hash), now)
	})

	// The compliance record that a human was shown a credential (artifact only, no value).
	c.auditCredentialDisplayedOutOfBand(ctx, &aid, target.Email, "one_time_password")

	return &OneTimePasswordResult{Email: target.Email, OTPValue: otp, ExpiresAt: expiresAt}, nil
}
