package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// One-time passwords expire (OTP-EXPIRY-1). Every one-time password the system
// issues carries an expiry; after it the password is refused at login exactly like
// a wrong one (same error, same latency, counted toward the account lockout) and
// the refusal is audited server-side. A new password (SetPasswordHash) clears the
// expiry.
const (
	// DefaultRecoveryOneTimePasswordTTL is the default life of the one-time password
	// `keyorix-server admin recover-admin` issues: an admin credential issued
	// out-of-band should be used the same day.
	DefaultRecoveryOneTimePasswordTTL = 24 * time.Hour

	// DefaultOneTimePasswordTTL is the default life of an admin-created
	// (`user create --one-time-password`) one-time password. Longer than recovery's
	// because the recipient is a new colleague who may not log in until the next
	// working day, and 72h still covers a weekend; the cost of expiry is only that
	// the admin issues another.
	DefaultOneTimePasswordTTL = 72 * time.Hour
)

// EventOneTimePasswordExpired audits a login attempt that presented the correct but
// expired one-time password. It is written server-side only; the client sees the
// ordinary "invalid credentials" response.
const EventOneTimePasswordExpired = "auth.one_time_password_expired" // #nosec G101 -- audit event type, not a credential

// SetOneTimePasswordTTL sets the life of admin-created one-time passwords
// (security.one_time_password_ttl). A non-positive value restores the default:
// there is deliberately no way to configure "never expires".
func (c *KeyorixCore) SetOneTimePasswordTTL(d time.Duration) {
	c.oneTimePasswordTTL = d
}

func (c *KeyorixCore) effectiveOneTimePasswordTTL() time.Duration {
	if c.oneTimePasswordTTL > 0 {
		return c.oneTimePasswordTTL
	}
	return DefaultOneTimePasswordTTL
}

// oneTimePasswordExpired reports whether u's one-time password has expired at now.
// A user with no recorded expiry has an ordinary password and is never expired.
func oneTimePasswordExpired(u *models.User, now time.Time) bool {
	return u.OneTimePasswordExpiresAt != nil && !now.Before(*u.OneTimePasswordExpiresAt)
}

// refuseExpiredOneTimePassword is called by VerifyPasswordCredentials after the
// password itself matched. It returns true when the credential is an expired
// one-time password, in which case the caller must treat the login exactly as a
// wrong password: the failure is counted toward the lockout here and audited, and
// the caller returns its ordinary "invalid credentials" error. The audit text names
// the account and the expiry but never the password.
func (c *KeyorixCore) refuseExpiredOneTimePassword(ctx context.Context, user *models.User) bool {
	now := c.now()
	if !oneTimePasswordExpired(user, now) {
		return false
	}
	c.recordFailedLogin(ctx, user)
	uid := user.ID
	desc := fmt.Sprintf("login refused for user %d: the one-time password expired at %s",
		uid, user.OneTimePasswordExpiresAt.UTC().Format(time.RFC3339))
	// Asynchronous (goSafe), like the transport's auth.login_failed audit: a
	// synchronous hash-chained insert here, on the expired branch only, would make it
	// measurably slower than the wrong-password branch and turn the audit itself into
	// the timing oracle this change exists to avoid (see denyAfterCredentialMatched).
	// Detached so the write outlives the request context.
	detached := DetachedAuditContext(ctx)
	goSafe(func() {
		c.writeAuditEventFailed(detached, EventOneTimePasswordExpired, &uid, nil, "", desc)
	})
	return true
}
