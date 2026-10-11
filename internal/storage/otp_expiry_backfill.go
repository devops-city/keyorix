package storage

import (
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"
)

// LegacyOneTimePasswordGrace is how long a one-time password that already existed
// when users.one_time_password_expires_at was introduced keeps working: upgrade time
// plus this window (OTP-EXPIRY-1).
//
// It equals the recover-admin default (24h), the shortest of the two defaults, on
// purpose: the legacy rows cannot be told apart by kind (see
// backfillLegacyOneTimePasswordExpiry), and the riskiest of them is a recover-admin
// credential on an admin account, so the rule is sized for that one.
const LegacyOneTimePasswordGrace = 24 * time.Hour

// backfillLegacyOneTimePasswordExpiry gives every live account that is still waiting
// on a password change an expiry of now + LegacyOneTimePasswordGrace.
//
// Before OTP-EXPIRY-1 nothing recorded that a password was a one-time one, and the
// two creators (admin `--one-time-password`, recover-admin) leave the account in
// exactly the state an admin-forced reset or an expired-password gate does:
// password_reset_required, with the password hash set. The two cannot be separated
// afterwards (password_changed_at and updated_at are written by both and bumped by
// failed logins), so the rule fails closed: every password_reset_required account
// gets the window, and an account whose owner has not changed their password by then
// has to be re-issued a one-time password by an admin. The alternative (leaving them
// all without an expiry) would keep every pre-upgrade recover-admin password valid
// forever, which is the gap this change closes.
//
// pending_first_login is not touched: those accounts hold a random unusable
// password, and the credential is a setup link with its own expiry.
//
// NOT idempotent by design: it must run exactly once, per legacy data set: in the
// same transaction that adds the column (factory.go), or, for a restored pre-expiry
// archive, in the transaction that loads it (BackfillLegacyOneTimePasswordExpiry).
// Re-running it on a later boot would put an expiry on accounts forced into a reset
// after the upgrade.
func backfillLegacyOneTimePasswordExpiry(tx *gorm.DB, now time.Time) error {
	res := tx.Exec(
		"UPDATE users SET one_time_password_expires_at = ? WHERE account_state = ? AND deleted_at IS NULL",
		now.Add(LegacyOneTimePasswordGrace), "password_reset_required")
	if res.Error != nil {
		return fmt.Errorf("failed to backfill one_time_password_expires_at: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		log.Printf("SECURITY: %d account(s) in password_reset_required had no recorded one-time-password expiry; "+
			"each now expires %s after this upgrade (%s) and will then refuse login until an administrator "+
			"re-issues a one-time password. Accounts that changed their password in time are unaffected.",
			res.RowsAffected, LegacyOneTimePasswordGrace, now.Add(LegacyOneTimePasswordGrace).UTC().Format(time.RFC3339))
	}
	return nil
}
