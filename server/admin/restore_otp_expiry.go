package admin

import (
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// otpExpiryColumn is users.one_time_password_expires_at (OTP-EXPIRY-1).
const otpExpiryColumn = "one_time_password_expires_at"

// archiveLacksOTPExpiry reports whether the archive has a users table that predates
// the one-time-password expiry column.
func archiveLacksOTPExpiry(manifest backupfmt.Manifest) bool {
	for _, te := range manifest.Tables {
		if te.Name != "users" {
			continue
		}
		for _, col := range te.Columns {
			if col == otpExpiryColumn {
				return false
			}
		}
		return true
	}
	return false
}

// backfillOTPExpiryForOlderArchive applies the upgrade rule to a restored pre-expiry
// archive. Restore migrates a FRESH database (the column exists) and then loads the
// archive, so the migration's one-off backfill, gated on the column being absent,
// never runs; without this, every password_reset_required account in an older
// archive would come back with a one-time password that never expires. It runs in
// the load transaction, so the load and the stamp are atomic. An archive that has
// the column is loaded as-is: a NULL there is real data, not a legacy row.
func backfillOTPExpiryForOlderArchive(tx *gorm.DB, manifest backupfmt.Manifest) error {
	if !archiveLacksOTPExpiry(manifest) {
		return nil
	}
	return storage.BackfillLegacyOneTimePasswordExpiry(tx, time.Now().UTC())
}
