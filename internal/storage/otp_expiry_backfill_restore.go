package storage

import (
	"time"

	"gorm.io/gorm"
)

// BackfillLegacyOneTimePasswordExpiry is the one-off legacy rule
// (backfillLegacyOneTimePasswordExpiry) for a restore. An archive taken before
// users.one_time_password_expires_at existed is loaded into a database that already
// HAS the column (the fresh target was just migrated), so the migration's
// column-absent gate never fires and the loaded password_reset_required rows would
// carry no expiry: credentials that never expire. The restore calls this inside the
// load transaction when the archive's users table lacks the column.
func BackfillLegacyOneTimePasswordExpiry(tx *gorm.DB, now time.Time) error {
	return backfillLegacyOneTimePasswordExpiry(tx, now)
}
