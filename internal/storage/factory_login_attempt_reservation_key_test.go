package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestLoginAttemptReservationKey_AddedOnUpgrade: an install whose
// login_attempts table predates identifiable reservations (#2956 follow-up)
// gains the reservation_key column AND its unique index on the next boot. The
// unique index is load-bearing, not a performance companion: it is what makes
// ReserveLoginAttempt idempotent per key, so without it a retried reservation
// would count twice.
func TestLoginAttemptReservationKey_AddedOnUpgrade(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "reservation-key.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}

	require.NoError(t, f.migrateDatabase(db))
	m := db.Migrator()
	require.True(t, m.HasColumn(&models.LoginAttempt{}, "ReservationKey"), "fresh install must have the column")
	require.True(t, indexExists(db, "idx_login_attempt_reservation_key"), "fresh install must have the unique index")

	// Simulate the pre-change schema.
	require.NoError(t, db.Exec("DROP INDEX idx_login_attempt_reservation_key").Error)
	require.NoError(t, m.DropColumn(&models.LoginAttempt{}, "ReservationKey"))
	require.False(t, m.HasColumn(&models.LoginAttempt{}, "ReservationKey"))

	require.NoError(t, f.migrateDatabase(db))
	require.True(t, m.HasColumn(&models.LoginAttempt{}, "ReservationKey"), "upgrade must add the column")
	require.True(t, indexExists(db, "idx_login_attempt_reservation_key"), "upgrade must add the unique index")

	key := "k1"
	require.NoError(t, db.Create(&models.LoginAttempt{IP: "198.51.100.1", ReservationKey: &key}).Error)
	require.Error(t, db.Create(&models.LoginAttempt{IP: "198.51.100.1", ReservationKey: &key}).Error,
		"the upgraded index must be UNIQUE: a second row with the same key is what idempotency forbids")
	require.NoError(t, db.Create(&models.LoginAttempt{IP: "198.51.100.1"}).Error)
	require.NoError(t, db.Create(&models.LoginAttempt{IP: "198.51.100.1"}).Error, "keyless rows never conflict")
}
