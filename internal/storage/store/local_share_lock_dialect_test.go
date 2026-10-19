package store

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// shareLockSQL returns the SQL LockShareRecordForUpdate issues against db, as a
// DryRun session (nothing is executed).
func shareLockSQL(t *testing.T, db *gorm.DB) string {
	t.Helper()
	capture := &sqlCapture{Interface: logger.Discard}
	db = db.Session(&gorm.Session{DryRun: true, Logger: capture})
	_, _ = NewLocalStorage(db).LockShareRecordForUpdate(context.Background(), 1)
	require.Len(t, capture.sql, 1, "the lock lookup must issue exactly one SELECT")
	return capture.sql[0]
}

// TestLockShareRecordForUpdate_DialectMatchedLocking is the default-CI half of
// SHARE-CAS-1: Postgres MUST be sent FOR UPDATE (core.UpdateSharePermission's
// classification holds until its write only through this lock) and the read
// stays soft-delete scoped; SQLite emits none. Same limits as
// TestLockMachineIdentityForUpdate_DialectMatchedLocking: the Postgres subtest
// is the load-bearing one, the SQLite one guards GORM's driver dropping the
// clause. That the lock serializes two replicas is the pg-gated
// TestCTAReview_UpdateSharePermission_*VsConcurrent*_CrossReplicaPostgres in
// internal/core.
func TestLockShareRecordForUpdate_DialectMatchedLocking(t *testing.T) {
	t.Run("sqlite omits FOR UPDATE", func(t *testing.T) {
		db := newMachineStore(t).db
		assert.NotContains(t, strings.ToUpper(shareLockSQL(t, db)), "FOR UPDATE")
	})

	t.Run("postgres adds FOR UPDATE", func(t *testing.T) {
		db, err := gorm.Open(
			postgres.New(postgres.Config{DSN: "host=127.0.0.1 port=1 user=x dbname=x sslmode=disable"}),
			&gorm.Config{DisableAutomaticPing: true, Logger: logger.Discard},
		)
		require.NoError(t, err)
		sql := strings.ToUpper(shareLockSQL(t, db))
		assert.Contains(t, sql, "FOR UPDATE")
		assert.Contains(t, sql, "DELETED_AT\" IS NULL", "the locked read must not see a revoked share")
	})
}
