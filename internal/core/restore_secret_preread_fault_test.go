// restore_secret_preread_fault_test.go — #2694, the one real hit of
// TestLockOrder_InProcessLocksFollowDeclaredOrder on main.
//
// RestoreSecret reads the secret first to learn its environment, takes that
// environment's named lock, and only then opens the restore transaction. When
// the read failed it used to carry on with no lock: the storage restore re-read
// the row inside the transaction and took the environment lock there, inside
// the transaction (SQLite: holding the write gate while queueing for a lock
// whose holder may be queueing for the gate). Now a failed read restores
// nothing.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestRestoreSecret_PreReadFaultRestoresNothing(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{},
		&models.UserRole{}, &models.GroupRole{}, &models.UserGroup{}, &models.Role{}, &models.Group{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	))
	base := store.NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 7, ProjectID: 1, Name: "env"}).Error)
	s, err := base.CreateSecret(ctx, &models.SecretNode{Name: "k", ProjectID: 1, EnvironmentID: 7, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	require.NoError(t, base.DeleteSecret(ctx, s.ID))

	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "GetSecretIncludingDeleted", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: GetSecretIncludingDeleted"),
	})
	c := &KeyorixCore{storage: fs, now: time.Now}
	err = c.RestoreSecret(ctx, 42, s.ID)

	require.True(t, fs.Fired(), "the pre-read must have been attempted and faulted")
	require.Error(t, err, "a failed pre-read must fail the restore")
	assert.Contains(t, err.Error(), "injected: GetSecretIncludingDeleted")
	var row models.SecretNode
	require.NoError(t, db.Unscoped().First(&row, s.ID).Error)
	assert.True(t, row.DeletedAt.Valid, "the secret must still be soft-deleted: the restore must not have run")
	var restored int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventSecretRestored).Count(&restored).Error)
	assert.Zero(t, restored, "no secret.restored row for a restore that did not happen")

	// Calibration: the same restore without the fault succeeds.
	require.NoError(t, (&KeyorixCore{storage: base, now: time.Now}).RestoreSecret(ctx, 42, s.ID))
}
