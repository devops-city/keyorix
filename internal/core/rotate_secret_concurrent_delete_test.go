package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// afterFirstGetSecret runs hook once, right after the first GetSecret returns: the window
// between RotateSecret's read of the row and its write.
type afterFirstGetSecret struct {
	inner storage.Storage
	hook  func()
	done  bool
}

func (s *afterFirstGetSecret) GetSecret(next storage.Storage, ctx context.Context, id uint) (*models.SecretNode, error) {
	sec, err := next.GetSecret(ctx, id)
	if !s.done {
		s.done = true
		s.hook()
	}
	return sec, err
}

// wrap returns inner decorated with afterFirstGetSecret's overrides.
func (s *afterFirstGetSecret) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		GetSecret: s.GetSecret,
	})
}

// store returns s.inner decorated with afterFirstGetSecret's overrides.
func (s *afterFirstGetSecret) store() storage.Storage { return s.wrap(s.inner) }

// TestRotateSecret_ConcurrentDelete_LeavesNoOrphanVersion pins #2873 for a secret with no
// rotation backend: a DeleteSecret that commits between RotateSecret's read and its write
// makes the rotation fail AND leaves no new version behind, because the version, the
// timestamp and the audit row commit as one transaction (AUDIT-MUTATION-TX-1, #2842).
// A backend-bound rotation is deliberately not atomic (the upstream credential has already
// changed, so the version is Keyorix's only record of it) and is not covered here.
func TestRotateSecret_ConcurrentDelete_LeavesNoOrphanVersion(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.AuditEvent{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()
	sec, err := c.CreateSecret(ctx, &CreateSecretRequest{Name: "s", Value: []byte("v0"), ProjectID: 1,
		EnvironmentID: 1, Type: "password", Classification: "internal", OwnerID: 1, CreatedBy: "owner"})
	require.NoError(t, err)

	c.storage = (&afterFirstGetSecret{inner: c.storage, hook: func() {
		require.NoError(t, db.Delete(&models.SecretNode{}, sec.ID).Error) // a concurrent DeleteSecret commits
	}}).store()
	_, rerr := c.RotateSecret(ctx, sec.ID, []byte("rotated-value-2"), 0, "rotator")
	require.Error(t, rerr, "the rotation of a secret deleted under it must fail")

	var versions int64
	require.NoError(t, db.Model(&models.SecretVersion{}).Where("secret_node_id = ?", sec.ID).Count(&versions).Error)
	require.EqualValues(t, 1, versions, "a rotation reported as failed must not leave an orphan version")
}
