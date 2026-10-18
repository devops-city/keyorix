package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// Session CR round 2, finding #5: FuzzStorageFaultOperations
// (op="REST POST /api/v1/secrets/{id}/copy", fault=CreateSecretAccessLog#1/panic)
// found that CopySecret's pre-copy LogSecretReadWithProject call
// (secret_copy.go:71) panics all the way out through writeAccessLog when
// CreateSecretAccessLog panics, aborting the copy with a 500 even though the
// caller is authorized and the copy would otherwise have succeeded — an
// access-log write failing shouldn't block a legitimate operation any more
// than an audit-log write failing does (see emitAudit's own recover(),
// service.go:647-665, the established precedent this follows).
//
// The storage-snapshot fuzz oracle alone cannot distinguish "panic recovered,
// copy proceeds" from "panic propagated, copy aborted" here — in both cases
// only an AuditEvent row differs from the before-state (the panic happens
// before CreateSecret runs either way), which is already tolerated as
// outcome-log noise. This test instead asserts the actual effect: the copy
// must succeed despite the panic, not merely "no oracle violation."
type copySecretAccessLogPanicStorage struct {
	storage.Storage
	calls int
}

func (s *copySecretAccessLogPanicStorage) CreateSecretAccessLog(ctx context.Context, entry *models.SecretAccessLog) error {
	s.calls++
	if s.calls == 1 {
		panic("simulated CreateSecretAccessLog panic")
	}
	return s.Storage.CreateSecretAccessLog(ctx, entry)
}

func TestCopySecret_PanicInAccessLogDuringSourceRead_StillSucceeds(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.SecretAccessSchedule{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	real := store.NewLocalStorage(db)
	spy := &copySecretAccessLogPanicStorage{Storage: real}
	c := &KeyorixCore{storage: spy, now: time.Now}
	ctx := context.Background()

	p1, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	staging, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p1.ID})
	prod, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p1.ID}).Error)

	src, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name: "db-url", Value: []byte("postgres://secret"), ProjectID: p1.ID, EnvironmentID: staging.ID,
		Type: "connection-string", Classification: "confidential", Description: "the prod DB",
		CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)
	spy.calls = 0 // reset: CreateSecret above may itself write an access log for the creation

	copied, err := c.CopySecret(ctx, src.ID, prod.ID, "", "owner", 1, "203.0.113.5", "test-agent/1.0")
	require.NoError(t, err, "a panic writing the source-read access log must not abort an otherwise-authorized copy")
	require.NotNil(t, copied)
	require.NotEqual(t, src.ID, copied.ID)

	val, err := c.GetSecretValueWithPermissionCheck(ctx, copied.ID, 1)
	require.NoError(t, err)
	require.Equal(t, "postgres://secret", string(val), "the copy must have actually run, not just reported success")
}
