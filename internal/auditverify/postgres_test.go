package auditverify_test

// Postgres-backed counterpart to differential_test.go's SQLite fixtures.
// SKIPS unless $KEYORIX_TEST_PG_DSN is set (a rig with PG, or the demo
// container) — mirrors internal/storage/store's own
// FuzzStorageBackendDifferential gating and schema-isolation pattern.

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var auditverifyPGSchemaSeq atomic.Int64

func requirePGDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — Postgres-backed auditverify tests need a real Postgres (rig-only)")
	}
	return dsn
}

// pgFixture mirrors diffFixture but over an isolated Postgres schema.
type pgFixture struct {
	t      *testing.T
	dsn    string // schema-scoped DSN, usable by both gorm and auditverify.OpenPostgres
	db     *gorm.DB
	local  *store.LocalStorage
	core   *core.KeyorixCore
	ctx    context.Context
	nextID int
}

func newPGFixture(t *testing.T) *pgFixture {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	baseDSN := requirePGDSN(t)

	schema := fmt.Sprintf("auditverify_%d_%d", os.Getpid(), auditverifyPGSchemaSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(baseDSN), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		if c, e := gorm.Open(postgres.Open(baseDSN), &gorm.Config{Logger: logger.Discard}); e == nil {
			_ = c.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		}
	})

	scoped := pgdsn.PGSearchPathDSN(baseDSN, schema)
	db, err := gorm.Open(postgres.Open(scoped), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{}))

	local := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(local)
	c.SetAuditCheckpointKey(fixedCheckpointKey, "v1")

	return &pgFixture{t: t, dsn: scoped, db: db, local: local, core: c, ctx: context.Background()}
}

func (f *pgFixture) logEvents(n int, age time.Duration) {
	f.t.Helper()
	base := time.Now().UTC().Add(-age).Truncate(time.Second)
	tr := true
	for i := range n {
		f.nextID++
		require.NoError(f.t, f.local.LogAuditEvent(f.ctx, &models.AuditEvent{
			EventType:   "secret.read",
			Description: fmt.Sprintf("event %d", f.nextID),
			Success:     &tr,
			EventTime:   base.Add(time.Duration(i) * time.Second),
			ActorType:   "user",
		}))
	}
}

func (f *pgFixture) openIndependent() *auditverify.DB {
	f.t.Helper()
	db, err := auditverify.OpenPostgres(f.dsn)
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestDifferential_Postgres_HappyPath is the Postgres counterpart to
// TestDifferential_HappyPath — same fixture shape, same assertions, over
// pgx/lib_pq instead of modernc.org/sqlite, since design §8 explicitly
// flags Postgres as the case a SQLite-only measurement/test run cannot
// speak to.
func TestDifferential_Postgres_HappyPath(t *testing.T) {
	t.Parallel()
	f := newPGFixture(t)
	f.logEvents(25, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	want, err := f.core.VerifyAuditChain(f.ctx)
	require.NoError(t, err)
	require.True(t, want.Valid)

	db := f.openIndependent()
	require.Equal(t, auditverify.BackendPostgres, db.Backend())
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)

	require.Equal(t, auditverify.VerdictValid, got.Verdict, "reason: %s", got.Reason)
	require.Equal(t, want.ChainedEvents, got.ChainedEvents)
	require.True(t, got.Checkpoint.Present)
	require.True(t, got.Checkpoint.Authenticated)

	assertEveryHashMatchesStored(t, db)
}

// TestDifferential_Postgres_TamperedRow proves a modified row is caught
// identically to the SQLite case over a real Postgres connection.
func TestDifferential_Postgres_TamperedRow(t *testing.T) {
	t.Parallel()
	f := newPGFixture(t)
	f.logEvents(10, time.Hour)
	require.NoError(t, f.db.Exec("UPDATE audit_events SET description = 'tampered' WHERE id = 3").Error)

	want, err := f.core.VerifyAuditChain(f.ctx)
	require.NoError(t, err)
	require.False(t, want.Valid)

	db := f.openIndependent()
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
}
