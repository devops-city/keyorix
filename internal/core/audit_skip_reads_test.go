package core

// audit_skip_reads_test.go -- ADR-112 Amendment 4
// (storage.database.insecure_audit_skip_reads), at the core's audit choke
// points, against a real SQLite store: a successful value read writes nothing
// and opens no transaction; a denied read and every other event class are
// still written; with the setting off, a read is audited exactly as before.

import (
	"context"
	"maps"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// auditCallCountingStorage counts every storage call an audit write can make,
// including opening a transaction, then delegates to the real store.
type auditCallCountingStorage struct {
	inner                   storage.Storage
	logAuditEvent           atomic.Int64
	logAuditEventWithAccess atomic.Int64
	withTransaction         atomic.Int64
}

func (s *auditCallCountingStorage) LogAuditEvent(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
	s.logAuditEvent.Add(1)
	return next.LogAuditEvent(ctx, e)
}

func (s *auditCallCountingStorage) LogAuditEventWithAccessLog(next storage.Storage, ctx context.Context, e *models.AuditEvent, l *models.SecretAccessLog) error {
	s.logAuditEventWithAccess.Add(1)
	return next.LogAuditEventWithAccessLog(ctx, e, l)
}

func (s *auditCallCountingStorage) WithTransaction(next storage.Storage, ctx context.Context, fn func(storage.Storage) error) error {
	s.withTransaction.Add(1)
	return next.WithTransaction(ctx, fn)
}

func (s *auditCallCountingStorage) total() int64 {
	return s.logAuditEvent.Load() + s.logAuditEventWithAccess.Load() + s.withTransaction.Load()
}

// wrap returns inner decorated with auditCallCountingStorage's overrides.
func (s *auditCallCountingStorage) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		LogAuditEvent:              s.LogAuditEvent,
		LogAuditEventWithAccessLog: s.LogAuditEventWithAccessLog,
		WithTransaction:            s.WithTransaction,
	})
}

// store returns s.inner decorated with auditCallCountingStorage's overrides.
func (s *auditCallCountingStorage) store() storage.Storage { return s.wrap(s.inner) }

// actor is the user ID the direct writer calls below attribute their event to.
var actor uint = 1

func newAuditSkipReadsWorld(t *testing.T, skipReads bool) (*KeyorixCore, *auditCallCountingStorage, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}, &models.SystemMetadata{},
		&models.SecretNode{}, &models.User{}, &models.Group{}))
	counting := &auditCallCountingStorage{inner: store.NewLocalStorage(db)}
	c := NewKeyorixCore(counting.store())
	c.SetInsecureAuditSkipReads(skipReads)
	return c, counting, db
}

func auditRows(t *testing.T, db *gorm.DB, eventType string) []models.AuditEvent {
	t.Helper()
	var rows []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", eventType).Find(&rows).Error)
	return rows
}

func accessLogRows(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.SecretAccessLog{}).Count(&n).Error)
	return n
}

// The default is off, and off audits a read exactly as before: one secret.read
// row and one access-log row, through one LogAuditEventWithAccessLog call.
func TestInsecureAuditSkipReads_OffAuditsSuccessfulReadAsBefore(t *testing.T) {
	c, counting, db := newAuditSkipReadsWorld(t, false)
	assert.False(t, NewKeyorixCore(counting.store()).InsecureAuditSkipReads(), "the setting must default to off")

	require.NoError(t, c.LogSecretReadWithProject(context.Background(), 1, 7, 1, "alice", "db-password", "10.0.0.1", "ua"))
	c.writeAuditEventFull(context.Background(), EventConnectSecretRead, &actor, nil, nil, "", "federated read")

	assert.Len(t, auditRows(t, db, "secret.read"), 1)
	assert.Len(t, auditRows(t, db, EventConnectSecretRead), 1)
	assert.EqualValues(t, 1, accessLogRows(t, db))
	assert.EqualValues(t, 1, counting.logAuditEventWithAccess.Load())
}

// With the setting on, a successful value read -- native or federated --
// writes no audit row and no access-log row, and makes no storage call at
// all: no audit write, no transaction (so no single_writer write path and no
// audit chain lock either).
func TestInsecureAuditSkipReads_SuccessfulReadWritesNothingAndOpensNoTransaction(t *testing.T) {
	c, counting, db := newAuditSkipReadsWorld(t, true)

	require.NoError(t, c.LogSecretReadWithProject(context.Background(), 1, 7, 1, "alice", "db-password", "10.0.0.1", "ua"),
		"a skipped read audit is not a failure: the read must still succeed")
	assert.True(t, c.writeAuditEventFull(context.Background(), EventConnectSecretRead, &actor, nil, nil, "", "federated read"))

	assert.Empty(t, auditRows(t, db, "secret.read"))
	assert.Empty(t, auditRows(t, db, EventConnectSecretRead))
	assert.Zero(t, accessLogRows(t, db))
	assert.Zero(t, counting.total(), "a skipped read must make no audit storage call and open no transaction "+
		"(LogAuditEvent=%d LogAuditEventWithAccessLog=%d WithTransaction=%d)",
		counting.logAuditEvent.Load(), counting.logAuditEventWithAccess.Load(), counting.withTransaction.Load())
}

// A DENIED read is still audited with the setting on: the real
// ReadFederatedSecret deny path writes connect.secret_read with Success=false.
// (Native-read denials write no audit row at either setting today.)
func TestInsecureAuditSkipReads_DeniedReadIsStillAudited(t *testing.T) {
	c, _, db := newAuditSkipReadsWorld(t, true)

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "vault", "kv/app")
	require.ErrorIs(t, err, ErrConnectDisabled)

	rows := auditRows(t, db, EventConnectSecretRead)
	require.Len(t, rows, 1, "a denied read must still be audited")
	require.NotNil(t, rows[0].Success)
	assert.False(t, *rows[0].Success)
}

// Every event class other than a successful value read is still written with
// the setting on, one subtest per class, each through the real core writer.
func TestInsecureAuditSkipReads_EveryOtherEventClassStillAudited(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		class     string
		eventType string
		write     func(c *KeyorixCore)
	}{
		{"secret create", "secret.created", func(c *KeyorixCore) {
			c.LogSecretCreatedWithProject(ctx, 1, 7, 1, "alice", "s", "", "")
		}},
		{"secret update", "secret.updated", func(c *KeyorixCore) {
			c.LogSecretUpdatedWithProject(ctx, 1, 7, 1, "alice", "s", "", "")
		}},
		{"secret version change (rotate)", "secret.rotated", func(c *KeyorixCore) {
			c.LogSecretRotatedWithProject(ctx, 1, 7, 1, "alice", "s", "", "")
		}},
		{"secret delete", "secret.deleted", func(c *KeyorixCore) {
			c.LogSecretDeletedWithProject(ctx, 1, 7, 1, "alice", "s", "", "")
		}},
		{"secret metadata read (no value)", EventSecretMetadataRead, func(c *KeyorixCore) {
			require.NoError(t, c.LogSecretMetadataRead(ctx, 1, 7, 1, "alice", "s", "", ""))
		}},
		{"secret version listing (no value)", EventSecretVersionsListed, func(c *KeyorixCore) {
			require.NoError(t, c.LogSecretVersionsListed(ctx, 1, 7, 1, "alice", "s", "", ""))
		}},
		{"role change", EventRoleAssigned, func(c *KeyorixCore) {
			c.LogRoleAssigned(ctx, 1, 2, 3, Scope{})
		}},
		{"role change inside a transaction", EventRoleRemoved, func(c *KeyorixCore) {
			sink := &auditForwardSink{}
			require.NoError(t, c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
				c.LogRoleRemovedOn(ctx, auditInto(tx, sink), 1, 2, 3, Scope{})
				return nil
			}))
		}},
		{"permission change", EventPermissionAdded, func(c *KeyorixCore) {
			c.LogPermissionAssigned(ctx, 1, 3, 4, false)
		}},
		{"share change", string(ShareAuditEventCreated), func(c *KeyorixCore) {
			c.LogShareCreated(ctx, &ShareAuditContext{ActorID: 1, SecretID: 7, RecipientID: 2, Permission: "read", ShareID: 9})
		}},
		{"authentication", "auth.login", func(c *KeyorixCore) {
			c.LogAuthLogin(ctx, 1, "alice", "10.0.0.1", "ua")
		}},
		{"authentication failure", "auth.login_failed", func(c *KeyorixCore) {
			c.LogAuthFailure(ctx, "alice", "10.0.0.1")
		}},
		{"denied read", EventConnectSecretRead, func(c *KeyorixCore) {
			c.writeAuditEventFailed(ctx, EventConnectSecretRead, &actor, nil, "", "federated read DENIED")
		}},
		{"break-glass", EventBreakGlassRevoked, func(c *KeyorixCore) {
			c.LogBreakGlassRevoked(ctx, 1, 1, 5, 2, 3, "admin")
		}},
		{"configuration change (settings diff)", EventSecurityPostureSettingChanged, func(c *KeyorixCore) {
			c.ReconcileSecurityPostureSnapshot(ctx, map[string]string{"storage.database.insecure_audit_skip_reads": "true"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.class, func(t *testing.T) {
			c, _, db := newAuditSkipReadsWorld(t, true)
			tc.write(c)
			assert.NotEmpty(t, auditRows(t, db, tc.eventType),
				"%s (%s) must still be audited with insecure_audit_skip_reads on", tc.class, tc.eventType)
		})
	}
}

// Admin, key and start-up events are written straight to storage outside this
// package (server/admin, internal/encryption, server/main.go), so the skip
// never sees them; the predicate would not skip them even if it did.
func TestInsecureAuditSkipReads_AdminKeyAndStartupEventsNotSkippable(t *testing.T) {
	c := NewKeyorixCore(nil)
	c.SetInsecureAuditSkipReads(true)
	ok := true
	for _, et := range []string{
		"admin.recover_admin", "admin.audit_checkpoint_key_exported", "admin.recovery_event",
		encryption.EventKeyProviderFallbackDowngrade, encryption.EventKMSContextFallbackUsed,
		"admin.audit_reads_skipped_at_startup", EventBreakGlassActivated,
	} {
		assert.False(t, c.skipsSuccessfulReadAudit(&models.AuditEvent{EventType: et, Success: &ok}), et)
	}
}

// The skip set is exactly the two value-disclosure event types, and only their
// successful form is skipped. Widening it is an ADR-112 decision, not an edit.
func TestInsecureAuditSkipReads_SkipSetIsExactlyTheSuccessfulValueReads(t *testing.T) {
	assert.Equal(t, []string{EventConnectSecretRead, "secret.read"},
		slices.Sorted(maps.Keys(successfulValueReadEventTypes)))

	c := NewKeyorixCore(nil)
	c.SetInsecureAuditSkipReads(true)
	yes, no := true, false
	for et := range successfulValueReadEventTypes {
		assert.True(t, c.skipsSuccessfulReadAudit(&models.AuditEvent{EventType: et, Success: &yes}), et)
		assert.False(t, c.skipsSuccessfulReadAudit(&models.AuditEvent{EventType: et, Success: &no}), "denied %s", et)
		assert.False(t, c.skipsSuccessfulReadAudit(&models.AuditEvent{EventType: et}), "nil Success %s", et)
	}
	c.SetInsecureAuditSkipReads(false)
	assert.False(t, c.skipsSuccessfulReadAudit(&models.AuditEvent{EventType: "secret.read", Success: &yes}))
}
