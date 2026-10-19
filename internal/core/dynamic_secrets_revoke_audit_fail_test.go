// dynamic_secrets_revoke_audit_fail_test.go — #2406 red/green proof.
//
// RevokeLease's success path drops the target credential (engine.Revoke),
// marks the lease row "revoked", then writes an audit event for the action
// — and, before this fix, returned nil regardless of whether that audit
// write actually persisted. A LogAuditEvent failure mid-revoke left the
// credential genuinely dropped (correct, irreversible, and must not be
// undone) but the only record of it silently missing, while RevokeLease —
// and RevokeLeasesForConfig, and RevokeAllLeases's REST/gRPC callers —
// still reported unconditional success.
//
// failLogAuditEventStorage is a thin storage.Storage decorator (same
// embedding pattern as concurrency_remove_user_role_toctou_test.go's
// delayedRemoveRoleStorage) that fails exactly the LogAuditEvent calls
// whose event type matches, letting every other call through to the real
// in-memory SQLite storage underneath — no production code is touched to
// force this.
package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func failLogAuditEventStorage(inner storage.Storage, eventType string) storage.Storage {
	return hooked(inner, &storeHooks{
		LogAuditEvent: func(next storage.Storage, ctx context.Context, event *models.AuditEvent) error {
			if event.EventType == eventType {
				return fmt.Errorf("fault-injected: %s audit write failed", eventType)
			}
			return next.LogAuditEvent(ctx, event)
		},
	})
}

// TestDynamicSecrets_RevokeLease_AuditWriteFailureIsNotSwallowed is the
// direct, single-lease proof: RevokeLease must return an error, not nil,
// when its own "dynamic_lease.revoked" audit write fails — while still
// NOT pretending the already-dropped target credential is somehow still
// live (it isn't, and claiming otherwise would be worse than the bug).
func TestDynamicSecrets_RevokeLease_AuditWriteFailureIsNotSwallowed(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	c.storage = failLogAuditEventStorage(c.storage, "dynamic_lease.revoked")

	err = c.RevokeLease(ctx, issued.LeaseID, 7, "manual")
	require.Error(t, err, "#2406: the caller must get an error, not OK, when the audit write for a revoke fails")

	assert.Contains(t, fake.Revoked, issued.Username,
		"the target credential WAS dropped -- that already happened and cannot (must not) be undone")

	lease, gerr := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, gerr)
	assert.Equal(t, "revoked", lease.Status, "the lease row reflects the true target state")
	assert.NotNil(t, lease.RevokedAt)
	assert.NotEmpty(t, lease.RevokeError, "the audit gap is recorded on the lease row for an operator to find")
}

// TestDynamicSecrets_RevokeLeasesForConfig_AuditWriteFailureIsNotSwallowed
// is the bulk-path proof (the shape RevokeAllLeases's REST/gRPC handlers
// actually call): a per-lease audit-write failure must surface as a
// non-nil error from RevokeLeasesForConfig itself, not just a nonzero
// "failed" count a caller might not check -- both existing REST
// (dynamic_secrets.go's RevokeAllLeases handler) and gRPC
// (dynamic_secret_service.go) callers already turn a non-nil error here
// into a non-2xx/non-OK response, and a nil one into unconditional
// success.
func TestDynamicSecrets_RevokeLeasesForConfig_AuditWriteFailureIsNotSwallowed(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	c.storage = failLogAuditEventStorage(c.storage, "dynamic_lease.revoked")

	revoked, failed, err := c.RevokeLeasesForConfig(ctx, cfg.ID, 7, "incident")
	require.Error(t, err, "#2406: a bulk revoke whose per-lease audit write failed must not report a clean success")
	assert.Equal(t, 0, revoked)
	assert.Equal(t, 1, failed)
	assert.Contains(t, fake.Revoked, issued.Username, "the target credential was still genuinely dropped")
}

// newDynamicTestCorePostgres is newDynamicTestCore (dynamic_secrets_test.go)
// against a real, isolated-schema Postgres database instead of in-memory
// SQLite, using the same pgTestDSN/pgIsolatedSchemaDSN/pgOpen helpers
// postgres_contention_helpers_test.go already provides (skips, not fails,
// when KEYORIX_TEST_PG_DSN is unset).
func newDynamicTestCorePostgres(t *testing.T) (*KeyorixCore, *dynamictest.FakeEngine) {
	t.Helper()
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)
	db := pgOpen(t, dsn)

	require.NoError(t, db.AutoMigrate(
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_dynamic_secret_configs_project_env_name_2406 "+
		"ON dynamic_secret_configs (project_id, environment_id, name)").Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testAdminActorID, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "dyn-test-project"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 1, Name: "dyn-test-env"}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	c.SetAuthEncryptor(enc)
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	return c, fake
}

// TestDynamicSecrets_RevokeLease_AuditWriteFailureIsNotSwallowed_Postgres is
// the Postgres-backed sibling of the SQLite test above -- same fault, same
// assertions, against a real database instead of in-memory SQLite. Skips
// (not fails) without KEYORIX_TEST_PG_DSN.
func TestDynamicSecrets_RevokeLease_AuditWriteFailureIsNotSwallowed_Postgres(t *testing.T) {
	c, fake := newDynamicTestCorePostgres(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	c.storage = failLogAuditEventStorage(c.storage, "dynamic_lease.revoked")

	err = c.RevokeLease(ctx, issued.LeaseID, 7, "manual")
	require.Error(t, err, "#2406: the caller must get an error, not OK, when the audit write for a revoke fails (Postgres)")

	assert.Contains(t, fake.Revoked, issued.Username,
		"the target credential WAS dropped -- that already happened and cannot (must not) be undone")

	lease, gerr := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, gerr)
	assert.Equal(t, "revoked", lease.Status, "the lease row reflects the true target state")
	assert.NotNil(t, lease.RevokedAt)
	assert.NotEmpty(t, lease.RevokeError, "the audit gap is recorded on the lease row for an operator to find")
}
