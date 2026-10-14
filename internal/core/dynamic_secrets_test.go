package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const adminDSNPlain = "postgres://admin:s3cr3t@db.internal:5432/app"

// testAdminActorID is a global-scope admin actor (#162: binding a dynamic-secret
// backend requires admin authority) seeded by newDynamicTestCore.
const testAdminActorID = uint(1)

// newDynamicTestCore builds a core over real SQLite with an enabled encryptor (so
// at-rest encryption of the admin DSN + issued credential is exercised), a fixed
// clock, and a fake credential engine in place of a real Postgres target. Seeds
// testAdminActorID with a global "admin" role grant so CreateDynamicSecretConfig's
// admin-authority check (#162) passes for the tests that use it.
func newDynamicTestCore(t *testing.T) (*KeyorixCore, *gorm.DB, *dynamictest.FakeEngine, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
	))
	// Mirror factory.go's ensureDynamicSecretConfigNameIndex exactly (#462), so tests in
	// this file exercise the same DB-level "one per (project, env, name)" guard
	// production installs get.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_dynamic_secret_configs_project_env_name "+
		"ON dynamic_secret_configs (project_id, environment_id, name)").Error)
	// ADR-084: the admin bypass is now the structural BypassesPermissionChecks
	// flag, not the "admin" name.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testAdminActorID, RoleID: 1}).Error)
	// Every config created via mkConfig (or inline in these tests) targets
	// ProjectID 1 / EnvironmentID 2 — seed real, live rows so IssueLease/
	// RenewLease's #369 project-liveness check passes for the ordinary-path
	// tests (project soft-delete behavior itself is exercised separately in
	// catalog_delete_project_test.go / a dedicated dynamic-secrets test below).
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "dyn-test-project"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 1, Name: "dyn-test-env"}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	// The default config in these tests is a "postgres" target, so the fake mimics a
	// backend with DB-level expiry (VALID UNTIL) — issuing does not require the
	// sweeper. Tests that exercise the no-native-expiry gate flip NativeExpiry off.
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	c.SetAuthEncryptor(enc)
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	return c, db, fake, fixed
}

func mkConfig(t *testing.T, c *KeyorixCore, ctx context.Context) *models.DynamicSecretConfig {
	t.Helper()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name:              "app-db",
		ProjectID:         1,
		EnvironmentID:     2,
		BackendType:       "postgres",
		AdminDSN:          adminDSNPlain,
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600,
		CreatedBy:         "alice",
		ActorID:           testAdminActorID,
	})
	require.NoError(t, err)
	return cfg
}

// TestSetDynamicSecretConfigEnabled_HappyPathAndNoop proves the ordinary
// enable/disable/no-op branches of SetDynamicSecretConfigEnabled still work
// after routing the write through the new conditional
// TransitionDynamicSecretConfigDisabled call.
func TestSetDynamicSecretConfigEnabled_HappyPathAndNoop(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)
	require.False(t, cfg.Disabled)

	// Disabling a currently-enabled config succeeds.
	updated, err := c.SetDynamicSecretConfigEnabled(ctx, testAdminActorID, cfg.ID, false)
	require.NoError(t, err)
	assert.True(t, updated.Disabled)
	reload, err := c.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.True(t, reload.Disabled)

	// Re-disabling (already disabled → target disabled) is a harmless no-op,
	// not an error — distinct from the lost-race case below.
	noop, err := c.SetDynamicSecretConfigEnabled(ctx, testAdminActorID, cfg.ID, false)
	require.NoError(t, err)
	assert.True(t, noop.Disabled)

	// Re-enabling succeeds.
	reenabled, err := c.SetDynamicSecretConfigEnabled(ctx, testAdminActorID, cfg.ID, true)
	require.NoError(t, err)
	assert.False(t, reenabled.Disabled)
}

// TestSetDynamicSecretConfigEnabled_LostRaceReportedCleanly is the
// StateTransitionMissingCAS regression, proven deterministically at the
// core-layer boundary — mirroring machine_identities_test.go's "lost race on
// the conditional write is reported like an illegal transition" case exactly,
// just for DynamicSecretConfig.Disabled instead of MachineIdentity.State.
// SetDynamicSecretConfigEnabled used to read the config, then persist the
// FULL mutated row via a plain unconditional UpdateDynamicSecretConfig — a
// TOCTOU window in which a racing caller (or an unrelated concurrent edit)
// landing between the read and the write could be silently clobbered. This
// drives MockStorage to hand back a stale pre-race read (Disabled=false) and
// has TransitionDynamicSecretConfigDisabled report matched=false — exactly
// what the real conditional UPDATE returns when a concurrent racer already
// moved the row's disabled value away from what this call observed — and
// asserts SetDynamicSecretConfigEnabled surfaces that as a clean "changed
// concurrently" error rather than treating a false match as success.
//
// (The storage-layer half of this fix — that the conditional UPDATE itself
// actually rejects a second write gated on a now-stale fromDisabled value —
// is proven directly, back-to-back and under real goroutine concurrency,
// against real SQLite in internal/storage/store's
// TestTransitionDynamicSecretConfigDisabled_ClosesRace and
// TestRaceReproStorageLayer-style coverage; this test's job is only to prove
// the CORE-LAYER caller's false→error translation, which is why it drives
// MockStorage directly instead of racing real goroutines against real SQLite
// — the latter is inherently timing-sensitive and would be flaky under
// `go test -race`, which this repo's CI runs.)
func TestSetDynamicSecretConfigEnabled_LostRaceReportedCleanly(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ctx := context.Background()

	staleCfg := &models.DynamicSecretConfig{ID: 7, ProjectID: 1, Name: "race-cfg", Disabled: false}
	ms.GetDynamicSecretConfigFunc = func(_ context.Context, id uint) (*models.DynamicSecretConfig, error) {
		require.Equal(t, uint(7), id)
		// Return a COPY each call so SetDynamicSecretConfigEnabled's in-memory
		// mutation of the returned cfg can't leak back into staleCfg.
		cp := *staleCfg
		return &cp, nil
	}
	ms.TransitionDynamicSecretConfigDisabledFunc = func(_ context.Context, cfg *models.DynamicSecretConfig, fromDisabled bool) (bool, error) {
		assert.False(t, fromDisabled, "must gate on the value observed via GetDynamicSecretConfig, not some other value")
		assert.True(t, cfg.Disabled, "must persist the caller's intended target (disabled=true)")
		// Simulate the concurrent racer having already flipped the row's
		// persisted disabled value away from fromDisabled: the conditional
		// UPDATE's WHERE clause no longer matches any row.
		return false, nil
	}

	_, err := c.SetDynamicSecretConfigEnabled(ctx, testAdminActorID, 7, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changed concurrently")
	assert.Contains(t, err.Error(), "7")
}

// #162: binding a dynamic-secret backend hands out standing access to mint live
// credentials against it (a DB admin DSN or a cloud-IAM role) — the route only
// requires secrets.write at the project/environment scope, which on its own would let
// any secrets.write holder bind an arbitrary powerful backend (exact sibling of #90's
// rotation-backend authz gap). A non-admin actor must be refused; an admin actor (the
// suite's default testAdminActorID) must still succeed, matching mkConfig's baseline.
func TestDynamicSecrets_CreateConfig_RequiresAdminAuthority(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()

	// A non-admin actor (no role grant at all) must be refused.
	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "attacker-cfg", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: adminDSNPlain, DefaultTTLSeconds: 3600, CreatedBy: "mallory", ActorID: 999,
	})
	require.Error(t, err, "a non-admin actor must not be able to bind a dynamic-secret backend")
	assert.Contains(t, err.Error(), "admin authority")

	// The admin actor succeeds (same actor mkConfig and every other test in this file use).
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "admin-cfg", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: adminDSNPlain, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.NoError(t, err)
	assert.NotZero(t, cfg.ID)
}

// TestDynamicSecrets_CreateConfig_DuplicateNameRejected is the (#462) regression:
// DynamicSecretConfig's doc comment states "one per (project, env, name)" but
// nothing enforced it. A second CreateDynamicSecretConfig call for the identical
// (project, environment, name) tuple must fail with a clear validation error, not
// silently create a duplicate row.
func TestDynamicSecrets_CreateConfig_DuplicateNameRejected(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	_ = mkConfig(t, c, ctx) // "app-db" on ProjectID 1 / EnvironmentID 2

	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "app-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: adminDSNPlain, DefaultTTLSeconds: 3600, CreatedBy: "bob", ActorID: testAdminActorID,
	})
	require.Error(t, err, "a duplicate (project, env, name) config must be rejected")
	assert.Contains(t, err.Error(), "already exists")

	configs, err := c.storage.ListDynamicSecretConfigs(ctx, 1, 2)
	require.NoError(t, err)
	assert.Len(t, configs, 1, "only the original config must exist")
}

// TestDynamicSecrets_CreateConfig_DifferentScopeAllowed asserts the "one per
// (project, env, name)" rule (#462) is scoped to the full tuple: a different
// environment, a different project, or a different name must all succeed
// independently of an existing config.
func TestDynamicSecrets_CreateConfig_DifferentScopeAllowed(t *testing.T) {
	t.Parallel()
	c, db, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	_ = mkConfig(t, c, ctx) // "app-db" on ProjectID 1 / EnvironmentID 2

	// Different environment, same project + name.
	require.NoError(t, db.Create(&models.Environment{ID: 3, ProjectID: 1, Name: "dyn-test-env-2"}).Error)
	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "app-db", ProjectID: 1, EnvironmentID: 3, BackendType: "postgres",
		AdminDSN: adminDSNPlain, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	assert.NoError(t, err, "the same name in a different environment must succeed")

	// Different project, same name — with its OWN environment (an environment ID
	// belongs to exactly one project; reusing project 1's EnvironmentID 2 here would
	// itself be the reference-confusion case CreateDynamicSecretConfig now rejects).
	require.NoError(t, db.Create(&models.Project{ID: 4, Name: "dyn-test-project-2"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 5, ProjectID: 4, Name: "dyn-test-env-3"}).Error)
	_, err = c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "app-db", ProjectID: 4, EnvironmentID: 5, BackendType: "postgres",
		AdminDSN: adminDSNPlain, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	assert.NoError(t, err, "the same name in a different project must succeed")

	// Same project + environment, different name.
	_, err = c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "app-db-2", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: adminDSNPlain, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	assert.NoError(t, err, "a different name in the same project/environment must succeed")
}

// TestDynamicSecrets_CreateConfig_RejectsCrossProjectEnvironment pins the fix for
// the reference-confusion follow-up: EnvironmentID 2 belongs to project 1, so a
// request naming a DIFFERENT project (4) with that same EnvironmentID must be
// rejected, not silently accepted with a config whose stored ProjectID and actual
// environment disagree about which project the config belongs to.
func TestDynamicSecrets_CreateConfig_RejectsCrossProjectEnvironment(t *testing.T) {
	t.Parallel()
	c, db, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Project{ID: 4, Name: "dyn-test-project-2"}).Error)

	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "cross-project-cfg", ProjectID: 4, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: adminDSNPlain, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.Error(t, err, "an environment belonging to a different project must be rejected")
	assert.Contains(t, err.Error(), "does not belong to project")

	configs, err := c.storage.ListDynamicSecretConfigs(ctx, 4, 2)
	require.NoError(t, err)
	assert.Empty(t, configs, "no config must have been created")
}

// TestDynamicSecrets_CreateConfig_RejectsUnknownEnvironment pins the sibling case:
// an EnvironmentID with no backing row at all must also be rejected, not just a
// mismatched one.
func TestDynamicSecrets_CreateConfig_RejectsUnknownEnvironment(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()

	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "nonexistent-env-cfg", ProjectID: 1, EnvironmentID: 999999, BackendType: "postgres",
		AdminDSN: adminDSNPlain, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestDynamicSecrets_CreateConfig_EnvironmentIDZeroIsProjectWide proves
// EnvironmentID: 0 -- the CLI's own --environment-id flag help text says
// "0 = project-wide" -- actually succeeds, rather than being rejected with
// "environment 0 not found". Before the fix, CreateDynamicSecretConfig called
// GetEnvironment(ctx, req.EnvironmentID) unconditionally, even when
// EnvironmentID was the project-wide sentinel 0 (no environment ever has
// primary key 0), so every project-wide config create failed regardless of
// project or actor. Found while writing scripts/e2e/journeys/journey7
// (R4 spec #1): `dynamic-secret create` with no --environment-id always
// returned HTTP 400.
func TestDynamicSecrets_CreateConfig_EnvironmentIDZeroIsProjectWide(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()

	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "project-wide-cfg", ProjectID: 1, EnvironmentID: 0, BackendType: "postgres",
		AdminDSN: adminDSNPlain, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 0, cfg.EnvironmentID)
	assert.EqualValues(t, 1, cfg.ProjectID)
}

func TestDynamicSecrets_ConfigEncryptsAdminDSN(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	stored, err := c.storage.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.NotContains(t, string(stored.AdminDSNEnc), "s3cr3t", "admin DSN must be encrypted at rest")
	assert.NotEqual(t, adminDSNPlain, string(stored.AdminDSNEnc))
}

// #94: a DB-write attacker who copies one config's encrypted admin DSN onto a
// DIFFERENT config's row must NOT have it decrypt successfully — that would let
// Keyorix connect to (and potentially reveal error/behavioral detail about) a
// target it was never configured to reach for that config, using credentials
// scoped to a different backend entirely. This exercises the live IssueLease
// (decryptAuthSecret) path end-to-end, not just the low-level AEAD primitive.
func TestDynamicSecrets_AdminDSNTransplantBetweenConfigsFailsToDecrypt(t *testing.T) {
	t.Parallel()
	c, db, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfgA := mkConfig(t, c, ctx)
	cfgB, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "other-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN:          "postgres://admin:different@other-db.internal:5432/app",
		DefaultTTLSeconds: 3600,
		ActorID:           testAdminActorID,
	})
	require.NoError(t, err)

	// Simulate a DB-write attacker: copy config A's encrypted admin DSN onto B's row.
	rowA, err := c.storage.GetDynamicSecretConfig(ctx, cfgA.ID)
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Where("id = ?", cfgB.ID).Updates(map[string]any{
		"admin_dsn_enc":  rowA.AdminDSNEnc,
		"admin_dsn_meta": rowA.AdminDSNMeta,
	}).Error)

	_, err = c.IssueLease(ctx, cfgB.ID, 0, 7)
	require.Error(t, err, "an admin DSN transplanted from a different config must fail to decrypt, not silently succeed")
	assert.Contains(t, err.Error(), "decrypt admin DSN")
}

func TestDynamicSecrets_MaxActiveLeasesCeiling(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "capped", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: adminDSNPlain, CreationTemplate: "GRANT SELECT TO {{name}};",
		DefaultTTLSeconds: 3600, MaxActiveLeases: 2, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.NoError(t, err)

	// Two leases are allowed...
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	// ...the third exceeds the ceiling.
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active-lease limit")

	// Revoking one frees a slot.
	leases, err := c.ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, err)
	require.NoError(t, c.RevokeLease(ctx, leases[0].LeaseID, 7, "manual"))
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err, "a slot opens after a revoke")
}

// #411: a lease stuck in revoke_failed still holds a live credential upstream (its
// earlier revoke attempt failed on the target) — CountActiveLeases must count it toward
// MaxActiveLeases exactly like an "active" lease, or an attacker (or ordinary backend
// flakiness) could force revokes to fail at issue time and silently mint past the
// configured ceiling forever, since every subsequent count would undercount the leftover
// live credential.
func TestDynamicSecrets_MaxActiveLeasesCeiling_CountsRevokeFailed(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "capped-revoke-failed", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: adminDSNPlain, CreationTemplate: "GRANT SELECT TO {{name}};",
		DefaultTTLSeconds: 3600, MaxActiveLeases: 1, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.NoError(t, err)

	// One lease is allowed at the ceiling of 1.
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	// Force its revoke to fail on the target — the lease is flagged revoke_failed but its
	// credential is still live upstream.
	fake.FailRevoke = true
	require.Error(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))
	lease, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, err)
	require.Equal(t, "revoke_failed", lease.Status, "precondition: the lease is stuck revoke_failed")

	// CountActiveLeases must reflect the revoke_failed lease as still occupying a slot.
	active, err := c.storage.CountActiveLeases(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), active, "a revoke_failed lease still holds a live credential and must count toward the ceiling")

	// With the sole slot occupied by the revoke_failed lease, issuing another must be
	// refused — not silently allowed because the lease is no longer literally "active".
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.Error(t, err, "the ceiling must not be evadable by forcing a revoke to fail")
	assert.Contains(t, err.Error(), "active-lease limit")
}

func TestDynamicSecrets_IssueListRevoke(t *testing.T) {
	t.Parallel()
	c, db, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	// ── Issue ──
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	require.NotEmpty(t, issued.LeaseID)
	require.NotEmpty(t, issued.Username)
	require.NotEmpty(t, issued.Password)
	assert.Len(t, fake.Issued, 1, "engine issued one role")

	// The credential is encrypted at rest — the stored bytes don't contain the password.
	stored, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, err)
	assert.Equal(t, "active", stored.Status)
	assert.NotContains(t, string(stored.CredentialEnc), issued.Password, "credential must be encrypted at rest")

	// ── List ──
	leases, err := c.ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, err)
	require.Len(t, leases, 1)

	// ── Revoke ──
	require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))
	assert.Equal(t, []string{issued.Username}, fake.Revoked, "engine revoked the issued role")
	after, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoked", after.Status)
	assert.NotNil(t, after.RevokedAt)

	// Revoking an already-revoked lease is rejected.
	require.Error(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))

	_ = db
}

func TestDynamicSecrets_SweepRevokesExpired(t *testing.T) {
	t.Parallel()
	c, _, fake, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	// Backdate the lease past its expiry, then sweep.
	lease, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	lease.ExpiresAt = fixed.Add(-time.Hour)
	require.NoError(t, c.storage.UpdateDynamicSecretLease(ctx, lease))

	n, err := c.RevokeExpiredLeases(ctx, fixed)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Contains(t, fake.Revoked, issued.Username)

	after, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoked", after.Status)
	assert.Equal(t, "expired", after.RevokeReason)
}

func TestDynamicSecrets_RevokeFailureMarksLease(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	fake.FailRevoke = true
	err = c.RevokeLease(ctx, issued.LeaseID, 7, "manual")
	require.Error(t, err, "a target revoke failure surfaces to the caller")

	after, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoke_failed", after.Status, "the lease is flagged for an operator")
	assert.NotEmpty(t, after.RevokeError)
	// RevokedAt must NOT be stamped on a failed attempt: the target drop failed, so the
	// credential is still live. Stamping it would make the audit trail falsely claim the
	// role was dropped at this time.
	assert.Nil(t, after.RevokedAt, "a failed revoke must not be timestamped as revoked")

	// A second attempt that also fails must leave the lease in revoke_failed, not
	// silently mark it revoked — and still without a RevokedAt timestamp.
	err = c.RevokeLease(ctx, issued.LeaseID, 7, "retry")
	require.Error(t, err, "the retry is attempted, not refused, but still fails on target")
	stillFailed, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoke_failed", stillFailed.Status, "a second failed attempt stays revoke_failed")
	assert.Nil(t, stillFailed.RevokedAt)
}

// A lease stuck in revoke_failed (its credential still live from an earlier failed
// attempt) must be directly retryable via RevokeLease once the target recovers — not
// just through the expiry sweep — and only THEN does RevokedAt get stamped.
func TestDynamicSecrets_RevokeLeaseRetrySucceeds(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	fake.FailRevoke = true
	require.Error(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))
	failed, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.Equal(t, "revoke_failed", failed.Status)
	require.Nil(t, failed.RevokedAt)

	// The target recovers; a direct retry (not the sweep) must be accepted and succeed.
	fake.FailRevoke = false
	require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "retry"))

	after, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoked", after.Status)
	assert.NotNil(t, after.RevokedAt, "a genuinely successful revoke IS timestamped")
	assert.Contains(t, fake.Revoked, issued.Username)
}

// A revoke_failed lease (its credential still live) must remain retryable — manually and
// via the sweep — not be a terminal dead-end. The sweep also surfaces a persistent
// failure as an error so a mass TTL-enforcement outage isn't reported as a clean pass.
func TestDynamicSecrets_RevokeFailedIsRetryable(t *testing.T) {
	t.Parallel()
	c, _, fake, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	// First revoke fails on the target → revoke_failed (the credential is still live).
	fake.FailRevoke = true
	require.Error(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))
	failed, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.Equal(t, "revoke_failed", failed.Status)

	// A manual retry must be ACCEPTED (not rejected as "not active"). While the target is
	// still down it fails again — but the lease stays retryable.
	require.Error(t, c.RevokeLease(ctx, issued.LeaseID, 7, "retry"), "retry is attempted, not refused")

	// Backdate past expiry: the sweep must pick up the revoke_failed lease and, while the
	// target is still down, surface the persistent failure as a non-nil error.
	failed.ExpiresAt = fixed.Add(-time.Hour)
	require.NoError(t, c.storage.UpdateDynamicSecretLease(ctx, failed))
	_, serr := c.RevokeExpiredLeases(ctx, fixed)
	require.Error(t, serr, "the sweep surfaces a still-failing revoke")

	// The target recovers — the sweep now drops the credential and the lease is revoked.
	fake.FailRevoke = false
	n, err := c.RevokeExpiredLeases(ctx, fixed)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	done, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoked", done.Status)
	assert.Contains(t, fake.Revoked, issued.Username)
}

func TestDynamicSecrets_IssueRejectsUnknownConfig(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	_, err := c.IssueLease(ctx, 999, 0, 7)
	require.Error(t, err)
}

func TestDynamicSecrets_MaxTTLClampsIssue(t *testing.T) {
	t.Parallel()
	c, _, _, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "capped", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		DefaultTTLSeconds: 600, MaxTTLSeconds: 1800, ActorID: testAdminActorID,
	})
	require.NoError(t, err)

	// Request 1h but the config caps at 30m → expiry is now+30m.
	issued, err := c.IssueLease(ctx, cfg.ID, 3600, 7)
	require.NoError(t, err)
	assert.Equal(t, fixed.Add(30*time.Minute), issued.ExpiresAt, "issue TTL must be clamped to max_ttl_seconds")
}

// A caller-supplied ttl_seconds large enough to overflow int64 nanoseconds when
// multiplied by time.Second must be rejected outright, not silently wrapped into an
// arbitrary (possibly negative) Duration that would mint a credential with an
// ExpiresAt in the past. 20_000_000_000 seconds (~634 years) comfortably exceeds the
// ~9.22e9s int64-nanosecond overflow threshold.
func TestDynamicSecrets_IssueRejectsOverflowingTTLSeconds(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "overflow-guard", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		ActorID: testAdminActorID,
	})
	require.NoError(t, err)

	_, err = c.IssueLease(ctx, cfg.ID, 20_000_000_000, 7)
	require.Error(t, err, "an overflowing ttl_seconds must be rejected, not silently wrapped into a negative Duration")
	assert.Contains(t, err.Error(), "exceeds the maximum")
}

// The same overflow guard applies to RenewLease's ttlSeconds parameter.
func TestDynamicSecrets_RenewRejectsOverflowingTTLSeconds(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "renew-overflow-guard", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		DefaultTTLSeconds: 600, ActorID: testAdminActorID,
	})
	require.NoError(t, err)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	_, err = c.RenewLease(ctx, issued.LeaseID, 20_000_000_000, 7)
	require.Error(t, err, "an overflowing renewal ttl_seconds must be rejected, not silently wrapped into a negative Duration")
	assert.Contains(t, err.Error(), "exceeds the maximum")
}

// Setting an oversized default_ttl_seconds/max_ttl_seconds at config-create time must
// also be rejected — both are multiplied by time.Second the same way a caller-supplied
// override is (in dynamicTTL's clamp and RenewLease's per-lease hardCap), so they carry
// the identical int64-nanosecond overflow risk.
func TestDynamicSecrets_CreateRejectsOverflowingConfigTTLFields(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()

	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "bad-default", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		DefaultTTLSeconds: 20_000_000_000, ActorID: testAdminActorID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the maximum")

	_, err = c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "bad-max", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		MaxTTLSeconds: 20_000_000_000, ActorID: testAdminActorID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the maximum")
}

// #97: an install-wide ceiling must clamp a lease's TTL even when the config's own
// MaxTTLSeconds is left unset (unbounded) — otherwise a caller-supplied override
// (or, on a misconfigured install, the config default) could mint an arbitrarily
// long-lived credential.
func TestDynamicSecrets_InstallWideMaxLeaseTTLClampsIssue(t *testing.T) {
	t.Parallel()
	c, _, _, fixed := newDynamicTestCore(t)
	c.SetDynamicMaxLeaseTTL(2 * time.Hour)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "unbounded", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		ActorID: testAdminActorID,
		// No MaxTTLSeconds — the per-config ceiling is unset/unbounded.
	})
	require.NoError(t, err)

	// A caller requests a 1000-hour (~41-day) lease; nothing in the config stops it.
	issued, err := c.IssueLease(ctx, cfg.ID, 1000*3600, 7)
	require.NoError(t, err)
	assert.Equal(t, fixed.Add(2*time.Hour), issued.ExpiresAt, "the install-wide ceiling must clamp an otherwise-unbounded request")
}

// A zero/unset install-wide ceiling must fall back to the package default (90 days),
// not disable the ceiling entirely.
func TestDynamicSecrets_InstallWideMaxLeaseTTLDefaultsWhenUnset(t *testing.T) {
	t.Parallel()
	c, _, _, fixed := newDynamicTestCore(t)
	// SetDynamicMaxLeaseTTL is never called — dynamicMaxLeaseTTL stays its zero value.
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "unbounded", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		ActorID: testAdminActorID,
	})
	require.NoError(t, err)

	issued, err := c.IssueLease(ctx, cfg.ID, 1000*24*3600, 7) // ~1000 days requested
	require.NoError(t, err)
	assert.Equal(t, fixed.Add(defaultMaxLeaseTTL), issued.ExpiresAt, "an unset install ceiling must fall back to the 90-day default, not disable clamping")
}

// #97: when the engine surfaces the provider's actual granted expiry (Fields
// ["expiration"], set by the AWS STS / Kubernetes engines after their own
// 900s/600s duration floor), the persisted lease must use THAT value rather than
// naively computing now+requestedTTL — otherwise Keyorix's own bookkeeping (and the
// auto-revoke sweep, which acts on ExpiresAt) would understate the credential's true
// lifetime.
func TestDynamicSecrets_ExpiresAtUsesProviderActualExpiryWhenSurfaced(t *testing.T) {
	t.Parallel()
	c, _, fake, fixed := newDynamicTestCore(t)
	fake.Ephemeral = true
	// The engine floored a short requested TTL up to its own provider minimum — the
	// actual granted expiry is well past what a naive now+requestedTTL would compute.
	actualExpiry := fixed.Add(15 * time.Minute)
	fake.IssueFields = map[string]string{"expiration": actualExpiry.UTC().Format(time.RFC3339)}
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	// Request only 60s — far below the provider's actual floor.
	issued, err := c.IssueLease(ctx, cfg.ID, 60, 7)
	require.NoError(t, err)
	assert.Equal(t, actualExpiry, issued.ExpiresAt, "ExpiresAt must reflect the provider's actual granted expiry, not now+60s")

	stored, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, err)
	assert.Equal(t, actualExpiry, stored.ExpiresAt, "the persisted lease row must carry the corrected expiry too")
}

// Without a surfaced provider expiry (Fields["expiration"] absent, e.g. a DB backend),
// ExpiresAt must still fall back to the requested-ttl computation — the correction is
// additive, not a behavior change for backends that don't surface one.
func TestDynamicSecrets_ExpiresAtFallsBackWithoutProviderExpiry(t *testing.T) {
	t.Parallel()
	c, _, _, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 1800, 7)
	require.NoError(t, err)
	assert.Equal(t, fixed.Add(30*time.Minute), issued.ExpiresAt)
}

// #97: RevokeLease's audit trail must not claim an ephemeral (no-op-Revoke) backend's
// credential was actually killed — it remains live at the provider until its own
// natural expiry. The lease is still marked "revoked" locally (so it drops out of
// active-lease accounting / stops appearing as issuable-from-this-lease), but the
// audit message must say so honestly.
func TestDynamicSecrets_RevokeEphemeralBackendAuditsHonestly(t *testing.T) {
	t.Parallel()
	c, db, fake, _ := newDynamicTestCore(t)
	fake.Ephemeral = true
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))

	lease, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, err)
	assert.Equal(t, "revoked", lease.Status, "still marked revoked locally")

	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "dynamic_lease.revoked").Order("id DESC").First(&ev).Error)
	assert.Contains(t, ev.Description, "cannot be invalidated early", "the audit trail must not claim a full provider-side revoke for an ephemeral backend")
}

// #97: the flip side of the test above — an ephemeral backend whose Revoke DID
// genuinely invalidate the credential early (e.g. Kubernetes with
// "revocable":true — see kubernetes.go) must NOT be lumped in with the no-op
// backends' misleading "cannot be invalidated early" message.
func TestDynamicSecrets_RevokeEffectiveEphemeralBackendAuditsAsGenuineRevoke(t *testing.T) {
	t.Parallel()
	c, db, fake, _ := newDynamicTestCore(t)
	fake.Ephemeral = true
	effective := true
	fake.RevokeEffective = &effective
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))

	lease, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, err)
	assert.Equal(t, "revoked", lease.Status)

	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "dynamic_lease.revoked").Order("id DESC").First(&ev).Error)
	assert.NotContains(t, ev.Description, "cannot be invalidated early", "a backend that genuinely revoked the credential must not be audited as a no-op")
}

func TestDynamicSecrets_CreateRejectsDefaultOverMax(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	_, err := c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: "bad", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		DefaultTTLSeconds: 3600, MaxTTLSeconds: 600, ActorID: testAdminActorID,
	})
	require.Error(t, err)
}

// #97: renewal must respect the install-wide ceiling too, not just the (optional,
// default-unbounded) per-config MaxTTLSeconds — otherwise a config left without its
// own ceiling could have its lease's total lifetime stretched arbitrarily far by
// repeated renewals.
func TestDynamicSecrets_RenewRespectsInstallWideMaxLeaseTTL(t *testing.T) {
	t.Parallel()
	c, _, _, fixed := newDynamicTestCore(t)
	c.SetDynamicMaxLeaseTTL(20 * time.Minute)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "unbounded", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		DefaultTTLSeconds: 300, // no MaxTTLSeconds — per-config ceiling unset
		ActorID:           testAdminActorID,
	})
	require.NoError(t, err)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7) // expiry = fixed+5m
	require.NoError(t, err)
	require.Equal(t, fixed.Add(5*time.Minute), issued.ExpiresAt)

	// Ask to renew far past the 20m install ceiling (measured from IssuedAt).
	exp, err := c.RenewLease(ctx, issued.LeaseID, 3600, 7)
	require.NoError(t, err)
	assert.Equal(t, fixed.Add(20*time.Minute), exp, "renewal must clamp to the install-wide ceiling from IssuedAt")
}

func TestDynamicSecrets_RenewExtendsAndRespectsMaxTTL(t *testing.T) {
	t.Parallel()
	c, _, fake, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "renewable", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		DefaultTTLSeconds: 600, MaxTTLSeconds: 1200, // 10m default, 20m hard cap
		ActorID: testAdminActorID,
	})
	require.NoError(t, err)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7) // expiry = fixed+10m
	require.NoError(t, err)
	require.Equal(t, fixed.Add(10*time.Minute), issued.ExpiresAt)

	// Renew for 20m from now; the fixed clock means now=issue time, so the new
	// expiry is fixed+20m — exactly the IssuedAt+max ceiling, extending from +10m.
	exp, err := c.RenewLease(ctx, issued.LeaseID, 1200, 7)
	require.NoError(t, err)
	assert.Equal(t, fixed.Add(20*time.Minute), exp)
	assert.Contains(t, fake.Renewed, issued.Username, "the engine renewed the role")

	// A further renewal can't extend past IssuedAt+max (20m) → rejected.
	_, err = c.RenewLease(ctx, issued.LeaseID, 1200, 7)
	require.Error(t, err, "renewal beyond the max-TTL ceiling is rejected")
}

// An ephemeral (cloud-IAM, e.g. AWS STS) backend surfaces its credential via Fields
// and refuses renewal — its lifetime is fixed by the provider at issue.
func TestDynamicSecrets_EphemeralBackendFieldsAndRenewRefused(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	fake.Ephemeral = true
	fake.IssueFields = map[string]string{"access_key_id": "AKIA", "session_token": "tok"}
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	assert.Equal(t, "AKIA", issued.Fields["access_key_id"])
	assert.Equal(t, "tok", issued.Fields["session_token"])

	_, err = c.RenewLease(ctx, issued.LeaseID, 1200, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be renewed")
}

func TestDynamicSecrets_RevokeLeasesForConfig(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	i1, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	i2, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	revoked, failed, err := c.RevokeLeasesForConfig(ctx, cfg.ID, 7, "incident")
	require.NoError(t, err)
	assert.Equal(t, 2, revoked)
	assert.Equal(t, 0, failed)
	assert.ElementsMatch(t, []string{i1.Username, i2.Username}, fake.Revoked)

	// Both leases are now revoked; a second bulk-revoke finds nothing active.
	for _, lid := range []string{i1.LeaseID, i2.LeaseID} {
		l, _ := c.storage.GetDynamicSecretLease(ctx, lid)
		assert.Equal(t, "revoked", l.Status)
	}
	revoked2, _, err := c.RevokeLeasesForConfig(ctx, cfg.ID, 7, "incident")
	require.NoError(t, err)
	assert.Equal(t, 0, revoked2)
}

// The bulk incident-response kill switch is the last line of defense for
// backends with no DB-level native expiry (MySQL/Mongo/Redis): the target
// drop/dropUser/ACL-DELUSER call is the only enforcement mechanism. A lease already
// stuck in revoke_failed (its credential still live from an earlier failed attempt)
// must NOT be silently skipped — it must be retried right alongside the still-active
// leases, so an operator responding to "this target/config is compromised" actually
// kills every outstanding credential, not just the ones that happened to revoke
// cleanly on the first try. Also pins #192: a successful retry must clear the
// earlier RevokeError, not leave a stale failure message on a now-clean lease.
func TestDynamicSecrets_RevokeLeasesForConfigRetriesRevokeFailed(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	stuck, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	stillActive, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	// The first lease's revoke fails once (transient outage) and is left revoke_failed —
	// its credential is still live on the target.
	fake.FailRevoke = true
	require.Error(t, c.RevokeLease(ctx, stuck.LeaseID, 7, "manual"))
	before, _ := c.storage.GetDynamicSecretLease(ctx, stuck.LeaseID)
	require.Equal(t, "revoke_failed", before.Status, "precondition: the lease is stuck")
	require.Nil(t, before.RevokedAt, "precondition: not falsely timestamped as revoked")
	require.NotEmpty(t, before.RevokeError, "precondition: the earlier failure left a RevokeError message")

	// The target recovers, and an incident responder now believes the whole config is
	// compromised and pulls the kill switch.
	fake.FailRevoke = false
	revoked, failed, err := c.RevokeLeasesForConfig(ctx, cfg.ID, 7, "incident: compromised target")
	require.NoError(t, err)
	assert.Equal(t, 0, failed)
	assert.Equal(t, 2, revoked, "both the still-active lease AND the previously revoke_failed one must be revoked")

	after, _ := c.storage.GetDynamicSecretLease(ctx, stuck.LeaseID)
	assert.Equal(t, "revoked", after.Status, "the revoke_failed lease is NOT permanently stuck — the kill switch reaches it")
	assert.NotNil(t, after.RevokedAt, "the now-successful revoke IS timestamped")
	assert.Empty(t, after.RevokeError, "a successful retry clears the earlier error")
	assert.Contains(t, fake.Revoked, stuck.Username, "the previously-stranded credential was actually dropped on the target")
	assert.Contains(t, fake.Revoked, stillActive.Username)
}

// If the target is still down when the kill switch is pulled, a revoke_failed lease
// must remain revoke_failed (not be silently marked revoked) and still carry no
// RevokedAt timestamp — the bulk path must not paper over a persistent failure.
func TestDynamicSecrets_RevokeLeasesForConfigReportsPersistentFailure(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	stuck, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	fake.FailRevoke = true
	require.Error(t, c.RevokeLease(ctx, stuck.LeaseID, 7, "manual"))
	before, _ := c.storage.GetDynamicSecretLease(ctx, stuck.LeaseID)
	require.Equal(t, "revoke_failed", before.Status)

	// Target is STILL down when the kill switch is pulled.
	revoked, failed, err := c.RevokeLeasesForConfig(ctx, cfg.ID, 7, "incident: still down")
	require.Error(t, err, "#2406: a partial bulk-revoke must not report a clean success — the counts alone are not enough, since callers that only check err would otherwise see nil/OK")
	assert.Equal(t, 0, revoked)
	assert.Equal(t, 1, failed)

	after, _ := c.storage.GetDynamicSecretLease(ctx, stuck.LeaseID)
	assert.Equal(t, "revoke_failed", after.Status, "still stuck, not silently marked revoked")
	assert.Nil(t, after.RevokedAt, "not falsely timestamped as revoked")
}

func TestDynamicSecrets_RenewRejectsInactiveLease(t *testing.T) {
	t.Parallel()
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))
	_, err = c.RenewLease(ctx, issued.LeaseID, 0, 7)
	require.Error(t, err, "a revoked lease cannot be renewed")
}

// A lease whose expiry has already passed must not be renewable even while its status
// is still "active" (the sweeper has not flipped it yet, or is disabled). Renewing it
// would push the backend credential's lifetime forward and resurrect a credential that
// should be dead, so RenewLease must refuse and must NOT call the engine.
func TestDynamicSecrets_RenewRejectsExpiredLease(t *testing.T) {
	t.Parallel()
	c, _, fake, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	// Backdate the lease past its expiry while leaving status "active" (pre-sweep).
	lease, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, err)
	lease.ExpiresAt = fixed.Add(-time.Minute)
	require.NoError(t, c.storage.UpdateDynamicSecretLease(ctx, lease))
	require.Equal(t, "active", lease.Status)

	_, err = c.RenewLease(ctx, issued.LeaseID, 1200, 7)
	require.Error(t, err, "an expired lease cannot be renewed")
	assert.Contains(t, err.Error(), "expired")
	assert.NotContains(t, fake.Renewed, issued.Username, "the engine must not renew a dead credential")
}

// TestDynamicSecrets_RealFactoryValidatesBackend checks the real engine factory
// (no fake): config creation accepts the supported backends and rejects others.
func TestDynamicSecrets_RealFactoryValidatesBackend(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.DynamicSecretConfig{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
	))
	// ADR-084: the admin bypass is now the structural BypassesPermissionChecks
	// flag, not the "admin" name.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testAdminActorID, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "real-factory-project"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 1, Name: "real-factory-env"}).Error)
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	// ADR-109 step 3: internal/core no longer defaults to dynamic.New internally
	// (that would mean importing internal/dynamic from production code) — wire
	// it explicitly here, exactly as server/main.go's DefaultIntegrations does,
	// so this test still exercises the REAL factory's backend-name validation.
	c.SetDynamicEngineFactory(func(bt string) (dynamic.CredentialEngine, error) { return dynamic.New(bt, false, false) })

	for _, backend := range []string{"postgres", "mysql", "mongodb", "redis"} {
		_, err := c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
			Name: backend + "-cfg", ProjectID: 1, EnvironmentID: 2, BackendType: backend, AdminDSN: "admin:p@tcp(h:3306)/",
			ActorID: testAdminActorID,
		})
		require.NoError(t, err, "backend %s must be accepted", backend)
	}

	_, err = c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: "bad", ProjectID: 1, BackendType: "cassandra", AdminDSN: "x", ActorID: testAdminActorID,
	})
	require.Error(t, err, "an unsupported backend must be rejected at config creation")
}

// TestDynamicSecrets_NoFactoryConfigured_FailsClosed confirms ADR-109's "nil
// implementation means the feature is unavailable, never fails open": a
// KeyorixCore with no dynamicEngineFactory wired (SetDynamicEngineFactory
// never called — the shape a caller gets by constructing *KeyorixCore
// directly rather than through server/main.go's DefaultIntegrations) must
// refuse to mint or resolve a dynamic-secret engine, not silently reach for a
// concrete backend.
func TestDynamicSecrets_NoFactoryConfigured_FailsClosed(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.DynamicSecretConfig{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testAdminActorID, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "no-factory-project"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 1, Name: "no-factory-env"}).Error)
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	// Deliberately no SetDynamicEngineFactory call.

	_, err = c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: "pg-cfg", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres", AdminDSN: adminDSNPlain,
		ActorID: testAdminActorID,
	})
	require.Error(t, err, "config creation must fail closed with no engine factory wired")
	assert.Contains(t, err.Error(), "unavailable")
}

// A backend without DB-level expiry (MySQL/MongoDB) must not issue while the
// auto-revoke sweeper is disabled — otherwise the lease TTL is never enforced.
func TestDynamicSecrets_IssueRequiresSweeperForNoExpiryBackend(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)
	fake.NativeExpiry = false // mimic MySQL/MongoDB

	// Sweeper disabled (the default): refuse, and mint nothing.
	_, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sweep_enabled")
	assert.Empty(t, fake.Issued, "no role is minted when the issue is refused")

	// Enable the sweeper → issuing proceeds.
	c.SetDynamicSweepEnabled(true)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	assert.NotEmpty(t, issued.LeaseID)
	assert.Len(t, fake.Issued, 1)
}

// A failed cleanup-revoke after an aborted issue must leave a visible
// revoke_failed lease (so the orphaned target role is not silently permanent),
// while a clean drop records nothing.
func TestDynamicSecrets_CleanupOrphanedRole(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	t.Run("clean drop leaves no trace", func(t *testing.T) {
		c.cleanupOrphanedRole(ctx, cfg, fake, adminDSNPlain, "kx_orphan_ok", 7)
		assert.Contains(t, fake.Revoked, "kx_orphan_ok")
		leases, err := c.ListDynamicSecretLeases(ctx, cfg.ID)
		require.NoError(t, err)
		assert.Empty(t, leases, "a clean drop records no lease")
	})

	t.Run("failed drop records a revoke_failed lease", func(t *testing.T) {
		fake.FailRevoke = true
		c.cleanupOrphanedRole(ctx, cfg, fake, adminDSNPlain, "kx_orphan_stuck", 7)
		leases, err := c.ListDynamicSecretLeases(ctx, cfg.ID)
		require.NoError(t, err)
		require.Len(t, leases, 1)
		assert.Equal(t, "revoke_failed", leases[0].Status)
		assert.Equal(t, "kx_orphan_stuck", leases[0].RoleName)
		assert.Contains(t, leases[0].RevokeError, "orphaned")
	})
}
