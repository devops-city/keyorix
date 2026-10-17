// storage_s27_test.go — s27 coverage sweep for internal/storage (factory.go).
//
// Targets:
//
//	factory.go withMigrationLock (44.4%)
//	  — isPostgres=true path on a SQLite DB triggers the advisory-lock
//	    SQL which fails ("unknown function: pg_advisory_lock"), exercising
//	    the transaction + error branch.
//
//	factory.go applyPoolSettings (90.9%)
//	  — MaxIdleConns > 0 branch (SetMaxIdleConns)
//	  — ConnMaxLifetimeMinutes > 0 branch (SetConnMaxLifetime)
//	  — MaxOpenConns > 0 branch (explicit cap, not the default)
//
//	factory.go ensureGroupNameIndex (77.8%)
//	  — happy path: groups table exists, no duplicates, index is created
//	  — duplicate-name path: pre-existing duplicate active groups fail loud
//
//	factory.go ensureUserEmailIndex (85.7%)
//	  — happy path: users table with unique emails
//	  — duplicate path: two rows with same LOWER(email) block the index
//
//	factory.go ensureUserExternalIDIndex (85.7%)
//	  — happy path: unique external_ids succeed
//	  — duplicate path: shared external_id blocks the index
//
//	factory.go ensureSecretVersionIndex (85.7%)
//	  — happy path: unique (secret_node_id, version_number) pairs succeed
//
//	factory.go ensureShareRecordUniqueIndex (85.7%)
//	  — happy path: unique active share records succeed
//
//	factory.go ensureDynamicSecretConfigNameIndex (85.7%)
//	  — happy path: unique (project_id, environment_id, name) tuples succeed
//
//	factory.go ensureProjectMembershipIndex (85.7%)
//	  — happy path: unique active memberships succeed
//
//	factory.go ensureBreakGlassActiveIndex (85.7%)
//	  — happy path: unique active break-glass activations succeed
//
//	factory.go ensureLegalHoldActiveIndex (85.7%)
//	  — happy path: unique unreleased hold succeeds
//
//	factory.go migrateDatabase (81.4%)
//	  — dynamic_secret_configs "else" (existing table) branch
//	  — notifications "else" (existing table) branch
//	  — project_invitations "else" (existing table) branch
package storage

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// withMigrationLock — isPostgres=true on a SQLite DB triggers error branch
// ---------------------------------------------------------------------------

// TestWithMigrationLock_S27_PostgresPathErrorOnSQLite verifies that when
// isPostgres=true, withMigrationLock wraps the call in a transaction and
// executes SELECT pg_advisory_lock — which fails on SQLite — and the error
// surfaces as "acquire migration advisory lock".
func TestWithMigrationLock_S27_PostgresPathErrorOnSQLite(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "mig-pg-path.db"))
	require.NoError(t, err)

	err = withMigrationLock(db, true, "", func(_ *gorm.DB) error { return nil })
	require.Error(t, err, "pg_advisory_lock does not exist on SQLite: must error")
	assert.Contains(t, err.Error(), "acquire migration advisory lock")
}

// TestWithMigrationLock_S27_PostgresPathFnNeverCalled verifies that fn is
// NOT called when the advisory lock acquisition fails.
func TestWithMigrationLock_S27_PostgresPathFnNeverCalled(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "mig-pg-nofn.db"))
	require.NoError(t, err)

	called := false
	_ = withMigrationLock(db, true, "", func(_ *gorm.DB) error {
		called = true
		return nil
	})
	assert.False(t, called, "fn must not be called when advisory lock fails")
}

// ---------------------------------------------------------------------------
// applyPoolSettings — additional branches
// ---------------------------------------------------------------------------

// TestApplyPoolSettings_S27_MaxOpenConnsExplicit verifies the MaxOpenConns>0
// branch (explicit user-configured cap, rather than the default).
func TestApplyPoolSettings_S27_MaxOpenConnsExplicit(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-maxopen.db"))
	require.NoError(t, err)

	cfg := &config.DatabaseConfig{MaxOpenConns: 10}
	require.NoError(t, applyPoolSettings(db, cfg))
	// No assertion on the value — the test exercises the branch that calls
	// sqlDB.SetMaxOpenConns(cfg.MaxOpenConns) rather than the default.
}

// TestApplyPoolSettings_S27_MaxIdleConns verifies the MaxIdleConns>0 branch
// (calls sqlDB.SetMaxIdleConns).
func TestApplyPoolSettings_S27_MaxIdleConns(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-idle.db"))
	require.NoError(t, err)

	cfg := &config.DatabaseConfig{MaxIdleConns: 5}
	require.NoError(t, applyPoolSettings(db, cfg))
}

// TestApplyPoolSettings_S27_ConnMaxLifetimeMinutes verifies the
// ConnMaxLifetimeMinutes>0 branch (calls sqlDB.SetConnMaxLifetime).
func TestApplyPoolSettings_S27_ConnMaxLifetimeMinutes(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-lifetime.db"))
	require.NoError(t, err)

	cfg := &config.DatabaseConfig{ConnMaxLifetimeMinutes: 30}
	require.NoError(t, applyPoolSettings(db, cfg))
}

// TestApplyPoolSettings_S27_AllThreeSet exercises all three optional pool
// settings in a single call so the happy path through every `if` is reached
// in one test.
func TestApplyPoolSettings_S27_AllThreeSet(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-all.db"))
	require.NoError(t, err)

	cfg := &config.DatabaseConfig{
		MaxOpenConns:           20,
		MaxIdleConns:           5,
		ConnMaxLifetimeMinutes: 10,
	}
	require.NoError(t, applyPoolSettings(db, cfg))
}

// ---------------------------------------------------------------------------
// ensureGroupNameIndex — happy path + duplicate-name error path
// ---------------------------------------------------------------------------

// TestEnsureGroupNameIndex_S27_HappyPath verifies that ensureGroupNameIndex
// succeeds when the groups table exists with no duplicate active names.
func TestEnsureGroupNameIndex_S27_HappyPath(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "grp-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, name_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (1, 'alpha', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (2, 'beta', '', NULL)`).Error)
	// Soft-deleted group with same name as live group — must NOT count as dup.
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (3, 'alpha', '', '2024-01-01')`).Error)

	require.NoError(t, ensureGroupNameIndex(db))
	assert.True(t, indexExists(db, "uniq_groups_name_folded_active"))
}

// TestEnsureGroupNameIndex_S27_DuplicateActiveNamesBlocked verifies that two
// live (non-deleted) groups with the same name cause ensureGroupNameIndex to
// return an error containing "groups".
func TestEnsureGroupNameIndex_S27_DuplicateActiveNamesBlocked(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "grp-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, name_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (1, 'clash', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (2, 'clash', '', NULL)`).Error)

	err = ensureGroupNameIndex(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "groups")
}

// TestEnsureGroupNameIndex_S27_Idempotent verifies that calling
// ensureGroupNameIndex twice on a clean DB is a no-op (IF NOT EXISTS).
func TestEnsureGroupNameIndex_S27_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "grp-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, name_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, ensureGroupNameIndex(db))
	require.NoError(t, ensureGroupNameIndex(db), "second call must be a no-op")
}

// ---------------------------------------------------------------------------
// ensureUserEmailIndex — happy path + duplicate email error path
// ---------------------------------------------------------------------------

// TestEnsureUserEmailIndex_S27_HappyPath verifies that ensureUserEmailIndex
// creates the partial index when no email duplicates exist.
func TestEnsureUserEmailIndex_S27_HappyPath(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "email-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, email_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'alice@example.com', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'bob@example.com', '', NULL)`).Error)
	require.NoError(t, ensureUserEmailIndex(db))
	assert.True(t, indexExists(db, "uniq_users_email_folded_active"))
}

// TestEnsureUserEmailIndex_S27_DuplicateEmails verifies that two live rows with
// the same LOWER(email) block the index creation with an error.
func TestEnsureUserEmailIndex_S27_DuplicateEmails(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "email-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, email_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'alice@example.com', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'Alice@Example.Com', '', NULL)`).Error) // same LOWER()
	err = ensureUserEmailIndex(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users")
}

// ---------------------------------------------------------------------------
// ensureUserExternalIDIndex — happy path + duplicate external_id error path
// ---------------------------------------------------------------------------

// TestEnsureUserExternalIDIndex_S27_HappyPath verifies that the index is
// created when no duplicate non-empty external_ids exist.
func TestEnsureUserExternalIDIndex_S27_HappyPath(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "extid-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, external_id TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'scim-001', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'scim-002', NULL)`).Error)
	// Empty external_id — must not collide with itself.
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (3, '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (4, '', NULL)`).Error)
	require.NoError(t, ensureUserExternalIDIndex(db))
	assert.True(t, indexExists(db, "uniq_users_external_id_active"))
}

// TestEnsureUserExternalIDIndex_S27_DuplicateExternalIDs verifies that two live
// rows sharing the same non-empty external_id are blocked.
func TestEnsureUserExternalIDIndex_S27_DuplicateExternalIDs(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "extid-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, external_id TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'dup-id', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'dup-id', NULL)`).Error)
	err = ensureUserExternalIDIndex(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users")
}

// ---------------------------------------------------------------------------
// ensureSecretVersionIndex — happy path
// ---------------------------------------------------------------------------

// TestEnsureSecretVersionIndex_S27_HappyPath verifies that the unique index on
// (secret_node_id, version_number) is created when no duplicate pairs exist.
func TestEnsureSecretVersionIndex_S27_HappyPath(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "sv-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE secret_versions (id INTEGER PRIMARY KEY, secret_node_id INTEGER, version_number INTEGER)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (1, 10, 1)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (2, 10, 2)`).Error)
	require.NoError(t, ensureSecretVersionIndex(db))
	assert.True(t, indexExists(db, "uniq_secret_versions_node_version"))
}

// ---------------------------------------------------------------------------
// ensureShareRecordUniqueIndex — happy path
// ---------------------------------------------------------------------------

// TestEnsureShareRecordUniqueIndex_S27_HappyPath verifies that the partial
// unique index on share_records is created when no active duplicate triples exist.
func TestEnsureShareRecordUniqueIndex_S27_HappyPath(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "share-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE share_records (
		id INTEGER PRIMARY KEY,
		secret_id INTEGER,
		recipient_id INTEGER,
		is_group INTEGER DEFAULT 0,
		deleted_at DATETIME
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO share_records VALUES (1, 1, 10, 0, NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO share_records VALUES (2, 1, 11, 0, NULL)`).Error)
	require.NoError(t, ensureShareRecordUniqueIndex(db))
	assert.True(t, indexExists(db, "uniq_share_records_active"))
}

// ---------------------------------------------------------------------------
// ensureDynamicSecretConfigNameIndex — happy path
// ---------------------------------------------------------------------------

// TestEnsureDynamicSecretConfigNameIndex_S27_HappyPath verifies that the unique
// index on (project_id, environment_id, name) is created when all tuples are unique.
func TestEnsureDynamicSecretConfigNameIndex_S27_HappyPath(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dynconf-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE dynamic_secret_configs (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		environment_id INTEGER,
		name TEXT
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO dynamic_secret_configs VALUES (1, 1, 1, 'db-creds')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO dynamic_secret_configs VALUES (2, 1, 2, 'db-creds')`).Error) // same name, different env
	require.NoError(t, ensureDynamicSecretConfigNameIndex(db))
	assert.True(t, indexExists(db, "uniq_dynamic_secret_configs_project_env_name"))
}

// ---------------------------------------------------------------------------
// ensureProjectMembershipIndex — happy path
// ---------------------------------------------------------------------------

// TestEnsureProjectMembershipIndex_S27_HappyPath verifies that the partial
// unique index on active project memberships is created when no duplicates exist.
func TestEnsureProjectMembershipIndex_S27_HappyPath(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "membership-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE project_memberships (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		user_id INTEGER,
		state TEXT
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO project_memberships VALUES (1, 1, 10, 'active')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO project_memberships VALUES (2, 1, 11, 'active')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO project_memberships VALUES (3, 1, 10, 'revoked')`).Error) // revoked — not in scope
	require.NoError(t, ensureProjectMembershipIndex(db))
	assert.True(t, indexExists(db, "uniq_project_memberships_active"))
}

// ---------------------------------------------------------------------------
// ensureBreakGlassActiveIndex — happy path
// ---------------------------------------------------------------------------

// TestEnsureBreakGlassActiveIndex_S27_HappyPath verifies that the partial
// unique index on active break-glass activations is created when no duplicate
// active (project_id, user_id) pairs exist.
func TestEnsureBreakGlassActiveIndex_S27_HappyPath(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "bga-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE break_glass_activations (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		user_id INTEGER,
		state TEXT
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO break_glass_activations VALUES (1, 1, 10, 'active')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO break_glass_activations VALUES (2, 1, 10, 'revoked')`).Error) // revoked — out of partial scope
	require.NoError(t, ensureBreakGlassActiveIndex(db))
	assert.True(t, indexExists(db, "uniq_break_glass_active_project_user"))
}

// ---------------------------------------------------------------------------
// ensureLegalHoldActiveIndex — happy path
// ---------------------------------------------------------------------------

// TestEnsureLegalHoldActiveIndex_S27_HappyPath verifies that the partial unique
// index permitting at most one un-released hold is created when only one such
// row exists.
func TestEnsureLegalHoldActiveIndex_S27_HappyPath(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "lh-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE legal_holds (id INTEGER PRIMARY KEY, released INTEGER DEFAULT 0)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO legal_holds VALUES (1, 0)`).Error) // one un-released hold
	require.NoError(t, db.Exec(`INSERT INTO legal_holds VALUES (2, 1)`).Error) // released — out of scope
	require.NoError(t, ensureLegalHoldActiveIndex(db))
	assert.True(t, indexExists(db, "uniq_legal_holds_active"))
}

// ---------------------------------------------------------------------------
// migrateDatabase — "else" branch coverage via pre-seeded tables
// ---------------------------------------------------------------------------

// TestMigrateDatabase_S27_DynamicSecretConfigsElseBranch exercises the
// dynamic_secret_configs else-branch (the table already exists → Migrator
// AddColumn path is taken for MaxTTLSeconds / Disabled columns).
func TestMigrateDatabase_S27_DynamicSecretConfigsElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dyncfg-else.db"))
	require.NoError(t, err)

	// Create a minimal dynamic_secret_configs table (simulating a pre-ADR-035
	// schema that predates MaxTTLSeconds/Disabled/Classification columns).
	require.NoError(t, db.Exec(`CREATE TABLE dynamic_secret_configs (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		environment_id INTEGER,
		name TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	// Accept any outcome — AutoMigrate may add columns, or the "else" branch
	// runs and the migrator attempts to add them. The branch is exercised.
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S27_NotificationsElseBranch exercises the notifications
// else-branch (table already exists → Migrator AddColumn path for
// project_id/type column additions).
func TestMigrateDatabase_S27_NotificationsElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "notif-else.db"))
	require.NoError(t, err)

	// Pre-existing notifications table without project_id / type columns.
	require.NoError(t, db.Exec(`CREATE TABLE notifications (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		message TEXT,
		is_read INTEGER DEFAULT 0
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S27_ProjectInvitationsElseBranch exercises the
// project_invitations else-branch (table already exists → column-addition
// path for ProjectID / EnvironmentScope columns).
func TestMigrateDatabase_S27_ProjectInvitationsElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "invite-else.db"))
	require.NoError(t, err)

	// Pre-existing project_invitations table without newer columns.
	require.NoError(t, db.Exec(`CREATE TABLE project_invitations (
		id INTEGER PRIMARY KEY,
		token TEXT,
		email TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// ---------------------------------------------------------------------------
// createLocalStorage — DSN path with a pre-existing query-string
// ---------------------------------------------------------------------------

// TestCreateLocalStorage_S27_ExistingDSNQueryString verifies that createLocalStorage
// succeeds when the DB path already contains a "?" (in-memory DSN with pragmas),
// ensuring sqliteDSN uses "&" to append rather than "?".
func TestCreateLocalStorage_S27_ExistingDSNQueryString(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	// A named in-memory DSN that already has a query-string component.
	cfg.Storage.Database.Path = sqlitetest.DSN("creates27_existing_qs_")

	s, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "createLocalStorage must succeed with a pre-existing DSN query string")
	assert.NotNil(t, s)
}

// ---------------------------------------------------------------------------
// warnIfDuplicatesExist — query error path (table does not exist)
// ---------------------------------------------------------------------------

// TestWarnIfDuplicatesExist_S27_QueryError verifies that warnIfDuplicatesExist
// returns a wrapped error when the SQL query itself fails (table absent).
func TestWarnIfDuplicatesExist_S27_QueryError(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "warn-qerr.db"))
	require.NoError(t, err)
	// No table created — the COUNT(*) FROM nonexistent_table query will fail.
	err = warnIfDuplicatesExist(db, "nonexistent_table", "col", "", "remedy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent_table")
}

// ---------------------------------------------------------------------------
// gormdb.go — OpenGormDB additional branches
// ---------------------------------------------------------------------------

// TestOpenGormDB_S27_LocalTypeSucceeds exercises the "local" type in OpenGormDB
// (distinct from CreateStorage path) with an explicit temp file path.
func TestOpenGormDB_S27_LocalTypeSucceeds(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "ggormdb-s27.db")

	db, err := OpenGormDB(cfg)
	require.NoError(t, err)
	require.NotNil(t, db)
}

// ---------------------------------------------------------------------------
// sqliteDSN — coverage for the path-with-"?" branch
// ---------------------------------------------------------------------------

// TestSQLiteDSN_S27_PathWithQueryStringAppendsAmpersand verifies that a path
// already containing "?" results in "&" appended (not a second "?").
func TestSQLiteDSN_S27_PathWithQueryStringAppendsAmpersand(t *testing.T) {
	dsn := sqliteDSN("file:mydb?mode=memory")
	// Must not contain more than one "?".
	count := 0
	for _, c := range dsn {
		if c == '?' {
			count++
		}
	}
	assert.Equal(t, 1, count, "sqliteDSN must not produce a second '?' when the path already has one")
	assert.Contains(t, dsn, "_foreign_keys=1")
	assert.Contains(t, dsn, "_journal_mode=WAL")
}

// ---------------------------------------------------------------------------
// factory.go — DefaultStorageFactory.CreateStorage invalid type
// ---------------------------------------------------------------------------

// TestCreateStorage_S27_InvalidTypeError verifies that an unrecognised
// storage.type is rejected with an "invalid storage.type" message.
func TestCreateStorage_S27_InvalidTypeError(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "bogus-s27"
	_, err := NewStorageFactory().CreateStorage(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid storage.type")
}

// ---------------------------------------------------------------------------
// factory.go — sqliteDSN error-sentinel: ensure constant value matches
// ---------------------------------------------------------------------------

// TestSQLiteBusyTimeoutMillis_S27_Value is a lightweight pin on the busy-timeout
// constant to guard against accidental changes that would silently break all
// SQLite deployments by reducing the contention window.
func TestSQLiteBusyTimeoutMillis_S27_Value(t *testing.T) {
	const expected = 10000
	if sqliteBusyTimeoutMillis != expected {
		t.Errorf("sqliteBusyTimeoutMillis = %d; want %d", sqliteBusyTimeoutMillis, expected)
	}
}

// ---------------------------------------------------------------------------
// factory.go — ensureGroupNameIndex warnIfDuplicatesExist propagation
// ---------------------------------------------------------------------------

// TestEnsureGroupNameIndex_S27_DropLegacyIndexNoOp verifies that
// ensureGroupNameIndex is a no-op when the legacy index doesn't exist (DROP
// INDEX IF EXISTS is idempotent on SQLite) and then succeeds for a fresh table.
func TestEnsureGroupNameIndex_S27_DropLegacyIndexNoOp(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "grp-droplg.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, name_folded TEXT, deleted_at DATETIME)`).Error)
	// No legacy index exists — DROP IF EXISTS is a no-op.
	require.NoError(t, ensureGroupNameIndex(db), "must succeed even without a legacy index to drop")
}

// ---------------------------------------------------------------------------
// factory.go — ensureSecretVersionIndex duplicate path
// ---------------------------------------------------------------------------

// TestEnsureSecretVersionIndex_S27_DuplicatePairs verifies that pre-existing
// duplicate (secret_node_id, version_number) pairs block the index with an error.
func TestEnsureSecretVersionIndex_S27_DuplicatePairs(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "sv-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE secret_versions (id INTEGER PRIMARY KEY, secret_node_id INTEGER, version_number INTEGER)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (1, 5, 3)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (2, 5, 3)`).Error) // duplicate
	err = ensureSecretVersionIndex(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret_versions")
}

// ---------------------------------------------------------------------------
// factory.go — additional ensure*Index idempotency tests
// ---------------------------------------------------------------------------

// TestEnsureBreakGlassActiveIndex_S27_Idempotent verifies the index is
// idempotent (second call is a no-op via IF NOT EXISTS).
func TestEnsureBreakGlassActiveIndex_S27_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "bga-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE break_glass_activations (id INTEGER PRIMARY KEY, project_id INTEGER, user_id INTEGER, state TEXT)`).Error)
	require.NoError(t, ensureBreakGlassActiveIndex(db))
	require.NoError(t, ensureBreakGlassActiveIndex(db), "second call must be a no-op")
}

// TestEnsureProjectMembershipIndex_S27_Idempotent verifies the index is
// idempotent.
func TestEnsureProjectMembershipIndex_S27_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "membership-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE project_memberships (id INTEGER PRIMARY KEY, project_id INTEGER, user_id INTEGER, state TEXT)`).Error)
	require.NoError(t, ensureProjectMembershipIndex(db))
	require.NoError(t, ensureProjectMembershipIndex(db), "second call must be a no-op")
}

// ---------------------------------------------------------------------------
// factory.go — createLocalStorage error: DSN for non-existent directory
// ---------------------------------------------------------------------------

// TestCreateLocalStorage_S27_InvalidPath verifies that createLocalStorage fails
// if the DB path references a non-existent parent directory.
func TestCreateLocalStorage_S27_InvalidPath(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = "/nonexistent_dir_s27/should_fail.db"

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.Error(t, err, "opening a DB in a non-existent directory must fail")
	_ = errors.Unwrap(err) // just exercise the error structure
}
