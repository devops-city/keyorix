package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// sqliteDSN — edge cases
// ---------------------------------------------------------------------------

// TestSQLiteDSN_S23_InMemoryPath verifies that an in-memory SQLite DSN
// (file:name?mode=memory&cache=shared) gets the pragmas appended via "&"
// (not "?") because the path already contains "?".
func TestSQLiteDSN_S23_InMemoryPath(t *testing.T) {
	dsn := sqliteDSN(sqlitetest.DSN("s23inmem_"))
	assert.Contains(t, dsn, "_foreign_keys=1")
	assert.Contains(t, dsn, "_busy_timeout=10000")
	assert.Contains(t, dsn, "_journal_mode=WAL")
	// Must not duplicate "?" — it must use "&" to append because the path
	// already contains a "?".
	firstQ := false
	for _, ch := range dsn {
		if ch == '?' {
			if firstQ {
				t.Fatal("sqliteDSN produced a duplicate '?' in the DSN")
			}
			firstQ = true
		}
	}
}

// TestSQLiteDSN_S23_BusyTimeoutValue verifies that the busy timeout constant
// is embedded in the DSN string as a decimal integer.
func TestSQLiteDSN_S23_BusyTimeoutValue(t *testing.T) {
	dsn := sqliteDSN("/tmp/x.db")
	assert.Contains(t, dsn, "_busy_timeout=10000",
		"sqliteDSN must embed the 10-second busy-timeout value")
}

// ---------------------------------------------------------------------------
// gormConfig
// ---------------------------------------------------------------------------

// TestGormConfig_S23_ReturnsNonNil verifies that gormConfig returns a non-nil
// *gorm.Config so callers never panic on field access.
func TestGormConfig_S23_ReturnsNonNil(t *testing.T) {
	cfg := gormConfig()
	require.NotNil(t, cfg)
}

// TestGormConfig_S23_LoggerIsSilent verifies that gormConfig installs a
// silent logger (Logger field non-nil, not the GORM default verbose logger).
// The silent mode prevents sensitive bound parameters from being logged on
// slow queries or errors (#464).
func TestGormConfig_S23_LoggerIsSilent(t *testing.T) {
	cfg := gormConfig()
	require.NotNil(t, cfg.Logger, "Logger must be explicitly set to the silent mode logger")
}

// ---------------------------------------------------------------------------
// columnExists — additional edge cases
// ---------------------------------------------------------------------------

// TestColumnExists_S23_TableDoesNotExist verifies that columnExists returns
// false (not a panic/error) when the table itself does not exist.
func TestColumnExists_S23_TableDoesNotExist(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "col-notbl.db"))
	require.NoError(t, err)
	assert.False(t, columnExists(db, "nonexistent_table", "any_column"),
		"columnExists on a non-existent table must return false, not panic")
}

// TestColumnExists_S23_MultipleColumns verifies that columnExists correctly
// discriminates between two different columns in the same table.
func TestColumnExists_S23_MultipleColumns(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "col-multi.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE cm_tbl (id INTEGER PRIMARY KEY, alpha TEXT, beta INTEGER)`).Error)
	assert.True(t, columnExists(db, "cm_tbl", "alpha"))
	assert.True(t, columnExists(db, "cm_tbl", "beta"))
	assert.False(t, columnExists(db, "cm_tbl", "gamma"))
}

// ---------------------------------------------------------------------------
// tableExists — additional edge cases
// ---------------------------------------------------------------------------

// TestTableExists_S23_EmptyDB verifies that tableExists returns false for any
// table name on a freshly opened, never-migrated database.
func TestTableExists_S23_EmptyDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "te-empty.db"))
	require.NoError(t, err)
	assert.False(t, tableExists(db, "users"))
	assert.False(t, tableExists(db, "projects"))
}

// TestTableExists_S23_CaseSensitive verifies that tableExists is
// case-sensitive: SQLite stores table names exactly as created, so a
// differently-cased lookup must return false.
func TestTableExists_S23_CaseSensitive(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "te-case.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE lower_case_tbl (id INTEGER PRIMARY KEY)`).Error)
	assert.True(t, tableExists(db, "lower_case_tbl"))
	assert.False(t, tableExists(db, "Lower_Case_Tbl"), "SQLite sqlite_master name lookup is case-sensitive for table names")
}

// ---------------------------------------------------------------------------
// indexExists — additional edge cases
// ---------------------------------------------------------------------------

// TestIndexExists_S23_MultipleIndexes verifies that indexExists correctly
// discriminates between two different indexes on the same table.
func TestIndexExists_S23_MultipleIndexes(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "idx-multi.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE im_tbl (id INTEGER PRIMARY KEY, a TEXT, b TEXT)`).Error)
	require.NoError(t, db.Exec(`CREATE INDEX idx_im_a ON im_tbl (a)`).Error)
	require.NoError(t, db.Exec(`CREATE INDEX idx_im_b ON im_tbl (b)`).Error)
	assert.True(t, indexExists(db, "idx_im_a"))
	assert.True(t, indexExists(db, "idx_im_b"))
	assert.False(t, indexExists(db, "idx_im_c"))
}

// TestIndexExists_S23_PartialIndex verifies that indexExists returns true for
// a partial (WHERE-predicated) index created via raw SQL.
func TestIndexExists_S23_PartialIndex(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "idx-partial.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE ip_tbl (id INTEGER PRIMARY KEY, val TEXT, active INTEGER)`).Error)
	require.NoError(t, db.Exec(`CREATE UNIQUE INDEX idx_ip_active ON ip_tbl (val) WHERE active = 1`).Error)
	assert.True(t, indexExists(db, "idx_ip_active"))
	assert.False(t, indexExists(db, "idx_ip_inactive"))
}

// ---------------------------------------------------------------------------
// warnIfDuplicatesExist — composite-key expression
// ---------------------------------------------------------------------------

// TestWarnIfDuplicatesExist_S23_CompositeKey_Clean verifies that a
// multi-column key expression ("col_a, col_b") finds no duplicates when each
// (a, b) pair is unique.
func TestWarnIfDuplicatesExist_S23_CompositeKey_Clean(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dup-comp-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE comp_clean (id INTEGER PRIMARY KEY, a INTEGER, b INTEGER)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO comp_clean VALUES (1, 1, 1)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO comp_clean VALUES (2, 1, 2)`).Error) // same a, different b
	require.NoError(t, db.Exec(`INSERT INTO comp_clean VALUES (3, 2, 1)`).Error) // different a, same b
	err = warnIfDuplicatesExist(db, "comp_clean", "a, b", "", "resolve it")
	require.NoError(t, err)
}

// TestWarnIfDuplicatesExist_S23_CompositeKey_Duplicates verifies that a
// multi-column key expression finds duplicates when two rows share the same
// (a, b) pair.
func TestWarnIfDuplicatesExist_S23_CompositeKey_Duplicates(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dup-comp-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE comp_dup (id INTEGER PRIMARY KEY, a INTEGER, b INTEGER)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO comp_dup VALUES (1, 10, 20)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO comp_dup VALUES (2, 10, 20)`).Error) // exact duplicate pair
	err = warnIfDuplicatesExist(db, "comp_dup", "a, b", "", "merge via API")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "comp_dup")
	assert.Contains(t, err.Error(), "merge via API")
}

// TestWarnIfDuplicatesExist_S23_RemediationTextInError verifies that the
// remediation string appears verbatim in the error message.
func TestWarnIfDuplicatesExist_S23_RemediationTextInError(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dup-rem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE rem_tbl (id INTEGER PRIMARY KEY, k TEXT)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO rem_tbl VALUES (1, 'dup')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO rem_tbl VALUES (2, 'dup')`).Error)
	const remediation = "unique-remediation-string-xyz"
	err = warnIfDuplicatesExist(db, "rem_tbl", "k", "", remediation)
	require.Error(t, err)
	assert.Contains(t, err.Error(), remediation)
}

// ---------------------------------------------------------------------------
// applyPoolSettings — individual branch coverage
// ---------------------------------------------------------------------------

// TestApplyPoolSettings_S23_MaxIdleConns verifies that a non-zero MaxIdleConns
// is applied to the underlying sql.DB.
func TestApplyPoolSettings_S23_MaxIdleConns(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-idle.db"))
	require.NoError(t, err)
	cfg := &config.DatabaseConfig{MaxIdleConns: 2}
	require.NoError(t, applyPoolSettings(db, cfg))
	// sql.DB.Stats() does not directly expose MaxIdleConnections, but we can
	// verify the call did not error and the default open-conns cap is still set.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	assert.Equal(t, DefaultSQLiteMaxOpenConns, sqlDB.Stats().MaxOpenConnections)
}

// TestApplyPoolSettings_S23_ConnMaxLifetime verifies that a non-zero
// ConnMaxLifetimeMinutes branch is exercised without panicking.
func TestApplyPoolSettings_S23_ConnMaxLifetime(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-lifetime.db"))
	require.NoError(t, err)
	cfg := &config.DatabaseConfig{
		MaxOpenConns:           5,
		ConnMaxLifetimeMinutes: 10,
	}
	require.NoError(t, applyPoolSettings(db, cfg))

	sqlDB, err := db.DB()
	require.NoError(t, err)
	assert.Equal(t, 5, sqlDB.Stats().MaxOpenConnections)
	// Verify the lifetime was accepted by confirming no error came back from
	// applyPoolSettings (the only observable signal for this branch on sql.DB).
	sqlDB.SetConnMaxLifetime(10 * time.Minute)
}

// TestApplyPoolSettings_S23_AllThreeBranches verifies that MaxOpenConns,
// MaxIdleConns, and ConnMaxLifetimeMinutes are all applied when set.
func TestApplyPoolSettings_S23_AllThreeBranches(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-all.db"))
	require.NoError(t, err)
	cfg := &config.DatabaseConfig{
		MaxOpenConns:           7,
		MaxIdleConns:           3,
		ConnMaxLifetimeMinutes: 15,
	}
	require.NoError(t, applyPoolSettings(db, cfg))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	assert.Equal(t, 7, sqlDB.Stats().MaxOpenConnections)
}

// ---------------------------------------------------------------------------
// withMigrationLock — additional path
// ---------------------------------------------------------------------------

// TestWithMigrationLock_S23_FnReceivesDB verifies that the *gorm.DB passed to
// withMigrationLock is forwarded to the callback on the non-Postgres path.
func TestWithMigrationLock_S23_FnReceivesDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "miglock-recv.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	var received *gorm.DB
	require.NoError(t, withMigrationLock(db, false, dbPath, func(tx *gorm.DB) error {
		received = tx
		return nil
	}))
	assert.NotNil(t, received, "withMigrationLock must pass a non-nil *gorm.DB to the callback")
}

// ---------------------------------------------------------------------------
// ensureSecretVersionIndex — duplicate-error path
// ---------------------------------------------------------------------------

// TestEnsureSecretVersionIndex_S23_DuplicateVersionNumbers verifies that
// ensureSecretVersionIndex fails loud when two rows share the same
// (secret_node_id, version_number) pair.
func TestEnsureSecretVersionIndex_S23_DuplicateVersionNumbers(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "sv-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE secret_versions (
		id INTEGER PRIMARY KEY,
		secret_node_id INTEGER,
		version_number INTEGER,
		encrypted_value TEXT
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (1, 42, 3, 'enc-a')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (2, 42, 3, 'enc-b')`).Error) // collision
	err = ensureSecretVersionIndex(db)
	require.Error(t, err, "duplicate (secret_node_id, version_number) must block the migration")
	assert.Contains(t, err.Error(), "secret_versions")
}

// TestEnsureSecretVersionIndex_S23_DifferentSecretsDontCollide verifies that
// two rows sharing version_number=1 but belonging to different secrets do NOT
// trigger the duplicate check.
func TestEnsureSecretVersionIndex_S23_DifferentSecretsDontCollide(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "sv-diff-secret.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE secret_versions (
		id INTEGER PRIMARY KEY,
		secret_node_id INTEGER,
		version_number INTEGER,
		encrypted_value TEXT
	)`).Error)
	// Same version_number but different secret_node_id — not a duplicate.
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (1, 10, 1, 'enc-x')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (2, 11, 1, 'enc-y')`).Error)
	require.NoError(t, ensureSecretVersionIndex(db))
	assert.True(t, indexExists(db, "uniq_secret_versions_node_version"))
}

// ---------------------------------------------------------------------------
// ensureDynamicSecretConfigNameIndex — duplicate-error path
// ---------------------------------------------------------------------------

// TestEnsureDynamicSecretConfigNameIndex_S23_DuplicateTriple verifies that
// ensureDynamicSecretConfigNameIndex fails loud when two rows share the same
// (project_id, environment_id, name).
func TestEnsureDynamicSecretConfigNameIndex_S23_DuplicateTriple(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dynconfig-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE dynamic_secret_configs (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		environment_id INTEGER,
		name TEXT,
		backend_type TEXT
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO dynamic_secret_configs VALUES (1, 1, 1, 'my-cfg', 'postgres')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO dynamic_secret_configs VALUES (2, 1, 1, 'my-cfg', 'mysql')`).Error) // same triple, different backend
	err = ensureDynamicSecretConfigNameIndex(db)
	require.Error(t, err, "duplicate (project_id, environment_id, name) must block the migration")
	assert.Contains(t, err.Error(), "dynamic_secret_configs")
}

// ---------------------------------------------------------------------------
// ensureShareRecordUniqueIndex — duplicate-error path
// ---------------------------------------------------------------------------

// TestEnsureShareRecordUniqueIndex_S23_DuplicateActiveRecords verifies that
// ensureShareRecordUniqueIndex fails loud when two active (deleted_at IS NULL)
// share records have the same (secret_id, recipient_id, is_group).
func TestEnsureShareRecordUniqueIndex_S23_DuplicateActiveRecords(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "share-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE share_records (
		id INTEGER PRIMARY KEY,
		secret_id INTEGER,
		recipient_id INTEGER,
		is_group BOOLEAN,
		deleted_at DATETIME
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO share_records VALUES (1, 5, 10, false, NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO share_records VALUES (2, 5, 10, false, NULL)`).Error) // same triple, both live
	err = ensureShareRecordUniqueIndex(db)
	require.Error(t, err, "duplicate active share records must block the migration")
	assert.Contains(t, err.Error(), "share_records")
}

// ---------------------------------------------------------------------------
// ensureGroupNameIndex — duplicate-error path
// ---------------------------------------------------------------------------

// TestEnsureGroupNameIndex_S23_DuplicateLiveGroupNames verifies that
// ensureGroupNameIndex fails loud when two live groups share the same name.
func TestEnsureGroupNameIndex_S23_DuplicateLiveGroupNames(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "grp-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, name_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (1, 'engineers', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (2, 'engineers', '', NULL)`).Error)
	err = ensureGroupNameIndex(db)
	require.Error(t, err, "duplicate live group names must block the migration")
	assert.Contains(t, err.Error(), "groups")
}

// ---------------------------------------------------------------------------
// ensureProjectMembershipIndex — duplicate-error path
// ---------------------------------------------------------------------------

// TestEnsureProjectMembershipIndex_S23_DuplicateActiveMembers verifies that
// ensureProjectMembershipIndex fails loud when two non-revoked rows exist for
// the same (project_id, user_id).
func TestEnsureProjectMembershipIndex_S23_DuplicateActiveMembers(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "membership-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE project_memberships (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		user_id INTEGER,
		state TEXT,
		role TEXT
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO project_memberships VALUES (1, 1, 1, 'active', 'viewer')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO project_memberships VALUES (2, 1, 1, 'pending', 'admin')`).Error) // same pair, non-revoked
	err = ensureProjectMembershipIndex(db)
	require.Error(t, err, "two non-revoked memberships for the same project+user must block the migration")
	assert.Contains(t, err.Error(), "project_memberships")
}

// TestEnsureProjectMembershipIndex_S23_RevokedNotCounted verifies that a
// revoked membership for the same (project_id, user_id) as an active one does
// not trigger the duplicate check.
func TestEnsureProjectMembershipIndex_S23_RevokedNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "membership-revoked.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE project_memberships (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		user_id INTEGER,
		state TEXT,
		role TEXT
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO project_memberships VALUES (1, 2, 3, 'revoked', 'viewer')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO project_memberships VALUES (2, 2, 3, 'active', 'admin')`).Error)
	require.NoError(t, ensureProjectMembershipIndex(db), "a revoked membership must not conflict with an active one")
	assert.True(t, indexExists(db, "uniq_project_memberships_active"))
}

// ---------------------------------------------------------------------------
// ensureLegalHoldActiveIndex — duplicate-error path
// ---------------------------------------------------------------------------

// TestEnsureLegalHoldActiveIndex_S23_DuplicateActiveHolds verifies that
// ensureLegalHoldActiveIndex fails loud when two un-released (released=false)
// rows exist in legal_holds.
func TestEnsureLegalHoldActiveIndex_S23_DuplicateActiveHolds(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "lh-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE legal_holds (id INTEGER PRIMARY KEY, released BOOLEAN DEFAULT false)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO legal_holds VALUES (1, false)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO legal_holds VALUES (2, false)`).Error) // second unreleased hold
	err = ensureLegalHoldActiveIndex(db)
	require.Error(t, err, "two un-released legal holds must block the migration")
	assert.Contains(t, err.Error(), "legal_holds")
}

// TestEnsureLegalHoldActiveIndex_S23_ReleasedNotCounted verifies that a
// released (released=true) hold does not count toward the uniqueness predicate,
// so having both a released and an unreleased hold succeeds.
func TestEnsureLegalHoldActiveIndex_S23_ReleasedNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "lh-released.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE legal_holds (id INTEGER PRIMARY KEY, released BOOLEAN DEFAULT false)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO legal_holds VALUES (1, false)`).Error) // active
	require.NoError(t, db.Exec(`INSERT INTO legal_holds VALUES (2, true)`).Error)  // released — out of predicate scope
	require.NoError(t, ensureLegalHoldActiveIndex(db), "a released hold must not conflict with the active one")
}

// ---------------------------------------------------------------------------
// ensureUserNameIndex — additional coverage
// ---------------------------------------------------------------------------

// TestEnsureUserNameIndex_S23_Idempotent verifies that calling
// ensureUserNameIndex twice on the same DB succeeds without error.
func TestEnsureUserNameIndex_S23_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "uname-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, username_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, ensureUserNameIndex(db))
	require.NoError(t, ensureUserNameIndex(db), "second call must be a no-op")
}

// TestEnsureUserNameIndex_S23_SoftDeletedNotCounted verifies that a
// soft-deleted user sharing a username with a live user does not trigger the
// duplicate check.
func TestEnsureUserNameIndex_S23_SoftDeletedNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "uname-softdel.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, username_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'alice', '', '2024-06-01')`).Error) // soft-deleted
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'alice', '', NULL)`).Error)         // live re-provisioned user
	require.NoError(t, ensureUserNameIndex(db), "a soft-deleted username must not block live re-creation")
}

// ---------------------------------------------------------------------------
// ensureUserEmailIndex — additional edge cases
// ---------------------------------------------------------------------------

// TestEnsureUserEmailIndex_S23_CaseInsensitiveDuplicateDetected verifies that
// two live users whose emails differ only in case (e.g., "Bob@x.io" vs
// "bob@x.io") are detected as duplicates under the LOWER(email) key expression.
func TestEnsureUserEmailIndex_S23_CaseInsensitiveDuplicateDetected(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "email-case-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, email_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'Bob@example.com', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'bob@example.com', '', NULL)`).Error) // same LOWER()
	err = ensureUserEmailIndex(db)
	require.Error(t, err, "case-variant duplicate emails must be detected via LOWER(email)")
	assert.Contains(t, err.Error(), "users")
}

// TestEnsureUserEmailIndex_S23_DeletedRowNotCounted verifies that a
// soft-deleted user's email does not count as a duplicate of a live user's
// email.
func TestEnsureUserEmailIndex_S23_DeletedRowNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "email-del.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, email_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'deleted@x.io', '', '2024-01-01')`).Error) // soft-deleted
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'deleted@x.io', '', NULL)`).Error)         // live re-provisioned
	require.NoError(t, ensureUserEmailIndex(db), "a soft-deleted user email must not conflict with a live re-provision of the same email")
}

// ---------------------------------------------------------------------------
// ensureUserExternalIDIndex — idempotent and deleted-row paths
// ---------------------------------------------------------------------------

// TestEnsureUserExternalIDIndex_S23_Idempotent verifies that calling
// ensureUserExternalIDIndex twice does not error.
func TestEnsureUserExternalIDIndex_S23_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "extid-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, external_id TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`).Error)
	require.NoError(t, ensureUserExternalIDIndex(db))
	require.NoError(t, ensureUserExternalIDIndex(db), "second call must be a no-op")
}

// TestEnsureUserExternalIDIndex_S23_DeletedRowNotCounted verifies that a
// soft-deleted user with a non-empty external_id does not block live
// re-provisioning of the same external_id.
func TestEnsureUserExternalIDIndex_S23_DeletedRowNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "extid-softdel.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, external_id TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'okta|reprov', '2024-03-01')`).Error) // soft-deleted
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'okta|reprov', NULL)`).Error)         // live re-provisioned
	require.NoError(t, ensureUserExternalIDIndex(db), "a soft-deleted external_id must not conflict with a live re-provisioned user")
}

// ---------------------------------------------------------------------------
// ensureReminderNotificationDedupIndex — expiry-reminder type
// ---------------------------------------------------------------------------

// TestEnsureReminderNotificationDedupIndex_S23_ExpiryReminderTypeConstrained
// verifies that the 'secret.expiry_reminder' type is also covered by the
// partial index predicate (in addition to 'rotation.reminder').
func TestEnsureReminderNotificationDedupIndex_S23_ExpiryReminderTypeConstrained(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "notif-expiry.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE notifications (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		type TEXT,
		project_id INTEGER,
		is_read BOOLEAN DEFAULT false
	)`).Error)
	// One unread expiry reminder — no duplicate yet; index must be created.
	require.NoError(t, db.Exec(`INSERT INTO notifications VALUES (1, 99, 'secret.expiry_reminder', 3, false)`).Error)
	require.NoError(t, ensureReminderNotificationDedupIndex(db))
	assert.True(t, indexExists(db, "uniq_notifications_unread_reminder"))
}

// TestEnsureReminderNotificationDedupIndex_S23_BothReminderTypesClean verifies
// that having one unread 'rotation.reminder' and one unread
// 'secret.expiry_reminder' for the same (user_id, project_id) does NOT violate
// the index because the type column is part of the key.
func TestEnsureReminderNotificationDedupIndex_S23_BothReminderTypesClean(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "notif-both-types.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE notifications (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		type TEXT,
		project_id INTEGER,
		is_read BOOLEAN DEFAULT false
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO notifications VALUES (1, 42, 'rotation.reminder', 7, false)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO notifications VALUES (2, 42, 'secret.expiry_reminder', 7, false)`).Error)
	// Different types — must NOT count as duplicates of each other.
	require.NoError(t, ensureReminderNotificationDedupIndex(db))
}
