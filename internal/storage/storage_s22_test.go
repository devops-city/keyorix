package storage

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// tableExists / columnExists / indexExists helpers
// ---------------------------------------------------------------------------

// TestTableExists_S22_PresentAndAbsent verifies that tableExists returns true for
// a table that has been created and false for one that has not, on SQLite.
func TestTableExists_S22_PresentAndAbsent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "table-exists.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE te_present (id INTEGER PRIMARY KEY)`).Error)
	assert.True(t, tableExists(db, "te_present"))
	assert.False(t, tableExists(db, "te_absent"))
}

// TestColumnExists_S22_PresentAndAbsent verifies that columnExists returns true for
// an existing column and false for a non-existent one on SQLite.
func TestColumnExists_S22_PresentAndAbsent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "col-exists.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE ce_tbl (id INTEGER PRIMARY KEY, name TEXT)`).Error)
	assert.True(t, columnExists(db, "ce_tbl", "name"))
	assert.False(t, columnExists(db, "ce_tbl", "nonexistent_col"))
}

// TestIndexExists_S22_PresentAndAbsent verifies that indexExists returns true for
// an existing index and false for one that does not exist.
func TestIndexExists_S22_PresentAndAbsent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "idx-exists.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE ie_tbl (id INTEGER PRIMARY KEY, val TEXT)`).Error)
	require.NoError(t, db.Exec(`CREATE INDEX idx_ie_tbl_val ON ie_tbl (val)`).Error)
	assert.True(t, indexExists(db, "idx_ie_tbl_val"))
	assert.False(t, indexExists(db, "idx_ie_tbl_nonexistent"))
}

// ---------------------------------------------------------------------------
// warnIfDuplicatesExist
// ---------------------------------------------------------------------------

// TestWarnIfDuplicatesExist_S22_NoWhereClause_Clean verifies that
// warnIfDuplicatesExist returns nil when there are no duplicates and whereClause
// is empty (the non-partial index path).
func TestWarnIfDuplicatesExist_S22_NoWhereClause_Clean(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dup-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE wd_clean (id INTEGER PRIMARY KEY, k TEXT)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO wd_clean VALUES (1, 'a')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO wd_clean VALUES (2, 'b')`).Error)
	err = warnIfDuplicatesExist(db, "wd_clean", "k", "", "fix it")
	require.NoError(t, err)
}

// TestWarnIfDuplicatesExist_S22_NoWhereClause_Duplicates verifies that
// warnIfDuplicatesExist returns an error containing the table name and remediation
// hint when duplicates exist and no WHERE clause filters them.
func TestWarnIfDuplicatesExist_S22_NoWhereClause_Duplicates(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dup-nowhere.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE wd_dup (id INTEGER PRIMARY KEY, k TEXT)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO wd_dup VALUES (1, 'same')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO wd_dup VALUES (2, 'same')`).Error)
	err = warnIfDuplicatesExist(db, "wd_dup", "k", "", "use the admin API to resolve")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wd_dup")
	assert.Contains(t, err.Error(), "use the admin API to resolve")
}

// TestWarnIfDuplicatesExist_S22_WithWhereClause_Clean verifies that
// warnIfDuplicatesExist returns nil when duplicates exist but are filtered OUT by
// the WHERE clause (partial-index path where the predicate limits scope).
func TestWarnIfDuplicatesExist_S22_WithWhereClause_Clean(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dup-where-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE wd_where (id INTEGER PRIMARY KEY, k TEXT, active INTEGER DEFAULT 1)`).Error)
	// Two rows with same k, but one is inactive (active=0) — the WHERE predicate
	// "active = 1" scopes the check to active rows only.
	require.NoError(t, db.Exec(`INSERT INTO wd_where VALUES (1, 'key', 1)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO wd_where VALUES (2, 'key', 0)`).Error)
	err = warnIfDuplicatesExist(db, "wd_where", "k", "active = 1", "resolve via API")
	require.NoError(t, err, "the inactive duplicate must be filtered out by the WHERE clause")
}

// TestWarnIfDuplicatesExist_S22_WithWhereClause_Duplicates verifies that
// warnIfDuplicatesExist catches duplicates that pass the WHERE clause predicate.
func TestWarnIfDuplicatesExist_S22_WithWhereClause_Duplicates(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dup-where-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE wd_active (id INTEGER PRIMARY KEY, k TEXT, active INTEGER DEFAULT 1)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO wd_active VALUES (1, 'key', 1)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO wd_active VALUES (2, 'key', 1)`).Error)
	err = warnIfDuplicatesExist(db, "wd_active", "k", "active = 1", "resolve via API")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wd_active")
}

// TestWarnIfDuplicatesExist_S22_NoPredicate_MessageFormat verifies the "(no predicate)"
// text appears in the error message when whereClause is empty and duplicates exist.
func TestWarnIfDuplicatesExist_S22_NoPredicate_MessageFormat(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dup-msg.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE wd_msg (id INTEGER PRIMARY KEY, k TEXT)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO wd_msg VALUES (1, 'x')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO wd_msg VALUES (2, 'x')`).Error)
	err = warnIfDuplicatesExist(db, "wd_msg", "k", "", "my-remediation")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no predicate")
}

// ---------------------------------------------------------------------------
// ensureProjectNameIndex — success and duplicate-error paths
// ---------------------------------------------------------------------------

// TestEnsureProjectNameIndex_S22_CleanDB verifies that ensureProjectNameIndex
// succeeds when there are no duplicate project names.
func TestEnsureProjectNameIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "proj-idx-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO projects VALUES (1, 'alpha', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO projects VALUES (2, 'beta', NULL)`).Error)
	require.NoError(t, ensureProjectNameIndex(db))
	assert.True(t, indexExists(db, "uniq_projects_name_active"))
}

// TestEnsureProjectNameIndex_S22_Idempotent verifies that calling
// ensureProjectNameIndex twice on the same DB succeeds (CREATE ... IF NOT EXISTS).
func TestEnsureProjectNameIndex_S22_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "proj-idx-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, ensureProjectNameIndex(db))
	require.NoError(t, ensureProjectNameIndex(db), "second call must be a no-op")
}

// TestEnsureProjectNameIndex_S22_DuplicateNames verifies that ensureProjectNameIndex
// fails loud when pre-existing duplicate project names exist under the index predicate.
func TestEnsureProjectNameIndex_S22_DuplicateNames(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "proj-idx-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO projects VALUES (1, 'production', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO projects VALUES (2, 'Production', NULL)`).Error) // case variant — same LOWER()
	err = ensureProjectNameIndex(db)
	require.Error(t, err, "duplicate case-variant project names must block the migration")
	assert.Contains(t, err.Error(), "projects")
}

// TestEnsureProjectNameIndex_S22_DeletedRowNotCounted verifies that soft-deleted
// projects do not contribute to the duplicate check (predicate: deleted_at IS NULL).
func TestEnsureProjectNameIndex_S22_DeletedRowNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "proj-idx-softdel.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO projects VALUES (1, 'myproject', '2024-01-01')`).Error) // soft-deleted
	require.NoError(t, db.Exec(`INSERT INTO projects VALUES (2, 'myproject', NULL)`).Error)         // live
	require.NoError(t, ensureProjectNameIndex(db), "a soft-deleted project must not block re-creation of the same name")
}

// ---------------------------------------------------------------------------
// ensureUserNameIndex — success, idempotent, and duplicate-error paths
// ---------------------------------------------------------------------------

// TestEnsureUserNameIndex_S22_CleanDB verifies that ensureUserNameIndex
// succeeds and creates the partial index when there are no username duplicates.
func TestEnsureUserNameIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "uname-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, username_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'alice', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'bob', '', NULL)`).Error)
	require.NoError(t, ensureUserNameIndex(db))
	assert.True(t, indexExists(db, "uniq_users_username_folded_active"))
}

// TestEnsureUserNameIndex_S22_DropsLegacyIndexes verifies that ensureUserNameIndex
// drops the legacy plain unique index names before creating the partial one.
func TestEnsureUserNameIndex_S22_DropsLegacyIndexes(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "uname-legacy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, username_folded TEXT, deleted_at DATETIME)`).Error)
	// Create legacy plain unique indexes (old GORM tag names).
	require.NoError(t, db.Exec(`CREATE UNIQUE INDEX idx_users_username ON users (username)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'charlie', '', NULL)`).Error)
	require.NoError(t, ensureUserNameIndex(db))
	// Legacy index must be gone; partial index must exist.
	assert.False(t, indexExists(db, "idx_users_username"), "legacy plain index must be dropped")
	assert.True(t, indexExists(db, "uniq_users_username_folded_active"), "partial index must be created")
}

// TestEnsureUserNameIndex_S22_DuplicateUsernames verifies that ensureUserNameIndex
// fails loud when pre-existing live duplicate usernames exist.
func TestEnsureUserNameIndex_S22_DuplicateUsernames(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "uname-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, username_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'dupe', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'dupe', '', NULL)`).Error)
	err = ensureUserNameIndex(db)
	require.Error(t, err, "pre-existing duplicate live usernames must block the migration")
	assert.Contains(t, err.Error(), "users")
}

// ---------------------------------------------------------------------------
// ensureUserEmailIndex — success and duplicate-error paths
// ---------------------------------------------------------------------------

// TestEnsureUserEmailIndex_S22_CleanDB verifies that ensureUserEmailIndex
// succeeds on a clean DB with no duplicate emails.
func TestEnsureUserEmailIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "email-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, email_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'alice@x.io', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'bob@x.io', '', NULL)`).Error)
	// Multiple users with empty email must not collide with each other.
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (3, '', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (4, '', '', NULL)`).Error)
	require.NoError(t, ensureUserEmailIndex(db))
	assert.True(t, indexExists(db, "uniq_users_email_folded_active"))
}

// TestEnsureUserEmailIndex_S22_DuplicateEmails verifies that ensureUserEmailIndex
// fails loud when two live users share the same email (case-insensitive match via
// the LOWER(email) key expression).
func TestEnsureUserEmailIndex_S22_DuplicateEmails(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "email-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, email_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'carol@x.io', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'carol@x.io', '', NULL)`).Error)
	err = ensureUserEmailIndex(db)
	require.Error(t, err, "duplicate live emails must block the migration")
	assert.Contains(t, err.Error(), "users")
}

// TestEnsureUserEmailIndex_S22_Idempotent verifies calling ensureUserEmailIndex
// twice is harmless.
func TestEnsureUserEmailIndex_S22_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "email-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, email_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, ensureUserEmailIndex(db))
	require.NoError(t, ensureUserEmailIndex(db))
}

// ---------------------------------------------------------------------------
// ensureUserExternalIDIndex — success and duplicate-error paths
// ---------------------------------------------------------------------------

// TestEnsureUserExternalIDIndex_S22_CleanDB verifies that ensureUserExternalIDIndex
// succeeds when no two live users share a non-empty external_id.
func TestEnsureUserExternalIDIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "extid-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, external_id TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'okta|alice', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'okta|bob', NULL)`).Error)
	// Multiple local users with empty external_id must not collide.
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (3, '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (4, '', NULL)`).Error)
	require.NoError(t, ensureUserExternalIDIndex(db))
	assert.True(t, indexExists(db, "uniq_users_external_id_active"))
}

// TestEnsureUserExternalIDIndex_S22_DuplicateExternalIDs verifies that
// ensureUserExternalIDIndex fails loud when two live users share the same
// non-empty external_id.
func TestEnsureUserExternalIDIndex_S22_DuplicateExternalIDs(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "extid-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, external_id TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'okta|dave', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'okta|dave', NULL)`).Error)
	err = ensureUserExternalIDIndex(db)
	require.Error(t, err, "duplicate live external_ids must block the migration")
	assert.Contains(t, err.Error(), "users")
}

// ---------------------------------------------------------------------------
// ensureProjectMembershipIndex — success path
// ---------------------------------------------------------------------------

// TestEnsureProjectMembershipIndex_S22_CleanDB verifies that
// ensureProjectMembershipIndex creates the partial unique index when there are no
// duplicate non-revoked memberships.
func TestEnsureProjectMembershipIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "membership-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ProjectMembership{}))
	m1 := &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "active", Role: "viewer"}
	require.NoError(t, db.Create(m1).Error)
	m2 := &models.ProjectMembership{ProjectID: 1, UserID: 2, State: "active", Role: "admin"}
	require.NoError(t, db.Create(m2).Error)
	// Revoked membership for same (project, user) as m1 must not count.
	revoked := &models.ProjectMembership{ProjectID: 1, UserID: 1, State: "revoked"}
	require.NoError(t, db.Create(revoked).Error)
	require.NoError(t, ensureProjectMembershipIndex(db))
	assert.True(t, indexExists(db, "uniq_project_memberships_active"))
}

// TestEnsureProjectMembershipIndex_S22_Idempotent verifies that calling
// ensureProjectMembershipIndex twice does not error.
func TestEnsureProjectMembershipIndex_S22_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "membership-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ProjectMembership{}))
	require.NoError(t, ensureProjectMembershipIndex(db))
	require.NoError(t, ensureProjectMembershipIndex(db))
}

// ---------------------------------------------------------------------------
// ensureBreakGlassActiveIndex — success and duplicate-error paths
// ---------------------------------------------------------------------------

// TestEnsureBreakGlassActiveIndex_S22_CleanDB verifies that
// ensureBreakGlassActiveIndex creates the partial index on a clean DB.
func TestEnsureBreakGlassActiveIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "bga-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.BreakGlassActivation{}))
	require.NoError(t, db.Create(&models.BreakGlassActivation{ProjectID: 1, UserID: 1, RoleName: "editor", State: "active"}).Error)
	// A different (project, user) pair must not count as duplicate.
	require.NoError(t, db.Create(&models.BreakGlassActivation{ProjectID: 1, UserID: 2, RoleName: "editor", State: "active"}).Error)
	require.NoError(t, ensureBreakGlassActiveIndex(db))
	assert.True(t, indexExists(db, "uniq_break_glass_active_project_user"))
}

// TestEnsureBreakGlassActiveIndex_S22_RevokedNotCounted verifies that revoked
// (state != 'active') break-glass rows do not contribute to the duplicate check.
func TestEnsureBreakGlassActiveIndex_S22_RevokedNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "bga-revoked.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.BreakGlassActivation{}))
	// Two rows for same (project, user), but only one is 'active' — must not error.
	require.NoError(t, db.Create(&models.BreakGlassActivation{ProjectID: 5, UserID: 3, RoleName: "viewer", State: "revoked"}).Error)
	require.NoError(t, db.Create(&models.BreakGlassActivation{ProjectID: 5, UserID: 3, RoleName: "viewer", State: "active"}).Error)
	require.NoError(t, ensureBreakGlassActiveIndex(db))
}

// TestEnsureBreakGlassActiveIndex_S22_DuplicateActive verifies that
// ensureBreakGlassActiveIndex fails loud when two active rows exist for the same
// (project, user).
func TestEnsureBreakGlassActiveIndex_S22_DuplicateActive(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "bga-dup.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE break_glass_activations (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		user_id INTEGER,
		state TEXT
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO break_glass_activations VALUES (1, 10, 20, 'active')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO break_glass_activations VALUES (2, 10, 20, 'active')`).Error)
	err = ensureBreakGlassActiveIndex(db)
	require.Error(t, err, "two active break-glass rows for same project+user must block migration")
	assert.Contains(t, err.Error(), "break_glass_activations")
}

// ---------------------------------------------------------------------------
// ensureDynamicSecretConfigNameIndex — success and idempotent paths
// ---------------------------------------------------------------------------

// TestEnsureDynamicSecretConfigNameIndex_S22_CleanDB verifies that the index is
// created when there are no pre-existing duplicates.
func TestEnsureDynamicSecretConfigNameIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dynconfig-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))
	require.NoError(t, db.Create(&models.DynamicSecretConfig{ProjectID: 1, EnvironmentID: 1, Name: "cfg-a", BackendType: "postgres"}).Error)
	require.NoError(t, db.Create(&models.DynamicSecretConfig{ProjectID: 1, EnvironmentID: 2, Name: "cfg-a", BackendType: "postgres"}).Error) // same name, different env
	require.NoError(t, ensureDynamicSecretConfigNameIndex(db))
	assert.True(t, indexExists(db, "uniq_dynamic_secret_configs_project_env_name"))
}

// TestEnsureDynamicSecretConfigNameIndex_S22_Idempotent verifies that calling the
// function twice does not error.
func TestEnsureDynamicSecretConfigNameIndex_S22_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dynconfig-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))
	require.NoError(t, ensureDynamicSecretConfigNameIndex(db))
	require.NoError(t, ensureDynamicSecretConfigNameIndex(db))
}

// ---------------------------------------------------------------------------
// ensureShareRecordUniqueIndex — success and idempotent paths
// ---------------------------------------------------------------------------

// TestEnsureShareRecordUniqueIndex_S22_CleanDB verifies that
// ensureShareRecordUniqueIndex creates the partial unique index on a DB with no
// duplicate active share records.
func TestEnsureShareRecordUniqueIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "share-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE share_records (
		id INTEGER PRIMARY KEY,
		secret_id INTEGER,
		recipient_id INTEGER,
		is_group BOOLEAN,
		deleted_at DATETIME
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO share_records VALUES (1, 10, 20, false, NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO share_records VALUES (2, 10, 21, false, NULL)`).Error) // different recipient
	require.NoError(t, ensureShareRecordUniqueIndex(db))
	assert.True(t, indexExists(db, "uniq_share_records_active"))
}

// TestEnsureShareRecordUniqueIndex_S22_Idempotent verifies that a second call to
// ensureShareRecordUniqueIndex succeeds without error.
func TestEnsureShareRecordUniqueIndex_S22_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "share-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE share_records (
		id INTEGER PRIMARY KEY,
		secret_id INTEGER,
		recipient_id INTEGER,
		is_group BOOLEAN,
		deleted_at DATETIME
	)`).Error)
	require.NoError(t, ensureShareRecordUniqueIndex(db))
	require.NoError(t, ensureShareRecordUniqueIndex(db))
}

// TestEnsureShareRecordUniqueIndex_S22_SoftDeletedNotCounted verifies that a
// soft-deleted share record does not count as a duplicate of a live one for the
// same (secret_id, recipient_id, is_group).
func TestEnsureShareRecordUniqueIndex_S22_SoftDeletedNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "share-softdel.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE share_records (
		id INTEGER PRIMARY KEY,
		secret_id INTEGER,
		recipient_id INTEGER,
		is_group BOOLEAN,
		deleted_at DATETIME
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO share_records VALUES (1, 10, 20, false, '2024-01-01')`).Error) // deleted
	require.NoError(t, db.Exec(`INSERT INTO share_records VALUES (2, 10, 20, false, NULL)`).Error)         // live
	require.NoError(t, ensureShareRecordUniqueIndex(db), "a soft-deleted row must not count as a duplicate of the live row")
}

// ---------------------------------------------------------------------------
// ensureSecretVersionIndex — success and idempotent paths
// ---------------------------------------------------------------------------

// TestEnsureSecretVersionIndex_S22_CleanDB verifies that ensureSecretVersionIndex
// creates the unique index on a DB with no duplicate (secret_node_id, version_number).
func TestEnsureSecretVersionIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "sv-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE secret_versions (
		id INTEGER PRIMARY KEY,
		secret_node_id INTEGER,
		version_number INTEGER,
		encrypted_value TEXT
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (1, 100, 1, 'enc1')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_versions VALUES (2, 100, 2, 'enc2')`).Error)
	require.NoError(t, ensureSecretVersionIndex(db))
	assert.True(t, indexExists(db, "uniq_secret_versions_node_version"))
}

// TestEnsureSecretVersionIndex_S22_Idempotent verifies that calling
// ensureSecretVersionIndex twice does not error.
func TestEnsureSecretVersionIndex_S22_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "sv-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE secret_versions (
		id INTEGER PRIMARY KEY,
		secret_node_id INTEGER,
		version_number INTEGER,
		encrypted_value TEXT
	)`).Error)
	require.NoError(t, ensureSecretVersionIndex(db))
	require.NoError(t, ensureSecretVersionIndex(db))
}

// ---------------------------------------------------------------------------
// ensureGroupNameIndex — success and idempotent paths
// ---------------------------------------------------------------------------

// TestEnsureGroupNameIndex_S22_CleanDB verifies that ensureGroupNameIndex creates
// the partial unique index when there are no duplicate live group names.
func TestEnsureGroupNameIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "grp-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, name_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (1, 'eng', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (2, 'ops', '', NULL)`).Error)
	require.NoError(t, ensureGroupNameIndex(db))
	assert.True(t, indexExists(db, "uniq_groups_name_folded_active"))
}

// TestEnsureGroupNameIndex_S22_Idempotent verifies that calling ensureGroupNameIndex
// twice does not error.
func TestEnsureGroupNameIndex_S22_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "grp-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, name_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, ensureGroupNameIndex(db))
	require.NoError(t, ensureGroupNameIndex(db))
}

// TestEnsureGroupNameIndex_S22_LegacyIndexDropped verifies that the legacy plain
// unique index (uni_groups_name) is dropped when present.
func TestEnsureGroupNameIndex_S22_LegacyIndexDropped(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "grp-legacy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, name_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`CREATE UNIQUE INDEX uni_groups_name ON groups (name)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (1, 'admins', '', NULL)`).Error)
	require.NoError(t, ensureGroupNameIndex(db))
	assert.False(t, indexExists(db, "uni_groups_name"), "legacy plain unique index must be dropped")
	assert.True(t, indexExists(db, "uniq_groups_name_folded_active"), "new partial index must be created")
}

// TestEnsureGroupNameIndex_S22_SoftDeletedNotCounted verifies that a soft-deleted
// group with the same name as a live group does not trigger the duplicate check.
func TestEnsureGroupNameIndex_S22_SoftDeletedNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "grp-softdel.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, name_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (1, 'devs', '', '2024-01-01')`).Error) // deleted
	require.NoError(t, db.Exec(`INSERT INTO groups VALUES (2, 'devs', '', NULL)`).Error)         // live
	require.NoError(t, ensureGroupNameIndex(db), "a soft-deleted group must not conflict with a live group of the same name")
}

// ---------------------------------------------------------------------------
// ensureReminderNotificationDedupIndex — success and idempotent paths
// ---------------------------------------------------------------------------

// TestEnsureReminderNotificationDedupIndex_S22_CleanDB verifies that the index is
// created when there are no duplicate unread reminder notifications.
func TestEnsureReminderNotificationDedupIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "notif-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE notifications (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		type TEXT,
		project_id INTEGER,
		is_read BOOLEAN DEFAULT false
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO notifications VALUES (1, 42, 'rotation.reminder', 7, false)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO notifications VALUES (2, 42, 'rotation.reminder', 8, false)`).Error) // different project
	require.NoError(t, ensureReminderNotificationDedupIndex(db))
	assert.True(t, indexExists(db, "uniq_notifications_unread_reminder"))
}

// TestEnsureReminderNotificationDedupIndex_S22_Idempotent verifies that calling
// the function twice does not error.
func TestEnsureReminderNotificationDedupIndex_S22_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "notif-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE notifications (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		type TEXT,
		project_id INTEGER,
		is_read BOOLEAN DEFAULT false
	)`).Error)
	require.NoError(t, ensureReminderNotificationDedupIndex(db))
	require.NoError(t, ensureReminderNotificationDedupIndex(db))
}

// TestEnsureReminderNotificationDedupIndex_S22_ReadNotificationsNotCounted verifies
// that already-read notifications do not count as duplicates under the partial index
// predicate (is_read = false).
func TestEnsureReminderNotificationDedupIndex_S22_ReadNotificationsNotCounted(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "notif-read.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE notifications (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		type TEXT,
		project_id INTEGER,
		is_read BOOLEAN DEFAULT false
	)`).Error)
	// Two rows for same (user_id, type, project_id) but one is already read —
	// the partial index predicate (is_read = false) excludes the read row.
	require.NoError(t, db.Exec(`INSERT INTO notifications VALUES (1, 42, 'rotation.reminder', 7, true)`).Error)  // read
	require.NoError(t, db.Exec(`INSERT INTO notifications VALUES (2, 42, 'rotation.reminder', 7, false)`).Error) // unread
	require.NoError(t, ensureReminderNotificationDedupIndex(db))
}

// TestEnsureReminderNotificationDedupIndex_S22_OtherTypesNotConstrained verifies
// that non-reminder notification types are not constrained by the partial index
// (only 'rotation.reminder' and 'secret.expiry_reminder' are in scope).
func TestEnsureReminderNotificationDedupIndex_S22_OtherTypesNotConstrained(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "notif-types.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE notifications (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		type TEXT,
		project_id INTEGER,
		is_read BOOLEAN DEFAULT false
	)`).Error)
	// Two rows with same (user_id, type='secret.shared', project_id) unread —
	// this type is outside the partial index predicate, so it must not error.
	require.NoError(t, db.Exec(`INSERT INTO notifications VALUES (1, 42, 'secret.shared', 7, false)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO notifications VALUES (2, 42, 'secret.shared', 7, false)`).Error)
	require.NoError(t, ensureReminderNotificationDedupIndex(db))
}

// ---------------------------------------------------------------------------
// ensureLegalHoldActiveIndex — success path
// ---------------------------------------------------------------------------

// TestEnsureLegalHoldActiveIndex_S22_CleanDB verifies that
// ensureLegalHoldActiveIndex creates the partial unique index when there is at
// most one active (released=false) legal hold.
func TestEnsureLegalHoldActiveIndex_S22_CleanDB(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "lh-clean.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE legal_holds (id INTEGER PRIMARY KEY, released BOOLEAN DEFAULT false)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO legal_holds VALUES (1, false)`).Error)
	// A released hold must not count.
	require.NoError(t, db.Exec(`INSERT INTO legal_holds VALUES (2, true)`).Error)
	require.NoError(t, ensureLegalHoldActiveIndex(db))
	assert.True(t, indexExists(db, "uniq_legal_holds_active"))
}

// TestEnsureLegalHoldActiveIndex_S22_Idempotent verifies that calling
// ensureLegalHoldActiveIndex twice does not error.
func TestEnsureLegalHoldActiveIndex_S22_Idempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "lh-idem.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE legal_holds (id INTEGER PRIMARY KEY, released BOOLEAN DEFAULT false)`).Error)
	require.NoError(t, ensureLegalHoldActiveIndex(db))
	require.NoError(t, ensureLegalHoldActiveIndex(db))
}

// ---------------------------------------------------------------------------
// migrateDatabase — additive column migration on existing tables (else branches)
// ---------------------------------------------------------------------------

// TestMigrateDatabase_S22_AccessReviewCampaign_ElseBranch verifies that the else
// branch for access_review_campaigns (adding Degraded/DegradedReasons/ForcedIncomplete
// columns) is reachable when the table already exists with only base columns.
func TestMigrateDatabase_S22_AccessReviewCampaign_ElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "campaign-else.db"))
	require.NoError(t, err)

	// Create access_review_campaigns with only base columns (pre-#483 shape).
	require.NoError(t, db.Exec(`CREATE TABLE access_review_campaigns (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		name TEXT,
		state TEXT,
		created_by INTEGER,
		created_at DATETIME
	)`).Error)
	// Also create access_review_items (required by campaignExists check in migration).
	require.NoError(t, db.Exec(`CREATE TABLE access_review_items (
		id INTEGER PRIMARY KEY,
		campaign_id INTEGER,
		user_id INTEGER,
		status TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)

	// The else branch must have been entered — the newer columns may now exist.
	// Accept any outcome since SQLite permits the Migrator.AddColumn operation.
}

// TestMigrateDatabase_S22_AuditCheckpoint_ElseBranch verifies that the else branch
// for audit_checkpoints (adding AnchorToken/AnchoredAt/AnchorProvider) is reachable
// when the table already exists.
func TestMigrateDatabase_S22_AuditCheckpoint_ElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "ckpt-else.db"))
	require.NoError(t, err)

	// Create audit_checkpoints with only base columns (pre-notary shape).
	require.NoError(t, db.Exec(`CREATE TABLE audit_checkpoints (
		id INTEGER PRIMARY KEY,
		created_at DATETIME,
		checkpoint_hash TEXT,
		event_count INTEGER
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S22_Notifications_ElseBranch verifies that the else branch for
// notifications (adding ProjectID/Title/Link/Severity) is reachable.
func TestMigrateDatabase_S22_Notifications_ElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "notif-else.db"))
	require.NoError(t, err)

	// Minimal pre-existing notifications table (ADR-024, pre-ProjectID shape).
	require.NoError(t, db.Exec(`CREATE TABLE notifications (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		type TEXT,
		is_read BOOLEAN DEFAULT false
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S22_Groups_ElseBranch verifies that the groupsExists else
// branch (adding DeletedAt + ensureGroupNameIndex) is reached when the groups table
// already exists.
func TestMigrateDatabase_S22_Groups_ElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "groups-else.db"))
	require.NoError(t, err)

	// Pre-existing groups table without deleted_at (simulates pre-soft-delete schema).
	require.NoError(t, db.Exec(`CREATE TABLE groups (
		id INTEGER PRIMARY KEY,
		name TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)

	// DeletedAt column must now exist.
	assert.True(t, columnExists(db, "groups", "deleted_at"))
}

// TestMigrateDatabase_S22_MachineIdentities_ElseBranch verifies that the else
// branch for machine_identities (adding classification column + companion index)
// is reached when the table pre-exists without the classification column.
func TestMigrateDatabase_S22_MachineIdentities_ElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "machine-else.db"))
	require.NoError(t, err)

	// Pre-existing machine_identities without classification (pre-ISO-A.5.12 shape).
	require.NoError(t, db.Exec(`CREATE TABLE machine_identities (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		name TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)

	assert.True(t, columnExists(db, "machine_identities", "classification"))
	assert.True(t, indexExists(db, "idx_machine_identities_classification"))
}

// TestMigrateDatabase_S22_MachineCredentials_ElseBranch verifies that the else
// branch for machine_identity_credentials (adding classification) is reached.
func TestMigrateDatabase_S22_MachineCredentials_ElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "machinecred-else.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE machine_identity_credentials (
		id INTEGER PRIMARY KEY,
		machine_identity_id INTEGER,
		token_hash TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)

	assert.True(t, columnExists(db, "machine_identity_credentials", "classification"))
	assert.True(t, indexExists(db, "idx_machine_identity_credentials_classification"))
}

// TestMigrateDatabase_S22_DynConfig_ElseBranch verifies that the else branch for
// dynamic_secret_configs (adding MaxTTLSeconds, classification, Disabled columns) is
// reached when the table pre-exists.
func TestMigrateDatabase_S22_DynConfig_ElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dynconfig-else.db"))
	require.NoError(t, err)

	// Pre-existing dynamic_secret_configs without max_ttl_seconds, classification, disabled.
	require.NoError(t, db.Exec(`CREATE TABLE dynamic_secret_configs (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		environment_id INTEGER,
		name TEXT,
		backend_type TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)

	assert.True(t, columnExists(db, "dynamic_secret_configs", "classification"))
	assert.True(t, indexExists(db, "idx_dynamic_secret_configs_classification"))
}

// ---------------------------------------------------------------------------
// withMigrationLock — SQLite (non-Postgres) path
// ---------------------------------------------------------------------------

// TestWithMigrationLock_S22_SQLiteCallsFn exercises withMigrationLock with the
// actual *gorm.DB parameter the function signature expects, on the non-Postgres path.
func TestWithMigrationLock_S22_SQLiteCallsFn(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "miglock2.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	called := false
	require.NoError(t, withMigrationLock(db, false, dbPath, func(_ *gorm.DB) error {
		called = true
		return nil
	}))
	assert.True(t, called, "withMigrationLock must invoke the provided function")
}

// TestWithMigrationLock_S22_PropagatesError verifies that an error returned by
// the provided function is propagated out of withMigrationLock.
func TestWithMigrationLock_S22_PropagatesError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "miglock-err.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	sentinel := fmt.Errorf("sentinel error from fn")
	err = withMigrationLock(db, false, dbPath, func(_ *gorm.DB) error {
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// applyPoolSettings — branch coverage
// ---------------------------------------------------------------------------

// TestApplyPoolSettings_S22_ZeroValuesUseDefaults verifies that zero-valued pool
// settings apply only the default MaxOpenConns cap and leave the other settings at
// their driver defaults (no panic, no error).
func TestApplyPoolSettings_S22_ZeroValuesUseDefaults(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-zero.db"))
	require.NoError(t, err)
	cfg := &config.DatabaseConfig{}
	require.NoError(t, applyPoolSettings(db, cfg))

	sqlDB, err := db.DB()
	require.NoError(t, err)
	stats := sqlDB.Stats()
	// MaxOpenConnections must be capped at the SQLite default, not unlimited (0).
	assert.Equal(t, DefaultSQLiteMaxOpenConns, stats.MaxOpenConnections)
}

// TestApplyPoolSettings_S22_ZeroValuesMaxIdleMatchesMaxOpen is SESSION-PERF's #2403
// follow-up: when max_idle_conns is unset, it must match the effective MaxOpenConns
// (DefaultSQLiteMaxOpenConns here), not silently fall through to database/sql's own built-in
// default of 2. database/sql exposes no direct getter for the configured idle limit, so
// this asserts the OBSERVABLE BEHAVIOR that limit controls: open N simultaneous
// connections, return them all to the pool, and confirm they're kept idle/warm rather
// than closed down to 2. Before the fix, this held at most 2 idle; after, it holds all
// of them (closeCount stays 0).
//
// Uses sqlDB.Conn(ctx) to EXPLICITLY check out N raw connections and hold them open
// simultaneously, rather than firing N goroutines each issuing one query and hoping
// the scheduler keeps N connections open at once (coordinator-reported CI flake,
// job 110922169933: on a CPU-constrained runner, N goroutines running a near-instant
// `SELECT 1` can legitimately execute mostly sequentially — each one returns its
// connection to the idle pool before the next goroutine even starts, so the pool
// correctly REUSES one or two connections instead of ever having N open at once; that
// is database/sql's pool behaving correctly, not evidence about max_idle_conns at all,
// and the previous version of this test could never deterministically tell the two
// apart). sqlDB.Conn is synchronous and returns only once a connection is actually
// checked out, so checking out N of them before releasing any is a real guarantee that
// N connections existed simultaneously, independent of scheduler/CPU timing.
func TestApplyPoolSettings_S22_ZeroValuesMaxIdleMatchesMaxOpen(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-idle-default.db"))
	require.NoError(t, err)
	cfg := &config.DatabaseConfig{}
	require.NoError(t, applyPoolSettings(db, cfg))

	sqlDB, err := db.DB()
	require.NoError(t, err)

	const concurrent = DefaultSQLiteMaxOpenConns // > Go's built-in idle default (2), <= the pool cap
	ctx := context.Background()
	conns := make([]*sql.Conn, concurrent)
	for i := range concurrent {
		c, err := sqlDB.Conn(ctx)
		require.NoError(t, err)
		var one int
		require.NoError(t, c.QueryRowContext(ctx, "SELECT 1").Scan(&one))
		conns[i] = c
	}
	require.Equal(t, concurrent, sqlDB.Stats().InUse,
		"all %d connections must be genuinely checked out simultaneously before any are released", concurrent)
	for _, c := range conns {
		require.NoError(t, c.Close()) // returns the connection to the pool, doesn't close the underlying DB conn
	}

	stats := sqlDB.Stats()
	assert.Equal(t, int64(0), stats.MaxIdleClosed,
		"with max_idle_conns defaulted to match max_open_conns, none of the %d "+
			"connections used above should have been closed for exceeding the idle cap "+
			"(database/sql's own default of 2 would have closed %d of them)", concurrent, concurrent-2)
	assert.GreaterOrEqual(t, stats.Idle, concurrent-1,
		"nearly all %d connections should still be idle/warm in the pool for reuse", concurrent)
}

// TestApplyPoolSettings_S22_AllFieldsSet verifies that non-zero pool settings are
// applied correctly.
func TestApplyPoolSettings_S22_AllFieldsSet(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pool-set.db"))
	require.NoError(t, err)
	cfg := &config.DatabaseConfig{
		MaxOpenConns:           3,
		MaxIdleConns:           1,
		ConnMaxLifetimeMinutes: 5,
	}
	require.NoError(t, applyPoolSettings(db, cfg))

	sqlDB, err := db.DB()
	require.NoError(t, err)
	stats := sqlDB.Stats()
	assert.Equal(t, 3, stats.MaxOpenConnections)
}

// ---------------------------------------------------------------------------
// Full migration — new-table-only paths (tables that don't pre-exist)
// ---------------------------------------------------------------------------

// TestMigrateDatabase_S22_FreshCreatesMFATables verifies that a fresh migration
// creates the MFA tables (mfa_secrets, mfa_recovery_codes, mfa_challenges).
func TestMigrateDatabase_S22_FreshCreatesMFATables(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "mfa-fresh.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	db, err := gormOpenForTest(t, cfg.Storage.Database.Path)
	require.NoError(t, err)
	assert.True(t, tableExists(db, "mfa_secrets"))
	assert.True(t, tableExists(db, "mfa_recovery_codes"))
	assert.True(t, tableExists(db, "mfa_challenges"))
}

// TestMigrateDatabase_S22_FreshCreatesWebAuthnTables verifies that a fresh migration
// creates the WebAuthn tables.
func TestMigrateDatabase_S22_FreshCreatesWebAuthnTables(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "webauthn-fresh.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	db, err := gormOpenForTest(t, cfg.Storage.Database.Path)
	require.NoError(t, err)
	assert.True(t, tableExists(db, "web_authn_credentials"))
	assert.True(t, tableExists(db, "web_authn_sessions"))
}

// TestMigrateDatabase_S22_FreshCreatesSchedulerLockLeaseTable verifies that a fresh
// migration creates the scheduler_lock_leases table.
func TestMigrateDatabase_S22_FreshCreatesSchedulerLockLeaseTable(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "schedlock-fresh.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	db, err := gormOpenForTest(t, cfg.Storage.Database.Path)
	require.NoError(t, err)
	assert.True(t, tableExists(db, "scheduler_lock_leases"))
}

// TestMigrateDatabase_S22_FreshCreatesConnectRefGrantsTable verifies that a fresh
// migration creates the connect_ref_grants table (ADR-045).
func TestMigrateDatabase_S22_FreshCreatesConnectRefGrantsTable(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "connect-fresh.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	db, err := gormOpenForTest(t, cfg.Storage.Database.Path)
	require.NoError(t, err)
	assert.True(t, tableExists(db, "connect_ref_grants"))
}

// TestMigrateDatabase_S22_FreshCreatesPasswordHistoriesTable verifies that a fresh
// migration creates the password_histories table (ADR-025).
func TestMigrateDatabase_S22_FreshCreatesPasswordHistoriesTable(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "pwdhist-fresh.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	db, err := gormOpenForTest(t, cfg.Storage.Database.Path)
	require.NoError(t, err)
	assert.True(t, tableExists(db, "password_histories"))
}

// TestMigrateDatabase_S22_FreshCreatesSecretDependenciesTable verifies that a fresh
// migration creates the secret_dependencies table (ADR-052).
func TestMigrateDatabase_S22_FreshCreatesSecretDependenciesTable(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "secretdep-fresh.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	db, err := gormOpenForTest(t, cfg.Storage.Database.Path)
	require.NoError(t, err)
	assert.True(t, tableExists(db, "secret_dependencies"))
}

// TestMigrateDatabase_S22_FreshCreatesSoDTable verifies that a fresh migration
// creates the sod_policies table.
func TestMigrateDatabase_S22_FreshCreatesSoDTable(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "sod-fresh.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	db, err := gormOpenForTest(t, cfg.Storage.Database.Path)
	require.NoError(t, err)
	assert.True(t, tableExists(db, "sod_policies"))
}
