// Package migrations contains regression tests for the legacy, manual-only
// migrations/*.sql files described in migrations/README.md. These files are
// not exercised by any other automated harness (they're applied, if at all,
// via scripts/run_migrations.sh + the external golang-migrate CLI) — this
// test applies the raw SQL directly against a real SQLite database using the
// same modernc.org/sqlite driver used elsewhere in the codebase (ADR-048,
// indirectly via internal/storage/sqlitedialect), so no new test-only
// dependency is introduced.
//
// It covers backlog finding #203 and its round-140 follow-up: five
// destructive down-migrations (002_rbac_enhancements, 004_add_auth_encryption,
// 005_secret_sharing, 007_rotation_policies, 008_scope_user_group_roles) used
// to DROP (or, for 008, silently strip scoping from) security-relevant data
// with no export step. Each now copies the about-to-be-dropped data into a
// same-database backup table before the DROP/column-drop. These tests prove
// (1) real data present before rollback survives in the backup location
// afterward, and (2) the down-migration still performs its original
// structural change (the original column/table is genuinely gone), so the
// fix doesn't silently turn the down-migration into a no-op. 005's tests
// additionally pin a deliberate scope decision: secret_nodes.owner_id is kept
// (it's core ownership tracking used well beyond the sharing feature), only
// the sharing-specific is_shared column is dropped — see the down-migration's
// own comment for the investigation.
package migrations

import (
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"testing"

	_ "modernc.org/sqlite" // registers the "sqlite" driver with database/sql
)

// openTestDB opens a fresh, file-backed (not shared in-memory) SQLite
// database unique to this test, and applies 001_init.sql to establish the
// baseline schema every later migration builds on.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "migrations-test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// A single connection avoids any cross-connection SQLite locking
	// surprises for this short-lived, single-goroutine test DB.
	db.SetMaxOpenConns(1)

	execSQLFile(t, db, "001_init.sql")
	return db
}

func execSQLFile(t *testing.T, db *sql.DB, name string) {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if _, err := db.Exec(string(content)); err != nil {
		t.Fatalf("exec %s: %v", name, err)
	}
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()

	var name string
	err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table,
	).Scan(&name)
	if err == sql.ErrNoRows {
		return false
	}
	if err != nil {
		t.Fatalf("check table %s exists: %v", table, err)
	}
	return true
}

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()

	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     sql.NullString
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan table_info row: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}

// TestRBACAuditLogDownMigration_PreservesAuditTrail pins #203: rolling back
// migration 002 must not silently destroy the RBAC audit trail.
func TestRBACAuditLogDownMigration_PreservesAuditTrail(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")

	if _, err := db.Exec(
		`INSERT INTO rbac_audit_log (action, actor_user_id, target_user_id, role_id, namespace_id, details)
		 VALUES ('ASSIGN_ROLE', 1, 2, 3, 1, '{"note":"pin-203"}')`,
	); err != nil {
		t.Fatalf("seed rbac_audit_log: %v", err)
	}

	execSQLFile(t, db, "002_rbac_enhancements.down.sql")

	// Non-regression: the down-migration must still actually drop the table.
	if tableExists(t, db, "rbac_audit_log") {
		t.Fatal("rbac_audit_log still exists after down-migration; down-migration is a no-op")
	}

	// Regression fix: the row must survive in the backup table.
	var action string
	var details string
	err := db.QueryRow(
		`SELECT action, details FROM rbac_audit_log_backup WHERE action = 'ASSIGN_ROLE'`,
	).Scan(&action, &details)
	if err != nil {
		t.Fatalf("query rbac_audit_log_backup: %v", err)
	}
	if details != `{"note":"pin-203"}` {
		t.Fatalf("rbac_audit_log_backup.details = %q, want the seeded details preserved", details)
	}
}

// TestAuthEncryptionDownMigration_PreservesEncryptedColumns pins #203: rolling
// back migration 004 must not silently destroy encrypted credential material.
func TestAuthEncryptionDownMigration_PreservesEncryptedColumns(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "004_add_auth_encryption.up.sql")

	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'alice@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO api_clients (name, client_id, client_secret, encrypted_client_secret, client_secret_metadata)
		 VALUES ('client1', 'cid1', 'plain', X'DEADBEEF', '{"alg":"AES-256-GCM","kv":1}')`,
	); err != nil {
		t.Fatalf("seed api_clients: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO sessions (user_id, session_token, encrypted_session_token, session_token_metadata)
		 VALUES (1, 'tok1', X'CAFEBABE', '{"alg":"AES-256-GCM","kv":1}')`,
	); err != nil {
		t.Fatalf("seed sessions: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO api_tokens (client_id, token, encrypted_token, token_metadata)
		 VALUES (1, 'atok1', X'FEEDFACE', '{"alg":"AES-256-GCM","kv":1}')`,
	); err != nil {
		t.Fatalf("seed api_tokens: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO password_resets (user_id, token, encrypted_token, token_metadata)
		 VALUES (1, 'ptok1', X'B16B00B5', '{"alg":"AES-256-GCM","kv":1}')`,
	); err != nil {
		t.Fatalf("seed password_resets: %v", err)
	}

	execSQLFile(t, db, "004_add_auth_encryption.down.sql")

	// Non-regression: the encrypted_* / *_metadata columns must genuinely be
	// gone from their original tables.
	for _, tc := range []struct{ table, column string }{
		{"api_clients", "encrypted_client_secret"},
		{"api_clients", "client_secret_metadata"},
		{"sessions", "encrypted_session_token"},
		{"sessions", "session_token_metadata"},
		{"api_tokens", "encrypted_token"},
		{"api_tokens", "token_metadata"},
		{"password_resets", "encrypted_token"},
		{"password_resets", "token_metadata"},
	} {
		if columnExists(t, db, tc.table, tc.column) {
			t.Fatalf("%s.%s still exists after down-migration; down-migration is a no-op", tc.table, tc.column)
		}
	}

	// Regression fix: every dropped column's value must survive in the
	// shared backup table, keyed by source table/row id/column name.
	wantRows := map[string]string{
		"api_clients|encrypted_client_secret": string([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
		"api_clients|client_secret_metadata":  `{"alg":"AES-256-GCM","kv":1}`,
		"sessions|encrypted_session_token":    string([]byte{0xCA, 0xFE, 0xBA, 0xBE}),
		"sessions|session_token_metadata":     `{"alg":"AES-256-GCM","kv":1}`,
		"api_tokens|encrypted_token":          string([]byte{0xFE, 0xED, 0xFA, 0xCE}),
		"api_tokens|token_metadata":           `{"alg":"AES-256-GCM","kv":1}`,
		"password_resets|encrypted_token":     string([]byte{0xB1, 0x6B, 0x00, 0xB5}),
		"password_resets|token_metadata":      `{"alg":"AES-256-GCM","kv":1}`,
	}
	for key, want := range wantRows {
		var table, column string
		splitKV(key, &table, &column)
		var got []byte
		err := db.QueryRow(
			`SELECT column_value FROM auth_encryption_columns_backup
			 WHERE source_table = ? AND column_name = ? AND source_id = 1`,
			table, column,
		).Scan(&got)
		if err != nil {
			t.Fatalf("query auth_encryption_columns_backup for %s.%s: %v", table, column, err)
		}
		if string(got) != want {
			t.Fatalf("auth_encryption_columns_backup %s.%s = %q, want %q", table, column, got, want)
		}
	}
}

func splitKV(key string, table, column *string) {
	for i := range key {
		if key[i] == '|' {
			*table = key[:i]
			*column = key[i+1:]
			return
		}
	}
	*table = key
}

// TestShareRecordsDownMigration_PreservesShareHistory pins #203: rolling back
// migration 005 must not silently destroy share/access-grant history.
func TestShareRecordsDownMigration_PreservesShareHistory(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")

	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('owner1', 'owner1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users (owner): %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('recipient1', 'recipient1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users (recipient): %v", err)
	}
	if _, err := db.Exec(`INSERT INTO namespaces (name) VALUES ('ns1')`); err != nil {
		t.Fatalf("seed namespaces: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO zones (name) VALUES ('zone1')`); err != nil {
		t.Fatalf("seed zones: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO environments (name) VALUES ('env1')`); err != nil {
		t.Fatalf("seed environments: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO secret_nodes (namespace_id, zone_id, environment_id, name, is_secret, type, created_by)
		 VALUES (1, 1, 1, 's1', 1, 'secret', 'owner1')`,
	); err != nil {
		t.Fatalf("seed secret_nodes: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO share_records (secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at)
		 VALUES (1, 1, 2, 0, 'read', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
	); err != nil {
		t.Fatalf("seed share_records: %v", err)
	}

	execSQLFile(t, db, "005_secret_sharing.down.sql")

	// Non-regression: the down-migration must still actually drop the table.
	if tableExists(t, db, "share_records") {
		t.Fatal("share_records still exists after down-migration; down-migration is a no-op")
	}

	// Regression fix: the share record must survive in the backup table.
	var ownerID, recipientID int
	var permission string
	err := db.QueryRow(
		`SELECT owner_id, recipient_id, permission FROM share_records_backup WHERE secret_id = 1`,
	).Scan(&ownerID, &recipientID, &permission)
	if err != nil {
		t.Fatalf("query share_records_backup: %v", err)
	}
	if ownerID != 1 || recipientID != 2 || permission != "read" {
		t.Fatalf("share_records_backup row = (owner=%d, recipient=%d, permission=%q), want (1, 2, \"read\")",
			ownerID, recipientID, permission)
	}
}

// TestSecretNodesDownMigration_KeepsOwnerIDDropsIsShared pins the fix to
// 005_secret_sharing.down.sql's previously-stubbed secret_nodes column
// removal (see the file's own comment for the investigation: owner_id is
// core ownership-tracking infrastructure used far beyond the "sharing"
// feature — permissions.go's CheckSecretPermission, secret_ownership.go's
// TransferSecretOwnership, access reviews, blast-radius/risk analysis, and
// the inventory report all key off it — so only is_shared, which is
// sharing-specific and fully recomputable from share_records, is dropped.
func TestSecretNodesDownMigration_KeepsOwnerIDDropsIsShared(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")

	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('owner1', 'owner1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO namespaces (name) VALUES ('ns1')`); err != nil {
		t.Fatalf("seed namespaces: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO zones (name) VALUES ('zone1')`); err != nil {
		t.Fatalf("seed zones: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO environments (name) VALUES ('env1')`); err != nil {
		t.Fatalf("seed environments: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO secret_nodes (namespace_id, zone_id, environment_id, name, is_secret, type, created_by, owner_id, is_shared)
		 VALUES (1, 1, 1, 's1', 1, 'secret', 'owner1', 1, 1)`,
	); err != nil {
		t.Fatalf("seed secret_nodes: %v", err)
	}

	execSQLFile(t, db, "005_secret_sharing.down.sql")

	// Non-regression: is_shared is sharing-specific and genuinely dropped.
	if columnExists(t, db, "secret_nodes", "is_shared") {
		t.Fatal("secret_nodes.is_shared still exists after down-migration; the stub was never implemented")
	}

	// Regression fix, deliberate scope decision: owner_id is NOT dropped
	// (it's core ownership tracking, not sharing-specific) and its data must
	// survive the table rebuild intact.
	if !columnExists(t, db, "secret_nodes", "owner_id") {
		t.Fatal("secret_nodes.owner_id was dropped; it is core ownership tracking and must be preserved")
	}
	var ownerID int
	if err := db.QueryRow(`SELECT owner_id FROM secret_nodes WHERE id = 1`).Scan(&ownerID); err != nil {
		t.Fatalf("query secret_nodes.owner_id: %v", err)
	}
	if ownerID != 1 {
		t.Fatalf("secret_nodes.owner_id = %d, want 1 (preserved across the table rebuild)", ownerID)
	}

	// The owner_id index must survive the rebuild too, since the column did.
	if !tableExists(t, db, "secret_nodes") {
		t.Fatal("secret_nodes table itself must still exist (only is_shared should be removed)")
	}
	var idxName string
	err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_secret_nodes_owner_id'`,
	).Scan(&idxName)
	if err != nil {
		t.Fatalf("idx_secret_nodes_owner_id missing after rebuild: %v", err)
	}
}

// TestSecretNodesDownMigration_ReapplyingUpFailsLoudlyOnPreservedOwnerID
// documents an accepted, intentional consequence of keeping owner_id (see
// the test above and the comment in 005_secret_sharing.down.sql): because
// owner_id is deliberately NOT dropped, 005_secret_sharing.up.sql's
// `ALTER TABLE secret_nodes ADD COLUMN owner_id ...` can no longer be
// cleanly replayed after a down-migration — it now fails loudly with a
// duplicate-column error instead of silently succeeding. That's the correct
// trade-off (a loud, immediate failure beats silently duplicating or
// losing ownership data), but it means down-then-up is no longer fully
// symmetric for this migration; this test pins that as expected, not a
// regression to "fix" by reintroducing the drop.
func TestSecretNodesDownMigration_ReapplyingUpFailsLoudlyOnPreservedOwnerID(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")
	execSQLFile(t, db, "005_secret_sharing.down.sql")

	content, err := os.ReadFile(filepath.Join(".", "005_secret_sharing.up.sql"))
	if err != nil {
		t.Fatalf("read 005_secret_sharing.up.sql: %v", err)
	}
	_, execErr := db.Exec(string(content))
	if execErr == nil {
		t.Fatal("expected re-applying 005's up-migration to fail on the already-present owner_id column, got nil error")
	}
}

// TestRotationPoliciesDownMigration_PreservesComplianceData pins the fix to
// 007_rotation_policies.down.sql: rolling back must not silently destroy
// rotation-policy/compliance data (which secrets require rotation, alert
// thresholds, created_by accountability).
//
// 007_rotation_policies.up.sql uses PostgreSQL-only syntax (SERIAL, NOW())
// that modernc.org/sqlite's driver cannot execute (see migrations/README.md:
// these files are "dialect-inconsistent by construction" and "were never
// executed end-to-end as a single unit against one database engine"), so
// this test seeds the table directly with SQLite-compatible DDL matching the
// up-migration's column set, rather than executing the up file.
func TestRotationPoliciesDownMigration_PreservesComplianceData(t *testing.T) {
	db := openTestDB(t)

	if _, err := db.Exec(`CREATE TABLE rotation_policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		scope TEXT NOT NULL DEFAULT 'environment',
		project_id INTEGER,
		environment_id INTEGER,
		interval_days INTEGER NOT NULL,
		alert_days_before INTEGER NOT NULL DEFAULT 7,
		notify_on_breach BOOLEAN NOT NULL DEFAULT 1,
		is_active BOOLEAN NOT NULL DEFAULT 1,
		created_by TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP
	)`); err != nil {
		t.Fatalf("seed rotation_policies schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO rotation_policies (name, description, scope, interval_days, alert_days_before, notify_on_breach, is_active, created_by)
		 VALUES ('db-creds-90d', 'rotate DB creds quarterly', 'environment', 90, 14, 1, 1, 'alice')`,
	); err != nil {
		t.Fatalf("seed rotation_policies row: %v", err)
	}

	execSQLFile(t, db, "007_rotation_policies.down.sql")

	// Non-regression: the down-migration must still actually drop the table.
	if tableExists(t, db, "rotation_policies") {
		t.Fatal("rotation_policies still exists after down-migration; down-migration is a no-op")
	}

	// Regression fix: the row must survive in the backup table.
	var name, createdBy string
	var intervalDays int
	err := db.QueryRow(
		`SELECT name, interval_days, created_by FROM rotation_policies_backup WHERE name = 'db-creds-90d'`,
	).Scan(&name, &intervalDays, &createdBy)
	if err != nil {
		t.Fatalf("query rotation_policies_backup: %v", err)
	}
	if intervalDays != 90 || createdBy != "alice" {
		t.Fatalf("rotation_policies_backup row = (interval_days=%d, created_by=%q), want (90, \"alice\")",
			intervalDays, createdBy)
	}
}

// TestScopeUserGroupRolesDownMigration_PreservesEnvironmentScoping pins the
// fix to 008_scope_user_group_roles.down.sql: dropping environment_id must
// not silently widen every previously environment-scoped role/group binding
// to "all environments" (environment_id=0, per 008's up-migration and
// internal/core/access_review.go's EnvironmentID doc comment) on a future
// down-then-up cycle. The row itself (and its environment_id value) must
// survive in a backup table, and the live table's other columns/rows must be
// untouched by the column drop.
func TestScopeUserGroupRolesDownMigration_PreservesEnvironmentScoping(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")
	execSQLFile(t, db, "006_rename_namespace_to_project.up.sql")
	execSQLFile(t, db, "008_scope_user_group_roles.up.sql")

	if _, err := db.Exec(`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'alice@example.com', 'x')`); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO roles (name) VALUES ('admin')`); err != nil {
		t.Fatalf("seed roles: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO groups (name) VALUES ('g1')`); err != nil {
		t.Fatalf("seed groups: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO projects (name) VALUES ('proj1')`); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 7)`,
	); err != nil {
		t.Fatalf("seed user_roles: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 7)`,
	); err != nil {
		t.Fatalf("seed group_roles: %v", err)
	}

	execSQLFile(t, db, "008_scope_user_group_roles.down.sql")

	// Non-regression: the down-migration must still actually drop the column.
	if columnExists(t, db, "user_roles", "environment_id") {
		t.Fatal("user_roles.environment_id still exists after down-migration; down-migration is a no-op")
	}
	if columnExists(t, db, "group_roles", "environment_id") {
		t.Fatal("group_roles.environment_id still exists after down-migration; down-migration is a no-op")
	}

	// The row itself (minus environment_id) must survive the column drop.
	var projectID int
	if err := db.QueryRow(`SELECT project_id FROM user_roles WHERE user_id = 1 AND role_id = 1`).Scan(&projectID); err != nil {
		t.Fatalf("user_roles row missing after down-migration: %v", err)
	}
	if projectID != 1 {
		t.Fatalf("user_roles.project_id = %d, want 1 (untouched by the environment_id drop)", projectID)
	}

	// Regression fix: environment_id must survive in the backup tables.
	var envID int
	err := db.QueryRow(
		`SELECT environment_id FROM user_roles_backup WHERE user_id = 1 AND role_id = 1 AND project_id = 1`,
	).Scan(&envID)
	if err != nil {
		t.Fatalf("query user_roles_backup: %v", err)
	}
	if envID != 7 {
		t.Fatalf("user_roles_backup.environment_id = %d, want 7", envID)
	}

	err = db.QueryRow(
		`SELECT environment_id FROM group_roles_backup WHERE group_id = 1 AND role_id = 1 AND project_id = 1`,
	).Scan(&envID)
	if err != nil {
		t.Fatalf("query group_roles_backup: %v", err)
	}
	if envID != 7 {
		t.Fatalf("group_roles_backup.environment_id = %d, want 7", envID)
	}
}

// auditorPermissions returns every permission name granted to the 'auditor'
// role via role_permissions.
func auditorPermissions(t *testing.T, db *sql.DB) []string {
	t.Helper()

	rows, err := db.Query(`
		SELECT p.name FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN roles r ON r.id = rp.role_id
		WHERE r.name = 'auditor'
		ORDER BY p.name
	`)
	if err != nil {
		t.Fatalf("query auditor role_permissions: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var perms []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan permission name: %v", err)
		}
		perms = append(perms, name)
	}
	return perms
}

// TestAuditorSeedDoesNotGrantAuditAdmin pins findings-unreviewed/migrations.json#1:
// 003_rbac_seed_data.up.sql defines 'auditor' as a read-only role ("Can view
// audit logs and system information") but originally granted it both
// 'audit.read' and 'audit.admin' ("Full administrative access to audit
// system"). This is a non-regression check on 003 itself: applying only
// 001-003 (the historical bootstrap set) must show the over-grant existed,
// so the corrective migration below has something real to fix.
func TestAuditorSeedGrantsAuditAdminBefore009(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")
	execSQLFile(t, db, "003_rbac_seed_data.up.sql")

	perms := auditorPermissions(t, db)
	found := slices.Contains(perms, "audit.admin")
	if !found {
		t.Fatalf("auditor permissions = %v, want 'audit.admin' present pre-009 (this pins the documented bug, not the fix)", perms)
	}
}

// TestFixAuditorAuditAdminOvergrantMigration pins the fix for
// findings-unreviewed/migrations.json#1: after applying the corrective
// 009_fix_auditor_audit_admin_overgrant migration on top of 001-003 (the
// legacy bootstrap set this directory exists to serve, per
// migrations/README.md), the 'auditor' role must hold 'audit.read' but must
// NOT hold 'audit.admin' -- matching the role's own read-only description
// and the live app's canonical system_auditor/project_auditor definitions
// (internal/core/auth_bootstrap.go), which never grant audit.admin. It also
// confirms the migration doesn't collaterally touch any other role's
// grants -- namely 'admin', which never held audit.admin in the first place.
func TestFixAuditorAuditAdminOvergrantMigration(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")
	execSQLFile(t, db, "003_rbac_seed_data.up.sql")
	execSQLFile(t, db, "009_fix_auditor_audit_admin_overgrant.up.sql")

	perms := auditorPermissions(t, db)
	want := []string{"audit.read", "namespaces.read", "roles.read", "system.read", "users.read"}
	if len(perms) != len(want) {
		t.Fatalf("auditor permissions after 009 = %v, want %v", perms, want)
	}
	for i, p := range perms {
		if p != want[i] {
			t.Fatalf("auditor permissions after 009 = %v, want %v", perms, want)
		}
	}
	for _, p := range perms {
		if p == "audit.admin" {
			t.Fatal("auditor role still holds audit.admin after 009_fix_auditor_audit_admin_overgrant.up.sql")
		}
	}

	// Non-regression: 'admin' never held audit.admin, and 009 must not
	// change that (or grant it accidentally via a role-name typo/join bug).
	var adminHasAuditAdmin int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE r.name = 'admin' AND p.name = 'audit.admin'
	`).Scan(&adminHasAuditAdmin)
	if err != nil {
		t.Fatalf("query admin role_permissions: %v", err)
	}
	if adminHasAuditAdmin != 0 {
		t.Fatal("'admin' role unexpectedly holds audit.admin after 009_fix_auditor_audit_admin_overgrant.up.sql")
	}
}

// TestFixAuditorAuditAdminOvergrantDownMigration pins that the down-migration
// correctly reverts the correction: reapplying it restores the (legacy,
// over-broad) audit.admin grant on 'auditor'. This is deliberate symmetry
// with the rest of this directory's reversible migrations, not an
// endorsement of running the down-migration in production.
func TestFixAuditorAuditAdminOvergrantDownMigration(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")
	execSQLFile(t, db, "003_rbac_seed_data.up.sql")
	execSQLFile(t, db, "009_fix_auditor_audit_admin_overgrant.up.sql")
	execSQLFile(t, db, "009_fix_auditor_audit_admin_overgrant.down.sql")

	perms := auditorPermissions(t, db)
	found := slices.Contains(perms, "audit.admin")
	if !found {
		t.Fatalf("auditor permissions after up+down = %v, want 'audit.admin' restored by the down-migration", perms)
	}
}

// seedSharedSecretForStatusSyncTest seeds one owner, one recipient, and one
// secret shared between them (share_records row id=1, secret_nodes row
// id=1). 005_secret_sharing.up.sql's AFTER INSERT trigger fires on the
// share_records insert below and sets secret_nodes.is_shared to TRUE, so
// callers start from a known "currently shared" state.
func seedSharedSecretForStatusSyncTest(t *testing.T, db *sql.DB) {
	t.Helper()

	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('owner1', 'owner1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users (owner): %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('recipient1', 'recipient1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users (recipient): %v", err)
	}
	if _, err := db.Exec(`INSERT INTO namespaces (name) VALUES ('ns1')`); err != nil {
		t.Fatalf("seed namespaces: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO zones (name) VALUES ('zone1')`); err != nil {
		t.Fatalf("seed zones: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO environments (name) VALUES ('env1')`); err != nil {
		t.Fatalf("seed environments: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO secret_nodes (namespace_id, zone_id, environment_id, name, is_secret, type, created_by, owner_id)
		 VALUES (1, 1, 1, 's1', 1, 'secret', 'owner1', 1)`,
	); err != nil {
		t.Fatalf("seed secret_nodes: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO share_records (secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at)
		 VALUES (1, 1, 2, 0, 'read', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
	); err != nil {
		t.Fatalf("seed share_records: %v", err)
	}
}

// softDeleteShareRecord mirrors what internal/storage/store/local_sharing.go's
// DeleteShareRecord and DeleteExpiredShareRecords actually issue via GORM
// against a ShareRecord (whose DeletedAt field is a gorm.DeletedAt soft-delete
// column): an UPDATE setting deleted_at, never a raw SQL DELETE.
func softDeleteShareRecord(t *testing.T, db *sql.DB, id int) {
	t.Helper()

	if _, err := db.Exec(`UPDATE share_records SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		t.Fatalf("soft-delete share_records id=%d: %v", id, err)
	}
}

func assertSecretIsShared(t *testing.T, db *sql.DB, secretID int, want bool) {
	t.Helper()

	var isShared bool
	if err := db.QueryRow(`SELECT is_shared FROM secret_nodes WHERE id = ?`, secretID).Scan(&isShared); err != nil {
		t.Fatalf("query secret_nodes.is_shared for id=%d: %v", secretID, err)
	}
	if isShared != want {
		t.Fatalf("secret_nodes.is_shared for id=%d = %v, want %v", secretID, isShared, want)
	}
}

// TestShareStatusStaleAfterSoftDeleteBefore010 pins migrations-003: applying
// only 005 (the historical bootstrap set this migration's fix targets, per
// migrations/README.md), revoking the only share on a secret through the
// application's real GORM soft-delete path leaves secret_nodes.is_shared
// incorrectly TRUE, because 005's update_secret_shared_status_delete trigger
// only fires on a raw SQL DELETE, which the application never issues. This is
// a non-regression check on 005 itself: it must show the bug exists before
// 010 is applied, so the corrective migration below has something real to
// fix.
func TestShareStatusStaleAfterSoftDeleteBefore010(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")

	seedSharedSecretForStatusSyncTest(t, db)
	assertSecretIsShared(t, db, 1, true)

	softDeleteShareRecord(t, db, 1)

	// This pins the documented bug pre-010: the AFTER DELETE trigger never
	// fires for a soft delete, so is_shared incorrectly stays TRUE even
	// though the secret's only share was just revoked.
	assertSecretIsShared(t, db, 1, true)
}

// TestFixShareStatusSoftDeleteSyncMigration pins the fix for migrations-003:
// after applying the corrective 010_fix_share_status_soft_delete_sync
// migration on top of 005, revoking a secret's only share through the
// application's real GORM soft-delete path correctly flips
// secret_nodes.is_shared back to FALSE.
func TestFixShareStatusSoftDeleteSyncMigration(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")
	execSQLFile(t, db, "010_fix_share_status_soft_delete_sync.up.sql")

	seedSharedSecretForStatusSyncTest(t, db)
	assertSecretIsShared(t, db, 1, true)

	softDeleteShareRecord(t, db, 1)

	// Regression fix: is_shared must flip back to FALSE once the only share
	// on the secret has been soft-deleted.
	assertSecretIsShared(t, db, 1, false)

	// Non-regression: a secret that still has an active share must remain
	// marked as shared after some OTHER share on it is revoked.
	if _, err := db.Exec(
		`INSERT INTO share_records (secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at)
		 VALUES (1, 1, 2, 0, 'read', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
	); err != nil {
		t.Fatalf("seed second share_records row: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO share_records (secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at)
		 VALUES (1, 1, 2, 0, 'read', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
	); err != nil {
		t.Fatalf("seed third share_records row: %v", err)
	}
	assertSecretIsShared(t, db, 1, true)
	softDeleteShareRecord(t, db, 2)
	assertSecretIsShared(t, db, 1, true)
}

// TestFixShareStatusSoftDeleteSyncDownMigration pins that the down-migration
// correctly reverts the correction: reapplying it restores the original
// (stale) behaviour where a soft-deleted share no longer flips is_shared back
// to FALSE. This is deliberate symmetry with the rest of this directory's
// reversible migrations, not an endorsement of running the down-migration in
// production.
func TestFixShareStatusSoftDeleteSyncDownMigration(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")
	execSQLFile(t, db, "010_fix_share_status_soft_delete_sync.up.sql")
	execSQLFile(t, db, "010_fix_share_status_soft_delete_sync.down.sql")

	seedSharedSecretForStatusSyncTest(t, db)
	assertSecretIsShared(t, db, 1, true)

	softDeleteShareRecord(t, db, 1)

	// After up+down, the corrective trigger is gone again -- the original
	// stale is_shared bug is restored.
	assertSecretIsShared(t, db, 1, true)
}

// TestDropSessionReversibleEncryptionMigration pins #1641: sessions'
// encrypted_session_token/session_token_metadata columns (added by 004, never
// populated by any live write path) are genuinely dropped, any pre-existing
// value is preserved in the shared backup table first, and rolling back
// restores both the columns and their values.
func TestDropSessionReversibleEncryptionMigration(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "004_add_auth_encryption.up.sql")

	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'alice@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO sessions (user_id, session_token, encrypted_session_token, session_token_metadata)
		 VALUES (1, 'tok1', X'CAFEBABE', '{"alg":"AES-256-GCM","kv":1}')`,
	); err != nil {
		t.Fatalf("seed sessions: %v", err)
	}

	execSQLFile(t, db, "011_drop_session_reversible_encryption.up.sql")

	for _, column := range []string{"encrypted_session_token", "session_token_metadata"} {
		if columnExists(t, db, "sessions", column) {
			t.Fatalf("sessions.%s still exists after 011's up-migration; migration is a no-op", column)
		}
	}

	wantRows := map[string]string{
		"encrypted_session_token": string([]byte{0xCA, 0xFE, 0xBA, 0xBE}),
		"session_token_metadata":  `{"alg":"AES-256-GCM","kv":1}`,
	}
	for column, want := range wantRows {
		var got []byte
		err := db.QueryRow(
			`SELECT column_value FROM auth_encryption_columns_backup
			 WHERE source_table = 'sessions' AND column_name = ? AND source_id = 1`,
			column,
		).Scan(&got)
		if err != nil {
			t.Fatalf("query auth_encryption_columns_backup for sessions.%s: %v", column, err)
		}
		if string(got) != want {
			t.Fatalf("auth_encryption_columns_backup sessions.%s = %q, want %q", column, got, want)
		}
	}

	execSQLFile(t, db, "011_drop_session_reversible_encryption.down.sql")

	for _, column := range []string{"encrypted_session_token", "session_token_metadata"} {
		if !columnExists(t, db, "sessions", column) {
			t.Fatalf("sessions.%s missing after 011's down-migration", column)
		}
	}

	var gotToken []byte
	var gotMeta []byte
	if err := db.QueryRow(`SELECT encrypted_session_token, session_token_metadata FROM sessions WHERE id = 1`).
		Scan(&gotToken, &gotMeta); err != nil {
		t.Fatalf("query restored session row: %v", err)
	}
	if string(gotToken) != wantRows["encrypted_session_token"] {
		t.Fatalf("restored sessions.encrypted_session_token = %q, want %q", gotToken, wantRows["encrypted_session_token"])
	}
	if string(gotMeta) != wantRows["session_token_metadata"] {
		t.Fatalf("restored sessions.session_token_metadata = %q, want %q", gotMeta, wantRows["session_token_metadata"])
	}
}

// TestShareRecordsRecipientID_NoForeignKeyToUsers pins the fix removing
// 005_secret_sharing.up.sql's `FOREIGN KEY (recipient_id) REFERENCES
// users(id)`: recipient_id is polymorphic (a users(id) value when
// is_group=0, a groups(id) value when is_group=1 -- see
// internal/storage/store/local_sharing.go), so a hard FK to users(id) would
// reject every group share whose recipient_id doesn't happen to coincide
// with an existing users(id). This enables foreign_keys enforcement
// explicitly (SQLite defaults it off; every real connection in this
// codebase runs with it on) so the test would have failed loudly against
// the original schema, not passed vacuously.
func TestShareRecordsRecipientID_NoForeignKeyToUsers(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")

	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatalf("enable foreign_keys pragma: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('owner1', 'owner1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO namespaces (name) VALUES ('ns1')`); err != nil {
		t.Fatalf("seed namespaces: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO zones (name) VALUES ('zone1')`); err != nil {
		t.Fatalf("seed zones: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO environments (name) VALUES ('env1')`); err != nil {
		t.Fatalf("seed environments: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO secret_nodes (namespace_id, zone_id, environment_id, name, is_secret, type, created_by, owner_id)
		 VALUES (1, 1, 1, 's1', 1, 'secret', 'owner1', 1)`,
	); err != nil {
		t.Fatalf("seed secret_nodes: %v", err)
	}

	// Sanity check that foreign_keys enforcement is genuinely active: an
	// invalid owner_id (which still has a real FK to users(id)) must be
	// rejected, so a passing recipient_id insert below isn't just silently
	// unenforced FK checking across the board.
	if _, err := db.Exec(
		`INSERT INTO share_records (secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at)
		 VALUES (1, 999, 1, 0, 'read', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
	); err == nil {
		t.Fatal("expected invalid owner_id=999 to be rejected by its own FK with foreign_keys=ON, got nil error")
	}

	// recipient_id=999 has no matching row in users at all -- this is what a
	// group share's recipient_id looks like from users' point of view (it's
	// a groups(id), and 005_secret_sharing.up.sql seeds no groups). The
	// original FOREIGN KEY (recipient_id) REFERENCES users(id) would reject
	// this insert; the fix must not.
	if _, err := db.Exec(
		`INSERT INTO share_records (secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at)
		 VALUES (1, 1, 999, 1, 'read', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
	); err != nil {
		t.Fatalf("insert group share_records row with recipient_id=999 (no matching users row): %v", err)
	}
}

// TestUsersUsernameIndex_PartialUniqueAllowsReuseAfterSoftDelete pins the
// fix replacing users.username's inline UNIQUE column constraint (backed by
// an un-droppable SQLite auto-index) with a named partial unique index
// scoped to `WHERE deleted_at IS NULL`, matching the state
// internal/storage/factory.go's ensureUserNameIndex establishes via
// AutoMigrate. Also pins the non-regression: two LIVE rows must still
// collide.
func TestUsersUsernameIndex_PartialUniqueAllowsReuseAfterSoftDelete(t *testing.T) {
	db := openTestDB(t)

	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'a1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed first alice: %v", err)
	}

	// Non-regression: two live rows sharing a username must still collide.
	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'a2@example.com', 'x')`,
	); err == nil {
		t.Fatal("expected duplicate live username 'alice' to be rejected, got nil error")
	}

	if _, err := db.Exec(`UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE username = 'alice'`); err != nil {
		t.Fatalf("soft-delete alice: %v", err)
	}

	// Regression fix: once the original row is soft-deleted, the username is
	// free for reuse. An inline UNIQUE column constraint's auto-index could
	// never allow this, since it can't be scoped to live rows and can't be
	// dropped by name to replace with a partial one.
	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'a3@example.com', 'x')`,
	); err != nil {
		t.Fatalf("expected reused username 'alice' after soft-delete to succeed, got error: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = 'alice'`).Scan(&count); err != nil {
		t.Fatalf("count users named alice: %v", err)
	}
	if count != 2 {
		t.Fatalf("count of users named 'alice' = %d, want 2 (one soft-deleted, one live)", count)
	}
}

// TestGroupsNameIndex_PartialUniqueAllowsReuseAfterSoftDelete mirrors
// TestUsersUsernameIndex_PartialUniqueAllowsReuseAfterSoftDelete for
// groups.name, pinning the same fix (ensureGroupNameIndex's counterpart).
func TestGroupsNameIndex_PartialUniqueAllowsReuseAfterSoftDelete(t *testing.T) {
	db := openTestDB(t)

	if _, err := db.Exec(`INSERT INTO groups (name, description) VALUES ('g1', 'first')`); err != nil {
		t.Fatalf("seed first group g1: %v", err)
	}

	// Non-regression: two live groups sharing a name must still collide.
	if _, err := db.Exec(`INSERT INTO groups (name, description) VALUES ('g1', 'second')`); err == nil {
		t.Fatal("expected duplicate live group name 'g1' to be rejected, got nil error")
	}

	if _, err := db.Exec(`UPDATE groups SET deleted_at = CURRENT_TIMESTAMP WHERE name = 'g1'`); err != nil {
		t.Fatalf("soft-delete group g1: %v", err)
	}

	// Regression fix: once the original row is soft-deleted, the name is
	// free for reuse.
	if _, err := db.Exec(`INSERT INTO groups (name, description) VALUES ('g1', 'reused')`); err != nil {
		t.Fatalf("expected reused group name 'g1' after soft-delete to succeed, got error: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM groups WHERE name = 'g1'`).Scan(&count); err != nil {
		t.Fatalf("count groups named g1: %v", err)
	}
	if count != 2 {
		t.Fatalf("count of groups named 'g1' = %d, want 2 (one soft-deleted, one live)", count)
	}
}

// TestNamespacesNameIndex_PartialUniqueAllowsReuseAfterSoftDelete mirrors the
// same fix for namespaces.name (ensureProjectNameIndex's counterpart --
// namespaces is renamed to `projects` by 006, but this pins the state at
// 001_init.sql, before that rename).
func TestNamespacesNameIndex_PartialUniqueAllowsReuseAfterSoftDelete(t *testing.T) {
	db := openTestDB(t)

	if _, err := db.Exec(`INSERT INTO namespaces (name, description) VALUES ('proj1', 'first')`); err != nil {
		t.Fatalf("seed first namespace proj1: %v", err)
	}

	// Non-regression: two live namespaces sharing a name must still collide.
	if _, err := db.Exec(`INSERT INTO namespaces (name, description) VALUES ('proj1', 'second')`); err == nil {
		t.Fatal("expected duplicate live namespace name 'proj1' to be rejected, got nil error")
	}

	if _, err := db.Exec(`UPDATE namespaces SET deleted_at = CURRENT_TIMESTAMP WHERE name = 'proj1'`); err != nil {
		t.Fatalf("soft-delete namespace proj1: %v", err)
	}

	// Regression fix: once the original row is soft-deleted, the name is
	// free for reuse.
	if _, err := db.Exec(`INSERT INTO namespaces (name, description) VALUES ('proj1', 'reused')`); err != nil {
		t.Fatalf("expected reused namespace name 'proj1' after soft-delete to succeed, got error: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM namespaces WHERE name = 'proj1'`).Scan(&count); err != nil {
		t.Fatalf("count namespaces named proj1: %v", err)
	}
	if count != 2 {
		t.Fatalf("count of namespaces named 'proj1' = %d, want 2 (one soft-deleted, one live)", count)
	}

	// Case-insensitivity: uniq_projects_name_active is on LOWER(name), so
	// 'PROJ1' collides with the still-live 'proj1' reuse above too.
	if _, err := db.Exec(`INSERT INTO namespaces (name, description) VALUES ('PROJ1', 'case-collision')`); err == nil {
		t.Fatal("expected 'PROJ1' to collide case-insensitively with live 'proj1', got nil error")
	}
}

// TestScopeUserGroupRolesUpMigration_ProjectIDNotNullFourColumnPK pins the
// fix to 008_scope_user_group_roles.up.sql: project_id is genuinely NOT
// NULL (not just backfilled once), and the PRIMARY KEY is widened to
// (subject, role, project, environment) so two rows differing only in
// environment_id -- migration 008's entire stated purpose -- are no longer
// rejected by the original 3-column PK carried over from 001_init.sql.
func TestScopeUserGroupRolesUpMigration_ProjectIDNotNullFourColumnPK(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")
	execSQLFile(t, db, "006_rename_namespace_to_project.up.sql")

	if _, err := db.Exec(`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'alice@example.com', 'x')`); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO roles (name) VALUES ('admin')`); err != nil {
		t.Fatalf("seed roles: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO groups (name) VALUES ('g1')`); err != nil {
		t.Fatalf("seed groups: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO projects (name) VALUES ('proj1')`); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	// A legacy NULL project scope, as could exist pre-008 (namespace_id/
	// project_id was nullable prior to this migration).
	if _, err := db.Exec(`INSERT INTO user_roles (user_id, role_id, project_id) VALUES (1, 1, NULL)`); err != nil {
		t.Fatalf("seed user_roles with NULL project_id: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO group_roles (group_id, role_id, project_id) VALUES (1, 1, NULL)`); err != nil {
		t.Fatalf("seed group_roles with NULL project_id: %v", err)
	}

	execSQLFile(t, db, "008_scope_user_group_roles.up.sql")

	// Non-regression: the pre-existing NULL project scope is backfilled to
	// the 0 sentinel and survives the table rebuild.
	var projectID int
	if err := db.QueryRow(`SELECT project_id FROM user_roles WHERE user_id = 1 AND role_id = 1`).Scan(&projectID); err != nil {
		t.Fatalf("user_roles row missing after 008's up-migration: %v", err)
	}
	if projectID != 0 {
		t.Fatalf("user_roles.project_id = %d, want 0 (backfilled sentinel)", projectID)
	}

	// Regression fix 1: project_id is genuinely NOT NULL now, not just
	// backfilled once -- a fresh NULL insert must be rejected.
	if _, err := db.Exec(
		`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 1, NULL, 1)`,
	); err == nil {
		t.Fatal("expected inserting NULL project_id into user_roles to be rejected after 008, got nil error")
	}
	if _, err := db.Exec(
		`INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (1, 1, NULL, 1)`,
	); err == nil {
		t.Fatal("expected inserting NULL project_id into group_roles to be rejected after 008, got nil error")
	}

	// Regression fix 2: the PRIMARY KEY is widened to 4 columns, so two rows
	// differing only in environment_id (same subject/role/project) must both
	// be allowed.
	if _, err := db.Exec(
		`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 1)`,
	); err != nil {
		t.Fatalf("insert user_roles (project=1, environment=1): %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 2)`,
	); err != nil {
		t.Fatalf("insert user_roles (project=1, environment=2) alongside environment=1 for the same user/role/project: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 1)`,
	); err != nil {
		t.Fatalf("insert group_roles (project=1, environment=1): %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 2)`,
	); err != nil {
		t.Fatalf("insert group_roles (project=1, environment=2) alongside environment=1 for the same group/role/project: %v", err)
	}

	// Non-regression: an exact duplicate (subject, role, project,
	// environment) must still be rejected by the PK/unique index.
	if _, err := db.Exec(
		`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 1)`,
	); err == nil {
		t.Fatal("expected exact duplicate (1,1,1,1) user_roles row to be rejected, got nil error")
	}

	var userRolesCount, groupRolesCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_roles`).Scan(&userRolesCount); err != nil {
		t.Fatalf("count user_roles: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM group_roles`).Scan(&groupRolesCount); err != nil {
		t.Fatalf("count group_roles: %v", err)
	}
	// The backfilled (project=0,environment=0) row plus (project=1,
	// environment=1) and (project=1,environment=2) = 3 each.
	if userRolesCount != 3 {
		t.Fatalf("user_roles row count = %d, want 3", userRolesCount)
	}
	if groupRolesCount != 3 {
		t.Fatalf("group_roles row count = %d, want 3", groupRolesCount)
	}

	// The pre-existing indexes from 002/006 (dropped implicitly when the
	// rebuild's DROP TABLE ran) must have been recreated, not silently lost.
	for _, idx := range []string{
		"idx_user_roles_user_id", "idx_user_roles_role_id", "idx_user_roles_project_id",
		"idx_group_roles_group_id", "idx_group_roles_role_id", "idx_group_roles_project_id",
		"idx_user_roles_scope", "idx_group_roles_scope",
	} {
		var name string
		err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&name)
		if err != nil {
			t.Fatalf("index %s missing after 008's up-migration rebuild: %v", idx, err)
		}
	}
}

// TestScopeUserGroupRolesDownMigration_FourColumnPKDropsCleanly pins that
// 008's down-migration still works once environment_id is part of each
// table's PRIMARY KEY: a plain `ALTER TABLE ... DROP COLUMN environment_id`
// is rejected by SQLite for a column used in a PRIMARY KEY, so the
// down-migration itself had to move to the same rebuild idiom as the
// up-migration.
func TestScopeUserGroupRolesDownMigration_FourColumnPKDropsCleanly(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")
	execSQLFile(t, db, "006_rename_namespace_to_project.up.sql")
	execSQLFile(t, db, "008_scope_user_group_roles.up.sql")

	if _, err := db.Exec(`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'alice@example.com', 'x')`); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO roles (name) VALUES ('admin')`); err != nil {
		t.Fatalf("seed roles: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO groups (name) VALUES ('g1')`); err != nil {
		t.Fatalf("seed groups: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO projects (name) VALUES ('proj1')`); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 7)`,
	); err != nil {
		t.Fatalf("seed user_roles: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 7)`,
	); err != nil {
		t.Fatalf("seed group_roles: %v", err)
	}

	execSQLFile(t, db, "008_scope_user_group_roles.down.sql")

	if columnExists(t, db, "user_roles", "environment_id") {
		t.Fatal("user_roles.environment_id still exists after 008's down-migration; down-migration is a no-op")
	}
	if columnExists(t, db, "group_roles", "environment_id") {
		t.Fatal("group_roles.environment_id still exists after 008's down-migration; down-migration is a no-op")
	}

	// The row itself must survive, narrowed back to the 3-column scope.
	var projectID int
	if err := db.QueryRow(`SELECT project_id FROM user_roles WHERE user_id = 1 AND role_id = 1`).Scan(&projectID); err != nil {
		t.Fatalf("user_roles row missing after 008's down-migration: %v", err)
	}
	if projectID != 1 {
		t.Fatalf("user_roles.project_id = %d, want 1 (untouched by the rebuild)", projectID)
	}

	// The now-3-column PK must allow re-adding the row without an
	// environment_id, and must still enforce uniqueness on (user_id,
	// role_id, project_id) alone.
	if _, err := db.Exec(`INSERT INTO user_roles (user_id, role_id, project_id) VALUES (1, 1, 1)`); err == nil {
		t.Fatal("expected duplicate (user_id=1, role_id=1, project_id=1) to be rejected by the narrowed 3-column PK, got nil error")
	}
}

// TestRBACSeedDataDownMigration_BackupBeforeDelete pins #203's fix extended
// to 003_rbac_seed_data.down.sql: unlike its already-hardened siblings
// (002/004/005/007/008), this file used to delete seed
// roles/permissions/role_permissions/environments/zones/namespaces with no
// backup at all. It now copies every about-to-be-deleted row into a
// same-database `*_backup` table first, following the same pattern.
func TestRBACSeedDataDownMigration_BackupBeforeDelete(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")
	execSQLFile(t, db, "003_rbac_seed_data.up.sql")

	execSQLFile(t, db, "003_rbac_seed_data.down.sql")

	// Non-regression: the down-migration must still actually remove the seed
	// rows from every live table.
	for _, tc := range []struct{ query, label string }{
		{`SELECT COUNT(*) FROM roles WHERE name = 'super_admin'`, "roles.super_admin"},
		{`SELECT COUNT(*) FROM permissions WHERE resource = 'secrets'`, "permissions with resource='secrets'"},
		{`SELECT COUNT(*) FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE name = 'super_admin')`, "role_permissions for super_admin"},
		{`SELECT COUNT(*) FROM environments WHERE name = 'production'`, "environments.production"},
		{`SELECT COUNT(*) FROM zones WHERE name = 'global'`, "zones.global"},
		{`SELECT COUNT(*) FROM namespaces WHERE name = 'default'`, "namespaces.default"},
	} {
		var count int
		if err := db.QueryRow(tc.query).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", tc.label, err)
		}
		if count != 0 {
			t.Fatalf("%s still exists after 003's down-migration; down-migration is a no-op", tc.label)
		}
	}

	// Regression fix: every deleted row must survive in its backup table.
	for _, tc := range []struct{ table, where string }{
		{"roles_backup", "name = 'super_admin'"},
		{"permissions_backup", "name = 'secrets.read'"},
		{"role_permissions_backup", "role_id IN (SELECT id FROM roles_backup WHERE name = 'super_admin')"},
		{"environments_backup", "name = 'production'"},
		{"zones_backup", "name = 'global'"},
		{"namespaces_backup", "name = 'default'"},
	} {
		var count int
		query := `SELECT COUNT(*) FROM ` + tc.table + ` WHERE ` + tc.where
		if err := db.QueryRow(query).Scan(&count); err != nil {
			t.Fatalf("query %s: %v", tc.table, err)
		}
		if count == 0 {
			t.Fatalf("%s has no row matching %q; expected the deleted row to survive in the backup table", tc.table, tc.where)
		}
	}
}
