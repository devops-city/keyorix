// role_permission_generation_trigger.go — the database triggers that keep
// system_metadata.role_permissions_generation moving on EVERY write to
// role_permissions and permissions, whoever makes it (#3259).
//
// The role->permission cache (role_permission_cache.go) is validated by that
// generation. Until this file the only thing that bumped it was
// bumpRolePermissionsGenerationTx, i.e. this binary's own write paths. A change
// made directly in the database (an operator's SQL, a script, a data restore
// into a live database) left the generation where it was, so every running
// replica kept answering from its cache: a permission removed from a role that
// way kept authorizing until a restart. The same hole secret_nodes.cache_epoch
// closed with a trigger (secret_node_cache_epoch.go), closed the same way here.
//
// Two halves, both needed:
//
//   - The triggers (this file's installer, called from the migration on every
//     boot) bump the generation inside the writer's own transaction, so the new
//     value becomes visible atomically with the change.
//   - Every statement that READS the generation proves, in the same statement,
//     that the triggers exist and fire for every writer (rolePermGenerationExpr). A
//     database without them (a restore that skipped triggers, a bare AutoMigrate
//     fixture, an operator's DROP/DISABLE) reads the generation as NULL, which
//     every caller treats as "cannot validate": the cache is neither consulted
//     nor filled, and the live join answers. Fail closed, no window.
//
// bumpRolePermissionsGenerationTx stays: with the triggers present it is a
// second, harmless increment (the value only has to change, never by how much);
// it is what keeps an in-app write moving the generation on a database where
// the triggers were removed, even though the cache is bypassed there anyway.
//
// A session running with session_replication_role = replica skips ordinary
// triggers. The PostgreSQL triggers are installed ENABLE ALWAYS so they fire in
// such a session too, and the read-side proof accepts only that state on a
// connection in 'origin' (pgTriggerFiresForEveryWriter, shared with the
// cache-epoch proof). A later ALTER TABLE ... ENABLE TRIGGER (which pg_restore
// --disable-triggers issues on its way out) or ENABLE REPLICA TRIGGER makes the
// proof fail closed until the next migration re-issues ENABLE ALWAYS.
package store

import (
	"fmt"
	"strings"
	"sync"

	"gorm.io/gorm"
)

// Trigger and function names, exported so tests can drop or disable them to
// prove the read-side proof goes red.
const (
	RolePermissionsGenerationTrigger = "trg_role_permissions_generation"
	PermissionsGenerationTrigger     = "trg_permissions_generation"
	rolePermGenerationFunc           = "keyorix_bump_role_permissions_generation"
)

// postgresRolePermGenerationLockKey serialises concurrent installers (CREATE OR
// REPLACE FUNCTION races on the pg_proc tuple, see
// ensurePostgresCacheEpochTrigger). "KEYARPGN", the KEYA-tag convention from
// postgresCacheEpochLockKey.
const postgresRolePermGenerationLockKey = 0x4B455941_5250474E // "KEYARPGN"

// rolePermGenerationTables are the tables whose writes change what
// RoleSetHasPermission answers: the role->permission edges, and the permission
// rows they point at (a rename or delete of a permission changes the join's
// answer just as much).
var rolePermGenerationTables = []struct{ table, trigger string }{
	{"role_permissions", RolePermissionsGenerationTrigger},
	{"permissions", PermissionsGenerationTrigger},
}

// sqliteRolePermGenerationBody is the body of every SQLite trigger: seed the
// row if it is missing (it is created lazily, by the first bump), then
// increment. The same two steps, in the same order, as
// bumpRolePermissionsGenerationTx.
const sqliteRolePermGenerationBody = `
BEGIN
  INSERT OR IGNORE INTO system_metadata (key, value, updated_at) VALUES ('` + rolePermissionsGenerationKey + `', '0', datetime('now'));
  UPDATE system_metadata SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = '` + rolePermissionsGenerationKey + `';
END`

// sqliteRolePermGenerationOps are the per-row events a SQLite trigger is created
// for. SQLite has no statement-level triggers and no TRUNCATE.
var sqliteRolePermGenerationOps = []string{"INSERT", "UPDATE", "DELETE"}

// sqliteRolePermGenerationTriggerName is the per-event trigger name on SQLite.
func sqliteRolePermGenerationTriggerName(base, op string) string {
	return base + "_" + strings.ToLower(op)
}

// sqliteRolePermGenerationTriggerSQL is the exact CREATE text sqlite_master
// records, compared byte-for-byte for convergence.
func sqliteRolePermGenerationTriggerSQL(table, base, op string) string {
	return "CREATE TRIGGER " + sqliteRolePermGenerationTriggerName(base, op) +
		"\nAFTER " + op + " ON " + table + " FOR EACH ROW" + sqliteRolePermGenerationBody
}

// EnsureRolePermissionsGenerationTriggers installs the triggers on both
// backends. Idempotent, one transaction, and it never drops a trigger that is
// already correct (the lifecycle rule in secret_node_cache_epoch.go: a
// drop-then-create on boot leaves a trigger-less window other replicas serve
// through). A no-op until all three tables exist.
func EnsureRolePermissionsGenerationTriggers(db *gorm.DB) error {
	for _, tbl := range []string{"role_permissions", "permissions", "system_metadata"} {
		if !storeTableExists(db, tbl) {
			return nil
		}
	}
	isPostgres := db.Dialector.Name() == "postgres"
	return db.Transaction(func(tx *gorm.DB) error {
		if isPostgres {
			return ensurePostgresRolePermGenerationTriggers(tx)
		}
		return ensureSQLiteRolePermGenerationTriggers(tx)
	})
}

func ensurePostgresRolePermGenerationTriggers(tx *gorm.DB) error {
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(postgresRolePermGenerationLockKey)).Error; err != nil {
		return fmt.Errorf("acquire role-permission generation trigger advisory lock: %w", err)
	}
	// The table is qualified with the schema of the table that fired
	// (TG_TABLE_SCHEMA), not resolved through the writer's search_path: an
	// operator's session with a different search_path must still bump THIS
	// schema's generation, never another schema's or fail on a missing table.
	if err := tx.Exec(`CREATE OR REPLACE FUNCTION ` + rolePermGenerationFunc + `() RETURNS trigger
LANGUAGE plpgsql AS $keyorix$
BEGIN
  EXECUTE format('INSERT INTO %I.system_metadata (key, value, updated_at) VALUES ($1, ''0'', now()) ON CONFLICT (key) DO NOTHING', TG_TABLE_SCHEMA)
    USING '` + rolePermissionsGenerationKey + `';
  EXECUTE format('UPDATE %I.system_metadata SET value = CAST(CAST(value AS BIGINT) + 1 AS TEXT) WHERE key = $1', TG_TABLE_SCHEMA)
    USING '` + rolePermissionsGenerationKey + `';
  RETURN NULL;
END;
$keyorix$`).Error; err != nil {
		return fmt.Errorf("failed to create %s(): %w", rolePermGenerationFunc, err)
	}
	for _, t := range rolePermGenerationTables {
		var state []string
		if err := tx.Raw("SELECT tgenabled::text FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = ?::regclass AND tgname = ?",
			t.table, t.trigger).Scan(&state).Error; err != nil {
			return fmt.Errorf("failed to read %s state: %w", t.trigger, err)
		}
		if len(state) == 0 {
			// Statement-level: one bump per statement, TRUNCATE included.
			if err := tx.Exec("CREATE TRIGGER " + t.trigger + " AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON " + t.table +
				" FOR EACH STATEMENT EXECUTE PROCEDURE " + rolePermGenerationFunc + "()").Error; err != nil {
				return fmt.Errorf("failed to create %s: %w", t.trigger, err)
			}
		}
		if len(state) == 0 || state[0] != "A" {
			if err := tx.Exec("ALTER TABLE " + t.table + " ENABLE ALWAYS TRIGGER " + t.trigger).Error; err != nil {
				return fmt.Errorf("failed to enable %s: %w", t.trigger, err)
			}
		}
	}
	return nil
}

func ensureSQLiteRolePermGenerationTriggers(tx *gorm.DB) error {
	for _, t := range rolePermGenerationTables {
		for _, op := range sqliteRolePermGenerationOps {
			name := sqliteRolePermGenerationTriggerName(t.trigger, op)
			want := sqliteRolePermGenerationTriggerSQL(t.table, t.trigger, op)
			var rows []string
			if err := tx.Raw("SELECT COALESCE(sql, '') FROM sqlite_master WHERE type = 'trigger' AND name = ?", name).
				Scan(&rows).Error; err != nil {
				return fmt.Errorf("failed to read %s definition: %w", name, err)
			}
			if len(rows) > 0 && rows[0] == want {
				continue
			}
			if len(rows) > 0 {
				if err := tx.Exec("DROP TRIGGER " + name).Error; err != nil {
					return fmt.Errorf("failed to drop outdated %s: %w", name, err)
				}
			}
			if err := tx.Exec(want).Error; err != nil {
				return fmt.Errorf("failed to create %s: %w", name, err)
			}
		}
	}
	return nil
}

// rolePermGenerationExpr is the SELECT-list expression every statement uses to
// read the generation from the joined system_metadata row aliased genAlias:
// the value ("" when the row does not exist yet) when the triggers are present
// and fire for every writer on THIS connection's tables, NULL otherwise. NULL means "cannot
// validate" to every caller. No binds: the names are this file's constants.
func rolePermGenerationExpr(db *gorm.DB, genAlias string) string {
	key := db.Dialector.Name() + "\x00" + genAlias
	if q, ok := rolePermGenerationExprs.Load(key); ok {
		return q.(string)
	}
	q := "CASE WHEN " + rolePermGenerationTriggersPresentExpr(db) + " THEN COALESCE(" + genAlias + ".value, '') END"
	rolePermGenerationExprs.Store(key, q)
	return q
}

// rolePermGenerationExprs holds each dialect's expression once built: it is on
// every machine read's statement, so the per-request cost is a map lookup.
var rolePermGenerationExprs sync.Map // dialect + alias -> string

// rolePermGenerationTriggersPresentExpr is true when every trigger is present
// and, on PostgreSQL, fires for every writer: ENABLE ALWAYS, read on a
// connection in 'origin' (pgTriggerFiresForEveryWriter, the cache-epoch
// proof's condition). 'D', 'R' (fires only in replica sessions) and 'O'
// (skipped by a replica-role writer) all read as untrusted until the next
// migration converges them back to 'A'. tgrelid pins each one to the table
// this connection resolves (the reasons are in
// SecretNodeCacheEpochTriggerPresent).
func rolePermGenerationTriggersPresentExpr(db *gorm.DB) string {
	if db.Dialector.Name() == "postgres" {
		var conds []string
		for _, t := range rolePermGenerationTables {
			conds = append(conds, "(tgrelid = '"+t.table+"'::regclass AND tgname = '"+t.trigger+"')")
		}
		return fmt.Sprintf("(SELECT COUNT(*) FROM pg_trigger WHERE NOT tgisinternal AND %s AND (%s)) = %d",
			pgTriggerFiresForEveryWriter, strings.Join(conds, " OR "), len(rolePermGenerationTables))
	}
	var conds []string
	for _, t := range rolePermGenerationTables {
		for _, op := range sqliteRolePermGenerationOps {
			conds = append(conds, "(name = '"+sqliteRolePermGenerationTriggerName(t.trigger, op)+"' AND tbl_name = '"+t.table+"')")
		}
	}
	return fmt.Sprintf("(SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND (%s)) = %d",
		strings.Join(conds, " OR "), len(rolePermGenerationTables)*len(sqliteRolePermGenerationOps))
}

// RolePermissionsGenerationTriggersPresent reports whether every generation
// trigger exists (and, on PostgreSQL, fires for every writer) on this connection's
// tables: the same proof the read statements carry. Any error reads as false.
func RolePermissionsGenerationTriggersPresent(db *gorm.DB) bool {
	if db == nil {
		return false
	}
	var present int
	if err := db.Raw("SELECT CASE WHEN " + rolePermGenerationTriggersPresentExpr(db) + " THEN 1 ELSE 0 END").Scan(&present).Error; err != nil {
		return false
	}
	return present == 1
}

// storeTableExists is a raw catalog lookup (the Migrator path panics on an
// unusable handle; see secretNodesTableExists).
func storeTableExists(db *gorm.DB, table string) bool {
	var count int64
	q := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?"
	if db.Dialector.Name() == "postgres" {
		q = "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ? AND table_schema = CURRENT_SCHEMA()"
	}
	if err := db.Raw(q, table).Scan(&count).Error; err != nil {
		return false
	}
	return count > 0
}
