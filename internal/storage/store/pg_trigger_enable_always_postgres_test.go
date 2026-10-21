// pg_trigger_enable_always_postgres_test.go — every PostgreSQL trigger a
// migration in this package installs ends up ENABLE ALWAYS, whatever state an
// earlier binary, a restore or an operator left it in (REVIEW-COVERAGE-2).
//
// Why ALWAYS: in a session with session_replication_role = replica (a server
// default Helm postgresql.settings can set, #3246; a logical-replication apply
// worker; an operator session) PostgreSQL fires only ENABLE ALWAYS and ENABLE
// REPLICA triggers. pg_restore --disable-triggers ends with ENABLE TRIGGER ALL,
// which leaves every trigger ordinary ('O'). An installer that returns early
// when its trigger exists therefore keeps a trigger that never fires for those
// writers, for good (#3361 was the cache-epoch instance; the #3359 and #3362
// triggers had the same early return).
//
// pgTriggerInstallers is the registry; TestPGTriggerInstallersAreRegistered
// (pg_trigger_registry_guard_test.go, default CI) fails when a production file
// creates a PostgreSQL trigger and is not listed here or in
// pgTriggerInstallersElsewhere.
package store

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type pgTriggerInstaller struct {
	file     string // repo-relative production file holding the CREATE TRIGGER
	ensure   func(*gorm.DB) error
	models   []any // tables the installer needs before it does anything
	triggers []struct{ table, name string }
}

var pgTriggerInstallers = []pgTriggerInstaller{
	{
		file:     "internal/storage/store/secret_node_cache_epoch.go",
		ensure:   EnsureSecretNodeCacheEpoch,
		models:   []any{&models.SecretNode{}},
		triggers: []struct{ table, name string }{{"secret_nodes", SecretNodeCacheEpochTrigger}},
	},
	{
		file:   "internal/storage/store/role_permission_generation_trigger.go",
		ensure: EnsureRolePermissionsGenerationTriggers,
		models: []any{&models.RolePermission{}, &models.Permission{}, &models.SystemMetadata{}},
		triggers: []struct{ table, name string }{
			{"role_permissions", RolePermissionsGenerationTrigger},
			{"permissions", PermissionsGenerationTrigger},
		},
	},
	{
		file:     "internal/storage/store/secret_suspend_marker_trigger.go",
		ensure:   EnsureSecretSuspendMarkerTrigger,
		models:   []any{&models.SecretNode{}},
		triggers: []struct{ table, name string }{{"secret_nodes", SecretSuspendMarkerTrigger}},
	},
	{
		file:     "internal/storage/store/audit_retention_anchor_trigger.go",
		ensure:   EnsureAuditRetentionAnchorTrigger,
		models:   []any{&models.SystemMetadata{}},
		triggers: []struct{ table, name string }{{"system_metadata", AuditRetentionAnchorTrigger}},
	},
}

// pgTriggerInstallersElsewhere are production files outside this package that
// create PostgreSQL triggers, with the test that pins their ENABLE ALWAYS
// convergence.
var pgTriggerInstallersElsewhere = map[string]string{
	"internal/solewriter/fence.go": "internal/solewriter/solewriter_postgres_test.go (disable / enable-not-always cases)",
}

func pgTgEnabled(t *testing.T, db *gorm.DB, table, name string) string {
	t.Helper()
	var s []string
	require.NoError(t, db.Raw("SELECT tgenabled::text FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = ?::regclass AND tgname = ?",
		table, name).Scan(&s).Error)
	require.Len(t, s, 1, "trigger %s on %s", name, table)
	return s[0]
}

// TestPGTriggerInstallers_ConvergeToEnableAlways_Postgres: a fresh install is
// ENABLE ALWAYS, and a second run turns an ordinary ('O', what pg_restore
// --disable-triggers leaves), replica-only ('R') or disabled ('D') trigger
// back into ENABLE ALWAYS.
func TestPGTriggerInstallers_ConvergeToEnableAlways_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	states := []struct{ name, alter string }{
		{"ordinary", "ENABLE TRIGGER"},
		{"replica-only", "ENABLE REPLICA TRIGGER"},
		{"disabled", "DISABLE TRIGGER"},
	}
	for _, inst := range pgTriggerInstallers {
		for _, st := range states {
			t.Run(inst.file+"/"+st.name, func(t *testing.T) {
				db := pgOpen(t, pgIsolatedSchemaDSN(t, base))
				require.NoError(t, db.AutoMigrate(inst.models...))
				require.NoError(t, inst.ensure(db))
				for _, tr := range inst.triggers {
					require.Equal(t, "A", pgTgEnabled(t, db, tr.table, tr.name), "fresh install of %s", tr.name)
					require.NoError(t, db.Exec("ALTER TABLE "+tr.table+" "+st.alter+" "+tr.name).Error)
				}
				require.NoError(t, inst.ensure(db))
				for _, tr := range inst.triggers {
					require.Equal(t, "A", pgTgEnabled(t, db, tr.table, tr.name),
						"%s left %s: the next migration must converge it to ENABLE ALWAYS", st.name, tr.name)
				}
			})
		}
	}
}

// TestSecretSuspendMarkerTrigger_NextBootRepairsTrigger_Postgres asserts the
// effect, not tgenabled: after the trigger was left disabled, or ordinary by a
// restore, and the next boot migrated, an N-1 style resume (status only) still
// clears the marker. The replica-role case needs a role allowed to set
// session_replication_role (superuser, or GRANT SET); it skips only on that
// permission error.
func TestSecretSuspendMarkerTrigger_NextBootRepairsTrigger_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	cases := []struct {
		name, alter  string
		replicaWrite bool
	}{
		{"disabled, ordinary writer", "DISABLE TRIGGER", false},
		{"restored ordinary, replica-role writer", "ENABLE TRIGGER", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := pgOpen(t, pgIsolatedSchemaDSN(t, base))
			require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
			require.NoError(t, EnsureSecretSuspendMarkerTrigger(db))
			require.NoError(t, db.Exec("ALTER TABLE secret_nodes "+tc.alter+" "+SecretSuspendMarkerTrigger).Error)
			require.NoError(t, EnsureSecretSuspendMarkerTrigger(db)) // the next boot

			require.NoError(t, db.Exec(`INSERT INTO secret_nodes (name, project_id, environment_id, status, suspend_clear_synced_copies)
VALUES ('rc2-marker', 1, 1, 'suspended', true)`).Error)
			err := db.Transaction(func(tx *gorm.DB) error {
				if tc.replicaWrite {
					if err := tx.Exec("SET LOCAL session_replication_role = replica").Error; err != nil {
						return err
					}
				}
				return tx.Exec("UPDATE secret_nodes SET status = 'active' WHERE name = 'rc2-marker'").Error
			})
			if tc.replicaWrite && err != nil && strings.Contains(err.Error(), "SQLSTATE 42501") {
				t.Skipf("this test role may not set session_replication_role (needs superuser or GRANT SET): %v", err)
			}
			require.NoError(t, err)
			var marker bool
			require.NoError(t, db.Raw("SELECT suspend_clear_synced_copies FROM secret_nodes WHERE name = 'rc2-marker'").Scan(&marker).Error)
			require.False(t, marker, "an old binary's resume left the marker set on an active secret (#3362 reopened)")
		})
	}
}
