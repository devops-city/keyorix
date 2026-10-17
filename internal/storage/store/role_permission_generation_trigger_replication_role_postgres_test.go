// role_permission_generation_trigger_replication_role_postgres_test.go —
// REVIEW-FIXES-1 follow-up of #3361 for the role->permission generation.
//
// The generation proof (rolePermGenerationTriggersPresentExpr) accepted any
// trigger with tgenabled <> 'D' and did not read the session's
// session_replication_role, so:
//
//   - a trigger in ENABLE REPLICA ('R') never fires for an ordinary write and
//     still passed the proof: a direct permission removal kept authorizing
//     from a warm cache;
//   - an ordinary trigger ('O', ENABLE TRIGGER, which pg_restore
//     --disable-triggers leaves behind) is skipped by a writer in replica role
//     (an operator's session, a per-role default) and still passed;
//   - a reading connection in replica role trusted the generation.
//
// The fix: the proof uses the same condition as the secret_nodes cache-epoch
// proof (pgTriggerFiresForEveryWriter): ENABLE ALWAYS, and this connection in
// 'origin'. The migration already converges every other state back to ENABLE
// ALWAYS (ensurePostgresRolePermGenerationTriggers).
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// rpgPostgresWorld is newRPGWorld on Postgres, skipped without a DSN.
func rpgPostgresWorld(t *testing.T) rpgWorld {
	t.Helper()
	pgTestDSN(t)
	return newRPGWorld(t, "postgres")
}

// rpgTgenabled reads the tgenabled state of the role_permissions trigger.
func rpgTgenabled(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var s []string
	require.NoError(t, db.Raw("SELECT tgenabled::text FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = 'role_permissions'::regclass AND tgname = ?",
		RolePermissionsGenerationTrigger).Scan(&s).Error)
	require.Len(t, s, 1)
	return s[0]
}

// TestRolePermissionGeneration_ReplicaOnlyTriggerIsNotTrusted_Postgres: an
// ENABLE REPLICA trigger fires ONLY in replica sessions, so an ordinary
// direct DELETE leaves the generation where it was. The proof must refuse it,
// and the next decision must come from the live join. Red on the base: the
// proof accepted 'R' and the warm cache kept authorizing.
func TestRolePermissionGeneration_ReplicaOnlyTriggerIsNotTrusted_Postgres(t *testing.T) {
	w := rpgPostgresWorld(t)
	db := w.writer.db
	require.Equal(t, "A", rpgTgenabled(t, db), "the migration installs the trigger ENABLE ALWAYS")
	require.True(t, RolePermissionsGenerationTriggersPresent(db), "ENABLE ALWAYS in an origin session passes the proof")
	require.True(t, w.decide(t, w.perm.Name), "warm")

	require.NoError(t, db.Exec("ALTER TABLE role_permissions ENABLE REPLICA TRIGGER "+RolePermissionsGenerationTrigger).Error)
	require.Equal(t, "R", rpgTgenabled(t, db))
	require.False(t, RolePermissionsGenerationTriggersPresent(db),
		"an ENABLE REPLICA trigger never fires for an origin session's write, but the proof reported it present")
	_, trusted, err := liveRolePermissionsGeneration(context.Background(), w.ls)
	require.NoError(t, err)
	require.False(t, trusted, "the generation must read as untrusted while the trigger is ENABLE REPLICA")

	require.NoError(t, db.Exec("DELETE FROM role_permissions WHERE role_id = ?", w.role.ID).Error)
	require.False(t, w.decide(t, w.perm.Name), "a warm cache answered while the generation trigger was ENABLE REPLICA")

	// Repair: the next boot's migration re-issues ENABLE ALWAYS.
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
	require.Equal(t, "A", rpgTgenabled(t, db), "the migration must converge an ENABLE REPLICA trigger to ENABLE ALWAYS")
	require.True(t, RolePermissionsGenerationTriggersPresent(db))
}

// TestRolePermissionGeneration_OrdinaryTriggerSkippedByReplicaWriter_Postgres:
// an ordinary trigger ('O') does not fire for a writer in replica role. A
// permission removed from such a session must not keep authorizing from the
// cache. Red on the base.
func TestRolePermissionGeneration_OrdinaryTriggerSkippedByReplicaWriter_Postgres(t *testing.T) {
	w := rpgPostgresWorld(t)
	db := w.writer.db
	require.True(t, w.decide(t, w.perm.Name), "warm")
	require.True(t, w.decide(t, w.perm.Name), "warm, from the cache")

	require.NoError(t, db.Exec("ALTER TABLE role_permissions ENABLE TRIGGER "+RolePermissionsGenerationTrigger).Error)
	require.Equal(t, "O", rpgTgenabled(t, db))
	require.False(t, RolePermissionsGenerationTriggersPresent(db),
		"an ordinary trigger does not fire for a replica-role writer, so it must not pass the proof")

	ctx := context.Background()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	conn, err := sqlDB.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.ExecContext(ctx, "SET session_replication_role = replica")
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "DELETE FROM role_permissions WHERE role_id = $1", w.role.ID)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "RESET session_replication_role")
	require.NoError(t, err)

	require.False(t, w.decide(t, w.perm.Name),
		"a permission removed by a replica-role session kept authorizing from the cache: the ordinary trigger did not fire")

	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
	require.Equal(t, "A", rpgTgenabled(t, db), "the migration must converge an ordinary trigger to ENABLE ALWAYS")
	require.True(t, RolePermissionsGenerationTriggersPresent(db))
}

// TestRolePermissionGeneration_ProofFailsClosedInReplicaSession_Postgres: a
// reading connection in replica role (ALTER ROLE/DATABASE ... SET, a DSN
// option) must not trust the generation even with ENABLE ALWAYS triggers.
func TestRolePermissionGeneration_ProofFailsClosedInReplicaSession_Postgres(t *testing.T) {
	w := rpgPostgresWorld(t)
	db := w.writer.db
	require.True(t, RolePermissionsGenerationTriggersPresent(db))

	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // every statement below runs on the one session set to replica
	require.NoError(t, db.Exec("SET session_replication_role = replica").Error)
	t.Cleanup(func() { _ = db.Exec("RESET session_replication_role").Error })

	require.Equal(t, "A", rpgTgenabled(t, db))
	require.False(t, RolePermissionsGenerationTriggersPresent(db),
		"the proof reported the triggers present on a session in replica role")
	_, trusted, err := liveRolePermissionsGeneration(context.Background(), w.writer)
	require.NoError(t, err)
	require.False(t, trusted, "the generation was trusted on a session in replica role")
}
