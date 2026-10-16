// secret_node_cache_epoch_replication_role_postgres_test.go — #3361:
// session_replication_role must not let the secret-node read cache serve a
// row the database has since changed.
//
// In a session with session_replication_role = replica, PostgreSQL fires only
// ENABLE ALWAYS / ENABLE REPLICA triggers, and no foreign keys. The cache-epoch
// trigger was an ordinary trigger, and the trigger proof only checked
// tgenabled <> 'D', so:
//
//   - a write from such a session (the server default set by Helm
//     postgresql.settings, a per-role or per-database setting, or an
//     operator's own session) never moved cache_epoch, the proof still said
//     "present", and a warm entry kept serving the old row (a suspended
//     secret read as active);
//   - a trigger switched to ENABLE REPLICA (fires ONLY in replica sessions)
//     also passed the proof while never firing for normal writes.
//
// The fix: the trigger is converged to ENABLE ALWAYS at migration, and the
// proof trusts the stamp only when the trigger is ENABLE ALWAYS and this
// connection's session_replication_role is 'origin'. The server also refuses
// to start when its sessions are not in 'origin' (internal/storage factory).
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// cacheEpochReplicaWorld is a Postgres schema with secret_nodes migrated by the
// production EnsureSecretNodeCacheEpoch, a store on it, and one secret read
// once so its node-cache entry is warm.
func cacheEpochReplicaWorld(t *testing.T) (*gorm.DB, *LocalStorage, *models.SecretNode) {
	t.Helper()
	db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	ls := NewLocalStorage(db)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "replica-role-warm", ProjectID: 1, EnvironmentID: 1, Status: "active",
	})
	require.NoError(t, err)
	warm, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "active", warm.Status)
	return db, ls, created
}

// TestSecretNodeCacheEpoch_ReplicaRoleWriter_StillMovesStamp_Postgres is the
// REVIEW-1 reproduction: another session in replica role suspends the secret
// with a direct UPDATE. The warm entry must not be served.
func TestSecretNodeCacheEpoch_ReplicaRoleWriter_StillMovesStamp_Postgres(t *testing.T) {
	db, ls, created := cacheEpochReplicaWorld(t)
	ctx := context.Background()

	sqlDB, err := db.DB()
	require.NoError(t, err)
	conn, err := sqlDB.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.ExecContext(ctx, "SET session_replication_role = replica")
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "UPDATE secret_nodes SET status = 'suspended' WHERE id = $1", created.ID)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "RESET session_replication_role")
	require.NoError(t, err)

	got, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status,
		"a write from a session_replication_role=replica session did not move cache_epoch, and the warm entry served the pre-suspend row (#3361)")
}

// TestSecretNodeCacheEpoch_ProofFailsClosedInReplicaSession_Postgres: when the
// connection reading the stamp is itself in replica role (Helm's server
// default, ALTER ROLE/DATABASE ... SET), the proof must report the stamp as
// untrusted, so the cache neither hits nor stores.
func TestSecretNodeCacheEpoch_ProofFailsClosedInReplicaSession_Postgres(t *testing.T) {
	db, _, created := cacheEpochReplicaWorld(t)
	ctx := context.Background()

	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // every statement below runs on the one session set to replica
	require.NoError(t, db.Exec("SET session_replication_role = replica").Error)
	t.Cleanup(func() { _ = db.Exec("RESET session_replication_role").Error })

	require.False(t, SecretNodeCacheEpochTriggerPresent(db),
		"the proof reported the trigger as present on a session in replica role, where foreign keys and ordinary triggers do not fire (#3361)")
	stamp, err := readLiveNodeStamp(ctx, db, created.ID)
	require.NoError(t, err)
	require.True(t, stamp.found)
	require.False(t, stamp.trusted,
		"readLiveNodeStamp trusted the stamp on a session in replica role (#3361)")
}

// TestSecretNodeCacheEpoch_ReplicaOnlyTriggerIsNotTrusted_Postgres: ENABLE
// REPLICA makes the trigger fire ONLY in replica sessions, so it never fires
// for the server's own writes. tgenabled is 'R', not 'D', and the old proof
// accepted it.
func TestSecretNodeCacheEpoch_ReplicaOnlyTriggerIsNotTrusted_Postgres(t *testing.T) {
	db, ls, created := cacheEpochReplicaWorld(t)
	ctx := context.Background()

	require.NoError(t, db.Exec("ALTER TABLE secret_nodes ENABLE REPLICA TRIGGER "+SecretNodeCacheEpochTrigger).Error)
	require.False(t, SecretNodeCacheEpochTriggerPresent(db),
		"an ENABLE REPLICA trigger never fires for an origin session's write, but the proof reported it present (#3361)")

	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", created.ID).UpdateColumn("status", "suspended").Error)
	got, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status, "a warm entry was served while the trigger was ENABLE REPLICA (#3361)")
}

// TestSecretNodeCacheEpoch_MigrationConvergesToEnableAlways_Postgres: the
// migration installs the trigger ENABLE ALWAYS, and turns an existing
// ordinary (ENABLE) trigger, which an older binary created and pg_restore
// --disable-triggers leaves behind, back into ENABLE ALWAYS.
func TestSecretNodeCacheEpoch_MigrationConvergesToEnableAlways_Postgres(t *testing.T) {
	db, _, _ := cacheEpochReplicaWorld(t)
	tgenabled := func() string {
		var s []string
		require.NoError(t, db.Raw("SELECT tgenabled::text FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = 'secret_nodes'::regclass AND tgname = ?",
			SecretNodeCacheEpochTrigger).Scan(&s).Error)
		require.Len(t, s, 1)
		return s[0]
	}
	require.Equal(t, "A", tgenabled(), "a fresh migration must install the cache-epoch trigger ENABLE ALWAYS")

	require.NoError(t, db.Exec("ALTER TABLE secret_nodes ENABLE TRIGGER "+SecretNodeCacheEpochTrigger).Error)
	require.Equal(t, "O", tgenabled())
	require.False(t, SecretNodeCacheEpochTriggerPresent(db), "an ordinary trigger does not fire for a replica-role writer, so it is not trusted")
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	require.Equal(t, "A", tgenabled(), "the migration must converge an ordinary trigger to ENABLE ALWAYS")
	require.True(t, SecretNodeCacheEpochTriggerPresent(db))
}
