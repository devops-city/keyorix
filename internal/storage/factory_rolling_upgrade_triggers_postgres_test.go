package storage

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
)

// #3362: a writer that knows nothing about secret_nodes.suspend_clear_synced_copies
// (a pre-#3215 replica in a rolling upgrade) writes only status and updated_at.
// Its resume must still clear the marker, so its next plain suspend does not
// carry a stale "clear the synced Kubernetes copies". The statements below are
// that binary's TransitionSecretStatus shape. Also: the upgrade path (trigger
// missing, a stale row present) converges at the next CreateStorage.
func TestSecretSuspendMarker_ClearedByOldBinaryResume_Postgres(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	dsn := pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	db := pgRawOpen(t, dsn)
	require.NoError(t, db.Exec(`INSERT INTO secret_nodes (project_id, environment_id, name, is_secret, status, suspend_clear_synced_copies, created_at, updated_at)
VALUES (1, 1, 'marker-probe', true, 'suspended', true, now(), now())`).Error)
	marker := func() bool {
		var m bool
		require.NoError(t, db.Raw("SELECT suspend_clear_synced_copies FROM secret_nodes WHERE name = 'marker-probe'").Scan(&m).Error)
		return m
	}
	require.True(t, marker(), "a suspend with clear-copies keeps the marker")

	// Old binary's resume, then its plain suspend.
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'active', updated_at = now() WHERE name = 'marker-probe'").Error)
	require.False(t, marker(), "resume by a writer that does not know the marker left it set")
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'suspended', updated_at = now() WHERE name = 'marker-probe'").Error)
	require.False(t, marker(), "a plain suspend after an old-binary resume carries a stale clear-copies marker")

	// This binary's suspend with clear-copies still sets it.
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'active' WHERE name = 'marker-probe'").Error)
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'suspended', suspend_clear_synced_copies = true WHERE name = 'marker-probe'").Error)
	require.True(t, marker())

	// Upgrade path: no trigger, a row an old binary left stale.
	require.NoError(t, db.Exec("DROP TRIGGER "+store.SecretSuspendMarkerTrigger+" ON secret_nodes").Error)
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'active' WHERE name = 'marker-probe'").Error)
	require.True(t, marker(), "fixture: without the trigger the marker survives the resume")
	_, err = NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	require.False(t, marker(), "the next start must clear a marker left on an active secret")
	var n int64
	require.NoError(t, db.Raw("SELECT count(*) FROM pg_trigger WHERE tgname = ? AND tgenabled = 'A'", store.SecretSuspendMarkerTrigger).Scan(&n).Error)
	require.EqualValues(t, 1, n, "trigger reinstalled, ENABLE ALWAYS")
}

// #3359: a pre-#3258 binary's purge upserts a v1 retention anchor in the same
// transaction as its delete (SetSystemMetadata's ON CONFLICT DO UPDATE). Over a
// v2 anchor that write must fail, so the purge rolls back; every other
// transition (v1->v1, v1->v2, v2->v2, any other key) still works.
func TestAuditRetentionAnchor_OlderLayoutCannotReplaceV2_Postgres(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	dsn := pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	db := pgRawOpen(t, dsn)
	upsert := func(key, value string) error {
		return db.Exec(`INSERT INTO system_metadata (key, value, updated_at) VALUES (?, ?, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`, key, value).Error
	}
	const k = "audit_retention_anchor"
	v1 := "v1\x1f10\x1fp\x1fe\x1fack\x1fsig"
	v2 := "v2\x1f20\x1fp\x1fe\x1f5\x1fack\x1fsig"
	require.NoError(t, upsert(k, v1))
	require.NoError(t, upsert(k, v1), "v1 -> v1")
	require.NoError(t, upsert(k, v2), "v1 -> v2 (the upgrade)")
	require.NoError(t, upsert(k, v2), "v2 -> v2")
	require.ErrorContains(t, upsert(k, v1), "refusing to replace the v2 audit retention anchor", "v2 -> v1")

	// The whole purge transaction rolls back: a delete before the anchor write is undone.
	require.NoError(t, upsert("rollback_probe", "x"))
	tx := db.Begin()
	require.NoError(t, tx.Exec("DELETE FROM system_metadata WHERE key = 'rollback_probe'").Error)
	require.Error(t, tx.Exec(`INSERT INTO system_metadata (key, value, updated_at) VALUES (?, ?, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, k, v1).Error)
	tx.Rollback()
	var n int64
	require.NoError(t, db.Raw("SELECT count(*) FROM system_metadata WHERE key = 'rollback_probe'").Scan(&n).Error)
	require.EqualValues(t, 1, n)

	var stored string
	require.NoError(t, db.Raw("SELECT value FROM system_metadata WHERE key = ?", k).Scan(&stored).Error)
	require.Equal(t, v2, stored)
	require.NoError(t, upsert("other_key", "v2\x1fx"))
	require.NoError(t, upsert("other_key", "v1"), "other keys are not guarded")
	require.NoError(t, db.Raw("SELECT count(*) FROM pg_trigger WHERE tgname = ? AND tgenabled = 'A'", store.AuditRetentionAnchorTrigger).Scan(&n).Error)
	require.EqualValues(t, 1, n, "trigger installed, ENABLE ALWAYS")
}
