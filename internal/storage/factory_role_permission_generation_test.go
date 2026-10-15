// factory_role_permission_generation_test.go — the MIGRATION half of #3259:
// the real migration creates the role_permissions / permissions generation
// triggers on a fresh install and on an UPGRADE of a database that predates
// them, on both backends, and concurrent boots never leave a trigger-less
// window. The triggers' behaviour against the cache is tested next to it
// (internal/storage/store/role_permission_generation_trigger_test.go).
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

func rolePermGenerationValue(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var vals []string
	require.NoError(t, db.Raw("SELECT value FROM system_metadata WHERE key = 'role_permissions_generation'").Scan(&vals).Error)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// assertRolePermGenerationMoves: the triggers are present and a raw write to
// each table, naming no generation at all, moves the generation.
func assertRolePermGenerationMoves(t *testing.T, db *gorm.DB, label string) {
	t.Helper()
	require.True(t, store.RolePermissionsGenerationTriggersPresent(db), "%s: generation triggers missing", label)
	before := rolePermGenerationValue(t, db)
	name := fmt.Sprintf("rpg.%s.%d", label, os.Getpid())
	require.NoError(t, db.Exec("INSERT INTO permissions (name, resource, action) VALUES (?, 'rpg', ?)", name, name).Error)
	afterPerm := rolePermGenerationValue(t, db)
	require.NotEqual(t, before, afterPerm, "%s: a raw INSERT into permissions did not move the generation", label)
	role := models.Role{Name: name, NameFolded: name}
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Exec("INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = ?", role.ID, name).Error)
	require.NotEqual(t, afterPerm, rolePermGenerationValue(t, db), "%s: a raw INSERT into role_permissions did not move the generation", label)
}

func dropRolePermGenerationTriggers(t *testing.T, db *gorm.DB, postgres bool) {
	t.Helper()
	if postgres {
		require.NoError(t, db.Exec("DROP TRIGGER "+store.RolePermissionsGenerationTrigger+" ON role_permissions").Error)
		require.NoError(t, db.Exec("DROP TRIGGER "+store.PermissionsGenerationTrigger+" ON permissions").Error)
	} else {
		for _, base := range []string{store.RolePermissionsGenerationTrigger, store.PermissionsGenerationTrigger} {
			for _, op := range []string{"insert", "update", "delete"} {
				require.NoError(t, db.Exec("DROP TRIGGER "+base+"_"+op).Error)
			}
		}
	}
	require.False(t, store.RolePermissionsGenerationTriggersPresent(db), "the triggers must actually be gone, or the upgrade half proves nothing")
}

func TestRolePermissionGenerationTriggers_FreshInstallAndUpgrade_SQLite(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "rpg.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	assertRolePermGenerationMoves(t, db, "fresh")

	// A database that predates the triggers (with data), booted by this binary.
	dropRolePermGenerationTriggers(t, db, false)
	require.NoError(t, f.migrateDatabase(db))
	assertRolePermGenerationMoves(t, db, "upgrade")

	require.NoError(t, f.migrateDatabase(db))
	assertRolePermGenerationMoves(t, db, "third-boot")
}

func rpgPostgresDB(t *testing.T, label string) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — the Postgres trigger form is unverified in this run")
	}
	schema := fmt.Sprintf("rpg_%s_%d", label, os.Getpid())
	admin, err := gorm.Open(postgres.Open(dsn), gormConfig())
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), gormConfig())
	require.NoError(t, err)
	return db
}

func TestRolePermissionGenerationTriggers_FreshInstallAndUpgrade_Postgres(t *testing.T) {
	db := rpgPostgresDB(t, "mig")
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	assertRolePermGenerationMoves(t, db, "fresh")

	dropRolePermGenerationTriggers(t, db, true)
	require.NoError(t, f.migrateDatabase(db))
	assertRolePermGenerationMoves(t, db, "upgrade")

	require.NoError(t, f.migrateDatabase(db))
	assertRolePermGenerationMoves(t, db, "third-boot")
}

// TestRolePermissionGenerationTriggers_ConcurrentEnsureOnPostgres: replicas
// booting together must neither fail nor expose a moment with no trigger (a
// direct write in that moment would not move the generation).
func TestRolePermissionGenerationTriggers_ConcurrentEnsureOnPostgres(t *testing.T) {
	db := rpgPostgresDB(t, "conc")
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))

	const runners, observers = 6, 3
	var absent atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, runners)
	for range observers {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !store.RolePermissionsGenerationTriggersPresent(db) {
					absent.Add(1)
				}
			}
		})
	}
	var runnerWG sync.WaitGroup
	for range runners {
		runnerWG.Go(func() {
			if err := store.EnsureRolePermissionsGenerationTriggers(db); err != nil {
				errs <- err
			}
		})
	}
	runnerWG.Wait()
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Zero(t, absent.Load(), "an observer saw the generation triggers missing while the migration ran")
	assertRolePermGenerationMoves(t, db, "after-concurrent")
}
