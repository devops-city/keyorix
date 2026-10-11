// factory_secret_node_cache_epoch_test.go — the MIGRATION half of
// secret_nodes.cache_epoch (store.EnsureSecretNodeCacheEpoch). The trigger's
// behaviour per column is tested next to the cache it serves
// (internal/storage/store/secret_metadata_cache_fieldledger_test.go); what is
// tested here is that the real migration path actually creates the column and
// the trigger — on a fresh install, on an UPGRADE of a database that already
// holds data, and on both backends.
//
// Both halves are needed and neither covers the other: a trigger that works
// perfectly but is never created by a migration is a cache with a stamp that
// never moves, and a migration that creates it only on a fresh install leaves
// every existing deployment silently uncovered — which is exactly the gap
// #STORAGE-FACTORY-MT006-FIRSTBOOT documents for the sibling
// ensureSecretNodeNameIndex call.
package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// cacheEpochOf reads the stamp directly, the same single-column PK lookup the
// read path does.
func cacheEpochOf(t *testing.T, db *gorm.DB, id uint) int64 {
	t.Helper()
	var row struct{ CacheEpoch int64 }
	require.NoError(t, db.Model(&models.SecretNode{}).
		Select("cache_epoch").Where("id = ?", id).Take(&row).Error)
	return row.CacheEpoch
}

// assertCacheEpochConverged is the shared body: the column and the trigger both
// exist and the trigger bumps on an UpdateColumn write (the idiom that bypasses
// GORM's auto-timestamp callback, i.e. the one a Go-side bump would miss).
func assertCacheEpochConverged(t *testing.T, db *gorm.DB, label string) uint {
	t.Helper()
	require.True(t, db.Migrator().HasColumn("secret_nodes", store.SecretNodeCacheEpochColumn),
		"%s: secret_nodes.cache_epoch missing — the node read-path cache's stamp would not exist", label)

	secret := models.SecretNode{Name: "epoch-" + label, ProjectID: 1, EnvironmentID: 1, Status: "active"}
	require.NoError(t, db.Create(&secret).Error)

	before := cacheEpochOf(t, db, secret.ID)
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", secret.ID).
		UpdateColumn("description", "bumped").Error)
	require.Greater(t, cacheEpochOf(t, db, secret.ID), before,
		"%s: the cache_epoch trigger did not fire on an UpdateColumn write — the stamp would not move and a warm cache entry would keep serving the pre-change row", label)
	return secret.ID
}

// TestSecretNodeCacheEpoch_FreshInstallAndUpgrade_SQLite covers both paths on
// the dev/test backend. The upgrade half is the one that matters most: it
// stands in for every deployment that already exists, and it is done on a
// database that already HOLDS DATA, because a migration that only works on an
// empty table is not a migration.
func TestSecretNodeCacheEpoch_FreshInstallAndUpgrade_SQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache-epoch.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)
	f := &DefaultStorageFactory{}

	// Fresh install: projects does not exist yet, so the full AutoMigrate block
	// runs. cache_epoch is NOT a model field, so only the explicit ensure call
	// can have created it — if that call were in the wrong place, this fails.
	require.NoError(t, f.migrateDatabase(db))
	assertCacheEpochConverged(t, db, "fresh")

	// Now stand in for a pre-upgrade database: real rows, then drop the trigger
	// and the column the way a deployment that predates this change would have
	// them — absent.
	var seeded []uint
	for i := 0; i < 3; i++ {
		s := models.SecretNode{Name: fmt.Sprintf("legacy-%d", i), ProjectID: 1, EnvironmentID: 1, Status: "active"}
		require.NoError(t, db.Create(&s).Error)
		seeded = append(seeded, s.ID)
	}
	require.NoError(t, db.Exec("DROP TRIGGER IF EXISTS "+store.SecretNodeCacheEpochTrigger).Error)
	require.NoError(t, db.Exec("ALTER TABLE secret_nodes DROP COLUMN cache_epoch").Error)
	require.False(t, db.Migrator().HasColumn("secret_nodes", store.SecretNodeCacheEpochColumn),
		"the column must actually be gone, or the upgrade half of this test proves nothing")

	// Second run: exactly what a real process boot does against an existing
	// database (projects present).
	require.NoError(t, f.migrateDatabase(db))
	assertCacheEpochConverged(t, db, "upgrade")

	// The rows that already existed must have a usable stamp immediately — the
	// column is NOT NULL DEFAULT 0, so no backfill pass is needed and no row is
	// left NULL (which would make the stamp read fail, not merely miss).
	for _, id := range seeded {
		require.Equal(t, int64(0), cacheEpochOf(t, db, id),
			"pre-existing row %d should read as epoch 0 after the upgrade, not NULL or an error", id)
		before := cacheEpochOf(t, db, id)
		require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", id).
			UpdateColumn("classification", "internal").Error)
		require.Greater(t, cacheEpochOf(t, db, id), before,
			"a row that predates the migration must still get its epoch bumped once the trigger exists")
	}

	// Idempotence: a third boot must not fail, and must leave a working trigger
	// (DROP+CREATE every time is deliberate — see EnsureSecretNodeCacheEpoch).
	require.NoError(t, f.migrateDatabase(db))
	assertCacheEpochConverged(t, db, "third boot")
}

// TestSecretNodeCacheEpoch_FreshInstallAndUpgrade_Postgres is the same on the
// production backend, where the trigger has a COMPLETELY DIFFERENT form (a
// BEFORE trigger plus a plpgsql function, because SQLite cannot assign to NEW
// and Postgres cannot run SQLite's nested-UPDATE form). Two implementations
// means two things to verify; the SQLite result says nothing about this one.
//
// pg-gated: skipped without KEYORIX_TEST_PG_DSN, and the one CI job that sets
// it (.github/workflows/ci.yml test-suite, core leg) is what actually proves it.
func TestSecretNodeCacheEpoch_FreshInstallAndUpgrade_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — the Postgres trigger form is unverified in this run")
	}
	schema := fmt.Sprintf("cache_epoch_%d", os.Getpid())
	admin, err := gorm.Open(postgres.Open(dsn), gormConfig())
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })

	// PGSearchPathDSN, not string concatenation: KEYORIX_TEST_PG_DSN is
	// accepted in BOTH keyword ("host=... dbname=...") and URL
	// ("postgres://...?sslmode=disable") form, and appending " search_path=x"
	// to the URL form produces a DSN pgx refuses to parse (#1973). CI happens
	// to set the keyword form, so concatenation passed there and failed the
	// moment it met a URL-form DSN locally.
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), gormConfig())
	require.NoError(t, err)
	f := &DefaultStorageFactory{}

	require.NoError(t, f.migrateDatabase(db))
	assertCacheEpochConverged(t, db, "postgres fresh")

	var seeded []uint
	for i := 0; i < 3; i++ {
		s := models.SecretNode{Name: fmt.Sprintf("pg-legacy-%d", i), ProjectID: 1, EnvironmentID: 1, Status: "active"}
		require.NoError(t, db.Create(&s).Error)
		seeded = append(seeded, s.ID)
	}
	require.NoError(t, db.Exec("DROP TRIGGER IF EXISTS "+store.SecretNodeCacheEpochTrigger+" ON secret_nodes").Error)
	require.NoError(t, db.Exec("ALTER TABLE secret_nodes DROP COLUMN cache_epoch").Error)
	require.False(t, db.Migrator().HasColumn("secret_nodes", store.SecretNodeCacheEpochColumn))

	require.NoError(t, f.migrateDatabase(db))
	assertCacheEpochConverged(t, db, "postgres upgrade")

	for _, id := range seeded {
		require.Equal(t, int64(0), cacheEpochOf(t, db, id))
		before := cacheEpochOf(t, db, id)
		require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", id).
			UpdateColumn("classification", "internal").Error)
		require.Greater(t, cacheEpochOf(t, db, id), before)
	}

	require.NoError(t, f.migrateDatabase(db))
	assertCacheEpochConverged(t, db, "postgres third boot")

	// Postgres-specific: a client that explicitly SETS cache_epoch must not be
	// able to choose it. The BEFORE trigger overwrites NEW, which is what makes
	// "no Go write can set this column" true at the database rather than by
	// convention.
	s := models.SecretNode{Name: "pg-cannot-set", ProjectID: 1, EnvironmentID: 1, Status: "active"}
	require.NoError(t, db.Create(&s).Error)
	require.NoError(t, db.Exec("UPDATE secret_nodes SET cache_epoch = 9999 WHERE id = ?", s.ID).Error)
	require.Equal(t, int64(1), cacheEpochOf(t, db, s.ID),
		"a client-supplied cache_epoch must be overwritten by the BEFORE trigger (expected OLD+1), not honoured")
}

// TestSecretNodeCacheEpoch_NeedsNoSchemaEpochBump records, as a check rather
// than as a claim in a commit message, WHY this migration deliberately does not
// bump currentSchemaEpoch.
//
// The constant's own doc comment says to bump it for "a new column", and
// schema_epoch_tripwire_test.go refuses any bump above 1 until ADR-101's
// minCompatibleEpoch mechanism lands. Those two rules conflict for this
// migration, and the conflict resolves in favour of NOT bumping — because the
// hazard the epoch exists to prevent is specifically "an old binary writing new
// rows via a migrated-in column's DEFAULT, blind to whatever invariant that
// column encodes", and cache_epoch's invariant is not encoded in application
// code at all. The DATABASE maintains it. A binary that has never heard of the
// column cannot leave it inconsistent, which is exactly the safe case ADR-101's
// declared floor is designed to stop refusing.
//
// This test is that argument, executable: it writes the way a binary with no
// knowledge of cache_epoch writes — raw SQL naming only the columns it knows —
// and asserts the stamp is still maintained correctly.
func TestSecretNodeCacheEpoch_NeedsNoSchemaEpochBump(t *testing.T) {
	require.Equal(t, 1, currentSchemaEpoch,
		"this test encodes the reasoning for leaving the epoch at 1; if you bump it, ADR-101's minCompatibleEpoch must land first (schema_epoch_tripwire_test.go) and this test's premise needs revisiting")

	dbPath := filepath.Join(t.TempDir(), "epoch-compat.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))

	// An INSERT that does not mention cache_epoch — what any older binary emits,
	// since the column is on no model. It must land a USABLE stamp, not NULL:
	// a NULL would make the read path's stamp query fail rather than miss.
	require.NoError(t, db.Exec(
		"INSERT INTO secret_nodes (name, project_id, environment_id, status, created_at, updated_at) VALUES (?, 1, 1, 'active', ?, ?)",
		"old-binary-insert", "2026-01-01 00:00:00", "2026-01-01 00:00:00").Error)
	var id uint
	require.NoError(t, db.Raw("SELECT id FROM secret_nodes WHERE name = ?", "old-binary-insert").Scan(&id).Error)
	require.Equal(t, int64(0), cacheEpochOf(t, db, id),
		"an insert that never mentions cache_epoch must still produce a valid stamp (0), not NULL")

	// An UPDATE that does not mention cache_epoch — again, what an older binary
	// emits. The trigger maintains the stamp regardless of which binary wrote.
	before := cacheEpochOf(t, db, id)
	require.NoError(t, db.Exec("UPDATE secret_nodes SET description = ? WHERE id = ?", "written by a binary that has never heard of cache_epoch", id).Error)
	require.Greater(t, cacheEpochOf(t, db, id), before,
		"the stamp must be maintained by the DATABASE for a write that knows nothing about the column — that is the whole reason this migration is backwards compatible and needs no epoch bump")
}

// TestSecretNodeCacheEpoch_CreateStorageEntryPointCreatesIt covers the
// coordinator's "admin migrate/upgrade paths create it" requirement at its
// single real chokepoint rather than by enumerating commands.
//
// Every admin path — `admin migrate`, both `admin restore` variants, and
// withStorage's generic helper — reaches the schema through exactly ONE call,
// storage.NewStorageFactory().CreateStorage(cfg) (see server/admin/migrate.go's
// own doc comment: "reusing the SAME migration code the server itself runs at
// every boot ... rather than a separate implementation"). There is no second
// migration implementation to cover, so asserting on that entry point covers
// all of them — and if a future admin command grows its own migration path,
// that comment's premise is what breaks, not this test's coverage.
func TestSecretNodeCacheEpoch_CreateStorageEntryPointCreatesIt(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "entrypoint.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	// Re-open the same file to inspect the schema the entry point produced.
	db, err := gormOpenForTest(t, cfg.Storage.Database.Path)
	require.NoError(t, err)
	assertCacheEpochConverged(t, db, "CreateStorage entry point")
}

// TestSecretNodeCacheEpoch_ConcurrentEnsureOnPostgres is the Postgres half of
// the lifecycle guarantee (coordinator review of #2764, item 1): the migration
// must never expose a trigger-less window, and must never fail when two callers
// run it at once.
//
// Postgres gets its own test rather than relying on the SQLite one because the
// two dialects take genuinely different paths — Postgres replaces the FUNCTION
// body with CREATE OR REPLACE and creates the trigger only when absent, SQLite
// compares the stored CREATE text. A proof for one says nothing about the other.
//
// The window is what matters here: a replica SERVING traffic while another
// replica boots is not serialised by withMigrationLock, so a write landing in a
// trigger-less window does not bump cache_epoch and every warm entry for that
// row is served stale forever.
func TestSecretNodeCacheEpoch_ConcurrentEnsureOnPostgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — the Postgres trigger lifecycle is unverified in this run")
	}
	schema := fmt.Sprintf("cache_epoch_conc_%d", os.Getpid())
	admin, err := gorm.Open(postgres.Open(dsn), gormConfig())
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), gormConfig())
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	require.NoError(t, store.EnsureSecretNodeCacheEpoch(db))

	const runners = 6
	const observers = 3
	var absent atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, runners)

	for range observers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !store.SecretNodeCacheEpochTriggerPresent(db) {
					absent.Add(1)
				}
			}
		}()
	}
	var runnerWG sync.WaitGroup
	for range runners {
		runnerWG.Add(1)
		go func() {
			defer runnerWG.Done()
			if err := store.EnsureSecretNodeCacheEpoch(db); err != nil {
				errs <- err
			}
		}()
	}
	runnerWG.Wait()
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "a concurrent EnsureSecretNodeCacheEpoch failed — the DROP+CREATE form failed here with \"trigger already exists\" when one runner's CREATE landed between another's DROP and CREATE")
	}

	require.Zero(t, absent.Load(),
		"an observer saw secret_nodes with NO cache_epoch trigger on Postgres while the migration ran: in that window another replica's write does not bump the epoch, so every warm entry for that row is served stale forever")
	require.True(t, store.SecretNodeCacheEpochTriggerPresent(db))

	// And the trigger still works afterwards — "present" is not the same claim
	// as "functioning", and a CREATE OR REPLACE of the function body could in
	// principle leave a trigger pointing at something wrong.
	s := &models.SecretNode{Name: "pg-conc", ProjectID: 1, EnvironmentID: 1}
	require.NoError(t, db.Create(s).Error)
	var before, after int64
	require.NoError(t, db.Model(&models.SecretNode{}).Select("cache_epoch").Where("id = ?", s.ID).Row().Scan(&before))
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", s.ID).UpdateColumn("status", "suspended").Error)
	require.NoError(t, db.Model(&models.SecretNode{}).Select("cache_epoch").Where("id = ?", s.ID).Row().Scan(&after))
	require.Greater(t, after, before, "the trigger survived the concurrent migration but no longer bumps the epoch")
}

// TestSecretNodeCacheEpoch_CrossSchemaTriggerDoesNotMaskADroppedOne_Postgres is
// coordinator round-5 item 1 (blocker): a tgname-only match against pg_trigger
// is not scoped to a table or a schema at all — pg_trigger is one catalog
// shared by every schema in the database — so a SAME-NAMED trigger on a
// DIFFERENT secret_nodes table, in a DIFFERENT schema, makes the old query
// report "present" for a schema whose own trigger is actually gone. The
// schema-per-test Postgres harness used everywhere else in this file cannot
// see this bug, because it only ever has ONE schema with the trigger at a
// time; this test deliberately builds two.
func TestSecretNodeCacheEpoch_CrossSchemaTriggerDoesNotMaskADroppedOne_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — the Postgres trigger lifecycle is unverified in this run")
	}
	ctx := context.Background()
	schemaA := fmt.Sprintf("cache_epoch_xschema_a_%d", os.Getpid())
	schemaB := fmt.Sprintf("cache_epoch_xschema_b_%d", os.Getpid())
	admin, err := gorm.Open(postgres.Open(dsn), gormConfig())
	require.NoError(t, err)
	for _, s := range []string{schemaA, schemaB} {
		require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+s+" CASCADE").Error)
		require.NoError(t, admin.Exec("CREATE SCHEMA "+s).Error)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schemaA + " CASCADE").Error
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schemaB + " CASCADE").Error
	})

	dbA, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schemaA)), gormConfig())
	require.NoError(t, err)
	dbB, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schemaB)), gormConfig())
	require.NoError(t, err)

	// Schema B gets its OWN secret_nodes and a real, correctly-firing trigger —
	// present ONLY so schema A's detection has something same-named to be fooled
	// by. Nothing in schema B is otherwise exercised.
	require.NoError(t, dbB.AutoMigrate(&models.SecretNode{}))
	require.NoError(t, store.EnsureSecretNodeCacheEpoch(dbB))

	// Schema A gets the trigger too, so a LocalStorage can warm against a real,
	// working cache first — the failure this test proves is specifically about
	// a stale HIT, not a cold miss.
	require.NoError(t, dbA.AutoMigrate(&models.SecretNode{}))
	require.NoError(t, store.EnsureSecretNodeCacheEpoch(dbA))

	ls := store.NewLocalStorage(dbA)
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "xschema-warm", ProjectID: 1, EnvironmentID: 1, Status: "active",
	})
	require.NoError(t, err)
	warm, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "active", warm.Status)

	// Schema A's own trigger is now dropped — an operator DROP, or a restore
	// that omitted it. Schema B's SAME-NAMED trigger, on a DIFFERENT table in a
	// DIFFERENT schema of the SAME database, is untouched. IF EXISTS: with the
	// bug this guards against, EnsureSecretNodeCacheEpoch(dbA) above may itself
	// have been fooled by B's trigger into never creating A's in the first
	// place, which is the SAME defect surfacing one step earlier.
	require.NoError(t, dbA.Exec("DROP TRIGGER IF EXISTS "+store.SecretNodeCacheEpochTrigger+" ON secret_nodes").Error)

	require.False(t, store.SecretNodeCacheEpochTriggerPresent(dbA),
		"schema A's own secret_nodes trigger is gone, but a tgname-only match against pg_trigger (global across every schema) finds schema B's same-named trigger on a different table and would report 'present' here — a false positive that lets a stale warm entry keep hitting forever")

	require.NoError(t, dbA.Model(&models.SecretNode{}).Where("id = ?", created.ID).
		UpdateColumn("status", "suspended").Error)
	got, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status,
		"a warm entry was served after schema A's trigger was dropped: schema B's same-named trigger made the detection report 'present' for the wrong table")
}

// TestSecretNodeCacheEpoch_DisabledTriggerIsNotTrusted_Postgres is coordinator
// round-5 item 2 (blocker): ALTER TABLE ... DISABLE TRIGGER (and
// pg_restore --disable-triggers, which produces the same state) leaves the
// trigger's row in pg_trigger exactly as it was — same tgname, tgisinternal
// still false — it simply never fires. A presence check that does not also
// read tgenabled cannot distinguish a disabled trigger from a working one, so
// it would report "present" for a stamp that has permanently stopped moving.
//
// Known, documented gap this does NOT cover: session_replication_role =
// replica suppresses ordinary triggers for the whole session without touching
// tgenabled at all, so a disabled-session check could still read "present"
// while nothing fires for that session. See SecretNodeCacheEpochTriggerPresent's
// doc comment.
func TestSecretNodeCacheEpoch_DisabledTriggerIsNotTrusted_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — the Postgres trigger lifecycle is unverified in this run")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("cache_epoch_disabled_%d", os.Getpid())
	admin, err := gorm.Open(postgres.Open(dsn), gormConfig())
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), gormConfig())
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	require.NoError(t, store.EnsureSecretNodeCacheEpoch(db))

	ls := store.NewLocalStorage(db)
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "disabled-trigger-warm", ProjectID: 1, EnvironmentID: 1, Status: "active",
	})
	require.NoError(t, err)
	warm, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "active", warm.Status)

	require.NoError(t, db.Exec("ALTER TABLE secret_nodes DISABLE TRIGGER "+store.SecretNodeCacheEpochTrigger).Error)

	require.False(t, store.SecretNodeCacheEpochTriggerPresent(db),
		"the trigger is DISABLED (tgenabled = 'D'): it still appears in pg_trigger under its own name on its own table, but a check that ignores tgenabled cannot tell firing from inert and would report 'present' for a trigger that will never bump the stamp again")

	before := cacheEpochOf(t, db, created.ID)
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", created.ID).
		UpdateColumn("status", "suspended").Error)
	require.Equal(t, before, cacheEpochOf(t, db, created.ID),
		"precondition: a disabled trigger must not bump cache_epoch, or this test is not exercising the disabled case")

	got, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status,
		"a warm entry was served after its trigger was disabled: the stamp was frozen and the trigger-presence check did not catch it")
}
