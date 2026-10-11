// secret_metadata_cache_fieldledger_test.go — the node cache's stamp is now
// secret_nodes.cache_epoch, maintained by a database trigger
// (EnsureSecretNodeCacheEpoch, secret_node_cache_epoch.go). The claim that
// makes that a valid stamp is "the trigger fires on EVERY update to the row",
// so this file asserts exactly that, column by column, derived from the model
// rather than from a hand list.
//
// This REPLACES the 25-column content-derived stamp and its exclusion ledger
// (coordinator review, 2026-10-05 23:45: "keep the reflection-driven field
// ledger only if it still adds value (e.g. it asserts the trigger exists and
// fires for every column); otherwise drop the 25-column stamp"). The
// reflection stayed, repointed: it used to prove the stamp COVERED every
// column, it now proves the trigger FIRES for every column — a stronger claim,
// because it is about the mechanism rather than about a list.
//
// The schedule stamp keeps its content-derived form and its own ledger (see
// TestScheduleGeneration_CoversEveryPersistedScheduleField below) — the reason
// is in the report: that row is tiny, so covering the whole access policy costs
// nothing and leaves no residual gap, whereas the node row is wide.
package store

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// nonUpdatableSecretNodeFields are models.SecretNode fields this test does NOT
// drive an UPDATE through, with the reason. Everything else gets an individual
// UPDATE and must bump cache_epoch.
var nonUpdatableSecretNodeFields = map[string]string{
	"ID":          "the primary key — updating it is not a write this application ever performs, and the cache key is the id itself.",
	"ValueStored": "not persisted (`gorm:\"-\"`, #499) — there is no column to update.",
	"CacheEpoch":  "the stamp itself. Writing it directly is not a write any Go code can make (`gorm:\"<-:false\"`, guarded by TestSecretNodeCacheEpoch_FieldStaysReadOnlyToGORM) and on SQLite the trigger's WHEN guard deliberately does NOT re-bump a statement that already changed cache_epoch — that guard is what stops the nested UPDATE recursing.",
	"DeletedAt":   "driven separately, by the soft-delete row of the race table and TestGetSecret_CacheReflectsDeleteSecret: a soft-deleted row stops matching the stamp query's own deleted_at IS NULL scope, which is a stronger guarantee than an epoch bump.",
}

// TestCacheEpochTrigger_FiresForEveryPersistedColumn is the load-bearing test
// for the whole design: for EVERY persisted column of models.SecretNode, an
// UPDATE touching only that column must advance cache_epoch. Derived from the
// model by reflection, so a newly added column is covered the moment it exists
// — a hand-written list is exactly the enumeration that goes stale.
//
// Red with the trigger dropped (see
// TestCacheEpochTrigger_IsRedWithoutTheTrigger below, which drops it and
// re-runs one representative update rather than asking a reader to take this
// on trust).
func TestCacheEpochTrigger_FiresForEveryPersistedColumn(t *testing.T) {
	t.Parallel()
	ls := newCacheEpochTestStorage(t)
	ctx := context.Background()

	modelType := reflect.TypeOf(models.SecretNode{})
	var skipped, checked []string

	for i := 0; i < modelType.NumField(); i++ {
		f := modelType.Field(i)
		if reason, ok := nonUpdatableSecretNodeFields[f.Name]; ok {
			require.NotEmpty(t, reason, "exclusion for %s needs a reason", f.Name)
			skipped = append(skipped, f.Name)
			continue
		}
		if f.Tag.Get("gorm") == "-" {
			skipped = append(skipped, f.Name+" (gorm:\"-\")")
			continue
		}
		column, value := columnAndProbeValueFor(t, ls, f)
		checked = append(checked, f.Name)

		created, err := ls.CreateSecret(ctx, &models.SecretNode{
			Name: fmt.Sprintf("probe-%s", f.Name), ProjectID: 1, EnvironmentID: 1,
			Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)

		before := readCacheEpoch(t, ls, created.ID)
		require.NoError(t, ls.db.Model(&models.SecretNode{}).Where(sqlWhereID, created.ID).
			UpdateColumn(column, value).Error,
			"updating %s (%s) must succeed", f.Name, column)
		after := readCacheEpoch(t, ls, created.ID)

		require.Greater(t, after, before,
			"an UPDATE of secret_nodes.%s did not advance cache_epoch (%d -> %d). The node cache's stamp is cache_epoch alone, "+
				"so a column the trigger does not cover can change while a warm cache entry keeps serving the pre-change row. "+
				"Either the trigger is missing/not firing, or this column lives on a table the trigger is not attached to.",
			column, before, after)
	}

	sort.Strings(checked)
	// UpdateColumn is used on purpose: it is the idiom that bypasses GORM's
	// auto-timestamp callback, i.e. the one a Go-side bump would miss. If the
	// trigger survives THIS, it survives Save()/Updates() too.
	require.GreaterOrEqual(t, len(checked), 20,
		"only %d columns were probed (%s); the reflection has stopped enumerating models.SecretNode, so this test would pass vacuously",
		len(checked), strings.Join(checked, ", "))
	t.Logf("cache_epoch trigger verified for %d columns; skipped with reasons: %s", len(checked), strings.Join(skipped, ", "))
}

// TestCacheEpochTrigger_IsRedWithoutTheTrigger is the negative control, run in
// the same CI pass as the positive one rather than left as a claim in a commit
// message: drop the trigger, repeat one representative hook-bypassing update,
// and the epoch must NOT move.
func TestCacheEpochTrigger_IsRedWithoutTheTrigger(t *testing.T) {
	t.Parallel()
	ls := newCacheEpochTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	// With the trigger: the epoch moves.
	before := readCacheEpoch(t, ls, created.ID)
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where(sqlWhereID, created.ID).
		UpdateColumn("description", "with-trigger").Error)
	require.Greater(t, readCacheEpoch(t, ls, created.ID), before)

	require.NoError(t, ls.db.Exec("DROP TRIGGER IF EXISTS trg_secret_nodes_cache_epoch").Error)

	// Without it: the same write leaves the epoch alone, which is precisely the
	// staleness the trigger exists to prevent.
	frozen := readCacheEpoch(t, ls, created.ID)
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where(sqlWhereID, created.ID).
		UpdateColumn("description", "without-trigger").Error)
	require.Equal(t, frozen, readCacheEpoch(t, ls, created.ID),
		"with the trigger dropped the epoch must stand still — if it still moves, something OTHER than the trigger is maintaining it and this test is not measuring what it claims")
}

// TestCacheEpochTrigger_FiresOncePerRowOnAMultiRowUpdate covers the SQLite
// shape specifically: there the trigger is AFTER UPDATE and issues a nested
// single-row UPDATE, so a statement touching many rows fires it many times,
// each nested write landing on the table currently being scanned. Every
// affected row must end up bumped exactly once — not zero times, and not
// recursively.
func TestCacheEpochTrigger_FiresOncePerRowOnAMultiRowUpdate(t *testing.T) {
	t.Parallel()
	ls := newCacheEpochTestStorage(t)
	ctx := context.Background()

	ids := make([]uint, 0, 3)
	for i := 0; i < 3; i++ {
		created, err := ls.CreateSecret(ctx, &models.SecretNode{
			Name: fmt.Sprintf("multi-%d", i), ProjectID: 7, EnvironmentID: 1,
			Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		ids = append(ids, created.ID)
	}
	before := map[uint]int64{}
	for _, id := range ids {
		before[id] = readCacheEpoch(t, ls, id)
	}

	// One statement, three rows — the soft-delete cascade's shape.
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where("project_id = ?", 7).
		UpdateColumn("classification", "internal").Error)

	for _, id := range ids {
		require.Equal(t, before[id]+1, readCacheEpoch(t, ls, id),
			"row %d's epoch moved by something other than exactly one: a multi-row UPDATE must bump each affected row once (zero = the trigger missed it, more = the nested write re-fired the trigger)", id)
	}
}

// TestCacheEpoch_HardDeletedIDIsNeverReissued closes the one way a per-row
// counter could repeat: hard-delete a row and have a new row take the same id
// with the epoch back at 0, so a warm entry for the OLD secret validates
// against the NEW one — a cross-secret read. Proven, not assumed (the review
// asked for proof either way).
func TestCacheEpoch_HardDeletedIDIsNeverReissued(t *testing.T) {
	t.Parallel()
	ls := newCacheEpochTestStorage(t)
	ctx := context.Background()

	first, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "first", ProjectID: 1, EnvironmentID: 1, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Hard delete — Unscoped, i.e. past the soft-delete layer, the way the
	// purge scheduler removes a row for good.
	require.NoError(t, ls.db.Unscoped().Delete(&models.SecretNode{}, first.ID).Error)
	var surviving int64
	require.NoError(t, ls.db.Unscoped().Model(&models.SecretNode{}).Where(sqlWhereID, first.ID).Count(&surviving).Error)
	require.Zero(t, surviving, "the row must really be gone for this test to mean anything")

	second, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "second", ProjectID: 1, EnvironmentID: 1, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	require.NotEqual(t, first.ID, second.ID,
		"a hard-deleted secret's id was reissued to a new row. The node cache keys on id and stamps on cache_epoch, which restarts at 0 for a new row, so a warm entry for the deleted secret would validate against the new one and serve the WRONG secret's metadata. "+
			"SQLite must declare the primary key AUTOINCREMENT (plain INTEGER PRIMARY KEY reuses max(rowid)+1 after deleting the highest row) and Postgres must use a sequence.")
}

// ── the schedule stamp keeps its content-derived ledger ────────────────────

var scheduleGenerationExcludedFields = map[string]string{
	"ID":           "surrogate key; nothing authorizes on it, and a schedule is addressed by SecretNodeID.",
	"SecretNodeID": "the cache KEY itself.",
	"CreatedAt":    "immutable after insert, so it cannot differ between two writes that tie on updated_at.",
}

func TestScheduleGeneration_CoversEveryPersistedScheduleField(t *testing.T) {
	t.Parallel()
	modelType := reflect.TypeOf(models.SecretAccessSchedule{})
	genType := reflect.TypeOf(scheduleGeneration{})

	genNames := map[string]bool{}
	for i := 0; i < genType.NumField(); i++ {
		genNames[strings.TrimSuffix(strings.ToLower(genType.Field(i).Name), "unixnano")] = true
	}

	var uncovered []string
	seen := map[string]bool{}
	for i := 0; i < modelType.NumField(); i++ {
		f := modelType.Field(i)
		seen[f.Name] = true
		if reason, ok := scheduleGenerationExcludedFields[f.Name]; ok {
			require.NotEmpty(t, reason, "exclusion for %s needs a reason", f.Name)
			continue
		}
		if !genNames[strings.ToLower(f.Name)] {
			uncovered = append(uncovered, f.Name)
		}
	}
	var stale []string
	for name := range scheduleGenerationExcludedFields {
		if !seen[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(uncovered)
	sort.Strings(stale)
	require.Empty(t, uncovered,
		"scheduleGeneration does not cover these SecretAccessSchedule fields and they are not in its ledger: %s.\n"+
			"An access schedule is a read GATE, so a field outside the stamp can change the window while a warm entry keeps serving the old one.",
		strings.Join(uncovered, ", "))
	require.Empty(t, stale, "the schedule exclusion ledger names fields that no longer exist: %s", strings.Join(stale, ", "))
}

// ── helpers ───────────────────────────────────────────────────────────────

// newCacheEpochTestStorage builds a store through the REAL migration path, not
// a bare AutoMigrate: cache_epoch and its trigger are created only by
// migrateDatabase (the column is not a model field), so a hand-rolled
// AutoMigrate test schema would silently have neither and every test here would
// pass vacuously against a stamp that never moves.
func newCacheEpochTestStorage(t *testing.T) *LocalStorage {
	t.Helper()
	return newCacheTestStorage(t)
}

func readCacheEpoch(t *testing.T, ls *LocalStorage, id uint) int64 {
	t.Helper()
	var row struct{ CacheEpoch int64 }
	require.NoError(t, ls.db.Model(&models.SecretNode{}).
		Select("cache_epoch").Where(sqlWhereID, id).Take(&row).Error)
	return row.CacheEpoch
}

// columnAndProbeValueFor maps a model field to its column name and a value
// guaranteed to differ from the zero value the row was created with, so the
// UPDATE genuinely changes something.
func columnAndProbeValueFor(t *testing.T, ls *LocalStorage, f reflect.StructField) (string, any) {
	t.Helper()
	// GORM's OWN namer, not a hand-rolled snake_case: it is what actually
	// decides the column name, so it cannot drift from the schema. (This
	// package's existing toSnakeCase is close but mis-handles a trailing
	// acronym — "ParentID" becomes parent_i_d — which would silently make this
	// test update a column that does not exist.)
	column := ls.db.NamingStrategy.ColumnName("", f.Name)
	switch f.Type.Kind() {
	case reflect.String:
		return column, "probe"
	case reflect.Bool:
		return column, true
	case reflect.Int, reflect.Int64, reflect.Uint, reflect.Uint64:
		return column, 7
	case reflect.Pointer, reflect.Struct, reflect.Slice:
		// *int / *time.Time / time.Time / JSON([]byte) — a time is always a
		// valid value for the pointer-to-time and struct-time cases, and the
		// int/JSON cases accept it as a non-zero scalar on both backends only
		// if typed correctly, so branch on the element type.
		switch f.Type.String() {
		case "*int":
			return column, 7
		case "*time.Time", "time.Time":
			return column, time.Now().UTC().Truncate(time.Second)
		case "models.JSON":
			return column, []byte(`{"probe":1}`)
		case "gorm.DeletedAt":
			return column, time.Now().UTC()
		}
		return column, "probe"
	default:
		t.Fatalf("columnAndProbeValueFor has no probe value for %s (%s) — add one rather than skipping the field, or the trigger goes unverified for it", f.Name, f.Type)
		return "", nil
	}
}

// TestSecretNodeCacheEpoch_FieldStaysReadOnlyToGORM pins the `<-:false` tag
// that makes the column read-only to Go. Without it a full-struct Save() of a
// stale struct would write a stale epoch back — rolling the stamp BACKWARDS,
// which is worse than not bumping it: a cache entry stamped with the higher
// value would start matching again.
//
// Asserted on behaviour, not on the tag string: GORM is what has to honour it,
// so the test writes a struct carrying a bogus epoch and checks the database
// ignored it.
func TestSecretNodeCacheEpoch_FieldStaysReadOnlyToGORM(t *testing.T) {
	t.Parallel()
	ls := newCacheEpochTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "readonly", ProjectID: 1, EnvironmentID: 1, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
		CacheEpoch: 4242, // must be ignored on INSERT
	})
	require.NoError(t, err)
	require.Equal(t, int64(0), readCacheEpoch(t, ls, created.ID),
		"a caller-supplied CacheEpoch must not reach the INSERT — `gorm:\"<-:false\"` makes the field read-only")

	// And on UPDATE: a full-struct Save() carrying a bogus (or stale) epoch must
	// leave the database's own value alone, then be bumped by the trigger.
	row, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	row.CacheEpoch = 1
	row.Description = "updated"
	_, err = ls.UpdateSecret(ctx, row)
	require.NoError(t, err)
	require.Equal(t, int64(1), readCacheEpoch(t, ls, created.ID),
		"Save() must not write CacheEpoch; the trigger alone advances it (0 -> 1), so a stale struct cannot roll the stamp backwards")

	after, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "updated", after.Description, "the rest of the Save() must still have applied")
}

// TestSecretNodeCacheEpoch_AbsentTriggerDisablesTheNodeCache is the fail-closed
// half of the design, and it is not hypothetical: a schema with the COLUMN but
// not the TRIGGER has a stamp frozen forever, so every hit would serve the row
// as first read. That is reachable in production (a Postgres restore that omits
// triggers) and it is what every bare-AutoMigrate test schema looks like — it
// surfaced as internal/core's suspend tests serving a stale `status` after
// SuspendSecret.
//
// The store must notice at construction and simply not use the node cache.
func TestSecretNodeCacheEpoch_AbsentTriggerDisablesTheNodeCache(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// The column arrives via AutoMigrate (it is a model field); the trigger does
	// NOT, because AutoMigrate knows nothing about triggers. Exactly the shape a
	// hand-rolled test schema — or a trigger-less restore — has.
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{},
		&models.SecretAccessSchedule{}, &models.ShareRecord{}, &models.SecretACL{}))
	require.True(t, db.Migrator().HasColumn("secret_nodes", SecretNodeCacheEpochColumn),
		"the column must be present for this test to be about the TRIGGER")
	require.False(t, SecretNodeCacheEpochTriggerPresent(db))

	ls := NewLocalStorage(db)
	require.False(t, ls.nodeStampTrusted(),
		"with no trigger the node stamp cannot be trusted and the cache must be off")

	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "no-trigger", ProjectID: 1, EnvironmentID: 1, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	warm, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "active", warm.Status)
	_, cached := ls.secretMetaCache.getNode(created.ID)
	require.False(t, cached, "nothing may be cached when the stamp cannot move")

	// A hook-bypassing write, the kind whose staleness started all of this. With
	// the cache off this must be visible immediately — the point being that an
	// untrustworthy stamp costs performance, never correctness.
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where(sqlWhereID, created.ID).
		UpdateColumn("status", "suspended").Error)
	after, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", after.Status,
		"with a frozen stamp the cache MUST be bypassed; serving 'active' here is the silent-staleness failure this check exists to prevent")

	// And the positive control: the same schema WITH the trigger does cache.
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	trusted := NewLocalStorage(db)
	require.True(t, trusted.nodeStampTrusted())
	_, err = trusted.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	_, cached = trusted.secretMetaCache.getNode(created.ID)
	require.True(t, cached, "with the trigger in place the node cache must be used again")
}

// TestSecretNodeCacheEpoch_TriggerDroppedWhileWarmIsAMissNotAStaleHit is the
// blocker's behavioural proof (coordinator review of #2764, item 1).
//
// The original design probed for the trigger ONCE per store. That is fine for a
// database that never had one, and useless for the case that actually bites: a
// warm replica whose trigger disappears underneath it — another replica's
// migration dropping and re-creating it, a restore, an operator's DROP. With a
// one-shot probe that store keeps trusting a stamp that can no longer move, so
// every entry it already holds is served forever, with no error.
//
// So the assertion is specifically "the next read is a MISS", not "the probe
// returns false": a stale hit is the symptom, and it is the only thing that
// distinguishes a fail-closed read path from a probe that merely looks right.
func TestSecretNodeCacheEpoch_TriggerDroppedWhileWarmIsAMissNotAStaleHit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{},
		&models.SecretAccessSchedule{}, &models.ShareRecord{}, &models.SecretACL{}))
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))

	ls := NewLocalStorage(db)
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "warm-then-trigger-dropped", ProjectID: 1, EnvironmentID: 1, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Warm the entry while the trigger is healthy, and confirm it really is warm
	// — otherwise the "miss" asserted below would be a miss for the wrong reason.
	warm, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "active", warm.Status)
	_, cached := ls.secretMetaCache.getNode(created.ID)
	require.True(t, cached, "the entry must be warm, or this test proves nothing about a stale HIT")

	// The trigger vanishes underneath the warm store. Note the store is NOT
	// rebuilt: this is the same long-lived *LocalStorage a replica serves from.
	require.NoError(t, db.Exec("DROP TRIGGER "+SecretNodeCacheEpochTrigger).Error)
	require.False(t, SecretNodeCacheEpochTriggerPresent(db))

	// A hook-bypassing write that the (now absent) trigger would have stamped.
	// cache_epoch therefore does NOT move, so the warm entry's stamp still
	// matches and a stamp-only check would hit and serve the stale row.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", created.ID).
		UpdateColumn("status", "suspended").Error)

	var epoch int64
	require.NoError(t, db.Model(&models.SecretNode{}).Select("cache_epoch").
		Where("id = ?", created.ID).Row().Scan(&epoch))
	require.Equal(t, warm.CacheEpoch, epoch,
		"precondition: with the trigger gone the epoch must be FROZEN — if it moved, the stamp alone would have caught this and the test would not be about fail-closed behaviour")

	got, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status,
		"a warm entry was served after its trigger was dropped: the read path trusted a frozen stamp")
}

// TestSecretNodeCacheEpoch_ConcurrentEnsureNeverLeavesTheTableTriggerless is the
// other half of item 1: the migration must be safe to run while other callers
// run it too, and must never pass through a trigger-less state.
//
// The DROP-then-CREATE version could fail this in two ways — an observer
// catching the window between the two statements, and two concurrent runs where
// one's DROP lands between the other's DROP and CREATE. Both call sites in
// production hold withMigrationLock's advisory lock, so this is defence in
// depth rather than the primary protection; it exists because the lock is not
// what makes the function correct, and a reader of the function should not have
// to know about the lock to trust it.
func TestSecretNodeCacheEpoch_ConcurrentEnsureNeverLeavesTheTableTriggerless(t *testing.T) {
	t.Parallel()
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))

	const runners = 8
	const observers = 4
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
				if !SecretNodeCacheEpochTriggerPresent(db) {
					absent.Add(1)
				}
			}
		}()
	}
	for range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := EnsureSecretNodeCacheEpoch(db); err != nil {
				errs <- err
			}
		}()
	}
	// The runners finish on their own; the observers run until told to stop.
	wgRunnersDone := make(chan struct{})
	go func() { wg.Wait(); close(wgRunnersDone) }()
	time.Sleep(150 * time.Millisecond)
	close(stop)
	<-wgRunnersDone
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	require.Zero(t, absent.Load(),
		"an observer saw secret_nodes with NO cache_epoch trigger while EnsureSecretNodeCacheEpoch ran: that is the window in which another replica's write does not bump the epoch, so every warm entry for that row is served stale forever")
	require.True(t, SecretNodeCacheEpochTriggerPresent(db))
}

// TestSecretNodeCacheEpoch_EnsureLeavesACorrectTriggerUntouched pins the
// "never drop a correct trigger" half directly, rather than inferring it from
// the absence of a window: re-running the migration must not even touch a
// trigger whose body already matches.
func TestSecretNodeCacheEpoch_EnsureLeavesACorrectTriggerUntouched(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))

	before, present, err := sqliteCacheEpochTriggerBody(db)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, sqliteCacheEpochTriggerSQL, before,
		"the installed body must be byte-identical to the constant, or the convergence compare can never say 'already correct' and every boot would replace the trigger")

	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	after, present, err := sqliteCacheEpochTriggerBody(db)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, before, after)
}

// TestSecretNodeCacheEpoch_EnsureConvergesAnOutdatedTriggerBody is the other
// direction of the same compare: a trigger whose body does NOT match must be
// replaced, or an install that predates a change to the body keeps the old one
// forever. Without this, "never drop a correct trigger" would have been
// satisfiable by never dropping anything at all.
func TestSecretNodeCacheEpoch_EnsureConvergesAnOutdatedTriggerBody(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))

	// An "old" trigger under the right name with a body that does nothing useful.
	require.NoError(t, db.Exec(`CREATE TRIGGER `+SecretNodeCacheEpochTrigger+`
AFTER UPDATE ON secret_nodes FOR EACH ROW
BEGIN
  SELECT 1;
END`).Error)
	stale, present, err := sqliteCacheEpochTriggerBody(db)
	require.NoError(t, err)
	require.True(t, present)
	require.NotEqual(t, sqliteCacheEpochTriggerSQL, stale)

	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	got, present, err := sqliteCacheEpochTriggerBody(db)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, sqliteCacheEpochTriggerSQL, got,
		"an outdated trigger body was left in place: the convergence compare is not replacing a WRONG trigger, only refusing to replace a right one")

	// And it must actually work now.
	s := &models.SecretNode{Name: "converged", ProjectID: 1, EnvironmentID: 1}
	require.NoError(t, db.Create(s).Error)
	var before, after int64
	require.NoError(t, db.Model(&models.SecretNode{}).Select("cache_epoch").Where("id = ?", s.ID).Row().Scan(&before))
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", s.ID).UpdateColumn("status", "suspended").Error)
	require.NoError(t, db.Model(&models.SecretNode{}).Select("cache_epoch").Where("id = ?", s.ID).Row().Scan(&after))
	require.Greater(t, after, before)
}
