// secret_node_cache_epoch.go — secret_nodes.cache_epoch and the database
// trigger that maintains it: the generation stamp for the read-path
// secret-metadata cache.
//
// This lives in package store, not in internal/storage's migrateDatabase, so
// that there is exactly ONE definition of the column and the trigger for
// production and tests alike: internal/storage already imports this package, so
// the real migration calls straight into EnsureSecretNodeCacheEpoch, and the
// cache's own tests (which live here) build their schema with the same call
// rather than a second copy of the SQL that could drift.
//
// The column IS a field on models.SecretNode — read-only to GORM, see its doc
// comment there — so AutoMigrate creates it everywhere. The TRIGGER is not
// something AutoMigrate can know about, which is why
// SecretNodeCacheEpochTriggerPresent exists and why its absence disables the
// node cache rather than silently freezing its stamp.
package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
)

// Trigger and function names, exported so a test can drop them to prove the
// guard that depends on them actually goes red.
const (
	SecretNodeCacheEpochColumn  = "cache_epoch"
	SecretNodeCacheEpochTrigger = "trg_secret_nodes_cache_epoch" // #nosec G101 -- database trigger name, not a credential
	secretNodeCacheEpochFunc    = "keyorix_secret_nodes_bump_cache_epoch"
)

// postgresCacheEpochLockKey is this migration's own advisory-lock key — see
// ensurePostgresCacheEpochTrigger. Found the hard way (coordinator round-5 CI
// run on #2764, server/admin's real admin-restore path, reproduced locally
// with pg_locks/pg_stat_activity, not reasoned out in advance): the previous
// value, 872342, was picked to be "distinct from postgresMigrationLockKey
// (872341)" and WAS distinct from that one key — but collided with
// internal/serverguard's serverPresenceLockKey, ALSO 872342, a completely
// unrelated SESSION-scoped lock that `admin restore` holds for its own
// duration. The restore's own serverguard connection held 872342 for the
// whole operation; this function's xact-scoped acquire of the SAME key, on a
// different connection, inside that same operation, then waited on itself
// forever. Small sequential integers invite exactly this: nothing enumerates
// them centrally, so "distinct from the one key I checked" is not "distinct
// from every key in the codebase". The pattern every other advisory lock key
// in package store already uses (auditAdvisoryLockKey, 0x4B455941_55444954 =
// "KEYAUDIT"; auditCheckpointAdvisoryLockKey, "KEYACHKP"; bootstrapAdvisoryLockKey,
// "KEYABOOT") makes a collision visible at the call site instead of needing a
// cross-repo grep to catch: "KEYACEPO" reads as this lock's own name, and a
// future key picked the same careless way would have to spell out "KEYA" plus
// a 4-letter tag that ALSO happens to already exist, not guess a 19-bit int.
const postgresCacheEpochLockKey = 0x4B455941_4345504F // "KEYACEPO"

// sqliteCacheEpochTriggerSQL is the EXACT text of the SQLite trigger, kept as
// one constant so the convergence check below can compare it byte-for-byte
// against what sqlite_master recorded. SQLite stores a trigger's CREATE
// statement verbatim, so an exact compare answers "is the installed body the
// one this binary wants" with no SQL normalisation guesswork.
const sqliteCacheEpochTriggerSQL = `CREATE TRIGGER ` + SecretNodeCacheEpochTrigger + `
AFTER UPDATE ON secret_nodes FOR EACH ROW
WHEN NEW.cache_epoch = OLD.cache_epoch
BEGIN
  UPDATE secret_nodes SET cache_epoch = OLD.cache_epoch + 1 WHERE id = NEW.id;
END`

// EnsureSecretNodeCacheEpoch adds secret_nodes.cache_epoch and the trigger that
// bumps it on EVERY update to the row, on both backends. Idempotent, and —
// load-bearing — it **never drops a trigger that is already correct**, and never
// leaves the table trigger-less if anything fails.
//
// # Why a database trigger, and why no Go code owns this column
//
// The cache's requirement is "the stamp changes whenever ANY column of the
// cached row changes". Every Go-side mechanism for that has a hole, and this
// repo hit three of them in a row on #2764:
//
//   - updated_at alone misses UpdateColumn/UpdateColumns, which bypass GORM's
//     auto-timestamp callback. That is how a stale read_count got served and
//     reset a burn-after-N-reads budget (#133).
//   - A GORM BeforeUpdate hook calling SetColumn is SILENTLY A NO-OP for a
//     full-struct Save() — which is exactly what UpdateSecret uses.
//   - Bumping it at each write site needs every current AND future writer to
//     remember, raw db.Exec SQL included: opt-in correctness, the recurring
//     defect shape here.
//
// A trigger has none of those holes: the database does it, so Save(),
// Updates(), UpdateColumn() and raw SQL are covered identically, with no Go
// code to forget and nothing for a new writer to opt into. The column is
// read-only to GORM (models.SecretNode's `gorm:"<-:false"`) so no Go write can
// set it even by accident — and on Postgres the BEFORE trigger overwrites
// whatever a client sent anyway.
//
// # The lifecycle rule, and the bug that produced it
//
// This function originally did DROP TRIGGER IF EXISTS then CREATE TRIGGER, on
// every boot, each as its own statement. That is wrong in two ways that only
// show up in a replicated deployment, because a booting replica is not the only
// replica:
//
//   - Between the DROP and the CREATE there is a live window in which the table
//     has NO trigger. Another replica serving traffic in that window updates a
//     row without bumping cache_epoch, so every warm entry for that row stays
//     "current" forever and serves pre-change data. The boot is serialised
//     against other BOOTS (both call sites run inside withMigrationLock's
//     advisory lock) but not against other replicas SERVING, which is the case
//     that matters.
//   - If the CREATE then fails — a permissions change, a disk error, a
//     cancelled context — the table is left with no trigger at all while every
//     warm replica carries on trusting its stamp.
//
// So: all of it runs in ONE transaction (DDL is transactional on both backends),
// and the normal path creates without dropping.
//
//   - Postgres: CREATE OR REPLACE FUNCTION updates the body atomically with no
//     window at all, and because the body lives in the function the TRIGGER
//     itself never needs replacing — it is created only when absent.
//   - SQLite cannot put the body in a function, so convergence needs a compare:
//     the installed CREATE text is read from sqlite_master and compared exactly
//     against sqliteCacheEpochTriggerSQL. Equal means correct, and a correct
//     trigger is left strictly alone. Only a DIFFERING body is replaced, and
//     because that drop+create is inside the transaction, a failed create rolls
//     the drop back — the old trigger survives rather than nothing surviving.
//
// SQLite's trigger body also cannot assign to NEW (a SQLite trigger body may
// only run INSERT/UPDATE/DELETE/SELECT), hence the AFTER UPDATE form with a
// nested single-row UPDATE. `WHEN NEW.cache_epoch = OLD.cache_epoch` is what
// stops that nested write re-firing the trigger: the nested write changes
// cache_epoch, so the guard is false for it. Deliberately NOT left to SQLite's
// recursive_triggers pragma (off by default, but a pragma is not something a
// migration should depend on).
//
// None of this makes the stamp trustworthy on its own — a database can lose its
// trigger by means this function never sees (pg_restore --disable-triggers, a
// schema-only restore, a bare AutoMigrate test fixture). That is why the READ
// path re-proves the trigger's existence in the same query as the stamp; see
// readLiveNodeStamp.
func EnsureSecretNodeCacheEpoch(db *gorm.DB) error {
	if !secretNodesTableExists(db) {
		return nil
	}
	isPostgres := db.Dialector.Name() == "postgres"
	return db.Transaction(func(tx *gorm.DB) error {
		if !secretNodeCacheEpochColumnExists(tx) {
			// NOT NULL DEFAULT 0 so existing rows get a usable stamp immediately
			// and no backfill pass is needed: a row reads as epoch 0 until its
			// first update, which is a perfectly valid stamp — it only ever has to
			// CHANGE when the row does.
			if err := tx.Exec("ALTER TABLE secret_nodes ADD COLUMN cache_epoch BIGINT NOT NULL DEFAULT 0").Error; err != nil {
				return fmt.Errorf("failed to add secret_nodes.cache_epoch: %w", err)
			}
		}
		if isPostgres {
			return ensurePostgresCacheEpochTrigger(tx)
		}
		return ensureSQLiteCacheEpochTrigger(tx)
	})
}

// ensurePostgresCacheEpochTrigger replaces the FUNCTION body atomically and
// creates the TRIGGER only when it is absent, so a correct trigger is never
// dropped and no trigger-less window exists.
func ensurePostgresCacheEpochTrigger(tx *gorm.DB) error {
	// Serialise concurrent callers before touching pg_proc.
	//
	// CREATE OR REPLACE FUNCTION is atomic with respect to READERS — there is no
	// window in which the function is missing — but it is NOT safe against a
	// concurrent replace of the same row: two of them race on the pg_proc tuple
	// and one fails with "tuple concurrently updated" (SQLSTATE XX000), which
	// aborts that replica's boot. Found by this fix's own Postgres concurrency
	// test rather than reasoned about in advance; the SQLite path never showed
	// it because its convergence compare short-circuits once the body matches.
	//
	// xact-scoped, so it releases on COMMIT or ROLLBACK with nothing to unlock
	// by hand and no way to leak a lock onto a pooled connection. Its own key,
	// distinct from internal/storage's postgresMigrationLockKey, because this
	// runs INSIDE that lock at both production call sites and must not look like
	// a re-entrant acquisition of it.
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(postgresCacheEpochLockKey)).Error; err != nil {
		return fmt.Errorf("acquire cache_epoch migration advisory lock: %w", err)
	}
	// Dollar-quoted with a NAMED tag rather than bare $$, so the body can never
	// be mistaken for a pgx $N placeholder.
	if err := tx.Exec(`CREATE OR REPLACE FUNCTION ` + secretNodeCacheEpochFunc + `() RETURNS trigger
LANGUAGE plpgsql AS $keyorix$
BEGIN
  NEW.cache_epoch := OLD.cache_epoch + 1;
  RETURN NEW;
END;
$keyorix$`).Error; err != nil {
		return fmt.Errorf("failed to create %s(): %w", secretNodeCacheEpochFunc, err)
	}
	if SecretNodeCacheEpochTriggerPresent(tx) {
		// Already there, and its body is whatever the function now says. Nothing
		// to drop, so no window and no risk.
		return nil
	}
	// EXECUTE PROCEDURE, not EXECUTE FUNCTION: the latter is Postgres 11+ only,
	// while the former is still accepted (a documented synonym) by every version
	// including 16 — so this works across the whole range.
	if err := tx.Exec("CREATE TRIGGER " + SecretNodeCacheEpochTrigger +
		" BEFORE UPDATE ON secret_nodes FOR EACH ROW EXECUTE PROCEDURE " + secretNodeCacheEpochFunc + "()").Error; err != nil {
		return fmt.Errorf("failed to create %s: %w", SecretNodeCacheEpochTrigger, err)
	}
	return nil
}

// ensureSQLiteCacheEpochTrigger leaves a byte-identical trigger untouched and
// replaces a differing one inside the caller's transaction.
func ensureSQLiteCacheEpochTrigger(tx *gorm.DB) error {
	installed, present, err := sqliteCacheEpochTriggerBody(tx)
	if err != nil {
		return err
	}
	if present && installed == sqliteCacheEpochTriggerSQL {
		return nil
	}
	if present {
		// The body differs from what this binary wants, so it has to go — but
		// only now that we know that, and only inside the transaction, so a
		// failing CREATE below rolls this back and the old trigger survives.
		if err := tx.Exec("DROP TRIGGER " + SecretNodeCacheEpochTrigger).Error; err != nil {
			return fmt.Errorf("failed to drop outdated %s: %w", SecretNodeCacheEpochTrigger, err)
		}
	}
	if err := tx.Exec(sqliteCacheEpochTriggerSQL).Error; err != nil {
		return fmt.Errorf("failed to create %s: %w", SecretNodeCacheEpochTrigger, err)
	}
	return nil
}

// sqliteCacheEpochTriggerBody returns the CREATE text sqlite_master recorded for
// the trigger, and whether it exists at all.
func sqliteCacheEpochTriggerBody(tx *gorm.DB) (string, bool, error) {
	var rows []string
	if err := tx.Raw(
		"SELECT COALESCE(sql, '') FROM sqlite_master WHERE type = 'trigger' AND name = ?",
		SecretNodeCacheEpochTrigger).Scan(&rows).Error; err != nil {
		return "", false, fmt.Errorf("failed to read %s definition: %w", SecretNodeCacheEpochTrigger, err)
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	return rows[0], true, nil
}

// SecretNodeCacheEpochTriggerPresent reports whether the cache_epoch trigger
// actually exists on this database. Queried once, at NewLocalStorage, and the
// node read-path cache is DISABLED for the lifetime of that store if the answer
// is no.
//
// This is fail-closed detection, not defensiveness for its own sake. The stamp
// is only a stamp because the trigger maintains it; a database that has the
// COLUMN but not the TRIGGER has a stamp frozen at 0 forever, so every cache
// hit would serve the row as it was when first read — indefinitely, with no
// error and no symptom. Two ways that happens for real:
//
//   - A Postgres restore that omits triggers. `pg_restore --disable-triggers`,
//     a schema-only restore, or a dump loaded into a database whose migration
//     has not run yet all leave the column (it is a plain column) without the
//     trigger.
//   - Any test schema built with a bare db.AutoMigrate(). The column is a model
//     field so AutoMigrate creates it; the trigger is not, so it does not. That
//     is how this check got written: internal/core's suspend/ownership tests
//     started serving a stale `status` after SuspendSecret, because their
//     hand-rolled schema had a stamp that never moved.
//
// An absent trigger is therefore treated the way every other uncertainty in
// this cache is treated — as a permanent miss. Correct, slower, and loud enough
// to find (the cache simply never hits) rather than silently wrong.
func SecretNodeCacheEpochTriggerPresent(db *gorm.DB) bool {
	if db == nil {
		return false
	}
	// A catalog query, NOT db.Migrator(): this package's own
	// sqlitedialect.Migrator.HasTable calls Row().Scan() without checking
	// Row()'s error, so it PANICS on a store whose *gorm.DB has no usable
	// connection — which several tests legitimately construct (the dialect-SQL
	// tests build a DryRun/unconnected handle on purpose). A Raw().Scan()
	// surfaces that as an error instead, and any error here means "cannot
	// confirm the trigger", i.e. false. Same reason internal/storage/factory.go
	// hand-rolls tableExists/columnExists rather than using the Migrator.
	//
	// Asking only about the TRIGGER is sufficient: its body references
	// cache_epoch, so a trigger cannot exist without the column.
	var count int64
	q := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?"
	if db.Dialector.Name() == "postgres" {
		// tgrelid = 'secret_nodes'::regclass (search_path-resolved, so this binds
		// to the SAME secret_nodes this connection would actually read) is load
		// bearing, not decorative: tgname alone matches a same-named trigger on
		// ANY table in ANY schema visible to this connection, including a
		// same-named trigger left on a table in a DIFFERENT schema of the same
		// database — which would report "present" while the real secret_nodes
		// has no trigger at all. tgenabled <> 'D' is load-bearing too: a
		// DISABLED trigger (pg_restore --disable-triggers, ALTER TABLE ...
		// DISABLE TRIGGER) still exists in pg_trigger and would otherwise read as
		// present while never actually firing. Known gap this does NOT cover:
		// session_replication_role = replica suppresses ordinary triggers for the
		// whole session without touching tgenabled, and is not checked here.
		q = "SELECT COUNT(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = 'secret_nodes'::regclass AND tgname = ? AND tgenabled <> 'D'"
	}
	if err := db.Raw(q, SecretNodeCacheEpochTrigger).Scan(&count).Error; err != nil {
		return false
	}
	return count > 0
}

// secretNodesTableExists / secretNodeCacheEpochColumnExists are raw catalog
// lookups for the same reason SecretNodeCacheEpochTriggerPresent is one: the
// Migrator path panics rather than erroring on an unusable handle. Any error is
// read as "not there", so the caller's next step is to create it — which is
// idempotent, and fails loudly if the real reason was something else.
func secretNodesTableExists(db *gorm.DB) bool {
	var count int64
	q := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'secret_nodes'"
	if db.Dialector.Name() == "postgres" {
		q = "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'secret_nodes' AND table_schema = CURRENT_SCHEMA()"
	}
	if err := db.Raw(q).Scan(&count).Error; err != nil {
		return false
	}
	return count > 0
}

func secretNodeCacheEpochColumnExists(db *gorm.DB) bool {
	var count int64
	if db.Dialector.Name() == "postgres" {
		if err := db.Raw(
			"SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'secret_nodes' AND column_name = ? AND table_schema = CURRENT_SCHEMA()",
			SecretNodeCacheEpochColumn).Scan(&count).Error; err != nil {
			return false
		}
		return count > 0
	}
	// SQLite: pragma_table_info is the portable way to ask without parsing DDL.
	if err := db.Raw(
		"SELECT COUNT(*) FROM pragma_table_info('secret_nodes') WHERE name = ?",
		SecretNodeCacheEpochColumn).Scan(&count).Error; err != nil {
		return false
	}
	return count > 0
}

// nodeStampProbe caches the one-shot answer to "does this database maintain
// cache_epoch". One query per LocalStorage, resolved on first use.
// nodeStampReprobeInterval bounds how long a store will keep STORING entries
// after the trigger has gone away. It deliberately does not bound how long a
// stale entry can be SERVED — that is zero, because the read path re-proves the
// trigger in the same query as the stamp (readLiveNodeStamp). See
// nodeStampTrusted.
const nodeStampReprobeInterval = 30 * time.Second

// nodeStampProbe is the WRITE-side trust cache: one catalog query per store per
// nodeStampReprobeInterval, rather than one per read.
//
// It was a sync.Once, and that was the bug the coordinator caught: a store that
// probed once at boot kept trusting the stamp for its whole lifetime, so a
// trigger that disappeared afterwards (another replica's migration, a restore,
// a manual DROP) left every warm replica serving pre-change rows indefinitely.
// A time-bounded re-probe closes the write side; the read side is closed
// outright, per-read, with no window at all.
type nodeStampProbe struct {
	mu        sync.Mutex
	checkedAt time.Time
	checked   bool
	trusted   bool
}

// nodeStampTrusted reports whether this store may STORE node cache entries.
// Fail-closed on every uncertainty: a derived store (nil probe) never trusts
// it, and a database with no trigger never does either.
//
// # What this is NOT load-bearing for
//
// Correctness does not rest on this answer being fresh, and saying so is the
// point: a stale `true` can only cause a pointless store — never a stale HIT —
// because every read re-proves the trigger's existence in the same query that
// reads the stamp, and refuses to hit when it is absent (readLiveNodeStamp,
// and getCachedSecret's use of its `trusted` result). A stale `false` only
// costs a window of not caching. So the re-probe interval is a cost knob, not
// a safety one, which is why 30s is a number and not an argument.
func (ls *LocalStorage) nodeStampTrusted() bool {
	if ls.nodeStampProbe == nil {
		return false
	}
	p := ls.nodeStampProbe
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.checked && time.Since(p.checkedAt) < nodeStampReprobeInterval {
		return p.trusted
	}
	p.trusted = SecretNodeCacheEpochTriggerPresent(ls.db)
	p.checkedAt = time.Now()
	p.checked = true
	return p.trusted
}

// nodeStampRead is one read of the node generation signal: the stamp, whether
// the row exists at all, and — in the SAME query — whether the trigger that
// maintains the stamp still exists.
type nodeStampRead struct {
	generation nodeGeneration
	found      bool
	// trusted is false when the cache_epoch trigger is absent, which makes the
	// stamp a frozen constant and therefore meaningless. A caller seeing
	// trusted=false must treat the read as a permanent miss: never hit, never
	// store.
	trusted bool
}

// readLiveNodeStamp reads secret_nodes.cache_epoch for id AND proves the trigger
// still exists, in ONE query and therefore at ONE snapshot.
//
// # Why the trigger check lives here and not in a separate probe
//
// A generation stamp is only a stamp because something moves it. A database
// with the COLUMN but no TRIGGER has a stamp frozen at 0 forever, so every
// cache hit serves the row as it was when first read — indefinitely, with no
// error and no symptom. Three ways that happens for real:
//
//   - A Postgres restore that omits triggers: pg_restore --disable-triggers, a
//     schema-only restore, or a dump loaded into a database whose migration has
//     not run yet all leave the column (it is a plain column) without the
//     trigger.
//   - Any test schema built with a bare db.AutoMigrate(). The column is a model
//     field so AutoMigrate creates it; the trigger is not, so it does not.
//   - An operator or a migration dropping it while replicas are warm.
//
// Checking it once per store cannot cover the third case, and covers the first
// two only if the trigger was already missing at boot. Asking in the same query
// as the stamp covers all three with no window: the answer is as of the same
// snapshot as the epoch it is validating, and it costs no extra round trip.
//
// The soft-delete scope is written out explicitly (deleted_at IS NULL) because
// this is raw SQL and therefore does not get GORM's Model() auto-scope — the
// same scope GetSecret itself relies on, so a soft-deleted row reads as
// not-found here exactly as it does there.
func readLiveNodeStamp(ctx context.Context, db *gorm.DB, id uint) (nodeStampRead, error) {
	triggerExists := "EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?)"
	if db.Dialector.Name() == "postgres" {
		// Same tgrelid + tgenabled qualification as SecretNodeCacheEpochTriggerPresent,
		// and for the same reason: tgname alone can match a same-named trigger on
		// a different table (even in a different schema), and a disabled trigger
		// still appears in pg_trigger without ever firing.
		triggerExists = "EXISTS (SELECT 1 FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = 'secret_nodes'::regclass AND tgname = ? AND tgenabled <> 'D')"
	}
	var rows []struct {
		CacheEpoch     int64
		TriggerPresent bool
	}
	q := "SELECT n.cache_epoch AS cache_epoch, " + triggerExists +
		" AS trigger_present FROM secret_nodes n WHERE n.id = ? AND n.deleted_at IS NULL"
	if err := db.WithContext(ctx).Raw(q, SecretNodeCacheEpochTrigger, id).Scan(&rows).Error; err != nil {
		return nodeStampRead{}, err
	}
	if len(rows) == 0 {
		// No row (or soft-deleted). Treated as a miss by every caller, so the
		// trigger's state is irrelevant and deliberately not reported.
		return nodeStampRead{}, nil
	}
	return nodeStampRead{
		generation: nodeGeneration{cacheEpoch: rows[0].CacheEpoch},
		found:      true,
		trusted:    rows[0].TriggerPresent,
	}, nil
}
