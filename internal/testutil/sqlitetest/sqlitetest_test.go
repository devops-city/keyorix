// sqlitetest_test.go is both halves of the measurement this package's doc
// comment cites: Open's pool cap must make "database table is locked"
// unreachable (the guard), and the uncapped pool this repo's test helpers used
// before #2906 must still be able to produce it (the control, so the guard
// cannot pass vacuously if SQLite or the driver changes under us).
package sqlitetest

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const hammerDuration = 2 * time.Second
const hammerGoroutines = 8

// migrate builds the two tables hammer uses. Deliberately raw SQL rather than
// internal/storage/models: this package must stay a leaf that any test package
// can import without dragging the model graph in.
func migrate(tb testing.TB, db *gorm.DB) {
	tb.Helper()
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT)`,
		`CREATE TABLE IF NOT EXISTS attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			tb.Fatalf("migrate: %v", err)
		}
	}
}

// hammerResult counts the two things worth separating: the specific
// shared-cache lock failure, and any other error at all.
type hammerResult struct {
	locked int
	other  int
	sample string
}

// hammer drives the read / write / read-then-write-in-one-transaction mix a
// handler test plus its detached goSafe audit writers produce, from several
// goroutines at once on the SAME tables — the shape that makes a shared-cache
// table-lock collision reachable.
func hammer(db *gorm.DB) hammerResult {
	var locked, other atomic.Int64
	var sample atomic.Value
	var wg sync.WaitGroup
	deadline := time.Now().Add(hammerDuration)
	for g := range hammerGoroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				var err error
				switch g % 4 {
				case 0:
					err = db.Exec(`INSERT INTO events (kind) VALUES ('w')`).Error
				case 1:
					var n int64
					err = db.Raw(`SELECT COUNT(*) FROM events`).Scan(&n).Error
				case 2:
					err = db.Transaction(func(tx *gorm.DB) error {
						var n int64
						if e := tx.Raw(`SELECT COUNT(*) FROM events`).Scan(&n).Error; e != nil {
							return e
						}
						return tx.Exec(`INSERT INTO events (kind) VALUES ('tx')`).Error
					})
				case 3:
					err = db.Exec(`INSERT INTO attempts (ip) VALUES ('1.2.3.4')`).Error
				}
				if err == nil {
					continue
				}
				sample.Store(err.Error())
				if strings.Contains(err.Error(), "table is locked") || strings.Contains(err.Error(), "database is locked") {
					locked.Add(1)
				} else {
					other.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	s, _ := sample.Load().(string)
	return hammerResult{locked: int(locked.Load()), other: int(other.Load()), sample: s}
}

// TestOpen_ConcurrentAccessIsNeverLocked is the guard: the whole point of this
// package is that a test using it cannot hit #2906's flake.
func TestOpen_ConcurrentAccessIsNeverLocked(t *testing.T) {
	db := Open(t, "sqlitetestguard")
	migrate(t, db)

	got := hammer(db)
	if got.locked != 0 {
		t.Errorf("Open's DB produced %d shared-cache lock failures under concurrent access — the pool cap is not holding (sample: %s)", got.locked, got.sample)
	}
	if got.other != 0 {
		t.Errorf("Open's DB produced %d other errors under concurrent access (sample: %s)", got.other, got.sample)
	}
}

// TestUncappedSharedCachePool_StillLocks is the control. Without it the guard
// above could pass because SQLite stopped raising SQLITE_LOCKED at all, or
// because `hammer` stopped actually running anything concurrently — either way
// the guard would be verifying nothing. This replicates the pre-#2906 helper
// shape EXACTLY, `_timeout=30000` and all, and requires it to still fail: that
// timeout drives the busy handler, which shared-cache SQLITE_LOCKED never
// consults.
func TestUncappedSharedCachePool_StillLocks(t *testing.T) {
	dsn := fmt.Sprintf("file:sqlitetestcontrol%d?mode=memory&cache=shared&_timeout=30000", dbSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	migrate(t, db)

	got := hammer(db)
	if got.locked == 0 {
		t.Errorf("an UNCAPPED shared-cache pool produced no lock failures — this control is what keeps "+
			"TestOpen_ConcurrentAccessIsNeverLocked from passing vacuously, so it going quiet means the "+
			"guard needs rebuilding, not that the problem is gone (other errors: %d, sample: %q)",
			got.other, got.sample)
	}
	t.Logf("control: %d lock failures on an uncapped pool in %s (sample: %q)", got.locked, hammerDuration, got.sample)
}

// TestOpen_CapsThePoolToOneConnection pins the mechanism itself, so a future
// edit that drops SetMaxOpenConns fails here with a clear reason rather than
// only as a rare flake somewhere else in the tree.
func TestOpen_CapsThePoolToOneConnection(t *testing.T) {
	db := Open(t, "sqlitetestpool")
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	if got := sqlDB.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1 — a shared-cache in-memory DB must be reached through exactly one connection", got)
	}
}

// TestOpen_EachCallIsAnIsolatedDatabase pins the other half of the contract:
// shared-cache names are process-global, so a fixed name would silently make
// two tests share state. Two Opens must not see each other's rows.
func TestOpen_EachCallIsAnIsolatedDatabase(t *testing.T) {
	a := Open(t, "sqlitetestiso")
	b := Open(t, "sqlitetestiso")
	migrate(t, a)
	migrate(t, b)

	if err := a.Exec(`INSERT INTO events (kind) VALUES ('only-in-a')`).Error; err != nil {
		t.Fatalf("insert: %v", err)
	}
	var n int64
	if err := b.Raw(`SELECT COUNT(*) FROM events`).Scan(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("the second Open saw %d row(s) written through the first — the two share a database", n)
	}
}
