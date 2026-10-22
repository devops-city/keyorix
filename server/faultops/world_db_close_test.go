package faultops

import "testing"

// FLAKE-4: openWorldDB's connection pool is released when the test that opened it
// finishes. The Postgres branch already closed its pool on cleanup; the SQLite branch
// did not, so every world a fuzz run built (two per iteration) left an open
// in-memory database behind until the process exited.
func TestOpenWorldDB_ClosesPoolOnCleanup(t *testing.T) {
	var leaked interface{ Ping() error }

	t.Run("owner", func(t *testing.T) {
		db, _ := openWorldDB(t)
		sqlDB, err := db.DB()
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlDB.Ping(); err != nil {
			t.Fatalf("pool unusable while the owning test is still running: %v", err)
		}
		leaked = sqlDB
	})

	// The subtest's cleanups have run by now: a closed pool refuses to ping.
	if err := leaked.Ping(); err == nil {
		t.Fatal("world DB pool still open after its test finished (connection leak)")
	}
}
