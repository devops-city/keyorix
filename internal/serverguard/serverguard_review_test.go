package serverguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// REVIEW-COVERAGE-2: the presence lock is only a guard if a server and an admin
// command that use the same database always meet on the same lock, however the
// config spells the storage type and the database path.

// TestStorageTypeAliases_MeetOnTheSameLock: every spelling internal/storage's
// factory accepts for SQLite ("local", "sqlite"; the server maps "" to "local")
// guards the same sidecar lock, so a server configured with one spelling and
// an admin command with another still exclude each other.
func TestStorageTypeAliases_MeetOnTheSameLock(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secrets.db")
	cfgFor := func(typ string) *config.Config {
		return &config.Config{Storage: config.StorageConfig{Type: typ, Database: config.DatabaseConfig{Path: dbPath}}}
	}
	for _, server := range []string{"local", "sqlite", ""} {
		for _, admin := range []string{"local", "sqlite", ""} {
			p, err := AcquirePresence(cfgFor(server))
			if err != nil {
				t.Fatalf("AcquirePresence(%q): %v", server, err)
			}
			if x, err := AcquireExclusive(cfgFor(admin)); err == nil {
				_ = x.Release()
				t.Errorf("a server on type %q and an admin command on type %q both held the lock", server, admin)
			} else if !IsLockHeld(err) {
				t.Errorf("type %q vs %q: want a lock-held refusal, got %v", server, admin, err)
			}
			_ = p.Release()
		}
	}
}

// TestPostgresTypeAliases_NeverFallBackToAFileLock: "postgres" and
// "postgresql" both go to the database's advisory lock. Against a database that
// cannot be reached the result is a connection error, never a silently
// granted file lock next to an unrelated path.
func TestPostgresTypeAliases_NeverFallBackToAFileLock(t *testing.T) {
	dir := t.TempDir()
	for _, typ := range []string{"postgres", "postgresql"} {
		cfg := &config.Config{Storage: config.StorageConfig{Type: typ, Database: config.DatabaseConfig{
			Host: "127.0.0.1", Port: "1", Name: "kx", User: "kx", Password: "x", SSLMode: "disable",
			Path: filepath.Join(dir, "secrets.db"),
		}}}
		if x, err := AcquireExclusive(cfg); err == nil {
			_ = x.Release()
			t.Errorf("type %q: AcquireExclusive succeeded against an unreachable PostgreSQL", typ)
		} else if IsLockHeld(err) {
			t.Errorf("type %q: a connection failure was reported as a held lock: %v", typ, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "secrets.db"+serverLockSuffix)); err == nil {
			t.Errorf("type %q created a SQLite sidecar lock", typ)
		}
	}
}

// TestSQLitePathSpellings_MeetOnTheSameLock: relative and absolute spellings,
// "." and ".." segments, DSN query parameters and a symlinked directory all
// name the same sidecar lock file, because the lock lives in the database's
// own directory.
//
// Not covered (documented in the package's Limits): a symlink to the database
// FILE itself, or a hard link, used by one side only. The two sides then lock
// different sidecar files.
func TestSQLitePathSpellings_MeetOnTheSameLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "data"), link); err != nil {
		t.Fatal(err)
	}
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(filepath.Join(dir, "data")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	canonical := filepath.Join(dir, "data", "secrets.db")
	spellings := []string{
		"secrets.db",
		"./secrets.db",
		"sub/../secrets.db",
		filepath.Join(dir, "data", ".", "secrets.db"),
		filepath.Join(link, "secrets.db"),
		canonical + "?_busy_timeout=5000",
	}
	cfgFor := func(p string) *config.Config {
		return &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: p}}}
	}
	for _, s := range spellings {
		p, err := AcquirePresence(cfgFor(canonical))
		if err != nil {
			t.Fatal(err)
		}
		if x, err := AcquireExclusive(cfgFor(s)); err == nil {
			_ = x.Release()
			t.Errorf("a server on %q and an admin command on %q both held the lock", canonical, s)
		}
		_ = p.Release()
	}
}
