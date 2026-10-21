package admin

// admin_test.go covers acquireDatabaseLock's two distinct failure messages (#2362): a
// connect-level failure (bad credentials, unreachable host -- presence was never actually
// determined) must say so plainly, not claim a server is using the database; a genuinely
// held lock keeps the original "appears to be using this database" message. Both still fail
// closed without --force.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
)

func TestAcquireDatabaseLock_ConnectFailureSurfacesRealError(t *testing.T) {
	forceFlag = false
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "postgres",
			Database: config.DatabaseConfig{
				Host: "127.0.0.1", Port: "1", Name: "nonexistent", User: "nouser", SSLMode: "disable",
			},
		},
	}
	_, err := acquireDatabaseLock(cfg)
	if err == nil {
		t.Fatal("expected acquireDatabaseLock to fail against an unreachable Postgres host")
	}
	if !strings.Contains(err.Error(), "cannot connect to the database to check for a running server") {
		t.Fatalf("expected the real-connect-error message, got: %v", err)
	}
	if strings.Contains(err.Error(), "appears to be using this database") {
		t.Fatalf("connect failure must not be misreported as a held lock, got: %v", err)
	}
}

func TestAcquireDatabaseLock_ActuallyHeldLockSurfacesPresenceMessage(t *testing.T) {
	forceFlag = false
	setInContainer(t, true)
	dir := t.TempDir()
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: filepath.Join(dir, "secrets.db")},
		},
	}
	first, err := serverguard.AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("first AcquireExclusive: %v", err)
	}
	defer first.Release() //nolint:errcheck

	_, err = acquireDatabaseLock(cfg)
	if err == nil {
		t.Fatal("expected acquireDatabaseLock to fail while another exclusive lock is held")
	}
	if !strings.Contains(err.Error(), "appears to be using this database") {
		t.Fatalf("expected the held-lock message, got: %v", err)
	}
	// #2540: the refusal must name the documented stopped-server sequence, not
	// leave a Docker operator who ran `docker compose exec` guessing.
	for _, want := range []string{"docker compose stop backend", "docker compose run --rm backend ./keyorix-server admin", "docker compose start backend"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("held-lock message must include %q, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "cannot connect to the database to check for a running server") {
		t.Fatalf("a genuine held lock must not be reported as a connect failure, got: %v", err)
	}
}

func setInContainer(t *testing.T, v bool) {
	t.Helper()
	old := runningInContainer
	runningInContainer = func() bool { return v }
	t.Cleanup(func() { runningInContainer = old })
}

// #3524: a binary (systemd/nohup) install has no compose service; the refusal
// must say "stop the server, run again, start it" and never name docker.
func TestAcquireDatabaseLock_HeldLockHintIsNeutralOutsideAContainer(t *testing.T) {
	forceFlag = false
	setInContainer(t, false)
	dir := t.TempDir()
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: filepath.Join(dir, "secrets.db")},
		},
	}
	first, err := serverguard.AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("first AcquireExclusive: %v", err)
	}
	defer first.Release() //nolint:errcheck

	_, err = acquireDatabaseLock(cfg)
	if err == nil {
		t.Fatal("expected acquireDatabaseLock to fail while another exclusive lock is held")
	}
	msg := err.Error()
	if strings.Contains(strings.ToLower(msg), "docker") || strings.Contains(msg, "compose") {
		t.Fatalf("a non-container install must not be told to run docker commands, got: %v", err)
	}
	for _, want := range []string{"appears to be using this database", "stop the server", "start the server"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("held-lock message must include %q, got: %v", want, err)
		}
	}
}

// SQLite cannot run key_dir_lock: database, so --force still overrides a
// failed lock attempt there.
func TestAcquireDatabaseLock_ForceProceedsOnAnyFailure(t *testing.T) {
	stubLockSeams(t, func(*config.Config) error { return nil })
	forceFlag = true
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "secrets.db")},
		},
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		t.Fatalf("expected --force to proceed despite the failed lock attempt, got error: %v", err)
	}
	if lock != nil {
		t.Fatalf("expected a nil lock when --force bypasses a failed acquisition, got: %v", lock)
	}
}

// Fail closed (HA-READY-1 review): on PostgreSQL, --force needs a successful
// read of the replicas' key_dir_lock record. A database that cannot be opened
// leaves the record unverified, so --force is refused, not let through.
func TestAcquireDatabaseLock_ForceRefusedWhenKeyDirLockRecordUnreadable(t *testing.T) {
	forceFlag = true
	defer func() { forceFlag = false }()
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "postgres",
			Database: config.DatabaseConfig{
				Host: "127.0.0.1", Port: "1", Name: "nonexistent", User: "nouser", SSLMode: "disable",
			},
		},
	}
	lock, err := acquireDatabaseLock(cfg)
	if err == nil {
		t.Fatalf("--force proceeded although the key_dir_lock record could not be read (lock=%v)", lock)
	}
	if !strings.Contains(err.Error(), "--force cannot override it: whether the replicas run with storage.encryption.key_dir_lock: database could not be verified") {
		t.Fatalf("unexpected refusal wording: %v", err)
	}
}

// storage.encryption.key_dir_lock: database (docs/multi-replica-keys.md): live
// replicas hold no key-directory flock, so --force must not drop the exclusive
// lock, whatever the database says.
func TestAcquireDatabaseLock_ForceRefusedWithDatabaseKeyDirLock(t *testing.T) {
	forceFlag = true
	defer func() { forceFlag = false }()
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "postgres",
			Database: config.DatabaseConfig{
				Host: "127.0.0.1", Port: "1", Name: "nonexistent", User: "nouser", SSLMode: "disable",
			},
			Encryption: config.EncryptionConfig{KeyDirLock: config.KeyDirLockDatabase},
		},
	}
	lock, err := acquireDatabaseLock(cfg)
	if err == nil {
		t.Fatalf("--force proceeded with key_dir_lock: database (lock=%v)", lock)
	}
	if !strings.Contains(err.Error(), "--force cannot override it with storage.encryption.key_dir_lock: database") {
		t.Fatalf("unexpected refusal wording: %v", err)
	}
}
