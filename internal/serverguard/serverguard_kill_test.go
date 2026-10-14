package serverguard

// serverguard_kill_test.go confirms task-4's review requirement: killing the
// process holding an AcquireExclusive lock releases it immediately (flock is
// owned by the open file description and released on process exit/crash by
// the kernel; a Postgres session-scoped advisory lock is released the
// instant its connection drops). Uses the standard Go "re-exec the test
// binary as a helper subprocess" pattern (see e.g. os/exec's own
// TestHelperProcess) rather than a separate helper binary, since the
// behavior under test is entirely inside this package.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestMain intercepts re-exec'd helper invocations (SERVERGUARD_HELPER_MODE
// set) before any normal test runs, so the child process does nothing but
// hold the lock and print a readiness line.
func TestMain(m *testing.M) {
	if mode := os.Getenv("SERVERGUARD_HELPER_MODE"); mode != "" {
		runLockHolderHelper(mode)
		return
	}
	os.Exit(m.Run())
}

func runLockHolderHelper(mode string) {
	var cfg *config.Config
	switch mode {
	case "sqlite":
		cfg = &config.Config{Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: os.Getenv("SERVERGUARD_HELPER_DB_PATH")},
		}}
	case "postgres":
		cfg = &config.Config{Storage: config.StorageConfig{
			Type:     "postgres",
			Database: config.DatabaseConfig{DSN: os.Getenv("SERVERGUARD_HELPER_DSN")},
		}}
		setTestPooler(&cfg.Storage.Database, os.Getenv("SERVERGUARD_HELPER_POOLER"))
	default:
		fmt.Fprintln(os.Stderr, "serverguard test helper: unknown SERVERGUARD_HELPER_MODE", mode)
		os.Exit(2)
	}
	lock, err := AcquireExclusive(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "serverguard test helper: AcquireExclusive failed:", err)
		os.Exit(1)
	}
	_ = lock
	fmt.Println("LOCKED")
	// NOT select{} -- with a single goroutine and nothing else runnable, Go's
	// own runtime deadlock detector proves no progress is possible and kills
	// the process itself ("fatal error: all goroutines are asleep -
	// deadlock!") almost immediately, which defeats the point: this process
	// must stay alive, holding the lock, until the PARENT test kills it.
	// time.Sleep registers a real timer, which the detector recognizes as a
	// pending event.
	time.Sleep(1 * time.Hour)
}

// startLockHolder re-execs the current test binary as a helper process that
// acquires AcquireExclusive and blocks, returning once it has confirmed (by
// reading "LOCKED" on stdout) that the lock is actually held.
func startLockHolder(t *testing.T, env []string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lock-holder helper: %v", err)
	}
	line := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			line <- scanner.Text()
		}
	}()
	select {
	case got := <-line:
		if got != "LOCKED" {
			t.Fatalf("expected helper to print LOCKED, got %q", got)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("timed out waiting for lock-holder helper to acquire the lock")
	}
	return cmd
}

func TestSQLite_KilledHolderProcess_ReleasesLock(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbPath}}}

	holder := startLockHolder(t, append(os.Environ(),
		"SERVERGUARD_HELPER_MODE=sqlite",
		"SERVERGUARD_HELPER_DB_PATH="+dbPath,
	))

	// While the helper holds it, this process's own AcquireExclusive must
	// fail (mirrors what a concurrently-started server/admin command would see).
	if _, err := AcquireExclusive(cfg); err == nil {
		_ = holder.Process.Kill()
		t.Fatal("expected AcquireExclusive to fail while the helper holds the lock")
	}

	if err := holder.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	_, _ = holder.Process.Wait()

	// Immediately after the killed process's file descriptors are reclaimed
	// by the kernel, the lock must be free -- no stale-lock cleanup needed.
	lock, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("expected AcquireExclusive to succeed immediately after the holder was killed, got: %v", err)
	}
	_ = lock.Release()
}

func TestPostgres_KilledHolderProcess_ReleasesLock(t *testing.T) {
	dsn := pgTestDSN(t)
	cfg := &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: dsn}}}

	holder := startLockHolder(t, append(os.Environ(),
		"SERVERGUARD_HELPER_MODE=postgres",
		"SERVERGUARD_HELPER_DSN="+dsn,
	))

	if _, err := AcquireExclusive(cfg); err == nil {
		_ = holder.Process.Kill()
		t.Fatal("expected AcquireExclusive to fail while the helper holds the lock")
	}

	if err := holder.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	_, _ = holder.Process.Wait()

	// Killing the process closes its Postgres connection at the OS/kernel
	// level immediately (the kernel closes the socket fd as part of process
	// teardown) -- Postgres's session-scoped advisory lock is released the
	// instant that connection drops, so this should succeed promptly, not
	// after a keepalive-timeout delay. Poll briefly rather than asserting
	// instantaneous success outright, to absorb ordinary scheduling jitter
	// without masking a REAL multi-second-or-longer delay if one exists.
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		lock, err := AcquireExclusive(cfg)
		if err == nil {
			_ = lock.Release()
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected AcquireExclusive to succeed within 5s after the holder was killed, last error: %v", lastErr)
}
