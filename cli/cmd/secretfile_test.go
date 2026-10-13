package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO named by NAME_FILE must be refused as "not a regular file", not hang
// `system init`: os.Open on a FIFO blocks until a writer appears, before the
// regular-file check could run. Same rule as internal/secretenv.
func TestLookupSecretEnv_FIFO_RefusesWithoutBlocking(t *testing.T) {
	const name = "KEYORIX_TEST_CLI_SECRETFILE"
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(name, "")
	t.Setenv(name+"_FILE", p)
	t.Cleanup(func() {
		// Pre-fix, the reader is stuck in open(2): a non-blocking writer open
		// releases it so the goroutine does not leak.
		if f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	done := make(chan error, 1)
	go func() { _, _, err := lookupSecretEnv(name); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("want a not-a-regular-file error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked opening a FIFO instead of refusing it")
	}
}

func TestLookupSecretEnv_FileRules(t *testing.T) {
	const name = "KEYORIX_TEST_CLI_SECRETFILE"
	write := func(t *testing.T, content string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("one terminator stripped", func(t *testing.T) {
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", write(t, "pw\r\n", 0o600))
		v, found, err := lookupSecretEnv(name)
		if err != nil || !found || v != "pw" {
			t.Fatalf("got %q %v %v", v, found, err)
		}
	})
	t.Run("both set refused", func(t *testing.T) {
		t.Setenv(name, "direct")
		t.Setenv(name+"_FILE", write(t, "pw", 0o600))
		if _, _, err := lookupSecretEnv(name); err == nil {
			t.Fatal("both NAME and NAME_FILE set must be refused")
		}
	})
	t.Run("world-readable refused, contents not echoed", func(t *testing.T) {
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", write(t, "do-not-echo-me", 0o644))
		_, _, err := lookupSecretEnv(name)
		if err == nil || strings.Contains(err.Error(), "do-not-echo-me") {
			t.Fatalf("want a mode error without the contents, got %v", err)
		}
	})
	t.Run("empty refused", func(t *testing.T) {
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", write(t, "\n", 0o600))
		if _, _, err := lookupSecretEnv(name); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("want an empty-file error, got %v", err)
		}
	})
}
