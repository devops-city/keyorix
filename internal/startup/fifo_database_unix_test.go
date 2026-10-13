//go:build unix

package startup

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// FIFO-4: the startup database reachability check opens storage.database.path; a
// FIFO there must be refused at once, not hang the validation in open(2).
func TestValidateDatabase_FIFORefusedWithoutBlocking(t *testing.T) {
	check := func(t *testing.T, path string, d time.Duration) error {
		t.Helper()
		cfg := &config.Config{}
		cfg.Storage.Database.Path = path
		done := make(chan error, 1)
		go func() { done <- validateDatabase(cfg, &ValidationResult{}) }()
		select {
		case err := <-done:
			return err
		case <-time.After(d):
			t.Fatalf("blocked on a FIFO instead of refusing it within %s", d)
			return nil
		}
	}

	fifo := filepath.Join(t.TempDir(), "db.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		// Release a reader still blocked in open(2) on old code.
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	dir := t.TempDir()
	reg := filepath.Join(dir, "keyorix.db")
	require.NoError(t, os.WriteFile(reg, []byte("data"), 0o600))
	link := filepath.Join(dir, "link.db")
	require.NoError(t, os.Symlink(reg, link))
	fifoLink := filepath.Join(dir, "fifo-link.db")
	require.NoError(t, os.Symlink(fifo, fifoLink))

	for _, p := range []string{fifo, fifoLink} {
		err := check(t, p, time.Second)
		require.Error(t, err, p)
		assert.Contains(t, err.Error(), "not a regular file", p)
	}
	for _, p := range []string{reg, link} {
		assert.NoError(t, check(t, p, 5*time.Second), p)
	}
}
