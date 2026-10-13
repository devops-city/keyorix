//go:build unix

package k8ssync

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FIFO-4: the agent's --config path is operator-supplied; a FIFO there must be
// refused at once, not hang the agent in open(2).
func TestLoadConfig_FIFORefusedWithoutBlocking(t *testing.T) {
	load := func(t *testing.T, path string, d time.Duration) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { _, err := LoadConfig(path); done <- err }()
		select {
		case err := <-done:
			return err
		case <-time.After(d):
			t.Fatalf("blocked on a FIFO instead of refusing it within %s", d)
			return nil
		}
	}

	fifo := filepath.Join(t.TempDir(), "cfg.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		// Release a reader still blocked in open(2) on old code.
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	dir := t.TempDir()
	reg := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(reg, []byte("keyorix_url: [unterminated"), 0o600))
	link := filepath.Join(dir, "link.yaml")
	require.NoError(t, os.Symlink(reg, link))
	fifoLink := filepath.Join(dir, "fifo-link.yaml")
	require.NoError(t, os.Symlink(fifo, fifoLink))

	for _, p := range []string{fifo, fifoLink, dir} {
		err := load(t, p, time.Second)
		require.Error(t, err, p)
		assert.Contains(t, err.Error(), "not a regular file", p)
	}
	// A regular file (and a symlink to one) is read: the failure is the YAML
	// parse, not the file kind.
	for _, p := range []string{reg, link} {
		err := load(t, p, 5*time.Second)
		require.Error(t, err, p)
		assert.Contains(t, err.Error(), "parse config", p)
		assert.NotContains(t, err.Error(), "not a regular file", p)
	}
}
