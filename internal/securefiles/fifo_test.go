package securefiles

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SafeReadFile reads the DEK, salt, wrapped KEK and TPM blob. A FIFO at one of
// those paths must be refused, not block in open(2) (REVIEW-3161 / FIFO-2).
func TestSafeReadFile_FIFO_RefusesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dek.bin")
	require.NoError(t, syscall.Mkfifo(p, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	done := make(chan error, 1)
	go func() { _, err := SafeReadFile(dir, "dek.bin"); done <- err }()
	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("blocked opening a FIFO instead of refusing it")
	}
}

// FixFilePerms opens each key file to fix its mode; a FIFO there must not hang it.
func TestFixFilePerms_FIFO_DoesNotBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kek.key")
	require.NoError(t, syscall.Mkfifo(p, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	done := make(chan error, 1)
	go func() { done <- FixFilePerms([]FilePermSpec{{Path: p, Mode: 0o600}}, false) }()
	select {
	case err := <-done:
		require.Error(t, err, "an unfixable (non-regular) key file is reported, not skipped")
	case <-time.After(5 * time.Second):
		t.Fatal("blocked opening a FIFO instead of refusing it")
	}
}
