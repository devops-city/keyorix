//go:build unix

package config

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A FIFO named as ssl_root_cert is refused, not opened and waited on: a
// blocking open(2) on a FIFO with no writer never returns, which would hang
// server boot (and every ResolvePostgresConnConfig caller) instead of failing closed.
func TestLoadDatabaseCAPool_FIFORefusedWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, syscall.Mkfifo(fifo, 0o644))

	done := make(chan error, 1)
	go func() {
		_, _, err := LoadDatabaseCAPool(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a regular file")
	case <-time.After(30 * time.Second):
		t.Fatal("LoadDatabaseCAPool blocked opening a FIFO with no writer")
	}
}
