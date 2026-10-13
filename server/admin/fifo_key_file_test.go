package admin

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The backup key-file reader and --checkpoint-key-file must refuse a FIFO, not
// block in open(2) (REVIEW-3161 / FIFO-2).
func TestKeyFileReaders_FIFO_RefuseWithoutBlocking(t *testing.T) {
	readers := map[string]func(string) error{
		"readKeyFile":           func(p string) error { _, err := readKeyFile(p); return err },
		"readCheckpointKeyFile": func(p string) error { _, err := readCheckpointKeyFile(p); return err },
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "fifo")
			require.NoError(t, syscall.Mkfifo(p, 0o600))
			t.Cleanup(func() {
				if f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = f.Close()
				}
			})
			done := make(chan error, 1)
			go func() { done <- read(p) }()
			select {
			case err := <-done:
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not a regular file")
			case <-time.After(5 * time.Second):
				t.Fatal("blocked opening a FIFO instead of refusing it")
			}
		})
	}
}
