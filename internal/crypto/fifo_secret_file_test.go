package crypto

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A FIFO at a KEK / Shamir share / --passphrase-file path must be refused, not
// block in open(2) until a writer shows up (a 0600 FIFO passes the mode check, so
// the hang used to hit after it). REVIEW-3161 / FIFO-2.
func TestSecretFileReaders_FIFO_RefuseWithoutBlocking(t *testing.T) {
	readers := map[string]func(path string) error{
		"FileKeyProvider.KEK": func(p string) error { _, err := NewFileKeyProvider(p).KEK(); return err },
		"ShamirKeyProvider.KEK": func(p string) error {
			_, err := NewShamirKeyProvider([]string{p, p}, nil, "").KEK()
			return err
		},
		"readPassphraseFile": func(p string) error { _, err := readPassphraseFile(p); return err },
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "fifo")
			require.NoError(t, syscall.Mkfifo(p, 0o600))
			t.Cleanup(func() {
				// Pre-fix the reader is stuck in open(2): a non-blocking writer open
				// releases it so the goroutine does not leak.
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
