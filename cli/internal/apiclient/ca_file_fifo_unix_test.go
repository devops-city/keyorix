//go:build unix

package apiclient

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO named as the CA file must be refused at once, not hang the CLI in open(2)
// waiting for a writer. Red on the old os.Open code (the call never returns), green
// with the non-blocking open + fstat.
func TestLoadCAPool_FIFORefusedWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ca.fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := LoadCAPool(p)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("LoadCAPool on a FIFO succeeded, want an error")
		}
		if !strings.Contains(err.Error(), "not a regular file") || !strings.Contains(err.Error(), p) {
			t.Fatalf("error = %v, want it to name the path and %q", err, "not a regular file")
		}
	case <-time.After(time.Second):
		// Unblock the stuck open(2) so the leaked goroutine and the temp dir can go.
		if f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatal("LoadCAPool blocked on a FIFO instead of refusing it within 1s")
	}
}

// Other non-regular files (a directory) are refused with the same message.
func TestLoadCAPool_DirectoryRefused(t *testing.T) {
	_, err := LoadCAPool(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("LoadCAPool(dir) error = %v, want %q", err, "not a regular file")
	}
}

// A regular file still loads, directly and through a symlink (Kubernetes Secret volumes
// expose each key as a symlink into ..data/).
func TestLoadCAPool_RegularFileAndSymlinkStillWork(t *testing.T) {
	srv := newTLSServer(t)
	p := writeServerCA(t, srv, 0o644)
	if _, err := LoadCAPool(p); err != nil {
		t.Fatalf("regular file: %v", err)
	}
	link := filepath.Join(t.TempDir(), "ca-link.pem")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCAPool(link); err != nil {
		t.Fatalf("symlink to a regular file: %v", err)
	}
	// A symlink to a FIFO is refused too (the open follows it, fstat sees the FIFO).
	fifo := filepath.Join(t.TempDir(), "f")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	flink := filepath.Join(t.TempDir(), "fifo-link.pem")
	if err := os.Symlink(fifo, flink); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCAPool(flink)
	if err == nil || errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink to FIFO: error = %v, want %q", err, "not a regular file")
	}
}
