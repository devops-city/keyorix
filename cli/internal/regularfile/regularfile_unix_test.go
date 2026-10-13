//go:build unix

package regularfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// within1s runs fn and fails the test if it does not return within a second (a FIFO
// blocking in open(2)). On timeout it opens the FIFO itself so the stuck goroutine and
// the temp dir can go.
func within1s(t *testing.T, fifo string, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatal("blocked on a FIFO instead of refusing it within 1s")
		return nil
	}
}

func TestOpenAndReadFile_RefuseFIFOAndDirectory(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "in.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"fifo": fifo, "symlink to fifo": link, "directory": t.TempDir()} {
		t.Run(name, func(t *testing.T) {
			err := within1s(t, fifo, func() error { _, err := ReadFile("thing", path); return err })
			if !errors.Is(err, ErrNotRegular) || !strings.Contains(err.Error(), "thing "+path+": not a regular file") {
				t.Fatalf("ReadFile error = %v, want %q naming the path", err, "thing "+path+": not a regular file")
			}
			err = within1s(t, fifo, func() error { _, _, err := Open("thing", path); return err })
			if !errors.Is(err, ErrNotRegular) {
				t.Fatalf("Open error = %v, want ErrNotRegular", err)
			}
		})
	}
}

func TestReadFile_RegularFileAndSymlinkStillWork(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "l")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p, link} {
		b, err := ReadFile("thing", path)
		if err != nil || string(b) != "hello" {
			t.Fatalf("ReadFile(%s) = %q, %v", path, b, err)
		}
	}
	if _, err := ReadFile("thing", filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v, want ErrNotExist", err)
	}
}
