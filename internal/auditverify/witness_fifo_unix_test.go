//go:build unix

package auditverify

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// FIFO-6: ReadWitness must refuse a non-regular witness path at once instead of
// blocking in open(2) (a plain os.ReadFile waits for a writer on a FIFO), and must
// not mistake it for "no witness yet".
func TestReadWitness_FIFORefusedWithoutBlocking(t *testing.T) {
	type result struct {
		found bool
		err   error
	}
	read := func(t *testing.T, path string, d time.Duration) result {
		t.Helper()
		done := make(chan result, 1)
		go func() {
			_, _, found, err := ReadWitness(path)
			done <- result{found, err}
		}()
		select {
		case r := <-done:
			return r
		case <-time.After(d):
			t.Fatalf("blocked on a FIFO instead of refusing it within %s", d)
			return result{}
		}
	}

	dir := t.TempDir()
	fifo := filepath.Join(dir, "witness.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Release a reader still blocked in open(2) on old code.
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	fifoLink := filepath.Join(dir, "witness-fifo-link")
	if err := os.Symlink(fifo, fifoLink); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "witness-dir")
	if err := os.Mkdir(subdir, 0o750); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{fifo, fifoLink, subdir} {
		r := read(t, p, time.Second)
		if r.err == nil || r.found {
			t.Fatalf("%s: want a refusal, got found=%v err=%v", p, r.found, r.err)
		}
		if want := "witness file " + p + ": not a regular file"; !strings.Contains(r.err.Error(), want) {
			t.Errorf("%s: error %q does not contain %q", p, r.err, want)
		}
	}

	reg := filepath.Join(dir, AuditHighWaterWitnessFileName)
	if err := os.WriteFile(reg, []byte(encodeHighWaterForTest(7)), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "witness-link")
	if err := os.Symlink(reg, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{reg, link} {
		r := read(t, p, 5*time.Second)
		if r.err != nil || !r.found {
			t.Errorf("%s: want found, got found=%v err=%v", p, r.found, r.err)
		}
	}
}
