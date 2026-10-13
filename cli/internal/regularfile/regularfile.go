// Package regularfile is the one way the CLI opens an operator-named input file
// (bundle, license, key, template, import source, ...) for reading.
//
// A plain os.Open / os.ReadFile blocks in open(2) on a FIFO until a writer appears,
// so a mis-pointed path hangs the command silently. Open opens non-blocking, fstats
// the SAME descriptor and refuses anything that is not a regular file (FIFO, device,
// socket, directory). A symlink to a regular file still works: the open follows it
// (Kubernetes Secret volumes expose every key as one).
//
// This is the cli module's counterpart of internal/secretenv.OpenRegular. It is a
// separate copy on purpose: this module must not import the main module's internal
// packages (ADR-108 Decision A, enforced by cli/internal/depguard). Keep the two in
// step. cli/internal/regularfile/guard_test.go fails when a read in cli/ bypasses it.
package regularfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// ErrNotRegular is wrapped by Open and ReadFile for a FIFO, device, socket or directory.
var ErrNotRegular = errors.New("not a regular file")

// Open opens path read-only and returns the file with its fstat info. what names the
// input for the error text ("bundle", "license file", ...): a refusal reads
// "<what> <path>: not a regular file". Other open errors are returned unchanged so
// callers keep their own wrapping.
func Open(what, path string) (*os.File, os.FileInfo, error) {
	return OpenFlags(what, path, 0)
}

// OpenFlags is Open with extraFlags OR-ed into the open flags (e.g. O_NOFOLLOW for a
// caller that refuses a symlink).
func OpenFlags(what, path string, extraFlags int) (*os.File, os.FileInfo, error) {
	// O_NONBLOCK returns at once on a FIFO instead of waiting for a writer; on a
	// regular file it changes nothing.
	// #nosec G304 G703 -- path is an operator-supplied CLI flag/argument; the file must
	// be a regular file, checked on the same descriptor below.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|extraFlags, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s %s: %w", what, path, ErrNotRegular)
	}
	return f, info, nil
}

// ReadFile is os.ReadFile for an operator-named file, refusing a non-regular one
// without blocking.
func ReadFile(what, path string) ([]byte, error) {
	f, _, err := Open(what, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}
