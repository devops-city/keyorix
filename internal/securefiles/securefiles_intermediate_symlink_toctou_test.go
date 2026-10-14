package securefiles

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSecureWriteFileSync_TOCTOUIntermediateComponentSymlinkNeverFollowed is the
// regression test for a TOCTOU race distinct from TestFixFilePerms_TOCTOUSymlinkSwapNeverFollowed
// above: isPathInsideBase/resolveInside can only resolve symlinks up to the longest
// EXISTING ancestor at check time, so a NOT-YET-EXISTING intermediate path component
// (here "tenant" in "tenant/secret.bin") is passed through the containment check
// unresolved. A bare O_NOFOLLOW on the final os.OpenFile call only protects the FINAL
// path component ("secret.bin") — it does nothing to stop an attacker who, in the
// window between the containment check and that final open, plants the INTERMEDIATE
// component ("tenant") as a symlink pointing outside baseDir: O_NOFOLLOW never sees it,
// because it isn't the component actually being opened with O_CREATE.
//
// This test hammers that exact window: one goroutine repeatedly removes "tenant" (so
// the containment check sees it as absent, its precondition) and replants it as a
// symlink pointing at a directory OUTSIDE base (the attacker's payload), while another
// goroutine repeatedly calls SecureWriteFileSync(base, "tenant/secret.bin", ...).
// Throughout, no file may ever be created inside the outside directory — proving the
// write path never traverses the symlinked intermediate component, regardless of when
// it gets swapped in relative to the containment check.
//
// Against the pre-fix implementation (a single os.OpenFile(cleanPath,
// O_WRONLY|O_CREATE|O_TRUNC|O_NOFOLLOW, perm) call after resolveInside), this
// reproduces the escape: when the writer's OpenFile call lands while "tenant" is
// symlinked, O_NOFOLLOW only guards "secret.bin" and the open follows "tenant" straight
// into the outside directory, creating secret.bin there. Against the fix
// (SecureOpenBeneath's per-component O_NOFOLLOW walk via openat), every attempt to
// traverse "tenant" while it is a symlink is refused outright (ELOOP), so the outside
// directory must remain empty for the whole test.
func TestSecureWriteFileSync_TOCTOUIntermediateComponentSymlinkNeverFollowed(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir() // attacker's target: NOT under base
	tenantPath := filepath.Join(base, "tenant")
	relPath := filepath.Join("tenant", "secret.bin")

	const iterations = 4000
	var stop atomic.Int32

	// require/assert's fatal helpers are documented as unsafe from a non-test goroutine;
	// this goroutine only performs best-effort filesystem toggling, so errors are simply
	// ignored (a failed Remove/Symlink just means that iteration doesn't hit the race
	// window, which does not invalidate the test).
	var wg sync.WaitGroup
	wg.Go(func() {
		defer stop.Store(1)
		for range iterations {
			// State A: "tenant" does not exist — the precondition the containment
			// check's "longest existing ancestor" logic requires to pass through the
			// not-yet-existing tail unresolved.
			_ = os.Remove(tenantPath)
			// State B: "tenant" is a symlink pointing OUTSIDE base — the attacker's
			// payload, planted as fast as possible after state A so the writer's
			// check-then-open window has maximum chance of straddling the swap.
			_ = os.Symlink(outside, tenantPath)
		}
		_ = os.Remove(tenantPath)
	})

	for stop.Load() == 0 {
		// Either outcome is acceptable here — ENOENT (tenant absent), access-denied
		// (tenant existed as a symlink at check time, caught by the pre-check), or a
		// refused-symlink error from the open walk. The only unacceptable outcome is
		// silently succeeding while having written outside base, which the final
		// assertion below checks for directly.
		_ = SecureWriteFileSync(base, relPath, []byte("tenant-secret-bytes"), 0600)
	}
	wg.Wait()

	_, statErr := os.Stat(filepath.Join(outside, "secret.bin"))
	assert.True(t, os.IsNotExist(statErr), "a write through a racily-symlinked INTERMEDIATE path component must never escape baseDir, even though the component did not exist when the containment check ran")
}

// TestSecureWriteFile_TOCTOUIntermediateComponentSymlinkNeverFollowed is the same
// race as above but against SecureWriteFile (the non-fsync variant), which shares the
// same resolveInside-then-open code shape and so must share the same protection.
func TestSecureWriteFile_TOCTOUIntermediateComponentSymlinkNeverFollowed(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	tenantPath := filepath.Join(base, "tenant")
	relPath := filepath.Join("tenant", "secret.bin")

	const iterations = 4000
	var stop atomic.Int32

	var wg sync.WaitGroup
	wg.Go(func() {
		defer stop.Store(1)
		for range iterations {
			_ = os.Remove(tenantPath)
			_ = os.Symlink(outside, tenantPath)
		}
		_ = os.Remove(tenantPath)
	})

	for stop.Load() == 0 {
		_ = SecureWriteFile(base, relPath, []byte("tenant-secret-bytes"), 0600)
	}
	wg.Wait()

	_, statErr := os.Stat(filepath.Join(outside, "secret.bin"))
	assert.True(t, os.IsNotExist(statErr), "a write through a racily-symlinked INTERMEDIATE path component must never escape baseDir, even though the component did not exist when the containment check ran")
}
