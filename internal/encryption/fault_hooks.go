// fault_hooks.go — a nil-in-production seam for fault-injection testing of the
// durability primitives KEK rotation and DEK rewrap use to persist key material
// (write-pending → rename → fsync).
//
// Distinct from rotation_crash_hooks.go's rotationCheckpoint (which interrupts
// BETWEEN two completed steps, modeling a process crash that skips the rest of the
// function): this hook replaces a chosen step's REAL outcome with an injected
// environment failure — ENOSPC/EIO/short write on the write itself, or an error at
// the rename/fsync call — modeling the disk or filesystem failing WHILE the process
// keeps running and the function's own error-return paths still execute. See
// FuzzFaultInjectedOperations.
//
// In production fileFaultHook is nil and every durableXxx helper below falls
// straight through to the real securefiles/os call, so this adds nothing to the hot
// path and changes no behavior.
package encryption

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// fileFaultKind enumerates the injectable failure shapes for a single durability
// step. Which kinds are meaningful for a given seam (write vs. rename vs. sync)
// varies — see each durableXxx helper.
type fileFaultKind int

const (
	// faultCleanError: the real underlying effect never happens — zero bytes reach
	// a write's target file, a rename is never attempted. Models ENOSPC/EIO/EROFS
	// detected before touching the file, or open()/rename() itself failing outright.
	// This is always a BEFORE-COMMIT fault: the function returns an error and every
	// caller in this package aborts without proceeding to the next durability step,
	// so the on-disk state this seam targets is deterministically unchanged.
	faultCleanError fileFaultKind = iota
	// faultShortWrite: exactly K of the real bytes are written to the real file
	// (no fsync), then the call reports an error — a short write(2), not a clean
	// failure. Meaningful for write seams only. Like faultCleanError this is
	// BEFORE-COMMIT: every write seam in this package targets a *.pending file
	// that is never renamed into place unless the write call returns nil, so a
	// short/corrupt .pending file never becomes the active one.
	faultShortWrite
	// faultRealEffectThenError: the real underlying effect (the full write, or the
	// rename, or — conceptually — the directory fsync) DOES happen for real, but
	// the call still reports an error, exactly as a real fsync(2)/rename(2) can
	// report EIO after the kernel has already applied the change, or as a crash
	// racing the return path can leave an operation's true outcome ambiguous to
	// its caller. This is the AMBIGUOUS class from the STEP 2 fault-model spec: a
	// caller cannot tell, from the error alone, whether the change is durable — the
	// oracle must accept EITHER the pre-change or the post-change state as valid,
	// and must reject anything that is neither (a torn/inconsistent state).
	faultRealEffectThenError
)

// fileFault is one injected failure: fail seam's next real durability call with
// kind, using k as the short-write byte count (ignored for other kinds) and err as
// the error the call should report.
type fileFault struct {
	kind fileFaultKind
	k    int
	err  error
}

// fileFaultHook, when non-nil, is consulted by every durableXxx helper below
// before it performs a real durability-critical file operation. It receives the
// seam's stable label (the same vocabulary rotationCheckpoint already uses, e.g.
// "kek:write-dek-pending") and returns the fault to apply, or nil to run for real.
// Set only by FuzzFaultInjectedOperations and its unit-test siblings, in this
// package's own _test.go files; nil in every production build.
var fileFaultHook func(seam string) *fileFault

// durableWriteSync performs securefiles.SecureWriteFileSync at seam, honoring
// fileFaultHook. A short-write fault writes the real file directly (bypassing
// securefiles' O_NOFOLLOW walk, irrelevant to what's under test here — every
// caller passes a fixed internal key-directory path, not attacker input) so the
// ACTUAL on-disk bytes after the fault are exactly what a real short write(2)
// would leave: a partial prefix of data, never fsynced.
func durableWriteSync(baseDir, path string, data []byte, perm os.FileMode, seam string) error {
	if fileFaultHook != nil {
		if f := fileFaultHook(seam); f != nil {
			return applyWriteFault(baseDir, path, data, perm, f)
		}
	}
	return securefiles.SecureWriteFileSync(baseDir, path, data, perm)
}

// durableRename performs os.Rename at seam, honoring fileFaultHook. For
// faultRealEffectThenError the real rename IS performed (the ambiguous case: the
// rename may have truly landed before the reported error); for faultCleanError it
// is not (deterministic no-op); faultShortWrite is not meaningful for a rename and
// is treated as faultCleanError by every caller (no caller constructs it here).
func durableRename(oldPath, newPath, seam string) error {
	if fileFaultHook != nil {
		if f := fileFaultHook(seam); f != nil {
			if f.kind == faultRealEffectThenError {
				if rerr := os.Rename(oldPath, newPath); rerr != nil {
					return rerr // a REAL failure reason takes precedence over the injected one
				}
			}
			return f.err
		}
	}
	return os.Rename(oldPath, newPath)
}

// durableSyncDir performs securefiles.SyncDir at seam, honoring fileFaultHook. A
// directory fsync has no observable in-process side effect to fake either way (the
// preceding rename this seam confirms has, by construction, already happened for
// real by the time this is called) — so every fault kind here simply returns the
// injected error without touching disk; the ambiguity is inherent to the seam, not
// modeled per-kind.
func durableSyncDir(dirPath, seam string) error {
	if fileFaultHook != nil {
		if f := fileFaultHook(seam); f != nil {
			return f.err
		}
	}
	return securefiles.SyncDir(dirPath)
}

// applyWriteFault materializes f directly against baseDir/path, bypassing
// securefiles.
func applyWriteFault(baseDir, path string, data []byte, perm os.FileMode, f *fileFault) error {
	full := filepath.Join(baseDir, path)
	switch f.kind {
	case faultCleanError:
		return f.err
	case faultShortWrite:
		k := min(max(f.k, 0), len(data))
		fh, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) // #nosec G304 -- fixed internal key-directory path, test-only fault path
		if err != nil {
			return err
		}
		if _, werr := fh.Write(data[:k]); werr != nil {
			_ = fh.Close()
			return werr
		}
		_ = fh.Close() // no fsync — the short write is what's under test
		return f.err
	case faultRealEffectThenError:
		// The full write happens for real (ambiguous: it may be durable even
		// though an error is reported) — only the fsync confirmation is faked.
		fh, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) // #nosec G304 -- fixed internal key-directory path, test-only fault path
		if err != nil {
			return err
		}
		if _, werr := fh.Write(data); werr != nil {
			_ = fh.Close()
			return werr
		}
		_ = fh.Close() // fsync intentionally skipped — the injected error stands in for it
		return f.err
	default:
		return fmt.Errorf("fault_hooks: unknown fileFaultKind %d", f.kind)
	}
}
