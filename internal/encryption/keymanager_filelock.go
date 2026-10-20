// keymanager_filelock.go — cross-process exclusive lock guarding the DEK
// read-modify-rename critical sections (#195).
//
// RewrapDEK/RewrapDEKWithProvider (the `keyorix-server admin encryption migrate-provider`
// command) and RotateDEKWithSweep (the `keyorix-server admin encryption rotate` command)
// both read the currently-active DEK, compute a new wrapped form, and
// atomically rename it onto keys/dek.key. Each is a separate, short-lived CLI
// process with its own KeyManager instance, so KeyManager.mu — an in-process
// sync.RWMutex — provides no protection against the two racing: if an
// operator runs `rotate --confirm` and, concurrently, automation runs
// `migrate-provider --confirm`, the migrate-provider process's Initialize()
// may have unwrapped the DEK *before* rotate replaces it, then win the
// rename race *after* rotate commits — silently overwriting the freshly
// rotated (and now fully re-encrypted-into) DEK with the stale, superseded
// one. Every row in the database, already durably re-encrypted under the new
// DEK, becomes permanently unreadable.
//
// Fix: an flock(2) advisory lock on a dedicated dek.key.lock file, held for
// the duration of each operation's critical section, makes the two mutually
// exclusive across processes. flock locks are owned by the open file
// descriptor and are released automatically by the kernel when the holding
// process exits or the fd is closed — including on crash or kill -9 — so
// there is no stale-lock/PID-liveness bookkeeping to get wrong (unlike a
// lockfile-with-PID pattern; grepping the repo for an existing single-
// instance/PID-lock convention to follow instead turned up none). Advisory
// locking is sufficient here: both operations are privileged, host-level CLI
// commands that already require local filesystem + host access to run.
//
// Mutual exclusion on its own is not quite enough, though: if the SECOND
// operation to acquire the lock is a RewrapDEK that read a since-superseded
// DEK before the lock was even contended for, serializing its write after
// the winner's does not stop it from clobbering the winner's result with
// stale data. RewrapDEK therefore also re-validates, under the lock, that
// the on-disk DEK is still the one it started from (see the staleness check
// in keymanager_rewrap.go) before writing — turning "these two operations
// never run at the same instant" into the actually-required "the DEK on
// disk after both finish matches what's in the database".
package encryption

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// keyFileLock holds an acquired exclusive flock(2) on the DEK lock file.
type keyFileLock struct {
	f *os.File
}

// release unlocks the flock and closes the underlying file descriptor. Safe
// to call at most once per successful acquireExclusiveKeyLock (callers defer
// it immediately after acquiring).
func (l *keyFileLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}

// acquireExclusiveKeyLock takes a blocking exclusive flock(2) on
// <baseDir>/<dekPath>.lock, serialising every DEK read-modify-rename
// critical section — RewrapDEK and RotateDEKWithSweep — across ALL
// processes sharing this key directory, not just goroutines within one
// process. The lock file itself carries no key material: it exists purely
// as a mutex handle and is never read for its contents.
//
// A non-blocking attempt is tried first purely so a genuine wait (another
// key-management operation actively in progress) can be logged; if that
// fails the call falls back to a blocking wait. Both operations this guards
// are expected to complete in well under a minute, and correctness — never
// letting the two interleave — matters far more here than failing fast.
func (km *KeyManager) acquireExclusiveKeyLock() (*keyFileLock, error) {
	lockPath := filepath.Join(km.baseDir, km.dekPath+".lock")
	// #nosec G304 -- lockPath is derived from the key manager's own configured
	// baseDir/dekPath (operator/config controlled), not attacker input.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open DEK lock file %s: %w", lockPath, err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		fmt.Printf("⏳ waiting for exclusive DEK lock — another key-management operation (rotate/migrate-provider) is in progress...\n")
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("acquire exclusive DEK lock %s: %w", lockPath, err)
		}
	}
	return &keyFileLock{f: f}, nil
}

// tryAcquireSharedKeyLock takes a NON-blocking SHARED flock(2) on the same
// <baseDir>/<dekPath>.lock file acquireExclusiveKeyLock serializes every
// key-file rewriter on (RotateDEKWithSweep, RotateKEKPassphrase, RewrapDEK*).
// Any number of shared holders coexist; a rewriter's exclusive request waits
// (acquireExclusiveKeyLock blocks) until every shared holder releases, and a
// shared request is refused while a rewriter already holds it. That makes it
// the read side of the same protocol: a holder sees no key-file write and no
// DEK-rotation sweep commit for as long as it holds the lock (#2602, a live
// `admin backup`). Non-blocking, so a backup started mid-rotation fails fast
// with a clear error instead of stalling behind it.
func (km *KeyManager) tryAcquireSharedKeyLock() (*keyFileLock, error) {
	lockPath := filepath.Join(km.baseDir, km.dekPath+".lock")
	// #nosec G304 -- lockPath is derived from the key manager's own configured
	// baseDir/dekPath (operator/config controlled), not attacker input.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open DEK lock file %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("a key-management operation (rotate/rotate-kek/migrate-provider) holds %s: %w", lockPath, err)
	}
	return &keyFileLock{f: f}, nil
}
