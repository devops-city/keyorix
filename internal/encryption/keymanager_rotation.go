// keymanager_rotation.go — DEK rotation with full re-encryption sweep (ADR-010).
//
// RotateDEKWithSweep, CleanPendingDEK, deleteBackupFiles.
// For initialisation see keymanager_lifecycle.go. For get/validate/wipe see keymanager_io.go.
package encryption

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// errSweepOutcomeUnknown marks a sweepFn error after which the sweep's
// transaction may have committed (the COMMIT itself failed, or a panic after
// it). The new DEK in dek.key.pending is then kept for RecoverInterruptedRotation
// to promote or discard from the redo marker.
var errSweepOutcomeUnknown = errors.New("the re-encryption sweep may have committed")

// RotateDEKWithSweep performs a true DEK rotation with a full re-encryption sweep (ADR-010).
//
// Algorithm:
//  1. Derive KEK from passphrase + existing salt
//  2. Generate new random DEK
//  3. Wrap new DEK → write to keys/dek.key.pending
//  4. Call sweepFn(oldSvc, newSvc, newKeyVersion) — caller runs this inside a DB transaction
//  5. On sweep success: atomic rename pending → active, wipe old DEK, delete backup files
//  6. On any error: delete pending file, keep old DEK active
//
// Secret values NEVER leave the sweep function — transient in memory only.
func (km *KeyManager) RotateDEKWithSweep(passphrase string, sweepFn func(oldSvc, newSvc *EncryptionService, newKeyVersion string) error) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.currentDEK == nil {
		return fmt.Errorf("key manager not initialized — cannot rotate")
	}

	// #195: acquire the same cross-process exclusive DEK lock as RewrapDEK.
	// Prior to this fix RotateDEKWithSweep held no cross-process lock here at
	// all — a concurrent RewrapDEK/RewrapDEKWithProvider (`migrate-provider`)
	// racing this rotation could read the DEK being replaced here and, if its
	// rename landed after this one's, silently overwrite the
	// freshly-rotated (and now fully re-encrypted-into) DEK with the
	// superseded one. Both operations write to the same
	// dek.key.pending → dek.key path, so they must be mutually exclusive.
	// (Distinct from #92's server-vs-rotation lock in service.go's
	// AcquireExclusiveKeyLock/`dek.lock`, which guards a live server process
	// against rotation — that fix is merged; this one guards two
	// rotation-family CLI ops against each other.)
	lock, err := km.acquireExclusiveKeyLock()
	if err != nil {
		return fmt.Errorf("rotate DEK: %w", err)
	}
	defer lock.release()

	kek, err := km.deriveKEK(passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive KEK for DEK rotation: %w", err)
	}
	defer wipeBytes(kek)

	newDEK, err := GenerateRandomKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate new DEK: %w", err)
	}

	pendingDEKPath := km.dekPath + ".pending"
	wrapped, err := wrapKey(newDEK, kek)
	if err != nil {
		wipeBytes(newDEK)
		return fmt.Errorf("failed to wrap new DEK: %w", err)
	}
	if err := securefiles.SecureWriteFileSync(km.baseDir, pendingDEKPath, wrapped, 0600); err != nil {
		wipeBytes(newDEK)
		return fmt.Errorf("failed to write pending DEK: %w", err)
	}
	// Make the pending file's DIRECTORY ENTRY durable before the sweep commits its redo
	// marker (service_rotation.go). SecureWriteFileSync fsyncs the file's DATA but not the
	// parent dir, so without this a crash could leave the marker committed while the pending
	// file's create is not yet durably linked — and crash recovery would have nothing to
	// promote. This closes the redo invariant "marker durable ⇒ pending DEK durably present".
	if err := securefiles.SyncDir(filepath.Dir(filepath.Join(km.baseDir, km.dekPath))); err != nil {
		wipeBytes(newDEK)
		_ = os.Remove(filepath.Join(km.baseDir, pendingDEKPath))
		return fmt.Errorf("failed to fsync key dir after writing pending DEK: %w", err)
	}
	// Crash-consistency seam (nil in prod): pending new-DEK written + dir-synced, DB not yet
	// swept, active DEK still the old one. See FuzzDEKSweepCrashConsistency.
	rotationCheckpointHook("sweep:after-write-dek-pending")

	oldEncSvc, err := NewEncryptionService(km.currentDEK)
	if err != nil {
		wipeBytes(newDEK)
		_ = os.Remove(filepath.Join(km.baseDir, pendingDEKPath))
		return fmt.Errorf("failed to create old encryption service: %w", err)
	}
	newEncSvc, err := NewEncryptionService(newDEK)
	if err != nil {
		wipeBytes(newDEK)
		_ = os.Remove(filepath.Join(km.baseDir, pendingDEKPath))
		return fmt.Errorf("failed to create new encryption service: %w", err)
	}
	newKeyVersion := fmt.Sprintf("v%d", time.Now().Unix())

	if err := sweepFn(oldEncSvc, newEncSvc, newKeyVersion); err != nil {
		wipeBytes(newDEK)
		if errors.Is(err, errSweepOutcomeUnknown) {
			// The rows may already be under the new DEK, and the pending file is
			// its only copy: keep it (REVIEW-COVERAGE-2).
			return fmt.Errorf("re-encryption sweep failed and may have committed — %s was kept; the next server start or `admin encryption rotate` promotes it if the database's rotation marker committed and discards it otherwise: %w", pendingDEKPath, err)
		}
		_ = os.Remove(filepath.Join(km.baseDir, pendingDEKPath))
		return fmt.Errorf("re-encryption sweep failed — old DEK remains active: %w", err)
	}
	// Crash-consistency seam (nil in prod): the sweep's DB transaction has COMMITTED
	// (rows now encrypted under the new DEK), but the active on-disk DEK is STILL the old
	// one — the pending → active rename below has not happened yet. This is the ordering
	// window FuzzDEKSweepCrashConsistency probes for durability.
	rotationCheckpointHook("sweep:after-sweep-commit")

	activePath := filepath.Join(km.baseDir, km.dekPath)
	pendingPath := filepath.Join(km.baseDir, pendingDEKPath)
	if err := os.Rename(pendingPath, activePath); err != nil {
		wipeBytes(newDEK)
		// The sweep committed: the rows and the redo marker are under the new DEK
		// and the pending file is its only copy. Never remove it here (it used to
		// be, losing every swept row); recovery promotes it (REVIEW-COVERAGE-2,
		// the DEK-sweep sibling of INV-ENCRYPTION-11).
		return fmt.Errorf("failed to promote pending DEK to active after the re-encryption sweep committed: %w — %s was kept; fix the cause, then start the server or run `admin encryption rotate`, which finish the promotion", err, pendingDEKPath)
	}
	// Crash-consistency seam (nil in prod): active DEK now the new one; dir fsync pending.
	rotationCheckpointHook("sweep:after-rename-dek")
	// Make the rename durable before deleting the old-DEK backups below — else a
	// crash could lose the new DEK while the backups are already gone.
	if err := securefiles.SyncDir(filepath.Dir(activePath)); err != nil {
		wipeBytes(newDEK)
		return fmt.Errorf("failed to fsync key directory after promote: %w", err)
	}
	// Crash-consistency seam (nil in prod): on-disk rotation complete.
	rotationCheckpointHook("sweep:after-syncdir")

	wipeBytes(km.currentDEK)
	km.currentDEK = newDEK
	km.dekSnapshot = append([]byte(nil), wrapped...)
	km.keyVersion = newKeyVersion
	km.deleteBackupFiles()

	fmt.Printf("✅ DEK rotated and full re-encryption sweep complete. New version: %s\n", km.keyVersion)
	return nil
}

// deleteBackupFiles removes all dek.key.backup.* files from old RotateDEK() calls.
func (km *KeyManager) deleteBackupFiles() {
	pattern := filepath.Join(km.baseDir, km.dekPath+".backup.*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("[WARN] failed to glob backup DEK files: %v", err)
		return
	}
	for _, f := range matches {
		if err := os.Remove(f); err != nil {
			log.Printf("[WARN] failed to delete backup DEK file %s: %v", f, err)
		} else {
			log.Printf("[sweep] deleted backup DEK file: %s", f)
		}
	}
}

// PromotePendingDEK atomically promotes a leftover dek.key.pending to the active dek.key
// and fsyncs the key directory. Crash recovery calls it (via Service.RecoverInterrupted
// Rotation) to COMPLETE a DEK-sweep rotation whose DB transaction committed (rows are
// under the new DEK) but whose pending→active rename did not happen before the crash. The
// pending file it promotes was fsync'd — data and directory entry both — before the sweep's
// redo marker committed, so whenever a marker says "promote", this file is present.
//
// A pure file rename: it does NOT touch km.currentDEK or any in-memory state, because
// recovery runs before Initialize, which then loads the freshly-promoted active DEK. Safe
// to call with no pending file present (no-op) — so a crash after the rename but before the
// marker is cleared replays harmlessly.
func (km *KeyManager) PromotePendingDEK() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	pendingPath := filepath.Join(km.baseDir, km.dekPath+".pending")
	activePath := filepath.Join(km.baseDir, km.dekPath)
	if _, err := os.Stat(pendingPath); err != nil {
		if os.IsNotExist(err) {
			return nil // already promoted (rename happened before the crash) — nothing to do
		}
		return fmt.Errorf("stat pending DEK during recovery: %w", err)
	}
	if err := os.Rename(pendingPath, activePath); err != nil {
		return fmt.Errorf("promote pending DEK during recovery: %w", err)
	}
	if err := securefiles.SyncDir(filepath.Dir(activePath)); err != nil {
		return fmt.Errorf("fsync key dir after promoting pending DEK during recovery: %w", err)
	}
	return nil
}

// CleanPendingDEK removes a leftover dek.key.pending file from a previously
// failed or interrupted rotation. Should be called at startup.
func (km *KeyManager) CleanPendingDEK() {
	pendingPath := filepath.Join(km.baseDir, km.dekPath+".pending")
	if _, err := os.Stat(pendingPath); err == nil {
		log.Printf("[WARN] found leftover pending DEK file %s — removing (previous rotation was interrupted)", pendingPath)
		_ = os.Remove(pendingPath)
	}
}
