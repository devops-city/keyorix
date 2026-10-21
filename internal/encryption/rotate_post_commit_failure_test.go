// rotate_post_commit_failure_test.go — REVIEW-COVERAGE-2: once the sweep's
// transaction has committed (or may have), dek.key.pending is the only copy of
// the DEK the rows are under, and RotateDEKWithSweep must keep it however the
// rest of the rotation fails. The kill-halfway test covers a crash at that point;
// these cover a running process that sees an error there.
package encryption

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestRotateDEKWithSweep_RenameFailsAfterCommit_NewDEKRecoverable: the
// pending -> active rename fails after the sweep committed (here dek.key is
// briefly a directory, EISDIR; in production a read-only remount, EIO or an
// NFS error). The rotation used to delete dek.key.pending on that error, so the
// redo marker pointed at a DEK that no longer existed and every swept row was
// lost. The next start-up must recover it.
func TestRotateDEKWithSweep_RenameFailsAfterCommit_NewDEKRecoverable(t *testing.T) {
	const passphrase = "rename-fails-after-commit"
	const plaintext = "value-swept-before-the-rename-failed"

	db := newTestDB(t)
	svc, dir := newTestService(t, passphrase)
	nodeID := seedSecretNode(t, db, 1)
	versionID := seedSecretVersion(t, db, svc, nodeID, 1, 1, plaintext)

	active := filepath.Join(dir, "dek.key")
	saved := filepath.Join(dir, "dek.key.saved")
	prev := rotationCheckpoint
	rotationCheckpoint = func(label string) {
		if label != "sweep:after-sweep-commit" {
			return
		}
		if err := os.Rename(active, saved); err != nil {
			t.Errorf("move dek.key aside: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(active, "blocker"), 0o700); err != nil {
			t.Errorf("make dek.key a directory: %v", err)
		}
	}
	_, err := svc.RotateDEKWithSweep(passphrase, db)
	rotationCheckpoint = prev
	if err == nil {
		t.Fatal("the rename was made to fail, but RotateDEKWithSweep reported success")
	}
	svc.Shutdown()

	// The operator fixes the cause.
	if err := os.RemoveAll(active); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, active); err != nil {
		t.Fatal(err)
	}

	rec := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir)
	if err := rec.RecoverInterruptedRotation(db); err != nil {
		t.Fatalf("RecoverInterruptedRotation: %v", err)
	}
	if err := rec.Initialize(passphrase); err != nil {
		t.Fatalf("Initialize after recovery: %v", err)
	}
	defer rec.Shutdown()
	var v models.SecretVersion
	if err := db.First(&v, versionID).Error; err != nil {
		t.Fatal(err)
	}
	got, err := rec.DecryptSecretWithAAD(v.EncryptedValue, SecretAAD(nodeID, 1, 1))
	if err != nil || string(got) != plaintext {
		t.Fatalf("DATA LOSS: the row swept before the failed rename does not decrypt after recovery (got %q, err %v)", got, err)
	}
}

// TestKeyManagerRotateDEKWithSweep_OutcomeUnknownKeepsPending: a sweep error
// marked errSweepOutcomeUnknown (the COMMIT itself failed, so the transaction
// may have committed) keeps dek.key.pending for recovery to decide from the
// redo marker. A definite pre-commit failure still removes it
// (TestRotateDEKWithSweep_SweepErrorKeepsOldDEK).
func TestKeyManagerRotateDEKWithSweep_OutcomeUnknownKeepsPending(t *testing.T) {
	km, dir := initKM(t, "outcome-unknown")
	err := km.RotateDEKWithSweep("outcome-unknown", func(_, _ *EncryptionService, _ string) error {
		return fmt.Errorf("failed to commit sweep transaction: connection reset: %w", errSweepOutcomeUnknown)
	})
	if !errors.Is(err, errSweepOutcomeUnknown) {
		t.Fatalf("want errSweepOutcomeUnknown to propagate, got %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "dek.key.pending")); serr != nil {
		t.Fatalf("dek.key.pending must be kept when the commit outcome is unknown: %v", serr)
	}
}
