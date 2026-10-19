package encryption

// dek_epoch_postgres_test.go: the cross-replica DEK epoch (dek_epoch.go) on
// real PostgreSQL. Each "replica" is a Service with its own key directory on
// one shared schema. Skips when KEYORIX_TEST_PG_DSN is unset (pg-gated).

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"gorm.io/gorm"
)

const epochPass = "epoch-test-passphrase"

func epochPGDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := fuzzworld.OpenPostgres(t, "dekepoch")
	if db == nil {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	fuzzworld.Bootstrap(t, db)
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	return db
}

// epochReplicas returns two replicas holding the same key set in separate key
// directories, plus a secret node to write versions for.
func epochReplicas(t *testing.T, db *gorm.DB) (dirA, dirB string, a, b *Service, node *models.SecretNode) {
	t.Helper()
	dirA, dirB = t.TempDir(), t.TempDir()
	a = newEpochTestService(t, dirA)
	copyKeyDir(t, dirA, dirB)
	b = newEpochTestService(t, dirB)
	t.Cleanup(a.Shutdown)
	t.Cleanup(b.Shutdown)
	node = &models.SecretNode{ProjectID: 1, Name: "epoch-node", IsSecret: true}
	if err := db.Create(node).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	return dirA, dirB, a, b, node
}

func epochWrite(t *testing.T, svc *Service, db *gorm.DB, node *models.SecretNode, version int) error {
	t.Helper()
	enc, meta, err := svc.EncryptSecretWithAAD([]byte("value"), SecretAAD(node.ID, node.ProjectID, version))
	if err != nil {
		return err
	}
	return db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: version, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error
}

func epochUndecryptable(t *testing.T, svc *Service, db *gorm.DB, node *models.SecretNode) []int {
	t.Helper()
	var rows []models.SecretVersion
	if err := db.Where("secret_node_id = ?", node.ID).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	var bad []int
	for _, r := range rows {
		if _, err := svc.DecryptSecretWithAAD(r.EncryptedValue, SecretAAD(node.ID, node.ProjectID, r.VersionNumber)); err != nil {
			bad = append(bad, r.VersionNumber)
		}
	}
	return bad
}

func fingerprintOf(t *testing.T, svc *Service) string {
	t.Helper()
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	fp, err := svc.encryptionService.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A running replica stops encrypting once another host rotates, keeps
// decrypting, and the epoch names the new DEK.
func TestDEKEpoch_Postgres_RunningReplicaFencedByRotationElsewhere(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, b, node := epochReplicas(t, db)

	if err := b.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatalf("replica B guard: %v", err)
	}
	if v, _ := epochValue(t, db); v != fingerprintOf(t, b) {
		t.Fatalf("epoch after first start = %q, want B's fingerprint", v)
	}
	if err := epochWrite(t, b, db, node, 1); err != nil {
		t.Fatalf("write before rotation: %v", err)
	}
	inMemory, _, err := b.EncryptSecretWithAAD([]byte("held"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.RotateDEKWithSweep(epochPass, db); err != nil {
		t.Fatalf("rotate on A: %v", err)
	}
	if v, _ := epochValue(t, db); v != fingerprintOf(t, a) {
		t.Fatalf("epoch after rotation = %q, want A's new fingerprint %q", v, fingerprintOf(t, a))
	}
	if err := epochWrite(t, b, db, node, 2); !errors.Is(err, ErrDEKWriteFenced) {
		t.Fatalf("replica B write after rotation: got %v, want ErrDEKWriteFenced", err)
	}
	if _, err := b.DecryptSecretWithAAD(inMemory, []byte("aad")); err != nil {
		t.Fatalf("a fenced replica must keep decrypting: %v", err)
	}
	if bad := epochUndecryptable(t, a, db, node); len(bad) != 0 {
		t.Fatalf("versions the active DEK cannot decrypt: %v", bad)
	}
}

// A rotation whose sweep fails lifts its fence: the epoch is the old DEK again
// and the running replica resumes writing.
func TestDEKEpoch_Postgres_FailedRotationLiftsFence(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, b, node := epochReplicas(t, db)
	if err := b.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatal(err)
	}
	old := fingerprintOf(t, a)
	// An undecryptable row makes the sweep fail after the fence was committed.
	if err := db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 99, EncryptedValue: []byte(`{"ciphertext":"AA==","nonce":"AAAAAAAAAAAAAAAA","metadata":{"algorithm":"AES-256-GCM","aad_version":"v2"}}`), EncryptionMetadata: models.JSON(`{"algorithm":"AES-256-GCM"}`)}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateDEKWithSweep(epochPass, db); err == nil {
		t.Fatal("rotation over an undecryptable row succeeded")
	}
	if v, _ := epochValue(t, db); v != old {
		t.Fatalf("epoch after the failed rotation = %q, want the old fingerprint %q", v, old)
	}
	waitFor(t, "replica B to resume writing", func() bool { return epochWrite(t, b, db, node, 1) == nil })
}

// A fence left by an interrupted rotation (no sweep committed) is lifted by the
// next server start that holds the old DEK.
func TestDEKEpoch_Postgres_StartupLiftsStaleFence(t *testing.T) {
	db := epochPGDB(t)
	_, _, _, b, _ := epochReplicas(t, db)
	own := fingerprintOf(t, b)
	if err := db.Create(&models.SystemMetadata{Key: dekEpochKey, Value: dekEpochRotatingPrefix + own}).Error; err != nil {
		t.Fatal(err)
	}
	if err := b.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatalf("start over a stale fence: %v", err)
	}
	if v, _ := epochValue(t, db); v != own {
		t.Fatalf("epoch = %q, want %q", v, own)
	}
}

// With no epoch recorded yet (first start after upgrading), a replica whose DEK
// cannot decrypt the newest secret version must not claim the epoch.
func TestDEKEpoch_Postgres_SeedRefusedForStaleDEK(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, _, node := epochReplicas(t, db)
	if err := epochWrite(t, a, db, node, 1); err != nil {
		t.Fatal(err)
	}
	stale := newEpochTestService(t, t.TempDir()) // another key set entirely
	defer stale.Shutdown()
	if err := stale.StartDEKEpochGuard(db, nil); !errors.Is(err, ErrDEKEpochMismatch) {
		t.Fatalf("stale replica start: got %v, want ErrDEKEpochMismatch", err)
	}
	if v, found := epochValue(t, db); found {
		t.Fatalf("stale replica recorded epoch %q", v)
	}
	if err := a.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatalf("current replica start: %v", err)
	}
}

// A host whose key files are not the database's current key set cannot rotate.
func TestDEKEpoch_Postgres_RotateRefusedFromStaleHost(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, _, node := epochReplicas(t, db)
	if err := epochWrite(t, a, db, node, 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.SystemMetadata{Key: dekEpochKey, Value: "0123456789abcdef0123456789abcdef"}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateDEKWithSweep(epochPass, db); !errors.Is(err, ErrDEKEpochMismatch) {
		t.Fatalf("rotate from a stale host: got %v, want ErrDEKEpochMismatch", err)
	}
	if bad := epochUndecryptable(t, a, db, node); len(bad) != 0 {
		t.Fatalf("refused rotation changed rows: %v", bad)
	}
}

// If the fence is lifted while the rotation waits (a server restarted and
// cleared it), the sweep's compare-and-set fails and the rotation rolls back.
func TestDEKEpoch_Postgres_FenceLiftedDuringRotation_RollsBack(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, _, node := epochReplicas(t, db)
	if err := epochWrite(t, a, db, node, 1); err != nil {
		t.Fatal(err)
	}
	old := fingerprintOf(t, a)
	done := make(chan error, 1)
	go func() { _, err := a.RotateDEKWithSweep(epochPass, db); done <- err }()
	waitFor(t, "the rotation fence", func() bool { v, _ := epochValue(t, db); return v == dekEpochRotatingPrefix+old })
	if ok, err := casDEKEpoch(db, dekEpochRotatingPrefix+old, old); err != nil || !ok {
		t.Fatalf("lift fence: ok=%v err=%v", ok, err)
	}
	if err := <-done; err == nil {
		t.Fatal("rotation succeeded although its fence was lifted")
	}
	if v, _ := epochValue(t, db); v != old {
		t.Fatalf("epoch = %q, want the old fingerprint", v)
	}
	if fingerprintOf(t, a) != old {
		t.Fatal("rotating service switched DEK although the rotation failed")
	}
	if bad := epochUndecryptable(t, a, db, node); len(bad) != 0 {
		t.Fatalf("rows the old (still active) DEK cannot decrypt: %v", bad)
	}
}

// A write transaction still open when the sweep starts (encrypted under the old
// DEK just before its replica saw the fence) must not survive the rotation as
// an old-DEK row: the sweep waits for it and re-encrypts it.
func TestDEKEpoch_Postgres_SweepWaitsForInFlightWriter(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, b, node := epochReplicas(t, db)
	enc, meta, err := b.EncryptSecretWithAAD([]byte("in-flight"), SecretAAD(node.ID, node.ProjectID, 1))
	if err != nil {
		t.Fatal(err)
	}
	writer := db.Begin()
	if err := writer.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error; err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { _, err := a.RotateDEKWithSweep(epochPass, db); done <- err }()
	// Commit only after the sweep had the chance to read the table.
	time.Sleep(dekEpochFenceWait + 500*time.Millisecond)
	if err := writer.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if bad := epochUndecryptable(t, a, db, node); len(bad) != 0 {
		t.Fatalf("DATA LOSS: in-flight version committed under the old DEK after the sweep: %v", bad)
	}
}

// A write transaction that never finishes makes the rotation fail after the
// sweep's lock timeout, never hang, and the fence is lifted again.
func TestDEKEpoch_Postgres_SweepLockTimeoutFailsCleanly(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, _, node := epochReplicas(t, db)
	prev := dekEpochSweepLockTimeout
	dekEpochSweepLockTimeout = "300ms"
	t.Cleanup(func() { dekEpochSweepLockTimeout = prev })

	writer := db.Begin()
	defer writer.Rollback()
	if err := writer.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: []byte("x"), EncryptionMetadata: models.JSON(`{}`)}).Error; err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := a.RotateDEKWithSweep(epochPass, db)
	if err == nil || !strings.Contains(err.Error(), "lock swept tables") {
		t.Fatalf("rotation with a stuck writer: got %v, want the sweep lock error", err)
	}
	if d := time.Since(start); d > dekEpochFenceWait+5*time.Second {
		t.Fatalf("rotation took %s with a 300ms lock timeout", d)
	}
	// No epoch existed before this rotation, so lifting the fence removes it.
	if v, found := epochValue(t, db); found {
		t.Fatalf("epoch after the failed rotation = %q, want none (as before)", v)
	}
}
