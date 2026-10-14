package encryption

// firstboot_lock_order_test.go — regression test for the first-boot
// key-bootstrap race: two processes (simulated here as independent Service
// instances sharing the same fresh key directory) must never both pass the
// unlocked check-then-write in ensureSaltExists/ensureWrappedDEKExists
// (keymanager_lifecycle.go). AcquireExclusiveKeyLock must be acquired BEFORE
// Initialize, not after, so the loser is refused immediately at the lock step
// — before it ever touches salt/dek files — rather than racing key-material
// generation and only surfacing as a corrupted/mismatched key pair on a LATER
// restart ("wrong passphrase or corrupted key file").
//
// TestFirstBootKeyBootstrap_LockBeforeInitialize_ExactlyOneWinner exercises the
// CORRECTED call order directly (AcquireExclusiveKeyLock() then Initialize()).
// Before the fix, AcquireExclusiveKeyLock required the Service to already be
// initialized, which made this order impossible to use at all — every racer
// failed at the lock step with "not initialized", not a lock-contention error,
// and none of the ordering's protection was exercised. That is confirmed
// separately by TestService_AcquireExclusiveKeyLock_BeforeInitialize_Succeeds
// in encryption_s2_test.go.

import (
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestFirstBootKeyBootstrap_LockBeforeInitialize_ExactlyOneWinner(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	const passphrase = "shared-first-boot-passphrase"

	const racers = 8
	var wg sync.WaitGroup
	wg.Add(racers)
	lockErrs := make([]error, racers)
	initErrs := make([]error, racers)
	svcs := make([]*Service, racers)
	for i := range racers {
		svcs[i] = NewService(cfg, dir)
	}

	for i := range racers {
		go func() {
			defer wg.Done()
			// The fix under test: acquire the exclusive lock BEFORE Initialize,
			// mirroring the corrected order in server/main.go's
			// initializeEncryption.
			if err := svcs[i].AcquireExclusiveKeyLock(); err != nil {
				lockErrs[i] = err
				return
			}
			initErrs[i] = svcs[i].Initialize(passphrase)
		}()
	}
	wg.Wait()
	for i := range racers {
		defer svcs[i].Shutdown()
	}

	winners := 0
	for i := range racers {
		if lockErrs[i] == nil {
			winners++
			if initErrs[i] != nil {
				t.Errorf("racer %d won the lock but Initialize failed: %v", i, initErrs[i])
			}
			continue
		}
		// A loser must be refused at the LOCK step with a clear
		// lock-contention error, and must never have gone on to run
		// Initialize (so it never touched the salt/dek files at all).
		if !strings.Contains(lockErrs[i].Error(), "DEK lock") {
			t.Errorf("racer %d: expected a DEK-lock contention error, got: %v", i, lockErrs[i])
		}
		if initErrs[i] != nil {
			t.Errorf("racer %d: Initialize must never run after a failed lock acquisition, got: %v", i, initErrs[i])
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly 1 racer to win the exclusive lock and complete first-boot Initialize, got %d", winners)
	}

	// Simulate a LATER restart: a brand-new Service, independent of any racer,
	// must unwrap the on-disk key material cleanly. This is the concrete
	// failure mode the race produces when unprotected — a delayed, confusing
	// "wrong passphrase or corrupted key file" on a later restart, rather than
	// an immediate, clear error at the moment of the actual race.
	restarted := NewService(cfg, dir)
	if err := restarted.Initialize(passphrase); err != nil {
		t.Fatalf("a later restart must unwrap the on-disk key material cleanly, got: %v", err)
	}
	restarted.Shutdown()
}
