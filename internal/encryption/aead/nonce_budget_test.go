package aead

// nonce_budget_test.go — regression test for the DEK nonce-budget observability
// nudge (Wave 6 info-severity finding): Encrypt/EncryptWithAAD draw a fresh random
// 96-bit nonce per call with no per-DEK invocation counter or warning anywhere in
// the package, so a long-lived, never-automatically-rotated DEK under sustained
// write volume has no signal steering an operator toward `keyorix encryption
// rotate` before nonce-collision risk (real, but only near 2^32 encryptions under
// one key) becomes material. This test drives EncryptionService.encryptCount
// directly to just below nonceBudgetWarnThreshold — rather than actually calling
// Encrypt ~268 million times — and asserts the warning fires exactly once, only
// after the threshold is crossed.

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// testKeyVersion mirrors package encryption's own test constant of the same
// name (encryption_test.go) — this file moved here with FuzzDecrypt/etc. and
// needs its own copy since it's now in a different package.
const testKeyVersion = "test-v1"

// captureLogOutput redirects the standard logger to a buffer for the duration of
// the test and restores the previous output/flags on cleanup.
func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	origOutput := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origOutput)
		log.SetFlags(origFlags)
	})
	return &buf
}

func TestNonceBudgetWarning_NoWarningBelowThreshold(t *testing.T) {
	kek, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}
	service, err := NewEncryptionService(kek)
	if err != nil {
		t.Fatalf("Failed to create encryption service: %v", err)
	}

	logBuf := captureLogOutput(t)

	// Seed the counter to just below the threshold without actually performing
	// hundreds of millions of encryptions.
	service.encryptCount.Store(nonceBudgetWarnThreshold - 2)

	if _, err := service.Encrypt([]byte("below threshold"), testKeyVersion); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if logBuf.Len() != 0 {
		t.Fatalf("expected no warning below nonceBudgetWarnThreshold, got: %q", logBuf.String())
	}
}

func TestNonceBudgetWarning_FiresExactlyOnceAtThreshold(t *testing.T) {
	kek, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}
	service, err := NewEncryptionService(kek)
	if err != nil {
		t.Fatalf("Failed to create encryption service: %v", err)
	}

	logBuf := captureLogOutput(t)

	// One call short of the threshold — this call's increment lands exactly on it.
	service.encryptCount.Store(nonceBudgetWarnThreshold - 1)

	if _, err := service.Encrypt([]byte("at threshold"), testKeyVersion); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	warning := logBuf.String()
	if !strings.Contains(warning, "encryption rotate") {
		t.Fatalf("expected a nonce-budget warning pointing at `keyorix-server admin encryption rotate`, got: %q", warning)
	}
	if strings.Count(warning, "encryption rotate") != 1 {
		t.Fatalf("expected exactly one warning line, got: %q", warning)
	}

	// Further calls past the threshold (via either Encrypt or EncryptWithAAD) must
	// NOT log a duplicate warning.
	logBuf.Reset()
	if _, err := service.Encrypt([]byte("past threshold #1"), testKeyVersion); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if _, err := service.EncryptWithAAD([]byte("past threshold #2"), testKeyVersion, []byte("aad")); err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}
	if logBuf.Len() != 0 {
		t.Fatalf("expected no duplicate nonce-budget warning after it already fired, got: %q", logBuf.String())
	}
}

// TestNonceBudgetWarning_EncryptWithAADAlsoCounts confirms EncryptWithAAD
// increments the same shared counter as Encrypt (they share one DEK's nonce
// budget), and can itself be the call that crosses the threshold.
func TestNonceBudgetWarning_EncryptWithAADAlsoCounts(t *testing.T) {
	kek, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}
	service, err := NewEncryptionService(kek)
	if err != nil {
		t.Fatalf("Failed to create encryption service: %v", err)
	}

	logBuf := captureLogOutput(t)

	service.encryptCount.Store(nonceBudgetWarnThreshold - 1)

	if _, err := service.EncryptWithAAD([]byte("at threshold via AAD path"), testKeyVersion, []byte("aad")); err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	if !strings.Contains(logBuf.String(), "encryption rotate") {
		t.Fatalf("expected EncryptWithAAD to trigger the nonce-budget warning at threshold, got: %q", logBuf.String())
	}
}
