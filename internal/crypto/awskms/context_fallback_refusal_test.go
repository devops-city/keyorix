package awskms

import (
	"bytes"
	"strings"
	"testing"

	keyorixcrypto "github.com/keyorixhq/keyorix/internal/crypto"
)

// #3398: insecure_allow_kms_context_fallback is a migration aid for a wrapped KEK
// that has no encryption context yet. These tests drive the real aws-kms client
// (over the context-checking fake) through the real KMSKeyProvider, which is what
// the server's boot unwraps the KEK with.

var installCtx = map[string]string{"keyorix-install": "inst-1"}

// A KEK that already decrypts WITH its context leaves nothing to migrate: the flag
// is refused, and the message says it can be removed.
func TestAWSKMS_ContextFallbackFlag_RefusedWhenKEKAlreadyBound(t *testing.T) {
	dir := t.TempDir()
	if _, err := keyorixcrypto.NewKMSKeyProvider(newTestClient(installCtx, false), "aws-kms", dir, "kek.kms").KEK(); err != nil {
		t.Fatalf("first run (wrap under the context): %v", err)
	}
	kek, err := keyorixcrypto.NewKMSKeyProvider(newTestClient(installCtx, true), "aws-kms", dir, "kek.kms").KEK()
	if err == nil {
		t.Fatal("a context-bound KEK with insecure_allow_kms_context_fallback set must be refused (nothing left to migrate)")
	}
	if kek != nil {
		t.Fatal("no KEK may be returned with the refusal")
	}
	for _, want := range []string{"insecure_allow_kms_context_fallback", "no longer needed", "can be removed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not say %q", err, want)
		}
	}
}

// A legacy KEK (wrapped with no context) still needs the flag: it boots.
func TestAWSKMS_ContextFallbackFlag_LegacyKEKStillBoots(t *testing.T) {
	dir := t.TempDir()
	legacy, err := keyorixcrypto.NewKMSKeyProvider(newTestClient(nil, false), "aws-kms", dir, "kek.kms").KEK()
	if err != nil {
		t.Fatalf("first run (legacy, no context): %v", err)
	}
	kek, err := keyorixcrypto.NewKMSKeyProvider(newTestClient(installCtx, true), "aws-kms", dir, "kek.kms").KEK()
	if err != nil {
		t.Fatalf("a legacy KEK with the flag set must still unwrap via the fallback: %v", err)
	}
	if !bytes.Equal(kek, legacy) {
		t.Fatal("the fallback must unwrap the same KEK")
	}
}

// Without the flag a bound KEK boots as before (the refusal is about the flag only).
func TestAWSKMS_ContextFallbackFlagOff_BoundKEKBoots(t *testing.T) {
	dir := t.TempDir()
	first, err := keyorixcrypto.NewKMSKeyProvider(newTestClient(installCtx, false), "aws-kms", dir, "kek.kms").KEK()
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	kek, err := keyorixcrypto.NewKMSKeyProvider(newTestClient(installCtx, false), "aws-kms", dir, "kek.kms").KEK()
	if err != nil || !bytes.Equal(kek, first) {
		t.Fatalf("restart without the flag: kek equal=%v err=%v", bytes.Equal(kek, first), err)
	}
}
