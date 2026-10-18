package encryption

import (
	"strings"
	"testing"
)

// BOOT-REFUSALS-1 "Misleading messages" item 7: a wrong passphrase read
// "failed to unwrap DEK: failed to unwrap DEK — wrong passphrase ...".
func TestKeyManager_WrongPassphrase_SaysUnwrapOnce(t *testing.T) {
	dir := t.TempDir()
	if err := NewKeyManager(dir, "dek.key", "kek.salt").Initialize("right passphrase"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	err := NewKeyManager(dir, "dek.key", "kek.salt").Initialize("wrong passphrase")
	if err == nil {
		t.Fatal("expected the wrong passphrase to be refused")
	}
	msg := err.Error()
	if !strings.Contains(msg, "wrong passphrase or corrupted key file") {
		t.Errorf("message %q lost the page's Match text", msg)
	}
	if n := strings.Count(msg, "failed to unwrap DEK"); n != 1 {
		t.Errorf("\"failed to unwrap DEK\" appears %d times, want 1: %q", n, msg)
	}
}
