package recoverykey

import (
	"math"
	"regexp"
	"strings"
	"testing"
)

var groupedForm = regexp.MustCompile(`^[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){9}-[A-HJ-NP-Z2-9]{2}$`)

func TestGenerate_CanonicalForm(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !groupedForm.MatchString(key) {
		t.Fatalf("Generate produced %q, does not match the expected grouped no-ambiguous-glyph form", key)
	}
}

func TestGenerate_NoImmediateCollisions(t *testing.T) {
	seen := make(map[string]bool, 200)
	for range 200 {
		key, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[key] {
			t.Fatalf("Generate produced a duplicate key within 200 draws: %q", key)
		}
		seen[key] = true
	}
}

func TestVerify_RoundTrip(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	hash := Hash(key)
	if !Verify(key, hash) {
		t.Fatalf("Verify(genuine key, its own hash) = false, want true")
	}
}

func TestVerify_WrongKeyRejected(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	other, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	hash := Hash(key)
	if Verify(other, hash) {
		t.Fatalf("Verify(different key, key's hash) = true, want false")
	}
}

func TestVerify_MalformedStoredHashFailsClosed(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cases := []string{"", "not-hex", Hash(key)[:10], Hash(key) + "extra"}
	for _, storedHash := range cases {
		if Verify(key, storedHash) {
			t.Fatalf("Verify(key, malformed hash %q) = true, want false (fail closed)", storedHash)
		}
	}
}

// TestVerify_OldKeyRejectedAfterRotation exercises design §6's "old key is
// rejected immediately after rotate-key completes — no grace window, no
// cached-hash staleness" adversarial-review item at the package level:
// verification is always against whatever hash the caller currently passes,
// never a value this package caches — so a caller that overwrites the
// stored hash on rotation (server/admin's job) gets that guarantee for
// free, and this test pins it.
func TestVerify_OldKeyRejectedAfterRotation(t *testing.T) {
	oldKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	newKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	newHash := Hash(newKey) // simulates the stored row after rotation
	if Verify(oldKey, newHash) {
		t.Fatalf("Verify(old key, post-rotation hash) = true, want false")
	}
	if !Verify(newKey, newHash) {
		t.Fatalf("Verify(new key, post-rotation hash) = false, want true")
	}
}

func TestNormalize_ToleratesReentryVariation(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	hash := Hash(key)

	lower := strings.ToLower(key)
	spaced := strings.ReplaceAll(key, "-", " ")
	wrapped := strings.ReplaceAll(key, "-", "-\n")
	padded := "  " + key + "  "

	for _, variant := range []string{lower, spaced, wrapped, padded} {
		if !Verify(variant, hash) {
			t.Fatalf("Verify(re-typed variant %q) = false, want true (Normalize should tolerate case/whitespace/dash variation)", variant)
		}
	}
}

func TestHash_Deterministic(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	first := Hash(key)
	second := Hash(key)
	if first != second {
		t.Fatalf("Hash is not deterministic for the same input: %q != %q", first, second)
	}
	if len(first) != 64 {
		t.Fatalf("Hash returned %d hex chars, want 64 (SHA-256)", len(first))
	}
}

// TestKeyEntropyAtLeast256Bits pins the design's >=256-bit target: the alphabet size and
// keyLength must together give at least 256 bits, and the generated key must carry exactly
// keyLength alphabet symbols (#2054 review: 51 symbols of a 32-symbol alphabet was 255 bits).
func TestKeyEntropyAtLeast256Bits(t *testing.T) {
	if len(alphabet) != 32 {
		t.Fatalf("alphabet has %d symbols, want 32 (update keyLength's entropy comment and this test if it changes)", len(alphabet))
	}
	if bits := float64(keyLength) * math.Log2(float64(len(alphabet))); bits < 256 {
		t.Fatalf("keyLength %d x log2(%d) = %.1f bits, want >= 256", keyLength, len(alphabet), bits)
	}
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range k {
		if c != '-' {
			n++
		}
	}
	if n != keyLength {
		t.Fatalf("generated key has %d symbols, want %d", n, keyLength)
	}
}
