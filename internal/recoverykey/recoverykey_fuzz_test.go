package recoverykey

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzHashAndVerify fuzzes Normalize/Hash/Verify against arbitrary
// attacker-shaped recovery-key input (design-b2-recover-admin.md §6:
// "recovery-key decode/format parsing — malformed groupings, wrong length").
// Unlike a decoder that parses structure out of its input, this package's
// parsing surface is Normalize's strip/uppercase pass, so the invariants
// worth pinning are: never panic or hang on any byte string (including
// invalid UTF-8, NUL, and pathological lengths), Hash is always a
// deterministic 64-hex-char digest, and Verify never accepts a value against
// a hash it wasn't actually derived from.
func FuzzHashAndVerify(f *testing.F) {
	f.Add("")
	f.Add("-")
	f.Add(strings.Repeat("-", 100))
	f.Add("ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2-3456-789A-BCDEF-GHJKL-MNPQR-S")
	f.Add("abcde-fghjk")
	f.Add("\x00\x00\x00")
	f.Add(strings.Repeat("A", 100000))
	f.Add("not even close to a key")
	f.Add("ABCDE\nFGHJK\r\nLMNPQ\t")
	f.Add(string([]byte{0xff, 0xfe, 0xfd}))
	// Well-formed (52 symbols) in canonical, lower-case and re-wrapped entry forms,
	// so the accept branch of invariant 2 is seeded, not only the refuse branch.
	f.Add("ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2-34567-89ABC-DEFGH-JKLMN-PQRST-UV")
	f.Add("abcdefghjklmnpqrstuvwxyz23456789abcdefghjklmnpqrstuv")
	f.Add("ABCDEFGHJKLMNPQRSTUVWXYZ2\n3456789ABCDEFGHJKLMNPQRSTUV\r\n")
	// 52 symbols, one of them a glyph the alphabet excludes.
	f.Add("0BCDEFGHJKLMNPQRSTUVWXYZ23456789ABCDEFGHJKLMNPQRSTUV")

	f.Fuzz(func(t *testing.T, raw string) {
		var normalized, hash string
		var verified bool
		fuzzutil.Guard(t.Fatalf, "recoverykey.HashAndVerify", func() {
			normalized = Normalize(raw)
			hash = Hash(raw)
			verified = Verify(raw, hash)
		})

		// Invariant 1: Hash always returns a fixed-length hex digest,
		// regardless of input shape or length.
		if len(hash) != 64 {
			t.Fatalf("Hash(%q) returned %d chars, want 64", raw, len(hash))
		}
		for _, c := range hash {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Fatalf("Hash(%q) returned non-hex character %q", raw, c)
			}
		}

		// Invariant 2: a WELL-FORMED value always verifies against its own
		// freshly computed hash (Hash and Verify never disagree on the same
		// input), and a malformed one never does, not even against its own
		// digest (TestVerify_RefusesMalformedKeyEvenWhenHashMatches). The
		// well-formedness oracle is re-derived here from the alphabet, not by
		// calling wellFormed.
		wantVerified := len(normalized) == keyLength
		for i := 0; wantVerified && i < len(normalized); i++ {
			wantVerified = strings.IndexByte(alphabet, normalized[i]) >= 0
		}
		if verified != wantVerified {
			t.Fatalf("Verify(%q, Hash(%q)) = %v, want %v (normalized %q, well-formed=%v)", raw, raw, verified, wantVerified, normalized, wantVerified)
		}

		// Invariant 3: Normalize is idempotent — normalizing an already
		// normalized string must be a no-op, or the hash a caller stores
		// could silently drift from the hash a later Verify call computes.
		if got := Normalize(normalized); got != normalized {
			t.Fatalf("Normalize(%q) = %q, want %q (Normalize must be idempotent)", normalized, got, normalized)
		}

		// Invariant 4: Verify against an unrelated hash never spuriously
		// accepts (a raw input that hashes to all-zero-equivalent bytes is
		// vanishingly unlikely but the check is cheap and catches a
		// constant-return regression outright).
		bogus := strings.Repeat("0", 64)
		if hash != bogus && Verify(raw, bogus) {
			t.Fatalf("Verify(%q, all-zero hash) = true, want false", raw)
		}
	})
}
