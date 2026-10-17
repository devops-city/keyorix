package recoverykey

import (
	"strings"
	"testing"
)

// TestVerify_RefusesMalformedKeyEvenWhenHashMatches pins Verify to failing
// closed on any input that is not a well-formed key (keyLength symbols from
// alphabet, after Normalize), whatever the stored hash says. Before
// REVIEW-COVERAGE-1, Verify was "SHA-256 of the normalised input equals the
// stored hash" and nothing else, so a recovery-key record whose KeyHash is the
// digest of a short or empty string (a hand-edited, corrupted or foreign-restored
// row) was satisfied by typing that string: `recover-admin --recovery-key ""`
// against KeyHash=Hash("") reset the admin. No key Generate can produce is
// refused by this rule, so it costs a real operator nothing.
func TestVerify_RefusesMalformedKeyEvenWhenHashMatches(t *testing.T) {
	genuine, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	normalized := Normalize(genuine)
	for name, raw := range map[string]string{
		"empty":                 "",
		"separators only":       "- -\t\n",
		"one symbol short":      normalized[:keyLength-1],
		"one symbol long":       normalized + "A",
		"ambiguous glyph 0":     "0" + normalized[1:],
		"ambiguous glyph O":     "O" + normalized[1:],
		"ambiguous glyph 1":     "1" + normalized[1:],
		"ambiguous glyph I":     "I" + normalized[1:],
		"non-ASCII letter":      "Ä" + normalized[1:],
		"embedded NUL":          normalized[:10] + "\x00" + normalized[11:],
		"invalid UTF-8":         "\xff" + normalized[1:],
		"mfa-style short code":  "ABCDE-FGHJK",
		"lower-case short code": "abcde",
	} {
		t.Run(name, func(t *testing.T) {
			if Verify(raw, Hash(raw)) {
				t.Fatalf("Verify(%q, Hash(%q)) = true: a malformed key must never verify, even against its own digest", raw, raw)
			}
		})
	}
}

// TestVerify_AcceptsEveryEntryFormOfAGenuineKey is the other direction: the
// well-formedness rule runs on the NORMALISED input, so the forgiving entry
// forms Normalize exists for (lower case, no dashes, re-wrapped lines) still
// verify.
func TestVerify_AcceptsEveryEntryFormOfAGenuineKey(t *testing.T) {
	genuine, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	stored := Hash(genuine)
	compact := strings.ReplaceAll(genuine, "-", "")
	for name, raw := range map[string]string{
		"canonical":         genuine,
		"lower case":        strings.ToLower(genuine),
		"no dashes":         compact,
		"re-wrapped":        compact[:26] + "\n" + compact[26:],
		"spaces for dashes": strings.ReplaceAll(genuine, "-", " "),
		"surrounding space": "  " + genuine + "\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if !Verify(raw, stored) {
				t.Fatalf("Verify(%q) = false for an entry form of the genuine key", raw)
			}
		})
	}
}
