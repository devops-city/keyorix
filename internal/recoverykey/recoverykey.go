// Package recoverykey implements the local Keyorix admin recovery key
// (docs/design-b2-recover-admin.md §2): a 256-bit offline second factor
// ("something you have") alongside host access ("something you are") that
// lets `keyorix-server admin recover-admin` restore a locked-out admin
// account without any network path. This package covers generation,
// canonical formatting, and verification only — the stored record shape,
// the CLI commands, and the audit/notification wiring live in
// internal/storage/models and server/admin.
package recoverykey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// alphabet matches the no-ambiguous-glyph convention already in this
// codebase (internal/core/mfa.go's generateRecoveryCodes): no 0/O, no 1/I —
// print/typo tolerant, which matters because this key is meant to be
// written down and stored offline, not copy-pasted from a terminal history.
const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// keyLength is the number of alphabet symbols in a generated key.
// len(alphabet)=32 (24 letters without I/O + digits 2-9), so each symbol carries exactly 5 bits;
// 52 symbols yield 260 bits, over the design's 256-bit target (51 would give only 255).
// randomSymbol's draw is exactly uniform (see its doc comment) -- unlike
// generateRecoveryCodes' per-byte-modulo draw, which accepts a small bias because MFA backup
// codes are a second factor to an already-checked password, not the standalone
// secret-equivalent value this key is. TestKeyEntropyAtLeast256Bits pins this.
const keyLength = 52

// groupSize matches the MFA-recovery-code display convention (grouped
// "XXXXX-XXXXX...").
const groupSize = 5

// Generate returns a fresh recovery key in its canonical, grouped display
// form (e.g. "ABCDE-FGHJK-..."), drawn from crypto/rand.
func Generate() (string, error) {
	symbols := make([]byte, keyLength)
	for i := range symbols {
		sym, err := randomSymbol()
		if err != nil {
			return "", fmt.Errorf("generate recovery key: %w", err)
		}
		symbols[i] = sym
	}
	return group(string(symbols)), nil
}

// randomSymbol draws one alphabet index uniformly via rejection sampling:
// crypto/rand one byte at a time, discarding any draw that would otherwise
// introduce modulo bias. With len(alphabet)=32, 256 is an exact multiple, so
// limit is 256 and every byte is accepted (b%32 is exactly uniform); the
// rejection loop stays so the draw remains unbiased if the alphabet changes.
func randomSymbol() (byte, error) {
	limit := 256 - (256 % len(alphabet))
	b := make([]byte, 1)
	for {
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return alphabet[int(b[0])%len(alphabet)], nil
		}
	}
}

// group inserts a '-' every groupSize characters.
func group(s string) string {
	var sb strings.Builder
	for i, r := range s {
		if i > 0 && i%groupSize == 0 {
			sb.WriteByte('-')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// Normalize makes entry forgiving: upper-cased, whitespace/dash-stripped —
// the same intent as internal/core/mfa.go's normalizeRecoveryCode, applied
// here so a key printed once and re-typed later (possibly re-wrapped across
// lines, possibly lower-cased by a terminal) still verifies. A single
// strings.Map pass, not TrimSpace-then-replace-specific-chars: a two-pass
// version was tried and failed FuzzHashAndVerify's idempotency check on the
// FIRST fuzz run — TrimSpace only trims the outer boundary, so a dash
// shielding an interior whitespace rune (e.g. "-\v0") left that rune
// exposed at the new boundary post-strip, un-trimmed, and only removed on
// a SECOND Normalize call. unicode.IsSpace covers \t \n \v \f \r and the
// Unicode space separators the two-pass version's literal-char replacer
// missed, and a single strings.Map pass has no ordering to get wrong.
func Normalize(raw string) string {
	return strings.ToUpper(strings.Map(func(r rune) rune {
		if r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return r
	}, raw))
}

// Hash returns the SHA-256 verifier hex-string stored server-side (design
// §2: plain SHA-256, not a slow KDF — the key is already high-entropy
// random, matching the PAT (internal/core/pat.go) and MFA-recovery-code
// precedent, not the password/passphrase-KEK one, where a slow KDF resists
// brute force over a low-entropy human-chosen input; a slow KDF here would
// only slow down the legitimate verification path during an incident).
// Hashes the NORMALIZED form, so storage and verification always agree
// regardless of how the key was re-typed.
func Hash(raw string) string {
	// codeql[go/weak-sensitive-data-hashing] -- raw is a 256-bit crypto/rand
	// recovery key (see this function's own doc comment), not a low-entropy
	// password; a slow KDF would only slow legitimate verification.
	sum := sha256.Sum256([]byte(Normalize(raw)))
	return hex.EncodeToString(sum[:])
}

// Verify reports whether raw matches storedHash, via a constant-time
// comparison of the hex digests (design §6's own explicit adversarial-review
// checklist item — a short-circuiting == here is exactly the kind of
// timing-channel finding this codebase has caught before in similar
// checks: internal/core/auth_bootstrap.go, internal/core/mfa.go).
// subtle.ConstantTimeCompare itself returns 0 (not a panic) on any length
// mismatch, so a malformed or truncated storedHash fails closed rather than
// comparing a partial prefix.
//
// An input that does not normalise to a well-formed key (keyLength symbols
// from alphabet) is refused before any hash is compared: otherwise a record
// whose KeyHash is the digest of a short or empty string -- hand-edited,
// corrupted, restored from elsewhere -- would be satisfied by typing that
// string (TestVerify_RefusesMalformedKeyEvenWhenHashMatches). The early return
// depends only on the caller's own input, never on storedHash.
func Verify(raw, storedHash string) bool {
	if !wellFormed(Normalize(raw)) {
		return false
	}
	computed := Hash(raw)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}

// wellFormed reports whether normalized is exactly what Generate produces once
// its grouping dashes are stripped: keyLength symbols, each from alphabet.
func wellFormed(normalized string) bool {
	if len(normalized) != keyLength {
		return false
	}
	for i := range len(normalized) {
		if strings.IndexByte(alphabet, normalized[i]) < 0 {
			return false
		}
	}
	return true
}
