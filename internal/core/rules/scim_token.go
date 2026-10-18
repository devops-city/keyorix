package rules

import (
	"crypto/subtle"
	"fmt"
	"slices"
	"strings"
)

// MinSCIMTokenLength is the minimum length required for the configured SCIM
// bearer token (scim.token / KEYORIX_SCIM_TOKEN). Unlike a PAT or machine token
// (always server-generated, 32 random bytes — see pat.go/machine_token.go), the
// SCIM token is operator-supplied and had no strength floor at all: an operator
// could configure a short, guessable string and the provisioning endpoint would
// accept it, in constant time, forever. 20 chars from a typical token alphabet is
// already >=119 bits of entropy, well above what's brute-forceable over the
// network — the same bar DefaultPasswordPolicy sets for a human password (16
// chars, but with mandatory character-class mixing this token doesn't have; the
// higher floor compensates). Checked once at server startup (see
// server/http/router.go), not per-request, so a misconfigured install fails fast
// with a clear error instead of quietly running with a weak provisioning
// credential.
const MinSCIMTokenLength = 20

// ValidateSCIMTokenStrength rejects a configured SCIM bearer token shorter than
// MinSCIMTokenLength. An empty token is NOT an error here — SCIM being disabled or
// not yet configured is legitimate; server/middleware/scim.go's SCIMToken already
// fails every request closed on an empty token. This only guards against a
// too-short but non-empty token, which the constant-time compare would otherwise
// accept as configured.
func ValidateSCIMTokenStrength(token string) error {
	if token == "" {
		return nil
	}
	if len(token) < MinSCIMTokenLength {
		return fmt.Errorf("SCIM token is too short (%d chars, minimum %d) — configure a longer, high-entropy token via KEYORIX_SCIM_TOKEN", len(token), MinSCIMTokenLength)
	}
	return nil
}

// MinSCIMTokenDistinctBytes is the fewest distinct byte values a SCIM token may
// contain (#3397). A token from `openssl rand -base64 32` has about 32, and even
// a 20-character random base64 token has fewer than 10 with probability about
// 1e-7. Hex is the exception: with only 16 symbols, a short hex token can fall
// under the bar by chance (20 characters, `openssl rand -hex 10`: about 5%; 32
// characters: about 1e-4; 64 characters, `openssl rand -hex 32`: about 1e-12).
const MinSCIMTokenDistinctBytes = 10

// scimTokenGenerateHint ends every CheckSCIMTokenShape refusal: the setting and
// how to make a good token.
const scimTokenGenerateHint = ` -- set KEYORIX_SCIM_TOKEN (or scim.token) to a generated value, for example the output of "openssl rand -base64 32", and give the same value to your IdP's SCIM connector`

// scimPlaceholderSubstrings are refused anywhere in the token, case-insensitively.
// Each is at least six letters long, so a random base64 token contains one by
// chance with probability under 1e-7 (and a hex token never: each has a letter
// outside a-f).
var scimPlaceholderSubstrings = []string{"changeme", "password", "passphrase", "example", "secret", "keyorix", "replace", "placeholder"}

// scimPlaceholderWords catch sample values made of words: a token whose letters
// (lowercased, with digits and punctuation dropped) are nothing but these words,
// at least one of them four letters or longer, is refused ("test-token-1234",
// "your-api-token-here", the docs' "choose-a-strong-..."). The letters of a random
// token never split this way; the four-letter rule keeps a hex token whose only
// letter is an "a" from matching, and no word of four or more letters is made of
// hex letters only.
var scimPlaceholderWords = []string{
	"a", "me", "my", "api", "key", "new", "dev", "idp", "here", "test", "token", "scim", "your",
	"with", "demo", "prod", "admin", "dummy", "value", "local", "change", "choose", "strong",
	"insert", "sample", "bearer", "default", "provisioning",
}

// CheckSCIMTokenShape refuses a configured SCIM token that passes the length
// floor (ValidateSCIMTokenStrength) but is obviously not random (#3397): a single
// repeated byte, fewer than MinSCIMTokenDistinctBytes distinct bytes, a known
// placeholder or sample value, or the same value as another configured secret
// (otherSecrets: name -> value; empty values are ignored, names appear in the
// message, values never do). An empty token is not this check's business, as for
// ValidateSCIMTokenStrength.
//
// What it does not do: estimate entropy. "12345678901234567890" (ten distinct
// digits) passes, as does any token a person typed that avoids the patterns
// above. The checks are structural on purpose, so that a token from
// `openssl rand -base64 32` or `-hex 32` is not refused
// (TestCheckSCIMTokenShape_AcceptsGeneratedTokens); see MinSCIMTokenDistinctBytes
// for short hex tokens.
func CheckSCIMTokenShape(token string, otherSecrets map[string]string) error {
	if token == "" {
		return nil
	}
	if reason := scimTokenShapeProblem(token); reason != "" {
		return fmt.Errorf("SCIM token is too weak: %s%s", reason, scimTokenGenerateHint)
	}
	names := make([]string, 0, len(otherSecrets))
	for name, v := range otherSecrets {
		if v != "" && subtle.ConstantTimeCompare([]byte(v), []byte(token)) == 1 {
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		slices.Sort(names)
		return fmt.Errorf("SCIM token is too weak: it is the same value as %s, so whoever holds one holds both%s", strings.Join(names, ", "), scimTokenGenerateHint)
	}
	return nil
}

func scimTokenShapeProblem(token string) string {
	var seen [256]bool
	distinct := 0
	for i := range len(token) {
		if !seen[token[i]] {
			seen[token[i]] = true
			distinct++
		}
	}
	switch {
	case distinct == 1:
		return "it is one byte repeated"
	case distinct < MinSCIMTokenDistinctBytes:
		return fmt.Sprintf("it has only %d distinct bytes (at least %d are required)", distinct, MinSCIMTokenDistinctBytes)
	}
	lower := strings.ToLower(token)
	for _, p := range scimPlaceholderSubstrings {
		if strings.Contains(lower, p) {
			return "it contains a known placeholder (" + p + ")"
		}
	}
	if onlyPlaceholderWords(lower) {
		return "it is a sample value made of placeholder words"
	}
	return ""
}

// onlyPlaceholderWords reports whether the letters of s split completely into
// scimPlaceholderWords with at least one word of four or more letters.
func onlyPlaceholderWords(s string) bool {
	letters := make([]byte, 0, len(s))
	for i := range len(s) {
		if c := s[i]; c >= 'a' && c <= 'z' {
			letters = append(letters, c)
		}
	}
	n := len(letters)
	if n < 4 {
		return false
	}
	// reach[i]: bit 1 = letters[:i] splits into words, bit 2 = and one of them
	// has four or more letters.
	reach := make([]uint8, n+1)
	reach[0] = 1
	for i := range n {
		if reach[i] == 0 {
			continue
		}
		for _, w := range scimPlaceholderWords {
			if i+len(w) > n || string(letters[i:i+len(w)]) != w {
				continue
			}
			next := reach[i]
			if len(w) >= 4 {
				next |= 2
			}
			reach[i+len(w)] |= next | 1
		}
	}
	return reach[n]&2 != 0
}
