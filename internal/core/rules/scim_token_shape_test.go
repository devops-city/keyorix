package rules

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	mathrand "math/rand/v2"
	"strings"
	"testing"
)

// #3397: tokens that pass the 20-byte floor but are obviously not random.
func TestCheckSCIMTokenShape_RefusesObviouslyNonRandom(t *testing.T) {
	cases := map[string]string{
		"single repeated byte":       "aaaaaaaaaaaaaaaaaaaa",
		"two distinct bytes":         "abababababababababab",
		"nine distinct bytes":        "123456789123456789123456789",
		"changeme":                   "changeme-changeme-ch",
		"CHANGEME upper":             "CHANGEME_0123456789ab",
		"env var name":               "KEYORIX_SCIM_TOKEN__",
		"example":                    "example-scim-token-0123456789",
		"password":                   "Password1234567890!!",
		"test words only":            "test-test-test-test-1",
		"test token":                 "test_token_1234567890",
		"doc sample your-api-token":  "your-api-token-0123456789",
		"doc sample REPLACE_WITH":    "REPLACE_WITH_KEYORIX_SCIM_TOKEN",
		"doc sample choose-a-strong": "choose-a-strong-token-0123456789",
		"secret":                     "my-secret-scim-token-1234",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if len(tok) < MinSCIMTokenLength {
				t.Fatalf("bad fixture: %q is under the length floor", tok)
			}
			err := CheckSCIMTokenShape(tok, nil)
			if err == nil {
				t.Fatalf("%q must be refused", tok)
			}
			msg := err.Error()
			if !strings.Contains(msg, "openssl rand -base64 32") || !strings.Contains(msg, "KEYORIX_SCIM_TOKEN") {
				t.Fatalf("the refusal must name the setting and how to generate a good token: %q", msg)
			}
			if strings.Contains(msg, tok) {
				t.Fatalf("the refusal must not print the token: %q", msg)
			}
		})
	}
}

// A token equal to another configured secret is refused, naming the other
// secret but printing neither value.
func TestCheckSCIMTokenShape_RefusesReuseOfAnotherSecret(t *testing.T) {
	tok := randB64(t)
	err := CheckSCIMTokenShape(tok, map[string]string{"KEYORIX_SIEM_TOKEN": "other", "KEYORIX_DB_PASSWORD": tok})
	if err == nil {
		t.Fatal("a SCIM token that equals the database password must be refused")
	}
	if !strings.Contains(err.Error(), "KEYORIX_DB_PASSWORD") || strings.Contains(err.Error(), tok) {
		t.Fatalf("message must name the other secret and not print the value: %q", err)
	}
	if err := CheckSCIMTokenShape(tok, map[string]string{"KEYORIX_DB_PASSWORD": tok + "x", "EMPTY": ""}); err != nil {
		t.Fatalf("distinct secrets must pass: %v", err)
	}
}

// What `openssl rand -base64 32` / `-hex 32` (and base64url) produce must not be
// refused: the checks look for structure, not for luck. The bytes come from a
// fixed-seed ChaCha8 stream, so the run is the same every time (a placeholder
// substring turns up in a random token with probability around 4e-8, which a
// fresh random sample of 80,000 tokens per CI run would hit now and then).
func TestCheckSCIMTokenShape_AcceptsGeneratedTokens(t *testing.T) {
	if err := CheckSCIMTokenShape("", nil); err != nil {
		t.Fatalf("empty token (SCIM not configured) is not this check's business: %v", err)
	}
	stream := mathrand.NewChaCha8([32]byte{3, 3, 9, 7})
	for range 20000 {
		b := make([]byte, 32)
		_, _ = stream.Read(b)
		for _, tok := range []string{
			base64.StdEncoding.EncodeToString(b),
			base64.RawURLEncoding.EncodeToString(b),
			hex.EncodeToString(b),
			base64.StdEncoding.EncodeToString(b[:15]), // 20 chars: the floor itself
		} {
			if err := CheckSCIMTokenShape(tok, nil); err != nil {
				t.Fatalf("generated token %q refused: %v", tok, err)
			}
		}
	}
}

func randB64(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
