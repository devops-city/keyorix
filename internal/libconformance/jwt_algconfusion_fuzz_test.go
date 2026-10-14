package libconformance

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// FuzzJWTAlgorithmConfusion is a lib-contract invariant fuzzer for golang-jwt/jwt/v5 on
// keyorix's call path (internal/core/sso.go, oidc.go verify id_tokens with it). It encodes
// the one property every JWT verifier must hold and that has produced real CVEs across the
// ecosystem: a token is trusted ONLY if it was signed with the exact expected algorithm AND
// key. Everything else — alg:none, HS/RS key-confusion, key substitution, a tampered
// signature — must be rejected.
//
// The verifier here is configured the SAFE way (methods pinned to RS256, keyfunc returns the
// RSA public key); the harness asserts that this correct configuration rejects every forged
// variant. It is a supply-chain regression guard: if a future golang-jwt bump loosens
// method-binding, or a refactor drops WithValidMethods, one of these forgeries starts
// verifying and the target goes red. Sound by construction — every assertion is in the
// "must reject" direction, which has no legitimate exceptions.
func FuzzJWTAlgorithmConfusion(f *testing.F) {
	// Two independent RSA keys, generated once per fuzz process (expensive; never per iter).
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("rsa key: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("rsa key 2: %v", err)
	}
	// The classic HS/RS-confusion secret is the verifier's RSA public key, in the byte forms
	// an attacker would try: PKCS#1 DER and its PEM wrapper.
	pubDER := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubDER})

	// The correct, safe verifier: algorithm pinned, key is the RSA public key.
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	keyfunc := func(*jwt.Token) (any, error) { return &priv.PublicKey, nil }
	verifies := func(s string) bool {
		tok, e := parser.Parse(s, keyfunc)
		return e == nil && tok != nil && tok.Valid
	}

	f.Add("subject-a")
	f.Add("")
	f.Add("admin")

	f.Fuzz(func(t *testing.T, sub string) {
		claims := jwt.MapClaims{"sub": sub, "iss": "keyorix-fuzz"} // no exp/nbf → no time-based rejection

		// Baseline: a correctly-signed RS256 token MUST verify under the correct key. (A
		// failure here is itself a real defect — a valid token the verifier won't accept.)
		good, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(priv)
		if err != nil {
			return // signing failure is not the property under test
		}
		if !verifies(good) {
			t.Fatalf("BASELINE: a correctly RS256-signed token failed to verify under the correct key (sub=%q)", sub)
		}

		// Forgery 1 — alg:none.
		if none, e := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType); e == nil && verifies(none) {
			t.Fatalf("ALG-NONE BYPASS: an alg=none token verified under an RS256-pinned verifier (sub=%q)", sub)
		}

		// Forgery 2 — HS/RS key confusion: HMAC-sign with the RSA public key as the secret.
		for _, secret := range [][]byte{pubDER, pubPEM} {
			if hs, e := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret); e == nil && verifies(hs) {
				t.Fatalf("HS/RS CONFUSION: an HS256 token keyed on the RSA public key verified under an RS256-pinned verifier (sub=%q)", sub)
			}
		}

		// Forgery 3 — key substitution: correct alg, wrong key.
		if sub2, e := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(other); e == nil && verifies(sub2) {
			t.Fatalf("KEY SUBSTITUTION: a token signed with a different RSA key verified under the pinned key (sub=%q)", sub)
		}

		// Forgery 4 — signature tamper: flip a bit in the last signature byte of the good token.
		if b := []byte(good); len(b) > 0 && bytes.IndexByte(b, '.') >= 0 {
			b[len(b)-1] ^= 0x01
			if verifies(string(b)) {
				t.Fatalf("SIGNATURE TAMPER: a token with a flipped signature byte verified (sub=%q)", sub)
			}
		}
	})
}
