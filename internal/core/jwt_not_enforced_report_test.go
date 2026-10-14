package core

// jwt_not_enforced_report_test.go — report-only probes for the constraint
// rows that remain NOT ENFORCED after the 2026-09-23 fix
// (docs/findings/2026-09-23-FINDING-oidc-future-iat-and-crit.md): a "typ"
// header mismatch (both paths — an open design question, not fixed here; see
// the finding doc), and — SSO path only — far-past iat (verifyIDToken still
// has no max-age ceiling; the far-FUTURE direction is now asserted via
// jwtViolationIatFutureBeyondLeeway in jwt_single_constraint_fuzz_test.go, and
// crit is now asserted via jwtViolationCritHeader in the same file — both
// removed from this report-only file since they're no longer NOT ENFORCED).
//
// These record accept/reject via t.Logf and never fail the test — the point
// is to put a verified CURRENT answer next to each remaining NOT ENFORCED row,
// not to gate CI on a change to intentionally-out-of-scope behaviour. New file
// only; does not touch any existing OIDC/SSO test file.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signWithHeaderOverride signs claims normally (RS256, trustedKid) and then
// sets one extra/overridden JOSE header field — used to probe typ/crit, which
// signJWTViolation has no notion of (those aren't claim or alg/kid concerns).
func signWithHeaderOverride(t *testing.T, claims jwt.MapClaims, rsaKey *rsa.PrivateKey, trustedKid, headerKey string, headerVal any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = trustedKid
	tok.Header[headerKey] = headerVal
	s, err := tok.SignedString(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signNormal signs claims with no violation at all (RS256, trustedKid) — used
// for probes that only mutate a claim (iat far-past/far-future), not a header.
func signNormal(t *testing.T, claims jwt.MapClaims, rsaKey *rsa.PrivateKey, trustedKid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = trustedKid
	s, err := tok.SignedString(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestJWTNotEnforcedConstraintMatrix(t *testing.T) {
	const trustedIss = "https://k8s.local"
	const trustedAud = "keyorix"
	const clientID = "client-1"
	const trustedKid = "kid-1"
	const correctNonce = "expected-nonce-value"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{{Issuer: trustedIss, Audiences: []string{trustedAud}}},
		staticResolver{kid: trustedKid, key: &key.PublicKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	c := &KeyorixCore{now: time.Now, ssoJWKS: staticResolver{kid: trustedKid, key: &key.PublicKey}}
	p := &SSOProvider{Name: "okta", Issuer: trustedIss, ClientID: clientID}

	logOIDC := func(label, raw string) {
		t.Helper()
		_, _, err := v.Verify(context.Background(), raw)
		if err != nil {
			t.Logf("OIDCVerifier.Verify  | %-40s | REJECTED (%v)", label, err)
		} else {
			t.Logf("OIDCVerifier.Verify  | %-40s | ACCEPTED", label)
		}
	}
	logSSO := func(label, raw string) {
		t.Helper()
		_, _, _, _, err := c.verifyIDToken(context.Background(), p, correctNonce, raw)
		if err != nil {
			t.Logf("verifyIDToken (SSO)  | %-40s | REJECTED (%v)", label, err)
		} else {
			t.Logf("verifyIDToken (SSO)  | %-40s | ACCEPTED", label)
		}
	}

	now := time.Now()

	// typ: a JOSE typ header naming something other than a JWT (RFC 8725 §3.11
	// explicit-typing recommendation — not required by either verifier's
	// config here). Open design question for the machine-federation path
	// specifically — should it reject typ="at+jwt" (access-token/ID-token
	// confusion)? — captured in the finding doc; behaviour intentionally
	// unchanged.
	typClaimsOIDC := oidcSingleConstraintBaseClaims(now, "sa-typ", trustedIss, trustedAud)
	logOIDC(`typ: "not-a-jwt"`, signWithHeaderOverride(t, typClaimsOIDC, key, trustedKid, "typ", "not-a-jwt"))
	typClaimsSSO := ssoSingleConstraintBaseClaims(now, "sub-typ", trustedIss, clientID, correctNonce)
	logSSO(`typ: "not-a-jwt"`, signWithHeaderOverride(t, typClaimsSSO, key, trustedKid, "typ", "not-a-jwt"))

	// SSO-path iat far-PAST only: verifyIDToken still has no max-age ceiling
	// (jwt.WithIssuedAt() only bounds the future direction) — expected
	// ACCEPTED. The far-future case is now asserted (jwtViolationIatFutureBeyondLeeway
	// in jwt_single_constraint_fuzz_test.go), not probed here.
	iatPastClaims := ssoSingleConstraintBaseClaims(now, "sub-iat-past", trustedIss, clientID, correctNonce)
	iatPastClaims["iat"] = now.Add(-10 * 365 * 24 * time.Hour).Unix() // 10 years ago
	logSSO("iat: 10 years in the past", signNormal(t, iatPastClaims, key, trustedKid))
}
