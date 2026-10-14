package core

// jwt_cross_verifier_differential_test.go — for every constraint BOTH
// OIDCVerifier.Verify and verifyIDToken enforce (alg allowlist, kid, iss,
// aud, azp, exp, nbf, sub, crit header, iat-in-the-future — sharedJWTViolationKinds
// in jwt_single_constraint_fuzz_test.go), builds the SAME single-violation kind
// against each verifier's own issuer/audience config and asserts BOTH reject.
// A divergence here (one accepts what the other rejects, for a constraint
// both are supposed to enforce) is exactly the shape of bug a lone
// per-verifier fuzz target can't see — each one only ever proves its own
// verifier self-consistent, never that the two independently-implemented
// "mirrors" (sso.go's own comment: "Mirrors OIDCVerifier.Verify in oidc.go")
// haven't drifted apart.
//
// Red-proof (run manually, not committed): widen OIDCVerifier.Verify's
// WithValidMethods allowlist in oidc.go to include "HS256", rerun this test
// — TestOIDCSSODifferential_SingleConstraintViolation/kind=alg_hs256_key_confusion
// goes red because OIDCVerifier now accepts what verifyIDToken still (correctly)
// rejects. See the report for the actual red/green transcript.
//
// New file only; does not touch any existing OIDC/SSO test file.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func TestOIDCSSODifferential_SingleConstraintViolation(t *testing.T) {
	const oidcIss = "https://k8s.local"
	const oidcAud = "keyorix"
	const ssoIss = "https://idp.test"
	const ssoClientID = "client-1"
	const trustedKid = "kid-1"
	const correctNonce = "expected-nonce-value"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	p := &SSOProvider{Name: "okta", Issuer: ssoIss, ClientID: ssoClientID}

	for _, kind := range sharedJWTViolationKinds {
		t.Run("kind="+kind.String(), func(t *testing.T) {
			// Pin each verifier's clock to this subtest's own `now` — see the
			// matching comment in jwt_single_constraint_fuzz_test.go's
			// FuzzOIDCIDTokenSingleConstraintViolation. Needed here too: this
			// test exercises the same boundaryMargin=1s exp/nbf edge cases via
			// t.Errorf (gating, not report-only), so a construction-vs-
			// verification clock drift under load could produce the same
			// false-negative flake the fuzz targets had before #1983.
			now := time.Now()
			v, err := NewOIDCVerifier(
				[]OIDCTrustedIssuer{{Issuer: oidcIss, Audiences: []string{oidcAud}}},
				staticResolver{kid: trustedKid, key: &key.PublicKey},
			)
			if err != nil {
				t.Fatal(err)
			}
			v.setClock(func() time.Time { return now })
			c := &KeyorixCore{now: time.Now, ssoJWKS: staticResolver{kid: trustedKid, key: &key.PublicKey}}
			c.SetClockForTesting(func() time.Time { return now })

			oidcClaims := oidcSingleConstraintBaseClaims(now, "sa-differential", oidcIss, oidcAud)
			applySharedJWTViolation(kind, oidcClaims, now, oidcIss, oidcAud, oidcClockSkew)
			oidcRaw := signJWTViolation(t, kind, oidcClaims, key, trustedKid)
			_, _, oidcErr := v.Verify(context.Background(), oidcRaw)

			ssoClaims := ssoSingleConstraintBaseClaims(now, "sub-differential", ssoIss, ssoClientID, correctNonce)
			applySharedJWTViolation(kind, ssoClaims, now, ssoIss, ssoClientID, ssoClockSkew)
			ssoRaw := signJWTViolation(t, kind, ssoClaims, key, trustedKid)
			_, _, _, _, ssoErr := c.verifyIDToken(context.Background(), p, correctNonce, ssoRaw)

			if oidcErr == nil {
				t.Errorf("differential: OIDCVerifier.Verify ACCEPTED violation %q that verifyIDToken should also reject", kind)
			}
			if ssoErr == nil {
				t.Errorf("differential: verifyIDToken ACCEPTED violation %q that OIDCVerifier.Verify should also reject", kind)
			}
		})
	}
}

// TestJWTViolationKindStringIsExhaustive fails if a kind added to any of the
// three kind lists doesn't have a name in jwtViolationKind.String() — a
// silent "unknown_violation_kind" in a differential sub-test name or a fuzz
// failure message would make a real finding harder to triage, not just be
// cosmetic.
func TestJWTViolationKindStringIsExhaustive(t *testing.T) {
	all := map[jwtViolationKind]bool{jwtViolationNone: true}
	for _, k := range oidcJWTViolationKinds {
		all[k] = true
	}
	for _, k := range ssoJWTViolationKinds {
		all[k] = true
	}
	for k := range all {
		if got := k.String(); got == "unknown_violation_kind" {
			t.Errorf("jwtViolationKind(%d).String() returned the default case — add a name", int(k))
		}
	}
}
