package core

// jwt_single_constraint_fuzz_test.go — builds a fully valid JWT/OIDC id_token
// signed with the harness's own trusted key, then violates EXACTLY ONE
// verification constraint chosen by the fuzz input (leaving every other claim/
// header valid) and asserts: 0 violations => accepted with the expected
// identity; 1 violation => rejected. Two independent fuzz targets, one per
// verifier — see docs on jwtViolationKind below for why the constraint sets
// differ between them.
//
// New file only. Does not edit FuzzOIDCVerifierVerify / FuzzVerifyIDToken /
// FuzzOIDCVerifierClaims / FuzzVerifyIDTokenClaims / jwt_algconfusion_fuzz_test.go
// (owned by another session) — it reuses their signing-helper PATTERN
// (RSA keygen + jwt.NewWithClaims(...).SignedString(key) + manual kid header)
// and their package-level test fixtures (staticResolver, signToken) by
// calling them, not by copying or editing their file.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// jsonRoundTripString returns what s becomes after passing through
// encoding/json.Marshal then Unmarshal — the same transform a claim value
// undergoes on its way into and back out of a signed JWT. encoding/json
// silently rewrites invalid UTF-8 bytes to U+FFFD on Marshal (documented
// behavior, not a bug), so a fuzzed subject containing invalid UTF-8 does
// NOT round-trip byte-for-byte; the "0 violations" identity check must
// compare against this, not the pre-encoding fuzz input, or a perfectly
// valid accept gets misreported as "wrong identity".
// boundaryMargin is how far past the verifier's clock-skew leeway an
// exp/nbf violation is pushed. Was widened to 10s (from 1s) because
// golang-jwt's exp/nbf checks used to always read the real wall clock
// directly (neither oidc.go nor sso.go called jwt.WithTimeFunc), so the gap
// between this test's `now := time.Now()` and the library's own
// verification-time now() was never zero, and under -parallel=2 CPU
// contention (GC pauses, goroutine scheduling delays) that gap occasionally
// exceeded 1 second — enough to make a token meant to be 1s past the boundary
// land back inside it, producing a false CONSTRAINT BYPASS (found live:
// kind=nbf_future_beyond_skew accepted after an 8s fuzz run, testdata/fuzz/
// FuzzOIDCIDTokenSingleConstraintViolation/de868c9cc60f40dd).
//
// #1983 closed the underlying gap: both fuzz targets below now freeze the
// verifier's clock (v.setClock / c.SetClockForTesting) to the exact `now`
// used to build the claims, for the duration of that one Verify call — via
// jwt.WithTimeFunc, golang-jwt's own exp/nbf/iat-future check reads that same
// frozen instant instead of a fresh real-time read. With construction-time
// and verification-time clock reads now byte-identical, the boundary can be
// asserted precisely again.
const boundaryMargin = 1 * time.Second

func jsonRoundTripString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	var out string
	if err := json.Unmarshal(b, &out); err != nil {
		return s
	}
	return out
}

// jwtViolationKind identifies exactly one verification constraint violated by
// a generated token. jwtViolationNone means "no violation" — the baseline
// token must verify and return the identity it names. Every other kind must
// be rejected regardless of what the fuzzer does to the non-violated fields
// (subject value, RSA key material is fixed per-run) — a single violated
// constraint is sufficient to force rejection, independent of every other
// claim being otherwise perfectly valid.
type jwtViolationKind int

const (
	jwtViolationNone jwtViolationKind = iota
	jwtViolationAlgNone
	jwtViolationAlgHS256KeyConfusion // HMAC-"sign" with the RSA public key's DER bytes as the secret
	jwtViolationAlgUnsupportedAsym   // EdDSA: a real asymmetric alg, just not one either verifier allowlists
	jwtViolationKidMissing
	jwtViolationKidUnknown
	jwtViolationIssMissing
	jwtViolationIssWrong
	jwtViolationAudMissing
	jwtViolationAudWrongSingle
	jwtViolationAudArrayAllWrong
	jwtViolationAudArrayRightAndWrongNoAzp
	jwtViolationAzpWrongMultiAud
	jwtViolationExpMissing
	jwtViolationExpPastSkewBoundary // exp = now - (skew + boundaryMargin): past the leeway
	jwtViolationNbfFutureBeyondSkew
	jwtViolationSubEmpty
	// jwtViolationCritHeader carries a "crit" JOSE header (RFC 7515 §4.1.11: a
	// recipient MUST reject a JWS whose crit header names an extension it
	// doesn't understand — both verifiers understand none). Fixed 2026-09-23
	// (docs/findings/2026-09-23-FINDING-oidc-future-iat-and-crit.md); shared
	// because both oidc.go's Verify and sso.go's verifyIDToken now reject any
	// crit header identically, regardless of what it names.
	jwtViolationCritHeader
	// jwtViolationIatFutureBeyondLeeway is shared: both oidc.go's Verify and
	// sso.go's verifyIDToken now pass jwt.WithIssuedAt() (golang-jwt v5),
	// which rejects an iat more than the verifier's leeway into the future.
	// Before the 2026-09-23 fix this was OIDC-only and asserted-but-failing —
	// a future-dated iat made oidc.go's max-age check's age computation
	// NEGATIVE, which can never exceed a positive maxAge+leeway bound, so
	// nothing rejected it (docs/findings/2026-09-23-FINDING-oidc-future-iat-and-crit.md).
	jwtViolationIatFutureBeyondLeeway

	// OIDCVerifier.Verify (machine-federation, oidc.go)-only: that path
	// additionally requires iat and bounds (now - iat) against a per-issuer
	// max age (oidc.go:198-203). verifyIDToken (sso.go, interactive SSO) has
	// no such max-age check — confirmed by direct read of sso.go, and safe to
	// exclude from that path's assert set because (1) sso.go:948 requires a
	// non-empty, single-use nonce (bound via a race-safe conditional DELETE
	// in ConsumeSSOLoginState, local_sso.go:35-56) so a captured id_token
	// cannot be replayed into a second login, and (2) the id_token is
	// obtained exclusively via the server-side token-endpoint exchange
	// (sso.go:217-221) — server/http/handlers/sso.go's callback handler reads
	// only "code"/"state" from the query string, never an id_token from the
	// front channel — so there is no long-lived-bearer-token replay surface
	// here the way there is for the standalone federation JWT. The SSO path's
	// far-past-iat is still accepted by design (see
	// jwt_not_enforced_report_test.go) — jwt.WithIssuedAt() only ever bounds
	// the future direction.
	jwtViolationIatMissing
	jwtViolationIatMaxAgeExceeded

	// verifyIDToken (interactive SSO, sso.go)-only.
	jwtViolationNonceMissing
	jwtViolationNonceMismatch
)

// String names a violation kind for failure messages and differential
// sub-test names — kept in sync with the const block above by a coverage
// test (jwt_cross_verifier_differential_test.go) that runs String() over
// every kind in sharedJWTViolationKinds ∪ oidcJWTViolationKinds ∪
// ssoJWTViolationKinds and fails on the default case.
func (k jwtViolationKind) String() string {
	switch k {
	case jwtViolationNone:
		return "none"
	case jwtViolationAlgNone:
		return "alg_none"
	case jwtViolationAlgHS256KeyConfusion:
		return "alg_hs256_key_confusion"
	case jwtViolationAlgUnsupportedAsym:
		return "alg_unsupported_asym_eddsa"
	case jwtViolationKidMissing:
		return "kid_missing"
	case jwtViolationKidUnknown:
		return "kid_unknown"
	case jwtViolationIssMissing:
		return "iss_missing"
	case jwtViolationIssWrong:
		return "iss_wrong"
	case jwtViolationAudMissing:
		return "aud_missing"
	case jwtViolationAudWrongSingle:
		return "aud_wrong_single"
	case jwtViolationAudArrayAllWrong:
		return "aud_array_all_wrong"
	case jwtViolationAudArrayRightAndWrongNoAzp:
		return "aud_array_right_and_wrong_no_azp"
	case jwtViolationAzpWrongMultiAud:
		return "azp_wrong_multi_aud"
	case jwtViolationExpMissing:
		return "exp_missing"
	case jwtViolationExpPastSkewBoundary:
		return "exp_past_skew_boundary"
	case jwtViolationNbfFutureBeyondSkew:
		return "nbf_future_beyond_skew"
	case jwtViolationSubEmpty:
		return "sub_empty"
	case jwtViolationCritHeader:
		return "crit_header"
	case jwtViolationIatMissing:
		return "iat_missing"
	case jwtViolationIatMaxAgeExceeded:
		return "iat_max_age_exceeded"
	case jwtViolationIatFutureBeyondLeeway:
		return "iat_future_beyond_leeway"
	case jwtViolationNonceMissing:
		return "nonce_missing"
	case jwtViolationNonceMismatch:
		return "nonce_mismatch"
	default:
		return "unknown_violation_kind"
	}
}

// sharedJWTViolationKinds are the constraints BOTH verifiers enforce —
// exercised against each verifier by its own fuzz target below, and reused
// verbatim by the cross-verifier differential test in
// jwt_cross_verifier_differential_test.go.
var sharedJWTViolationKinds = []jwtViolationKind{
	jwtViolationAlgNone,
	jwtViolationAlgHS256KeyConfusion,
	jwtViolationAlgUnsupportedAsym,
	jwtViolationKidMissing,
	jwtViolationKidUnknown,
	jwtViolationIssMissing,
	jwtViolationIssWrong,
	jwtViolationAudMissing,
	jwtViolationAudWrongSingle,
	jwtViolationAudArrayAllWrong,
	jwtViolationAudArrayRightAndWrongNoAzp,
	jwtViolationAzpWrongMultiAud,
	jwtViolationExpMissing,
	jwtViolationExpPastSkewBoundary,
	jwtViolationNbfFutureBeyondSkew,
	jwtViolationSubEmpty,
	jwtViolationCritHeader,
	jwtViolationIatFutureBeyondLeeway,
}

var oidcJWTViolationKinds = append(append([]jwtViolationKind{}, sharedJWTViolationKinds...),
	jwtViolationIatMissing, jwtViolationIatMaxAgeExceeded)

var ssoJWTViolationKinds = append(append([]jwtViolationKind{}, sharedJWTViolationKinds...),
	jwtViolationNonceMissing, jwtViolationNonceMismatch)

// signJWTViolation signs claims according to kind's alg/kid requirement
// (identical mechanics for both verifiers — alg/kid enforcement doesn't
// depend on which claims struct is parsing the result) and returns the
// non-alg/kid kinds signed normally (RS256, trustedKid) so the caller's claim
// mutation is the only thing under test.
func signJWTViolation(t *testing.T, kind jwtViolationKind, claims jwt.MapClaims, rsaKey *rsa.PrivateKey, trustedKid string) string {
	t.Helper()
	kid := trustedKid
	var method jwt.SigningMethod = jwt.SigningMethodRS256
	var signingKey any = rsaKey

	switch kind {
	case jwtViolationKidMissing:
		kid = ""
	case jwtViolationKidUnknown:
		kid = "not-the-real-kid"
	case jwtViolationAlgNone:
		method = jwt.SigningMethodNone
		signingKey = jwt.UnsafeAllowNoneSignatureType
	case jwtViolationAlgHS256KeyConfusion:
		method = jwt.SigningMethodHS256
		pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		signingKey = pubDER
	case jwtViolationAlgUnsupportedAsym:
		edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_ = edPub
		method = jwt.SigningMethodEdDSA
		signingKey = edPriv
	}

	tok := jwt.NewWithClaims(method, claims)
	if kind != jwtViolationKidMissing {
		tok.Header["kid"] = kid
	}
	if kind == jwtViolationCritHeader {
		// The extension name doesn't matter — both verifiers reject ANY crit
		// header, since they understand none.
		tok.Header["crit"] = []string{"exp"}
	}
	s, err := tok.SignedString(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// applySharedJWTViolation mutates claims in place for every constraint kind
// both verifiers enforce identically (parameterised by each verifier's own
// trusted issuer/audience so the differential test can drive both verifiers
// off the SAME kind with each one's own config). No-op for alg/kid/iat/nonce
// kinds — those are handled by signJWTViolation or the caller.
func applySharedJWTViolation(kind jwtViolationKind, claims jwt.MapClaims, now time.Time, trustedIss, trustedAud string, leeway time.Duration) {
	switch kind {
	case jwtViolationIssMissing:
		delete(claims, "iss")
	case jwtViolationIssWrong:
		claims["iss"] = "https://evil.test"
	case jwtViolationAudMissing:
		delete(claims, "aud")
	case jwtViolationAudWrongSingle:
		claims["aud"] = "wrong-aud"
	case jwtViolationAudArrayAllWrong:
		claims["aud"] = []string{"wrong-aud-1", "wrong-aud-2"}
	case jwtViolationAudArrayRightAndWrongNoAzp:
		claims["aud"] = []string{trustedAud, "wrong-aud"}
	case jwtViolationAzpWrongMultiAud:
		claims["aud"] = []string{trustedAud, "wrong-aud"}
		claims["azp"] = "not-a-trusted-azp"
	case jwtViolationExpMissing:
		delete(claims, "exp")
	case jwtViolationExpPastSkewBoundary:
		claims["exp"] = now.Add(-(leeway + boundaryMargin)).Unix()
	case jwtViolationNbfFutureBeyondSkew:
		claims["nbf"] = now.Add(leeway + boundaryMargin).Unix()
	case jwtViolationSubEmpty:
		claims["sub"] = ""
	case jwtViolationIatFutureBeyondLeeway:
		claims["iat"] = now.Add(leeway + time.Hour).Unix()
	}
}

// ---- OIDCVerifier.Verify (machine-identity federation, oidc.go) ----

func oidcSingleConstraintBaseClaims(now time.Time, sub, trustedIss, trustedAud string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": trustedIss,
		"aud": trustedAud, // single string: exercises the non-array unmarshal path for the baseline
		"sub": sub,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

func applyOIDCOnlyViolation(kind jwtViolationKind, claims jwt.MapClaims, now time.Time, maxAge, leeway time.Duration) {
	switch kind {
	case jwtViolationIatMissing:
		delete(claims, "iat")
	case jwtViolationIatMaxAgeExceeded:
		claims["iat"] = now.Add(-(maxAge + leeway + time.Second)).Unix()
	}
}

// FuzzOIDCIDTokenSingleConstraintViolation targets OIDCVerifier.Verify
// (internal/core/oidc.go), the machine-identity federation path (ADR-031).
func FuzzOIDCIDTokenSingleConstraintViolation(f *testing.F) {
	const trustedIss = "https://k8s.local"
	const trustedAud = "keyorix"
	const trustedKid = "kid-1"
	const leeway = oidcClockSkew

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{{Issuer: trustedIss, Audiences: []string{trustedAud}}},
		staticResolver{kid: trustedKid, key: &key.PublicKey},
	)
	if err != nil {
		f.Fatal(err)
	}

	kinds := oidcJWTViolationKinds
	f.Add(uint8(0), "service-account:ns/name") // 0 violations
	for i := range kinds {
		f.Add(uint8(i+1), "service-account:ns/name")
	}

	f.Fuzz(func(t *testing.T, selector uint8, sub string) {
		idx := int(selector) % (len(kinds) + 1)
		kind := jwtViolationNone
		if idx > 0 {
			kind = kinds[idx-1]
		}
		if strings.TrimSpace(sub) == "" && kind != jwtViolationSubEmpty {
			sub = "service-account:ns/fuzz" // don't let a fuzzed empty subject smuggle in a second, unintended violation
		}

		now := time.Now()
		// Freeze v's clock to the exact instant the claims below are built
		// against, so golang-jwt's own exp/nbf/iat-future check (wired via
		// jwt.WithTimeFunc) and the custom max-age check (effectiveNow) both
		// see the same "now" Verify was called with — no construction-vs-
		// verification clock drift left to produce a false boundary result.
		v.setClock(func() time.Time { return now })
		claims := oidcSingleConstraintBaseClaims(now, sub, trustedIss, trustedAud)
		applySharedJWTViolation(kind, claims, now, trustedIss, trustedAud, leeway)
		applyOIDCOnlyViolation(kind, claims, now, defaultOIDCMaxTokenAge, leeway)
		raw := signJWTViolation(t, kind, claims, key, trustedKid)

		var issuer, subject string
		var verr error
		fuzzutil.Guard(t.Fatalf, "OIDCVerifier.Verify(single-constraint)", func() {
			issuer, subject, verr = v.Verify(context.Background(), raw)
		})

		if kind == jwtViolationNone {
			if verr != nil {
				t.Fatalf("0 violations: expected acceptance, got rejection: %v", verr)
			}
			if wantSub := jsonRoundTripString(sub); issuer != trustedIss || subject != wantSub {
				t.Fatalf("0 violations: accepted with the wrong identity: issuer=%q subject=%q want iss=%q sub=%q", issuer, subject, trustedIss, wantSub)
			}
			return
		}
		if verr == nil {
			t.Fatalf("CONSTRAINT BYPASS: violation kind %d was accepted by OIDCVerifier.Verify (issuer=%q subject=%q)", kind, issuer, subject)
		}
	})
}

// ---- KeyorixCore.verifyIDToken (interactive SSO login, sso.go) ----

func ssoSingleConstraintBaseClaims(now time.Time, sub, trustedIss, clientID, nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   trustedIss,
		"aud":   clientID,
		"sub":   sub,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": nonce,
	}
}

func applySSOOnlyViolation(kind jwtViolationKind, claims jwt.MapClaims) {
	switch kind {
	case jwtViolationNonceMissing:
		delete(claims, "nonce")
	case jwtViolationNonceMismatch:
		claims["nonce"] = "wrong-nonce-value"
	}
}

// FuzzSSOIDTokenSingleConstraintViolation targets KeyorixCore.verifyIDToken
// (internal/core/sso.go), the interactive SSO login path.
func FuzzSSOIDTokenSingleConstraintViolation(f *testing.F) {
	const trustedIss = "https://idp.test"
	const clientID = "client-1"
	const trustedKid = "kid-1"
	const correctNonce = "expected-nonce-value"
	const leeway = ssoClockSkew

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	c := &KeyorixCore{
		now:     time.Now,
		ssoJWKS: staticResolver{kid: trustedKid, key: &key.PublicKey},
	}
	p := &SSOProvider{Name: "okta", Issuer: trustedIss, ClientID: clientID}

	kinds := ssoJWTViolationKinds
	f.Add(uint8(0), "okta|123")
	for i := range kinds {
		f.Add(uint8(i+1), "okta|123")
	}

	f.Fuzz(func(t *testing.T, selector uint8, sub string) {
		idx := int(selector) % (len(kinds) + 1)
		kind := jwtViolationNone
		if idx > 0 {
			kind = kinds[idx-1]
		}
		if strings.TrimSpace(sub) == "" && kind != jwtViolationSubEmpty {
			sub = "okta|fuzz"
		}

		now := time.Now()
		// Freeze c's clock to the exact instant the claims below are built
		// against — see the matching comment in FuzzOIDCIDTokenSingleConstraintViolation.
		c.SetClockForTesting(func() time.Time { return now })
		claims := ssoSingleConstraintBaseClaims(now, sub, trustedIss, clientID, correctNonce)
		applySharedJWTViolation(kind, claims, now, trustedIss, clientID, leeway)
		applySSOOnlyViolation(kind, claims)
		raw := signJWTViolation(t, kind, claims, key, trustedKid)

		var subject string
		var verr error
		fuzzutil.Guard(t.Fatalf, "verifyIDToken(single-constraint)", func() {
			subject, _, _, _, verr = c.verifyIDToken(context.Background(), p, correctNonce, raw)
		})

		if kind == jwtViolationNone {
			if verr != nil {
				t.Fatalf("0 violations: expected acceptance, got rejection: %v", verr)
			}
			if wantSub := jsonRoundTripString(sub); subject != wantSub {
				t.Fatalf("0 violations: accepted with the wrong identity: subject=%q want sub=%q", subject, wantSub)
			}
			return
		}
		if verr == nil {
			t.Fatalf("CONSTRAINT BYPASS: violation kind %d was accepted by verifyIDToken (subject=%q)", kind, subject)
		}
	})
}
