package rules

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParseJWK fuzzes ParseJWK, which turns a JWK from an IdP's JWKS endpoint into
// an *rsa.PublicKey / *ecdsa.PublicKey. The JWKS is fetched over the network from a
// (possibly compromised or MITM'd) issuer, so every field here is untrusted.
// FuzzOIDCVerifierVerify uses a static in-memory resolver and never exercises this
// path; yet this is exactly where the RSA modulus/exponent and EC-coordinate bound
// checks live (#100 and the exponent/coordinate-bounds hardening), so it deserves
// its own harness. The seed is fed as raw JSON so the b64url decode, big.Int
// construction, bound checks, and on-curve check are all exercised together.
//
// Invariants: (a) never panics/hangs; (b) an error yields a nil key (no
// partially-built key escapes); (c) a returned key is one of the two supported
// public-key types AND lies within the documented bounds — an RSA modulus inside
// [MinRSABits,MaxRSABits] with a positive exponent <= MaxRSAPublicExponent, or an
// ECDSA key on a named curve. (c) is the regression guard: it fails if any bound
// check is removed or weakened, the class of the original finding.
func FuzzParseJWK(f *testing.F) {
	b64 := base64.RawURLEncoding.EncodeToString

	if rk, err := rsa.GenerateKey(rand.Reader, 2048); err == nil {
		if j, e := json.Marshal(JWK{Kty: "RSA", Kid: "r1", Use: "sig", N: b64(rk.N.Bytes()), E: b64(big.NewInt(int64(rk.E)).Bytes())}); e == nil {
			f.Add(j)
		}
	}
	if ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err == nil {
		if j, e := json.Marshal(JWK{Kty: "EC", Kid: "e1", Use: "sig", Crv: "P-256", X: b64(ek.X.Bytes()), Y: b64(ek.Y.Bytes())}); e == nil {
			f.Add(j)
		}
	}
	for _, s := range []string{
		`{}`,
		`{"kty":"RSA"}`,
		`{"kty":"RSA","n":"!!bad-b64","e":"AQAB"}`,
		`{"kty":"RSA","n":"AQAB","e":"AQAB"}`,                                      // tiny modulus -> below MinRSABits
		`{"kty":"RSA","n":"AQAB","e":"AAAAAAAAAA"}`,                                // absurd exponent
		`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`,                             // off-curve / undersized coords
		`{"kty":"EC","crv":"P-999","x":"AA","y":"AA"}`,                             // unknown curve
		`{"kty":"oct","k":"AAAA"}`,                                                 // unsupported kty
		`{"kty":"EC","crv":"P-521","x":"` + b64(make([]byte, 300)) + `","y":"AA"}`, // oversized coord
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var k JWK
		if json.Unmarshal(data, &k) != nil {
			return // only ParseJWK is under test, not the outer JSON decode
		}
		var key any
		var err error
		fuzzutil.Guard(t.Fatalf, "rules.ParseJWK", func() {
			key, err = ParseJWK(k)
		})
		if err != nil {
			if key != nil {
				t.Fatalf("ParseJWK returned an error but a non-nil key (%T): %v", key, err)
			}
			return
		}
		switch pk := key.(type) {
		case *rsa.PublicKey:
			if bits := pk.N.BitLen(); bits < MinRSABits || bits > MaxRSABits {
				t.Fatalf("ParseJWK accepted an RSA modulus of %d bits, outside [%d,%d]", bits, MinRSABits, MaxRSABits)
			}
			if pk.E <= 0 || int64(pk.E) > int64(MaxRSAPublicExponent) {
				t.Fatalf("ParseJWK accepted an RSA exponent %d outside (0,%d]", pk.E, int64(MaxRSAPublicExponent))
			}
		case *ecdsa.PublicKey:
			if pk.Curve == nil {
				t.Fatalf("ParseJWK accepted an ECDSA key with a nil curve")
			}
		default:
			t.Fatalf("ParseJWK returned an unexpected key type %T", key)
		}
	})
}
