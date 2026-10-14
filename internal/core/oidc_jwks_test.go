package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPJWKSResolver_FetchAndCache(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &key.PublicKey

	// Serve a JWKS with the public key under kid "k1".
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	}))
	defer srv.Close()

	// srv.URL is http://127.0.0.1:… (loopback) — allowed for tests.
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	got, err := r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
	rsaKey, ok := got.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, 0, pub.N.Cmp(rsaKey.N), "modulus round-trips")
	assert.Equal(t, pub.E, rsaKey.E)

	// Second lookup of the same kid is served from cache (no new fetch).
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
	assert.Equal(t, 1, hits, "fresh cache is not refetched")

	// Unknown issuer fails.
	_, err = r.Key(context.Background(), "https://other", "k1")
	require.ErrorContains(t, err, "no jwks_uri")
}

// On a transient JWKS fetch failure, a cached key is served only within a bounded
// grace window past the TTL — so a key the issuer rotated out (e.g. compromised)
// cannot be honoured indefinitely while the issuer is unreachable.
func TestHTTPJWKSResolver_StaleFallbackBounded(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// A JWKS endpoint that always fails, forcing reliance on the cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	seedCache := func(age time.Duration) {
		r.mu.Lock()
		r.cache["https://iss"] = &jwksEntry{
			keys:      map[string]any{"k1": &key.PublicKey},
			fetchedAt: time.Now().Add(-age),
		}
		r.mu.Unlock()
	}

	// Stale but within the grace window: the cached key is served despite the fetch failure.
	seedCache(jwksCacheTTL + jwksStaleGrace - time.Minute)
	got, err := r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
	assert.Equal(t, &key.PublicKey, got)

	// Beyond the grace window: a failed refetch fails closed (rotated-out key not honoured).
	seedCache(jwksCacheTTL + jwksStaleGrace + time.Minute)
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.Error(t, err)
}

// An unknown kid on a fresh cache triggers at most one refetch per
// jwksMinRefetchInterval per issuer, so a flood of tokens bearing a trusted issuer
// and random kids can't amplify into a JWKS-fetch storm against the IdP.
func TestHTTPJWKSResolver_UnknownKidRefetchRateLimited(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &key.PublicKey
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	// Prime the cache (1 fetch).
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
	require.Equal(t, 1, hits)

	// A flood of distinct unknown kids on the now-fresh cache: the first one is
	// allowed to refetch (rotation), the rest within the interval are rejected
	// without any outbound fetch.
	for range 50 {
		_, _ = r.Key(context.Background(), "https://iss", "bogus-kid")
	}
	assert.LessOrEqual(t, hits, 2, "bogus-kid flood must not amplify into a fetch storm")

	// The legitimate kid is still served from cache throughout.
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
}

// The stale-cache refetch path (cache past jwksCacheTTL) is rate-limited the same
// way the fresh-cache-unknown-kid path is: at most one refetch ATTEMPT per
// jwksMinRefetchInterval per issuer. Before the fix this path had no gate at all —
// every single Key() call on a stale/expired cache triggered a real outbound
// fetch, so a caller (or an outage that keeps refetches failing) could force an
// unbounded stream of them.
func TestHTTPJWKSResolver_StaleRefetchRateLimited(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError) // keep failing so the cache stays stale
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	seedStaleCache := func() {
		r.mu.Lock()
		r.cache["https://iss"] = &jwksEntry{
			keys:      map[string]any{"k1": &key.PublicKey},
			fetchedAt: time.Now().Add(-(jwksCacheTTL + time.Minute)), // stale, still within grace
		}
		r.mu.Unlock()
	}

	seedStaleCache()
	// First call on the stale cache: not yet rate-limited, attempts a real refetch
	// (which fails), then falls back to the stale-but-in-grace cached key.
	got, err := r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
	assert.Equal(t, &key.PublicKey, got)
	require.Equal(t, 1, hits, "first stale-cache call attempts exactly one refetch")

	// A flood of further calls immediately after: all within jwksMinRefetchInterval
	// of the first attempt, so none should reach the server again.
	for range 20 {
		_, _ = r.Key(context.Background(), "https://iss", "k1")
	}
	assert.Equal(t, 1, hits, "repeated calls on a still-rate-limited stale cache must not amplify into a fetch storm")

	// Once the last-attempt timestamp is old enough, a call is allowed to attempt a
	// refetch again.
	r.mu.Lock()
	r.lastFetchAttempt["https://iss"] = time.Now().Add(-(jwksMinRefetchInterval + time.Second))
	r.mu.Unlock()
	_, _ = r.Key(context.Background(), "https://iss", "k1")
	assert.Equal(t, 2, hits, "after the rate-limit window elapses, a call may attempt a refetch again")
}

// The cold-start refetch path — an issuer that has NEVER had a successful
// fetch, so entry stays nil — is rate-limited the same way the stale-cache
// path is: at most one refetch ATTEMPT per jwksMinRefetchInterval per issuer.
// Before the fix this path had no gate at all: it required entry != nil, so
// an issuer whose JWKS endpoint has been unreachable since boot (e.g. an
// air-gapped deployment) fired a live outbound fetch and blocked for the full
// http.Client timeout on EVERY verification attempt, forever — reachable
// pre-authentication, since keyfunc runs during JWT parse before the token's
// signature is checked.
func TestHTTPJWKSResolver_ColdCacheRefetchRateLimited(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError) // always fails: cache is never seeded
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	// First-ever call: no prior attempt recorded, so it still attempts (and fails) a fetch.
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.Error(t, err)
	require.Equal(t, 1, hits, "first-ever call on a cold cache still attempts a fetch")

	// A flood of further calls immediately after, with no cache entry ever
	// populated: all within jwksMinRefetchInterval of the first attempt, so none
	// should reach the server again. This is exactly the bug: entry stays nil
	// forever here, so the old `entry != nil` gate condition never engaged.
	for range 20 {
		_, err := r.Key(context.Background(), "https://iss", "k1")
		require.Error(t, err, "a rate-limited cold cache must fail closed, never return a bypassed result")
	}
	assert.Equal(t, 1, hits, "repeated calls on a still-rate-limited cold cache must not fire a second outbound fetch")

	// Once the last-attempt timestamp is old enough, a call is allowed to attempt a
	// refetch again.
	r.mu.Lock()
	r.lastFetchAttempt["https://iss"] = time.Now().Add(-(jwksMinRefetchInterval + time.Second))
	r.mu.Unlock()
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.Error(t, err)
	assert.Equal(t, 2, hits, "after the rate-limit window elapses, a call may attempt a refetch again")
}

// A JWKS with more keys than maxJWKSKeys is capped so a pathological key set can't
// bloat the cache.
func TestHTTPJWKSResolver_CapsKeyCount(t *testing.T) {
	t.Parallel()
	// Generate all RSA-2048 keys UP FRONT, not inside the HTTP handler: generating
	// 70 of them (maxJWKSKeys+20) takes long enough under load (heavy parallel test
	// suite contention) that doing it per-request could exceed the resolver's 10s
	// HTTP client timeout, making r.Key() below return an error the test didn't
	// check — a nil-pointer panic on the next line (the cache entry was never
	// populated), observed as an intermittent flake. Precomputing removes the
	// timing dependency: the handler now does pure, fast JSON encoding.
	keys := make([]map[string]string, 0, maxJWKSKeys+20)
	for i := range maxJWKSKeys + 20 {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pub := &k.PublicKey
		keys = append(keys, map[string]string{
			"kty": "RSA", "kid": "k" + strconv.Itoa(i), "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	_, err = r.Key(context.Background(), "https://iss", "k0")
	require.NoError(t, err)
	r.mu.Lock()
	n := len(r.cache["https://iss"].keys)
	r.mu.Unlock()
	assert.LessOrEqual(t, n, maxJWKSKeys, "retained key count is capped")
}

// parseJWK must reject an RSA key whose modulus exceeds maxRSABits, rather than
// constructing an rsa.PublicKey from it. Without this check an oversized modulus
// from a malicious/compromised OIDC provider gets cached for up to jwksCacheTTL and
// its expensive modular-exponentiation cost is paid on every verification in that
// window — a sustained DoS, not just a one-time cost at fetch.
func TestParseJWK_RejectsOversizedRSAModulus(t *testing.T) {
	t.Parallel()
	// Construct a JWK whose modulus is artificially larger than maxRSABits, without
	// paying the cost of actually generating an RSA key that size: fill N with random
	// bytes sized just over the limit.
	nBytes := make([]byte, (maxRSABits/8)+16)
	nBytes[0] = 0xFF // ensure the top byte is set so BitLen reflects the full length
	_, err := rand.Read(nBytes)
	require.NoError(t, err)
	nBytes[0] |= 0x80

	k := jwk{
		Kty: "RSA",
		Kid: "oversized",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()),
	}
	got, err := parseJWK(k)
	require.Error(t, err, "an oversized RSA modulus must be rejected")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "outside allowed range")
}

// A JWKS response containing an oversized RSA key must not be cached or served: the
// key is skipped (parseJWK errors, and fetch continues past unparsable keys), so a
// lookup for that kid fails rather than yielding the oversized key.
func TestHTTPJWKSResolver_RejectsOversizedRSAKeyInJWKS(t *testing.T) {
	t.Parallel()
	nBytes := make([]byte, (maxRSABits/8)+16)
	_, err := rand.Read(nBytes)
	require.NoError(t, err)
	nBytes[0] |= 0x80

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "oversized", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(nBytes),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()),
			}},
		})
	}))
	defer srv.Close()

	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	_, err = r.Key(context.Background(), "https://iss", "oversized")
	require.Error(t, err, "an oversized RSA key must never be cached or returned")
	assert.Contains(t, err.Error(), "no usable signing keys")
}

func TestNewHTTPJWKSResolver_RejectsInsecureScheme(t *testing.T) {
	t.Parallel()
	// Plaintext http to a non-loopback host is refused (signing-key MITM).
	_, err := NewHTTPJWKSResolver(map[string]string{"https://iss": "http://idp.example.com/jwks"})
	require.ErrorContains(t, err, "must use https")

	// https is accepted.
	_, err = NewHTTPJWKSResolver(map[string]string{"https://iss": "https://idp.example.com/jwks"})
	require.NoError(t, err)

	// http to loopback is allowed (dev/test).
	for _, uri := range []string{"http://localhost:8200/jwks", "http://127.0.0.1:8200/jwks", "http://[::1]:8200/jwks"} {
		_, err = NewHTTPJWKSResolver(map[string]string{"https://iss": uri})
		require.NoErrorf(t, err, "loopback %s should be allowed", uri)
	}
}

// syntheticRSAModulus fabricates a big.Int of the given bit length (top bit set)
// for boundary testing — parseJWK only inspects structural size, so this doesn't
// need to be a real, factorable RSA modulus.
func syntheticRSAModulus(bits int) *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return n.SetBit(n, 0, 1) // odd, so it round-trips through byte encoding cleanly
}

// TestParseJWK_RejectsRSAModulusOutOfRange pins #100: an unbounded RSA modulus
// lets a compromised/MITM'd issuer serve a pathological (e.g. ~8M-bit) signing
// key — cached and reused for every subsequent token from that kid — turning
// each signature verification into a multi-second modexp (CPU-DoS amplifier).
func TestParseJWK_RejectsRSAModulusOutOfRange(t *testing.T) {
	t.Parallel()
	tooSmall := jwk{Kty: "RSA", Kid: "small", N: base64.RawURLEncoding.EncodeToString(syntheticRSAModulus(1024).Bytes()), E: "AQAB"}
	_, err := parseJWK(tooSmall)
	require.ErrorContains(t, err, "outside allowed range")

	tooBig := jwk{Kty: "RSA", Kid: "big", N: base64.RawURLEncoding.EncodeToString(syntheticRSAModulus(1 << 20).Bytes()), E: "AQAB"}
	_, err = parseJWK(tooBig)
	require.ErrorContains(t, err, "outside allowed range")

	// A real, in-range key still parses fine.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ok := jwk{Kty: "RSA", Kid: "ok",
		N: base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())}
	parsed, err := parseJWK(ok)
	require.NoError(t, err)
	require.IsType(t, &rsa.PublicKey{}, parsed)
}

// TestHTTPJWKSResolver_RejectsOversizedRSAKey confirms the size guard is wired
// through the full fetch path: a JWKS whose only key has a pathological modulus
// yields "no usable signing keys", not a cached, verifiable oversized key.
func TestHTTPJWKSResolver_RejectsOversizedRSAKey(t *testing.T) {
	t.Parallel()
	huge := syntheticRSAModulus(1 << 20) // ~1M bits
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "huge", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(huge.Bytes()),
				"e": "AQAB",
			}},
		})
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	_, err = r.Key(context.Background(), "https://iss", "huge")
	require.ErrorContains(t, err, "no usable signing keys")
}

// TestParseJWK_RejectsOversizedRSAExponent pins CORE-OIDC-05: an RSA modulus
// within [minRSABits,maxRSABits] paired with a needlessly huge public exponent
// (up to the ~63-bit int64 ceiling the old code allowed) makes every cached
// verification against that key several times more expensive than a normal
// e=65537 key — the same sustained-DoS shape maxRSABits guards against, via
// the other operand of the modexp.
func TestParseJWK_RejectsOversizedRSAExponent(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// e is a large-but-valid int64 (well above maxRSAPublicExponent, far below
	// the int64 ceiling the old code capped at).
	hugeE := new(big.Int).Lsh(big.NewInt(1), 62)
	k := jwk{
		Kty: "RSA",
		Kid: "huge-exponent",
		N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(hugeE.Bytes()),
	}
	got, err := parseJWK(k)
	require.Error(t, err, "an oversized RSA exponent must be rejected")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "exceeds allowed maximum")

	// A real, common exponent on the same modulus still parses fine.
	ok := jwk{Kty: "RSA", Kid: "ok",
		N: base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())}
	parsed, err := parseJWK(ok)
	require.NoError(t, err)
	require.IsType(t, &rsa.PublicKey{}, parsed)
}

// TestHTTPJWKSResolver_RejectsOversizedRSAExponentInJWKS confirms the exponent
// guard is wired through the full fetch path, mirroring
// TestHTTPJWKSResolver_RejectsOversizedRSAKeyInJWKS for the modulus check.
func TestHTTPJWKSResolver_RejectsOversizedRSAExponentInJWKS(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	hugeE := new(big.Int).Lsh(big.NewInt(1), 62)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "huge-exponent", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(hugeE.Bytes()),
			}},
		})
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	_, err = r.Key(context.Background(), "https://iss", "huge-exponent")
	require.ErrorContains(t, err, "no usable signing keys")
}

// TestParseJWK_RejectsOffCurveECPoint pins CORE-OIDC-05's EC half: parseJWK
// must independently verify a decoded (X,Y) actually lies on the claimed
// curve, rather than handing an unchecked point straight to ecdsa.PublicKey
// and relying solely on whatever validation the underlying crypto/ecdsa
// verification path happens to do internally.
func TestParseJWK_RejectsOffCurveECPoint(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Perturb Y so (X,Y) no longer satisfies the P-256 curve equation, while
	// keeping both coordinates comfortably within the field size.
	offY := new(big.Int).Add(priv.Y, big.NewInt(2))

	k := jwk{
		Kty: "EC",
		Kid: "off-curve",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(offY.Bytes()),
	}
	got, err := parseJWK(k)
	require.Error(t, err, "an off-curve EC point must be rejected")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "not on curve")

	// The genuine, on-curve point still parses fine.
	ok := jwk{Kty: "EC", Kid: "ok", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		Y: base64.RawURLEncoding.EncodeToString(priv.Y.Bytes())}
	parsed, err := parseJWK(ok)
	require.NoError(t, err)
	ecKey, isEC := parsed.(*ecdsa.PublicKey)
	require.True(t, isEC)
	assert.True(t, priv.PublicKey.Equal(ecKey))
}

// TestParseJWK_RejectsOversizedECCoordinate pins CORE-OIDC-05: a coordinate
// whose bit length exceeds the claimed curve's field size must be rejected by
// parseJWK's own check, independent of (in addition to) whatever bound the
// underlying crypto/ecdsa/nistec implementation happens to enforce.
func TestParseJWK_RejectsOversizedECCoordinate(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// P-256's field size is 256 bits; build an X well beyond that.
	oversizedX := new(big.Int).Lsh(big.NewInt(1), 512)
	oversizedX.Or(oversizedX, priv.X)

	k := jwk{
		Kty: "EC",
		Kid: "oversized-coord",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(oversizedX.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
	}
	got, err := parseJWK(k)
	require.Error(t, err, "an oversized EC coordinate must be rejected")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "exceeds curve")
}
