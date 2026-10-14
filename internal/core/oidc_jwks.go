// oidc_jwks.go — JWKS fetcher/cache for OIDC federation (ADR-031).
//
// Fetches an issuer's JSON Web Key Set from its jwks_uri, parses the RSA/EC
// signing keys, and caches them by (issuer, kid). On an unknown kid (key
// rotation) or an expired cache entry it refetches once. The actual signature
// check is done by golang-jwt with the key this returns.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/keyorixhq/keyorix/internal/netutil"
)

// jwksEgressTransport is the shared HTTP transport for the JWKS fetcher. It
// clones http.DefaultTransport (preserving proxy-from-environment, connection
// pooling, and HTTP/2 — the JWKS client used DefaultTransport before this, so an
// enterprise fetching JWKS through an egress proxy keeps working) and overrides
// only DialContext to re-validate every direct-dial target against
// netutil.IsLinkLocal. A misconfigured or compromised issuer whose jwks_uri
// resolves to the cloud instance-metadata endpoint (169.254.169.254) can never be
// dialed — defence in depth behind validateJWKSScheme + noCrossOriginRedirect
// (F2, adversarial-review 2026-09-14). The guard is deliberately link-local-only:
// RFC-1918/on-prem and loopback IdPs stay reachable, which is keyorix's primary
// deployment shape. When an egress proxy IS configured the dial targets the proxy
// (so the guard sees the proxy IP, not the eventual target) — accepted, since the
// no-proxy path is the one this guard is for.
var jwksEgressTransport = func() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&netutil.Dialer{Disallow: netutil.IsLinkLocal}).DialContext
	return tr
}()

// jwksCacheTTL bounds how long a fetched key set is trusted before a refetch.
const jwksCacheTTL = 1 * time.Hour

// jwksMinRefetchInterval bounds how often an *unknown kid* on an otherwise-fresh
// cache may trigger a rotation refetch, per issuer. The keyfunc runs during JWT
// parse — BEFORE the signature is verified — and only requires that the token's
// iss name a trusted issuer (a public, guessable value). Without this gate an
// unauthenticated attacker could stream tokens bearing a trusted iss and a fresh
// random kid, forcing one outbound JWKS GET each: a request storm that makes the
// IdP rate-limit/ban Keyorix (breaking real federation) and drains our outbound
// budget. With it, a bogus-kid flood costs at most one refetch per interval.
const jwksMinRefetchInterval = 1 * time.Minute

// maxJWKSBytes caps the JWKS response body we will read into memory. A compromised
// or MITM'd issuer (or one reached over a downgraded connection) could otherwise
// return an arbitrarily large body that we decode whole.
const maxJWKSBytes = 1 << 20 // 1 MiB

// maxJWKSKeys caps how many keys we retain from a single JWKS, bounding cache
// growth from a pathological key set.
const maxJWKSKeys = 50

// jwksStaleGrace bounds how far PAST the TTL a cached key set may still be served
// as a fallback when a JWKS refetch fails transiently. Without a bound, a key the
// issuer rotated out — e.g. because its private key was compromised — would keep
// verifying federation tokens for as long as the issuer's JWKS endpoint is
// unreachable from Keyorix, defeating rotation-as-revocation. After the grace
// window, a failed refetch fails closed.
const jwksStaleGrace = 10 * time.Minute

// HTTPJWKSResolver implements JWKSResolver by fetching each issuer's jwks_uri.
type HTTPJWKSResolver struct {
	jwksURIs map[string]string // issuer -> jwks_uri (operator-configured)
	client   *http.Client

	// group collapses concurrent fetches for the same issuer into one outbound
	// request, so a burst of unknown-kid tokens (see jwksMinRefetchInterval) can't
	// fan out into a thundering herd against the IdP.
	group singleflight.Group

	mu    sync.Mutex
	cache map[string]*jwksEntry // issuer -> cached keys
	// lastFetchAttempt records when a refetch was last ATTEMPTED for an issuer —
	// success or failure — so jwksMinRefetchInterval can gate the stale-cache
	// refetch path the same way it gates the fresh-cache-unknown-kid path (see Key).
	lastFetchAttempt map[string]time.Time
}

type jwksEntry struct {
	keys      map[string]any // kid -> public key
	fetchedAt time.Time
}

// NewHTTPJWKSResolver builds a resolver over the issuer->jwks_uri map. Each
// jwks_uri must use https so the issuer's signing keys are never fetched over
// plaintext — a MITM on an http jwks_uri could swap the keys and forge federation
// tokens. http is permitted only for loopback hosts (local development/testing).
func NewHTTPJWKSResolver(jwksURIs map[string]string) (*HTTPJWKSResolver, error) {
	for issuer, uri := range jwksURIs {
		if err := validateJWKSScheme(uri); err != nil {
			return nil, fmt.Errorf("issuer %q: %w", issuer, err)
		}
	}
	return &HTTPJWKSResolver{
		jwksURIs: jwksURIs,
		client: &http.Client{
			Timeout:       10 * time.Second,
			Transport:     jwksEgressTransport,
			CheckRedirect: noCrossOriginRedirect,
		},
		cache:            map[string]*jwksEntry{},
		lastFetchAttempt: map[string]time.Time{},
	}, nil
}

// noCrossOriginRedirect rejects a redirect that changes host or downgrades the
// scheme. validateJWKSScheme only vets the *configured* jwks_uri; without this a
// trusted https jwks_uri that 302s (open redirect on the IdP, or a compromised
// IdP) to http://attacker/ would be followed and attacker keys fetched, which
// would then validate forged tokens. Same-origin redirects are still allowed.
func noCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1].URL
	if !strings.EqualFold(req.URL.Hostname(), prev.Hostname()) {
		return fmt.Errorf("jwks fetch: refusing cross-host redirect to %q", req.URL.Host)
	}
	if prev.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("jwks fetch: refusing scheme downgrade to %q", req.URL.Scheme)
	}
	return nil
}

// validateJWKSScheme requires https for a jwks_uri (http only for loopback).
func validateJWKSScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid jwks_uri %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("jwks_uri %q must use https (http is allowed only for localhost)", raw)
	default:
		return fmt.Errorf("jwks_uri %q must use https", raw)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Key returns the public key for (issuer, kid), fetching/refreshing the issuer's
// JWKS as needed. An unknown kid forces one refetch (handles key rotation).
func (r *HTTPJWKSResolver) Key(ctx context.Context, issuer, kid string) (any, error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	jwksURI, ok := r.jwksURIs[issuer]
	if !ok {
		return nil, fmt.Errorf("no jwks_uri configured for issuer %q", issuer)
	}

	r.mu.Lock()
	entry := r.cache[issuer]
	fresh := entry != nil && time.Since(entry.fetchedAt) < jwksCacheTTL
	if fresh {
		if k, ok := entry.keys[kid]; ok {
			r.mu.Unlock()
			return k, nil
		}
	}
	// Past this point a refetch is needed — either because the cache is
	// stale/missing, or because it's fresh but doesn't have this kid (possible
	// rotation). ALL of those are rate-limited the same way: at most one refetch
	// ATTEMPT per jwksMinRefetchInterval per issuer, tracked by lastFetchAttempt
	// (set on every attempt, success or failure) rather than entry.fetchedAt (set
	// only on success). This also covers the cold-start case — an issuer that has
	// NEVER had a successful fetch (its JWKS endpoint has been unreachable since
	// boot, e.g. an air-gapped deployment). That case used to fall through this
	// gate unconditionally (it required entry != nil), so every verification
	// attempt fired a live outbound fetch and blocked for the full http.Client
	// timeout — reachable pre-authentication, since keyfunc runs during JWT parse
	// BEFORE the signature is verified and only requires the token's iss to name a
	// configured issuer (a public, guessable value). singleflight already
	// collapses CONCURRENT callers into one outbound fetch, so this was never an
	// amplification attack against the IdP; the cost was sequential, on Keyorix
	// itself — each blocked request held a goroutine and a connection for up to
	// the timeout, one after another.
	//
	// Accepted tradeoff: an issuer whose first-ever fetch fails now fails fast —
	// rejected immediately, not blocked — for up to jwksMinRefetchInterval before
	// the next attempt, rather than paying a full blocking fetch on every request
	// in that window. Intentional: a bounded, fast rejection beats an unbounded
	// number of full-timeout blocking calls.
	lastAttempt, attempted := r.lastFetchAttempt[issuer]
	if attempted && time.Since(lastAttempt) < jwksMinRefetchInterval {
		r.mu.Unlock()
		// Still within the stale-grace window: serve the cached key if we have it
		// rather than paying for (or waiting on) a refetch we've decided to skip.
		// entry is nil on the cold-start path (no fetch has ever succeeded), so
		// this is skipped there and we fall through to the rate-limited error.
		if entry != nil && time.Since(entry.fetchedAt) < jwksCacheTTL+jwksStaleGrace {
			if k, ok := entry.keys[kid]; ok {
				return k, nil
			}
		}
		return nil, fmt.Errorf("no signing key with kid %q at issuer %q (refetch rate-limited)", kid, issuer)
	}
	r.lastFetchAttempt[issuer] = time.Now()
	r.mu.Unlock()

	keys, err := r.fetchAndCache(ctx, issuer, jwksURI)
	if err != nil {
		// Fall back to a recently-cached key set on a transient fetch error — but
		// ONLY within a bounded grace window past the TTL, so a rotated-out (possibly
		// compromised) key cannot be honoured indefinitely while the issuer is
		// unreachable. Beyond the window, fail closed.
		if entry != nil && time.Since(entry.fetchedAt) < jwksCacheTTL+jwksStaleGrace {
			if k, ok := entry.keys[kid]; ok {
				return k, nil
			}
		}
		return nil, err
	}

	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no signing key with kid %q at issuer %q", kid, issuer)
}

// fetchAndCache fetches the issuer's JWKS and stores it, collapsing concurrent
// callers for the same issuer into a single outbound request via singleflight.
func (r *HTTPJWKSResolver) fetchAndCache(ctx context.Context, issuer, jwksURI string) (map[string]any, error) {
	v, err, _ := r.group.Do(issuer, func() (any, error) {
		keys, err := r.fetch(ctx, jwksURI)
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.cache[issuer] = &jwksEntry{keys: keys, fetchedAt: time.Now()}
		r.mu.Unlock()
		return keys, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]any), nil
}

func (r *HTTPJWKSResolver) fetch(ctx context.Context, jwksURI string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	// Bound the body we read so a compromised/MITM'd issuer can't OOM us with a huge
	// response; the LimitReader yields a decode error past the cap rather than reading on.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwks decode: %w", err)
	}

	out := make(map[string]any, len(doc.Keys))
	for _, k := range doc.Keys {
		if len(out) >= maxJWKSKeys {
			break // cap retained keys so a pathological JWKS can't bloat the cache
		}
		if k.Use != "" && k.Use != "sig" {
			continue // not a signing key
		}
		key, err := parseJWK(k)
		if err != nil {
			continue // skip keys we can't parse rather than failing the whole set
		}
		if k.Kid != "" {
			out[k.Kid] = key
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("jwks contained no usable signing keys")
	}
	return out, nil
}
