- **INV-MW-oidc-cache-capped-at-exp** A federated OIDC / Kubernetes-JWT principal's
  positive auth-cache entry never outlives the JWT's own `exp`: the slow path caches it
  until `min(now + validTokenTTL, exp)`, and does not cache it at all when `exp` is
  already past, within `oidcCacheSkew` (5 s) of now, or missing (a validator that reports
  no `exp` fails closed, uncached). The cache-hit path never re-verifies the JWT (it only
  re-reads the machine identity's state), so without the cap an expired token kept
  authenticating for up to `validTokenTTL`. `core.ValidateOIDCToken` returns the verified
  `exp` (`OIDCVerifier.VerifyWithExpiry`) for this. Uncached tokens are re-verified on every
  request by the verifier, which owns the real clock-skew leeway (`oidcClockSkew`, 60 s on
  the slow path). Why: OIDC-EXPIRY-CAP-1 (found by CACHE-FAILCLOSED-1). Guard:
  `oidc_cache_expiry_cap_test.go` (`TestOIDCCache_ExpBeyondTTL_CachedForTTL`,
  `TestOIDCCache_ExpInsideTTL_EntryEndsAtExp`, `TestOIDCCache_AtExp_EntryIsMiss`,
  `TestOIDCCache_NearOrPastExp_NeverCached`, `TestOIDCCache_JustOutsideSkew_Cached`; red
  before), `internal/core` `TestValidateOIDCToken_ResolvesMachine` (exp returned).
