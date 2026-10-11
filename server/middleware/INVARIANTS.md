# server/middleware invariants

Read this before changing anything in `server/middleware`. This package owns: HTTP auth-cache
mechanics (including cache-hit re-verification and eviction/tombstoning), CSRF, session/CSRF
cookie issuance, security headers, request body-size cap, client-IP trust, per-principal/
per-IP-failure rate limiting, the node-credential gate, account-restriction/MFA-enrollment
enforcement, and the SCIM bearer-token check. RBAC/permission checks (`RequirePermission`,
`Authorize`) live in `internal/core`, not here — do not file an RBAC invariant in this file.
Login-attempt rate limiting (`checkLoginRateLimit`/`reserveLoginAttempt`) is owned by
`server/http/handlers`, not here, despite the same security domain — see
`server/http/INVARIANTS.md`. CORS has no middleware-owned mechanism; it's wired in
`server/http/router.go`.

Format: `INV-MW-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Auth-cache hit re-verification

- **INV-MW-01** On a cache hit, a PAT's restriction/revoked/expired state is re-checked live
  (`CurrentPATRestriction`) before serving the cached principal. Guard:
  `auth.go:serveAuthCacheHit` (lines ~516-533); `g18_cache_hit_revocation_test.go`
  (`TestAuthentication_PATRevokedAfterCache_DeniedOnCacheHit`, `_PATExpiredAfterCache_DeniedOnCacheHit`).
- **INV-MW-02** On a cache hit, a machine token's restriction/revoked/expired/active-state is
  re-checked live (`CurrentMachineTokenRestriction`), including a CIDR-allowlist refresh. Guard:
  `g18_cache_hit_revocation_test.go` (`TestAuthentication_MachineTokenCIDR_RefreshesOnCacheHit`,
  `_MachineTokenRevokedAfterCache_DeniedOnCacheHit`).
- **INV-MW-03** On a session cache hit, account usability (`AccountUsabilityAndState`) is
  re-checked live; an outright-unusable account denies AND evicts, while a usable-but-newly-
  `Restricted` state (pending_first_login/password_reset_required) is cloned onto the effective
  context on EVERY hit, not only at eviction. Guard: `auth.go` lines ~544-557 (doc comment
  483-515); `g18_cache_hit_revocation_test.go:TestAuthentication_SessionAccountSuspendedAfterCache_DeniedOnCacheHit`;
  cross-package `server/http/session_revoke_race_test.go:TestSessionCacheHit_AccountRestrictionRefreshedOnHit`.
- **INV-MW-04** On a session cache hit, the SPECIFIC session row's own liveness
  (`SessionLiveForToken`) is re-checked live — an account-level state check alone can't see a
  single revoked session (logout-this-device, password change, MFA/WebAuthn enrollment change,
  setup-link reset). Why: `docs/findings/2026-09-20-FINDING-session-revoke-cache-race.md`.
  Guard: `auth.go` lines ~563-568; cross-package
  `server/http/session_revoke_race_test.go:TestSessionRevoke_ConcurrentRevokeDoesNotResurrectCachedAuth`,
  `TestSessionRevoke_SecondReplicaNeverInvalidatedCacheHitDenied`.
- **INV-MW-05** A definitive revocation signal (revoked/expired/inactive/session-gone) on a
  cache hit denies AND evicts (`denyRevokedCacheHit` → `InvalidateTokenCacheByHash`); a
  transient storage error degrades to the stale cached snapshot — with that snapshot's own
  restrictions still applied — rather than failing open or closed. Every definitive signal is
  a TYPED sentinel so the two halves are distinguishable by `errors.Is`, not by message.
  Why: #146's philosophy generalized by #G18; `docs/findings/2026-09-20-FINDING-session-revoke-cache-race.md`.
  Guard: `g18_cache_hit_revocation_test.go` (definitive half),
  `cache_hit_transient_degrade_test.go` (transient half, #2579 — note
  `auth_transient_error_test.go` covers only the SLOW path and never reaches
  `serveAuthCacheHit`), `internal/core/machine_identity_not_active_sentinel_test.go`
  (the sentinels themselves, with both calibration directions).
  Closed 2026-10-05 (#2518): `inactive` was listed in this invariant but not actually
  enforced. `CurrentMachineTokenRestriction` returned a no-longer-active owning machine
  identity as a bare `fmt.Errorf`, which this branch cannot tell apart from a storage blip,
  so it took the DEGRADE path — a suspended machine identity's token kept authenticating for
  up to `validTokenTTL` on every replica except the one that ran the suspension (only that one
  flushes, via `SetMachineTokenCacheFlusher`). Now `core.ErrMachineIdentityNotActive`, denied
  alongside the revoked/expired sentinels. The same sentinel is returned by
  `ValidateMachineToken` and the OIDC-federated path for the identical condition — not
  load-bearing there (their callers deny on any error) but kept in step, since a sibling
  returning a differently-typed error for the same condition is exactly how this one went
  unseen.
- **INV-MW-06** The network allowlist is enforced per-request even on a cache hit, using the
  freshly-refreshed restriction, never the stale cached one. Guard: `auth.go` lines ~571-577.
  UNGUARDED as an isolated assertion (#issue: no test isolates "allowlist checked against
  freshly-cloned `effective`, not stale `entry.userCtx`" — only covered incidentally by the
  CIDR-refresh test).

## Cache eviction / cross-transport invalidation

- **INV-MW-07** Cache eviction (`InvalidateTokenCacheByHash`/`InvalidateAllMachineTokenCache`)
  writes a short-lived NEGATIVE tombstone, never a plain delete — closes a race where an
  in-flight positive validation could resurrect a stale entry past a real revoke. Guard:
  `machine_cache_generation_test.go` (`TestMachineFlush_DropsInFlightPositiveForUncachedKey`,
  `_NoNegativeEntriesAndHumansUntouched`, `_OldGenerationEntryIsMiss`).
- **INV-MW-08** A machine token revoked/suspended via ANY transport stops authenticating over
  HTTP on the very next request — the eviction call is transport-agnostic and every mutation
  path must call it. Why: this was a real previously-missed gap — gRPC's `RevokeMachineToken`
  discarded the hash `core.RevokeMachineToken` returns for exactly this purpose, "on the
  mistaken premise gRPC has no auth cache." Guard: cross-package, from the gRPC side —
  `server/grpc/services/machine_identity_revoke_token_cache_invalidation_test.go`
  (`TestGRPCRevokeMachineToken_EvictsHTTPAuthCacheImmediately`,
  `machine_identity_transition_cache_invalidation_test.go:TestGRPCTransitionMachineIdentity_{Revoke,Suspend}EvictsHTTPAuthCacheImmediately`).
  See `server/grpc/services/INVARIANTS.md` for the gRPC-side half of this same invariant.
- **INV-MW-09** A removed global role stops being honored on the same user's next HTTP
  request, not lingering for the cache TTL — transport-agnostic via
  `core.removeUserRoleUnguarded`'s `evictUserSessionCache` call. Guard: cross-package, from
  gRPC: `server/grpc/services/role_removal_cross_transport_test.go` (drives real gRPC
  `RoleService.RemoveRole`, checks via the real HTTP middleware chain).
- **INV-MW-10** On a PANIC during best-effort cache eviction after a committed machine-identity
  revoke/suspend (not just a returned error), the middleware fails CLOSED by flushing ALL
  machine-token cache entries (`InvalidateAllMachineTokenCache`) rather than leaving the
  revoked identity live in cache — bounded to machine principals; human sessions/PATs
  untouched. Why: security-closures `machine-identity-evict-panic-fail-closed-001` (row filed
  under `./server/http`, but the fix is middleware-owned). Guard:
  `TestTransitionMachineIdentity_EvictionPanicStillRevokesAndFailsClosed`.
- **INV-MW-11** `FuzzAuthCacheDifferential`: the cached and cache-bypassed auth decision must
  agree for every account-state transition. Found `account-state-reactivate-pat-tombstone-001`
  live in `internal/core`. Guard: `authcache_differential_fuzz_test.go:FuzzAuthCacheDifferential`.

## CSRF / cookies

- **INV-MW-12** A state-changing request (POST/PUT/PATCH/DELETE) carrying the `kx_session`
  cookie must echo `csrf_token`'s value as `X-CSRF-Token`, compared with
  `subtle.ConstantTimeCompare`; Bearer-only callers (PAT/machine/no cookie) are exempt by
  construction. Guard: `csrf.go` lines ~28-61; `csrf_test.go`
  (`TestRequireCSRF_MissingCSRFCookieForbidden`, `_MissingCSRFHeaderForbidden`,
  `_MismatchedTokenForbidden`, `_MatchingTokenAllowed`, `_PUTAndDELETEAreCovered`); cross-package
  `server/http/integration_test.go:TestCSRF_RequiredForCookieAuthenticatedMutations`,
  `TestCSRF_RequiredForLogout`.
- **INV-MW-13** `kx_session`/`kx_admin_session` cookies are always `HttpOnly`, `Path=/`,
  `SameSite=Lax`, `Secure` iff TLS is enabled; `csrf_token` is deliberately NOT `HttpOnly` (the
  double-submit pattern requires JS read access — not an oversight). Guard:
  `session_cookie.go` lines ~16-56; `session_cookie_test.go` (`TestSetSessionCookie`,
  `TestSetCSRFCookie`, `TestSetAdminSessionCookie`); cross-package end-to-end
  `server/http/integration_test.go:TestSessionCookieAttrs_AcrossAuthFlows`,
  `TestSessionCookieAttrs_SecureFlagFollowsTLSConfig` (landed PR #1972/#1975 as a
  DAST-false-positive closure, confirming — not fixing — `csrf_token`'s non-HttpOnly-by-design
  status).
- **INV-MW-14** `AdminSessionCookieName` (the impersonation "return to admin" token) is
  round-tripped only via a second HttpOnly cookie, never server-side-stored — matches the "no
  plaintext token retained after issuing" design. Guard: `session_cookie.go` lines ~21-32;
  `session_cookie_test.go` (`TestSetAdminSessionCookie`, `TestClearAdminSessionCookie`,
  `TestBlockWhenImpersonating_*`); cross-package
  `server/http/integration_test.go:TestImpersonationRoundTrip_CookieSwapAndRestore`.

## Rate limiting / abuse resistance

- **INV-MW-15** `PrincipalRateLimit`: a general per-authenticated-principal (per-IP fallback)
  token-bucket budget across the authenticated API, in-memory/per-process, disabled by
  default, keyed post-`Authentication` — a nuisance backstop, not an authz boundary (every
  guarded route is already permission-gated). Guard: `rate_limit.go` lines ~16-133;
  `rate_limit_test.go` (`TestPrincipalRateLimit_EnforcesPerPrincipalBudget`,
  `_FallsBackToIPForUnauthenticated`, `_ZeroBurstFallsBackToRequestsPerSecond`, `_DisabledIsNoOp`).
- **INV-MW-16** `ipFailureLimiter`: a separate per-IP budget on FAILED token-authentication
  attempts (PAT/machine/session alike), amortized (not per-call) idle-bucket sweeping so sweep
  cost is bounded under a brute-force flood rather than scaling with distinct-IP count. Why:
  #G19 (the sweep previously ran full O(n) on every failed attempt). Guard: `rate_limit.go`
  lines ~140-189; `rate_limit_test.go` (`TestIPFailureLimiter_StillEnforcesBudget`,
  `TestIPFailureLimiter_SweepAmortized`).
- **INV-MW-17** `MaxBodyBytes`: every request body is capped via `http.MaxBytesReader`; a cap
  ≤0 disables it explicitly (a deliberate passthrough, not an accident). Guard:
  `body_limit.go` lines ~10-19; `body_limit_test.go` (`TestMaxBodyBytes_RejectsOversize`,
  `_AtLimitOK`, `_DisabledWhenNonPositive`).
- **INV-MW-18** `ClientIP` only trusts `X-Forwarded-For`/`X-Real-IP` when the immediate TCP
  peer is a configured trusted-proxy CIDR; with no trusted proxies configured, these headers
  are ignored entirely. Walks XFF right-to-left, stopping at the first non-trusted hop, so a
  client-prepended spoofed entry can't claim an arbitrary IP. This directly replaced chi's
  `middleware.RealIP` (which trusted headers unconditionally) specifically because it defeated
  the per-IP brute-force limiter above. Guard: `client_ip.go` lines ~26-89; `client_ip_test.go`;
  `pat_cidr_bypass_test.go` (`TestPATCIDRAllowlist_UnconditionalRealIP_WasBypassable`,
  `_ClientIPMiddleware_RejectsSpoofedHeader`, `_ClientIPMiddleware_HonorsTrustedProxy`).

## Security headers

- **INV-MW-19** `SecurityHeaders` sets a fixed hardening set unconditionally on every response
  (nosniff, DENY framing, no-referrer, a CSP without an `unsafe-inline`-bypassing `script-src
  'self'`, strict CORP/COEP/COOP, no Adobe cross-domain policy), with HSTS gated strictly on
  `tlsEnabled` — never sent over plain HTTP. Guard: `security_headers.go` lines ~21-71;
  `security_headers_test.go` (`TestSecurityHeaders_AlwaysSet`, `_CSPAlwaysSet`,
  `_HSTSOnlyWithTLS`, `_CORPAlwaysSet`, `_CrossOriginHeadersAlwaysSet`).

## Account/node gates

- **INV-MW-20** `EnforceAccountSetup` (which replaced the separate `EnforceAccountRestriction`/
  `EnforceMFAEnrollment` gates, #3024) is a middleware-layer gate applied post-authentication —
  not an RBAC check. Guard: `auth.go:EnforceAccountSetup`;
  `account_setup_test.go:TestEnforceAccountSetup`. See INV-MW-account-setup-union-of-pending-steps.
- **INV-MW-21** `RequireNodeCredential`/`isNodeCredential` gates a route group on holding a
  node-type machine credential; rejects every other principal type with 403, unauthenticated
  with 401. Currently UNWIRED — `router.go` never calls it; its OR-arm alternative
  (`RequireNodeCredentialOrPermission`) was removed per ADR-085's finding that no deployment
  topology can construct a node-credential-substitutes-for-`system.write` caller. Guard:
  `node_credential.go` lines ~34-66; `node_credential_test.go`
  (`TestRequireNodeCredential_NodeMachinePasses`, `_NonNodeMachineRefused`, `_NoUserContext`) —
  tested but dead; not a live invariant today, flagged so nobody re-wires it assuming it's
  already load-bearing.
- **INV-MW-22** The SCIM bearer-token check throttles repeated failures and denies all when
  config is empty (fail-closed on misconfiguration). Guard: `scim.go`; `scim_test.go`
  (`TestSCIMToken_EmptyConfigDeniesAll`, `TestSCIMToken_ThrottlesRepeatedFailures`).

## Cross-cutting notes

- `docs/adr-conformance-enforced.tsv` has zero rows for `server/middleware` despite several
  real, tested properties above (CSRF, cookie attributes, cache-hit re-verification) — none of
  these have been formally seeded into that ledger yet. Low-effort follow-up: add rows citing
  the tests already named here.
