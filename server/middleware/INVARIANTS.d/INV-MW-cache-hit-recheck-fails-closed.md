- **INV-MW-cache-hit-recheck-fails-closed** On an auth-cache hit, when the live re-check
  of the credential's revocation state fails (a storage error, not a verdict) the request
  is REFUSED with the slow path's "temporarily unavailable" response (503, `Retry-After`,
  fixed message, no error text; `refuseUnverifiedCacheHit`) and never authenticated from
  the cached principal. The entry is not evicted and the refusal is not counted against
  the per-IP failed-auth budget. It holds for every cache-hit branch of
  `serveAuthCacheHit`: PAT (`CurrentPATRestriction`), opaque machine token
  (`CurrentMachineTokenRestriction`), federated OIDC machine principal
  (`CurrentFederatedMachineState`) and interactive session (`SessionCacheHitLiveness`,
  either half). A definitive verdict readable from one half still denies and evicts
  (INV-MW-05). A healthy cache hit still makes exactly one storage read (its re-check) and
  no slow-path re-validation. gRPC has no auth cache: every RPC re-validates, and a storage
  error on the credential lookup is `codes.Unavailable`. This supersedes INV-MW-05's former
  transient half ("degrade to the stale cached snapshot"), under which the very read that
  would have seen a revocation could fail and the request was served anyway for up to
  `validTokenTTL`. Why: CACHE-FAILCLOSED-1 (security decision 2026-10-17, BACKLOG
  "SEC CACHE-HIT-DB-ERROR"). Guard: `cache_hit_fail_closed_test.go`
  (`TestCacheHit_RecheckStorageError_FailsClosed`,
  `TestCacheHit_RevokedCredentialAndStorageError_NeverAccepted`,
  `TestCacheHit_HealthyStorage_OneRecheckRead`; internal/faultstorage on each branch's exact
  re-check method, red before), `cache_hit_transient_refused_test.go` (real storage errors
  from a dropped table), `server/grpc/interceptors/auth_storage_error_fail_closed_test.go`
  (gRPC, PAT and machine token; a pin, green before).
