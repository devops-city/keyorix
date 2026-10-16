- **INV-CORE-credential-lookup-fault-is-not-a-bad-credential** A Validate*Token function
  (`ValidateSessionToken`, `ValidatePATToken`, `ValidateMachineToken`, `ValidateOIDCToken`) answers
  "invalid credential" only when a lookup positively found no row (`gorm.ErrRecordNotFound`,
  `ErrSessionNotFound`, `ErrUserNotFound`); a lookup that FAILED (connection refused or reset,
  timeout, closed pool) returns `ErrAuthStorageUnavailable`, which `IsAuthTransient` shares with
  `ErrRoleResolutionUnavailable`. The HTTP middleware answers 503, the gRPC interceptors
  `codes.Unavailable`, with no negative-cache entry and no brute-force strike. Unknown errors are
  classified as faults (the request is denied either way; a fault must never be cached as proof the
  token is bad). Why: a PostgreSQL outage answered every valid machine token and session with 401,
  negative-cached each for invalidTokenTTL (the 401s outlived the outage) and charged callers' IPs
  (`scripts/drills/disaster.sh` pgdown, PROD-OPS-1). Guard: `validate_storage_unavailable_test.go`
  (`TestValidateToken_CredentialLookupFault_IsAuthStorageUnavailable`,
  `TestValidateToken_PositiveNotFound_IsNotTransient`), middleware
  `TestHandleAuthRequest_AuthStorageUnavailable_Is503AndUncached`, gRPC
  `TestAuthInterceptor_MachineCredentialLookupFault_IsUnavailableAndUnthrottled`. Not covered: the
  cache-hit re-check path and the authorization (permission) lookups, which have their own
  fail-closed handling.
