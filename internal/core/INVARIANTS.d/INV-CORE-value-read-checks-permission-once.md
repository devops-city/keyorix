- **INV-CORE-value-read-checks-permission-once** A human value read checks per-secret read
  permission once and the value step reuses that check: `GetSecretForValueRead` (the same
  `EnforceSecretReadPermission` + access-schedule check as `GetSecretWithPermissionCheck`)
  returns a `ReadPermittedSecret`, and `GetPermittedSecretValue` accepts only that value. Its
  fields are unexported, so code outside `internal/core` can obtain one only from the check and
  cannot hand the value step an unchecked secret. The value step still runs the whole read-guard
  bundle (`enforceSecretReadGuards`: clock regression, expiry, suspended, classification gate
  with the real userID, schedule) and the atomic max-reads accounting. Callers: HTTP
  `SecretHandler.GetSecret` (include_value) and gRPC `SecretGRPCService.GetSecretValue`.
  Why: PERF-FIX-3 — both transports ran `GetSecretWithPermissionCheck` and then
  `GetSecretValueWithPermissionCheck`, i.e. the same `CheckSecretPermission(id, user, read)`
  twice (~12 statements) plus a second secret fetch. Guard:
  `server/http` `TestValueReadAuthorizeOnce_ChecksOnce` (one share lookup per value read, red
  before the change), `TestValueReadAuthorizeOnce_Equivalence` and
  `TestValueReadAuthorizeOnce_CrossReplica` (outcome, response and audit rows per case,
  unchanged from before, SQLite and two-pool Postgres), `server/grpc/services`
  `TestGRPCValueReadAuthorizeOnce_Equivalence`. **Not covered**: a future transport that calls
  `GetSecretWithPermissionCheck` and then `GetSecretValueWithPermissionCheck` is still correct,
  only slower; nothing flags it.
