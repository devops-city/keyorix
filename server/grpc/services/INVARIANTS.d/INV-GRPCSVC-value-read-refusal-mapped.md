- **INV-GRPCSVC-value-read-refusal-mapped** `GetSecretValue` (and `GetSecret`) map a refusal by
  the secret's own state through `mapSecretReadError`, only after `authorizeSecretScoped` and the
  per-user check passed: outside the access schedule PermissionDenied, expired / suspended /
  max reads exhausted FailedPrecondition, each with the fixed message the REST twin sends and an
  `ErrorInfo` detail (domain `keyorix.secrets`, reason = the REST `error` code), never Internal.
  The gRPC half of INV-HTTP-value-read-refusal-mapped. Why: ERRMAP-1. Guard:
  `server/http/secret_value_read_refusal_family_test.go:TestSecretValueReadRefusals_MapToClientErrorsOnEveryRoute`
  (gRPC rows), `secret_value_read_authorize_once_test.go:TestGRPCValueReadAuthorizeOnce_Equivalence`.
