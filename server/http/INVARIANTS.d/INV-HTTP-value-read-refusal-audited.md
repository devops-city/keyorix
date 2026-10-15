- **INV-HTTP-value-read-refusal-audited** Every router.go registration of a handler that
  reads a secret value (GET `/secrets/{id}`, `/secrets/value`, render, copy, environment
  copy and clone) carries `middleware.AuditSecretValueReadDenials` as its FIRST middleware,
  outside the scoped-permission gate, and gRPC `GetSecretValue` opens a
  `core.SecretReadDenialNote`. So every refusal (by the gate, the handler or core) writes
  one failed `secret.read` with its reason class (#3273), the response unchanged. A missing
  and a forbidden target answer identically and their rows carry no secret or project
  column. Why: ADR-112 Amendment 4, "denied reads stay audited". Guard:
  `secret_value_read_denial_audit_test.go` (`TestValueReadRoutes_AuditTheirRefusals`
  derives the value-read handlers from source like `TestValueReadRouteFamily_IsCovered`
  and checks every registration; `TestSecretValueReadDenials_*` drive every path and
  reason class at both `insecure_audit_skip_reads` settings).
