- **INV-HTTP-value-read-refusal-mapped** Every value-read route (`GET /secrets/{id}?include_value=true`,
  `GET /secrets/value?ref=`, `POST /projects/{id}/secrets/render`), for human and machine
  callers, answers a refusal by the secret's own state with a client error, a stable code in
  `error` and a fixed message, never 500 or internal text: outside the access schedule 403
  `SecretAccessOutsideSchedule`; expired, suspended, max reads exhausted 409 `SecretExpired`,
  `SecretSuspended`, `SecretMaxReadsExhausted` (409, not 410: each state is reversible). The
  mapping (`sendSecretReadRefusal`) runs only after the caller's read permission on that
  secret is established, so a caller who cannot read the secret gets the same 403/404 it got
  before the secret entered the refused state (INV-HTTP-08, ADR-096), and a refused read adds
  no audit or access-log row. Why: ERRMAP-1 (PERF-FIX-3/4 found 500s). Guard:
  `secret_value_read_refusal_family_test.go` (`TestSecretValueReadRefusals_MapToClientErrorsOnEveryRoute`
  over every route x principal x refusal, plus unauthorized-caller and audit-row invariance;
  `TestValueReadRouteFamily_IsCovered` derives the value-read family from source: every
  `server/` function calling a `*KeyorixCore` method that reaches a max-reads charge must be in
  that table or in its reasoned exclusion list).
<!-- section: Anti-enumeration (ADR-096) -->
