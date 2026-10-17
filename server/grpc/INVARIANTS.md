# server/grpc invariants

Read this before changing anything in `server/grpc` (top-level: server wiring, protoreflect
differential fuzzer) or `server/grpc/interceptors` (the gRPC analogue of the HTTP middleware
chain: auth, rate-limit, timeout, recovery, audit attribution). See
`server/grpc/services/INVARIANTS.md` for the per-RPC business-logic layer, and
`server/middleware/INVARIANTS.md` for the HTTP-side mechanisms some of these mirror.
`server/proto/pb/generated_code_test.go` is owned by `server/proto`, not this package — it
consumes the generated `pb` package but owns no freshness check of its own.

Format: `INV-GRPC-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Cross-transport parity

- **INV-GRPC-01** gRPC cannot bypass a control that HTTP enforces, because secret-read
  enforcement (expiry, suspension, access schedule, MFA-step-up-gated `restricted` reads) is
  implemented in `internal/core`, not the HTTP handler layer. Why: ADR-105 §"What is not
  wrong" — verified by a manual end-to-end trace for `GetSecretValue`. Guard (the secrets.read
  gate for a human caller): `internal/core/secret_value_read_core_gate_test.go:TestSecretValueRead_CoreRefusesCallerWithoutSecretsRead`
  calls the two core entry points the gRPC handler uses (`GetSecretForValueRead`,
  `GetPermittedSecretValue`) with a bare `context.Background()` — no server, no interceptor, no
  `UserContext` — for a caller with no role, with `secrets.read` on another project only, and with
  a role on this project that lacks it, and requires core itself to refuse each (and a positive
  control to be served), so moving the gate into a transport wrapper goes red. Red-proved by making
  `checkSecretReadPermission` skip its check (`go test -overlay`). **Not covered**: the machine
  branch. `GetSecretValueResolved` takes no principal by design, so for a machine the secrets.read
  call (`authorizeSecretScoped` -> `core.AuthorizeSecretPrincipalForSecretAction`) is enforced in
  the handler; moving that call out of the handler is not caught here. Expiry, suspension,
  schedule and restricted-read are core-guarded by their own tests, not re-asserted here.
- **INV-GRPC-02** gRPC/REST decision parity for secret reads: given the same principal and
  secret, gRPC and HTTP reach the same allow/deny decision. Guard: cross-package —
  `server/http/grpc_rest_authz_parity_fuzz_test.go:FuzzGRPCRESTSecretReadAuthzParity` (filed
  under `server/http`, not here — do not duplicate, reference it). See also
  `server/http/INVARIANTS.md` INV-HTTP-10 (the broader multi-tenant version of this same
  parity property, `FuzzMultiTenantIsolationGRPC`).
- **INV-GRPC-03** A machine-authenticated actor's secret mutation over gRPC is audit-attributed
  to the machine, never misattributed to a user or to nobody. Guard:
  `secrets_machine_attribution_grpc_test.go` (`TestSecretGRPC_UpdateSecret_MachineActor_AuditAttributedToMachine`,
  `TestSecretGRPC_DeleteSecret_MachineActor_AuditAttributedToMachine`) — this file sits directly
  under `server/grpc`, not `server/grpc/services`, despite testing a `services`-owned RPC path.

## Protoreflect differential fuzzer (whole-surface invariant)

- **INV-GRPC-04** Every registered RPC, regardless of which one is picked, satisfies four
  cross-cutting invariants: (1) no panic/raw-error/stack-trace leak via
  `codes.Unknown`/`Internal`; (2) a zero-grant identity never gets `OK` with either a DB-state
  change or the planted canary secret's plaintext in the response, and a read-only identity
  never gets `OK` with a DB-state change; (3) a non-OK status leaves the DB unchanged except
  for a documented best-effort async write; (4) handling time is bounded relative to request
  size. Guard: `protoreflect_fuzz_test.go:FuzzGRPCProtoreflectInvariants` (doc comment, lines
  1-50), with its four oracles independently red/green-proofed in
  `protoreflect_oracle_mechanism_test.go` (`TestClassifyStatusLeak` et al.). This fuzzer has
  already caught 3 real exemption-list gaps (`GetCompliancePosture` snapshot upsert,
  `LogSecretRead*` access-log write, `ValidateSessionToken`'s `last_seen_at` touch) — it is the
  differential mechanism ADR-105 §6 proposes, built independently of that ADR's (withdrawn)
  ledger-and-gate design.
- **INV-GRPC-05** `CreateSecretRequest`'s `reserved 11 to 20` field numbers (earmarked for
  retired `description`/`classification` fields) are never reassigned to unrelated fields —
  protobuf field numbers can never be reused once spent. Why: ADR-105 §2,
  `server/proto/keyorix.proto:263`. UNGUARDED at the unit-test level (#issue: `buf breaking:
  FILE` in `buf.yaml` would catch a field-number reuse against a previous commit if wired into
  CI — verify `.github/workflows/ci.yml` actually runs it before relying on this; no test
  asserts the `reserved` statement itself stays present).
- **INV-GRPC-06** ADR-105 §5's proposed ledger-and-CI-gate (three-state HTTP-capability
  classification, failing on any unclassified route) and ADR-106's generated-surface guarantee
  are explicitly **"proposed, not ratified"** / **"withdrawn"** — no such ledger or generated-
  surface check exists in code today. Do not cite either as an enforced invariant;
  INV-GRPC-04 is real, independently-built coverage in the same spirit, but is not what either
  ADR describes. Not a gap to file — a documented non-implementation.

## Interceptor chain (`server/grpc/interceptors`)

- **INV-GRPC-07** `AuthInterceptor`/`StreamAuthInterceptor` authenticate every RPC except an
  explicit, short public-method allowlist (`grpcPublicMethods`: health check,
  `SystemService/HealthCheck`); mirrors the HTTP `BlockWhenImpersonating` guard for
  credential-minting RPCs. Guard: `interceptors/auth.go` lines ~91-184, 466-473. UNGUARDED for
  completeness (#issue: no test enumerates every non-public registered RPC and asserts it
  actually runs through `AuthInterceptor` — only the narrower credential-minting blocklist
  below is guarded that way).
- **INV-GRPC-08** Any gRPC RPC whose name matches the mint-a-durable-credential naming
  convention (`^(Issue|Create|Generate|Mint)\w*Token$`) is in `credentialMintingMethods` and
  therefore blocked while impersonating — derived from the naming pattern across EVERY
  registered service, not a hand-maintained list alone, closing the "keep in sync with HTTP by
  hand" drift risk. Guard: `interceptors/auth.go` lines ~182-184;
  `credential_minting_parity_test.go` (`TestCredentialMintingMethods_CoversNamingConvention`,
  `_IncludesActivateBreakGlass`, `_NoUnknownEntries`).
- **INV-GRPC-09** A machine-authenticated caller and an impersonating admin are both correctly
  attributed in gRPC-originated audit events (actor kind, `MachineIdentityID`,
  `ImpersonatedBy`) — previously silently dropped both tags on the gRPC transport. Guard:
  `interceptors/auth.go` `withAuditAttribution`, observed through a real audit row (the tags'
  context keys are core-private): `interceptors/audit_attribution_test.go`
  (`TestWithAuditAttribution_StampsAuditFields` over every principal shape,
  `TestStreamAuthInterceptor_MachineTokenStampsMachineActorInAudit`,
  `TestStreamAuthInterceptor_ImpersonationSessionStampsAdminInAudit`) and, for the unary
  `AuthInterceptor` with a real machine token and a real impersonation session,
  `interceptors/audit_attribution_unary_test.go:TestAuthInterceptor_UnaryAuditRowCarriesActorKindMachineIDAndImpersonator`
  (actor kind, `MachineIdentityID`, `ImpersonatedBy`, `Impersonation` together). Red-proved by
  dropping `core.WithMachineActor` and, separately, `core.WithImpersonation` from
  `withAuditAttribution` with `go test -overlay` (`auth.go` itself is not edited): the machine and
  impersonation subtests go red respectively.
- **INV-GRPC-10** `TimeoutInterceptor` caps unary RPC duration (mirrors HTTP's request-timeout
  middleware); deliberately NOT applied to the stream chain since streaming RPCs (e.g.
  `StreamAuditLogs`) are legitimately long-lived; `context.WithTimeout` only ever shortens an
  existing deadline. Guard: `interceptors/timeout.go` lines ~10-27; `interceptors/timeout_test.go`.
- **INV-GRPC-11** `GRPCRateLimitInterceptor`/`StreamRateLimitInterceptor` +
  `grpcIPFailureLimiter` are gRPC's own analogues of the HTTP per-principal and
  per-IP-failure limiters (`server/middleware/rate_limit.go`) — a SEPARATE in-memory limiter,
  not shared state with the HTTP one. Guard: `interceptors/rate_limit.go`;
  `interceptors/rate_limit_test.go` (substantial, ~16KB — cite specific test names before
  relying on a particular one).
- **INV-GRPC-12** The recovery interceptor catches a panic raised by a DOWNSTREAM interceptor
  in the chain, not only a panic in the final handler — interceptor chain ORDER matters
  (recovery must wrap everything registered after it). Guard: `interceptors/recovery.go`;
  `recovery_chain_order_test.go` (`TestRecoveryInterceptor_CatchesPanicInDownstreamInterceptor`,
  `TestStreamRecoveryInterceptor_CatchesPanicInDownstreamInterceptor`).
- **INV-GRPC-13** A PAT whose role-resolution storage call fails transiently surfaces as a
  retryable gRPC error, not a hard denial. Guard: `interceptors/auth.go`
  (`authenticateRequest`); `auth_roles_unavailable_test.go:TestAuthInterceptor_PATRoleResolutionUnavailable_IsRetryable`.

## Ledger gap

- `docs/adr-conformance-enforced.tsv` has zero rows for `server/grpc` or
  `server/grpc/interceptors` despite real, tested properties above (items 04, 08, 10, 12, 13).
  Low-effort follow-up: seed rows citing the tests already named here.
