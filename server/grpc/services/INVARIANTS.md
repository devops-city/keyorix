# server/grpc/services invariants

Read this before changing anything in `server/grpc/services` — the per-RPC business-logic
implementations (authz, validation, error-mapping, audit attribution). See
`server/grpc/INVARIANTS.md` for the server-wiring and interceptor-chain layer underneath this
one.

Format: `INV-GRPCSVC-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

- **INV-GRPCSVC-01** `mapRoleError` classifies a role-creation/update validation failure via
  `errors.Is(err, core.ErrRoleValidation)` — an explicit sentinel — never by substring-matching
  the error text for "validation". A storage/driver error whose text merely CONTAINS
  "validation" (e.g. a constraint literally named `*_validation_*`) maps to `Internal`, not
  `InvalidArgument`. The underlying validation error wraps a raw-input echo (`%q` of
  caller-supplied text via `identity.NewFoldedName`) that is safe internally but must NOT be
  echoed to the client — the fixed message `"invalid role name or description"` is returned
  instead, satisfying the `keyorix-raw-error-to-client` Semgrep gate
  (`.semgrep/keyorix-rules.yml:95`). Why: security-closures `FIX-4-sentinel`; history: #1660/
  #1668 added the sentinel, #1669 (22 hours later) reverted the classification to
  substring-match as a side effect of an unrelated fix. Guard: `role_service.go` lines
  ~394-424; `services_s2_test.go` (`TestMapRoleError_Validation`,
  `TestMapRoleError_ValidationTextWithoutSentinel_NotEchoed`).
- **INV-GRPCSVC-02** ADR-096's "403 for both" extends to gRPC: `authorizeSecretScoped`/
  `loadConfigScoped`/`loadLeaseScoped` (via the shared `authorizeScopedTarget` in
  `conversions.go`; since #2941 `authorizeSecretScoped` decides a FOUND secret with the
  share-aware `core.AuthorizeSecretPrincipalForSecret` and denies with the same
  `"insufficient permissions"` text, see INV-CORE-share-elevates-member-on-one-secret) return the identical `PermissionDenied` code AND message for a
  real-but-forbidden resource ID and a nonexistent resource ID — an unprivileged caller cannot
  distinguish "exists, no access" from "doesn't exist." One deliberate exception (#3001
  follow-up): a caller who holds an active share covering secrets.write on the secret, refused
  because the RPC's `core.SecretAction` is not on the write-share allowlist, gets
  `core.ShareActionNotElevatedMessage` instead; that caller already knows the secret exists. Guard: `secret_403_convention_test.go`
  (`TestGetSecret_403ForBoth_UnprivilegedCallerCannotDistinguish`,
  `TestGetSecret_403ForBoth_GloballyPrivilegedCallerGetsRealNotFound`) — the gRPC analogue of
  `server/http/dynamic_secrets_403_convention_test.go`.
- **INV-GRPCSVC-03** `ShareSecret`/`UpdateSharePermission` over gRPC enforce share-expiry
  validation (expiry must be in the future; clearable) through the SAME `core.ShareSecret`/
  `UpdateSharePermission` call HTTP uses — no gRPC-side duplicate validation logic. Closes a
  prior REST-only capability gap (gRPC had no way to set/extend/clear a time-bound share at
  all). Guard: `share_expiry_parity_test.go` (`TestShareService_ShareSecret_WithExpiresAt`,
  `_ExpiresAtInPast_Rejected`, `_NoExpiresAt_IsPermanent`,
  `TestShareService_UpdateSharePermission_SetsExpiresAt`, `_ClearsExpiry`,
  `_ExpiresAtInPast_Rejected`).
- **INV-GRPCSVC-04** `GroupService.AddGroupMember` derives `actorIsMachine` from the ACTUAL
  authenticated actor's kind (`actor.ActorKind()`), never a hardcoded `false` assuming an outer
  gate guarantees a human — the gRPC auth interceptor routes a machine token through the SAME
  `UserContext` path as a human session for every RPC, so a machine identity holding only
  `roles.assign` could otherwise add a user to ANY group regardless of what roles that group
  confers (`AddUserToGroup`'s ceiling-check skip-gate `actorID != 0 || actorIsMachine` treated
  a hardcoded-false machine caller — `UserID==0` per ADR-030 — identically to no actor at all:
  a real, previously-shipped escalation). Guard: `group_service_machine_ceiling_test.go`
  (`TestGroupService_AddGroupMember_MachineActorMissingRolePermissionsBlocked`,
  `_MachineActorHoldingRolePermissionsAllowed`).
- **INV-GRPCSVC-05** A machine identity's token revoked/transitioned via the gRPC entry point
  evicts the HTTP middleware's positive auth cache immediately — the RPC handler must not
  discard the hash `core.RevokeMachineToken` returns. This is the gRPC-services-side half of
  `server/middleware/INVARIANTS.md` INV-MW-08 — same invariant, cite from there too. Guard:
  `machine_identity_revoke_token_cache_invalidation_test.go:TestGRPCRevokeMachineToken_EvictsHTTPAuthCacheImmediately`,
  `machine_identity_transition_cache_invalidation_test.go:TestGRPCTransitionMachineIdentity_{Revoke,Suspend}EvictsHTTPAuthCacheImmediately`.
  **Not yet in `docs/security-closures.d/`** despite being a real, previously-shipped defect
  fix — a closure-ledger gap, not a code gap.
- **INV-GRPCSVC-06** `StreamAuditLogs` periodically re-verifies the streaming principal's
  authorization mid-stream, not only once at open — a role revocation (#108), account
  suspension, or the specific session being individually revoked (#G18) terminates the feed
  within one fallback-poll interval, not only on client disconnect. Guard: `audit_service.go`
  (`reauthorizeAuditStream`); `audit_stream_test.go`
  (`TestAuditService_StreamAuditLogs_RevokedRoleTerminatesStream`,
  `_SuspendedAccountTerminatesStream`, `_RevokedSessionTerminatesStream`).
- **INV-GRPCSVC-07** `StreamAuditLogs` enforces a per-principal concurrent-stream cap
  (`auditStreamMaxPerPrincipal`) keyed on `actor.PrincipalID()`; during impersonation this
  resolves to the TARGET (the authenticating session), not the admin actually driving the
  client — deliberately, to prevent an admin bypassing their own cap via impersonation. Guard:
  `audit_service.go:acquireStreamSlot` (lines ~87-93);
  `audit_stream_test.go:TestAuditService_StreamAuditLogs_MaxConcurrentPerPrincipal`.
- **INV-GRPCSVC-08** `StreamAuditLogs`'s resume-from-cursor never skips or duplicates events
  across a reconnect. Guard: `audit_stream_test.go`
  (`TestAuditService_StreamAuditLogs_ResumesFromCursor`, `_TailsNewEvents`).

## Ledger gap

- None of INV-GRPCSVC-01/02/03/04 (sentinel, 403-for-both, share-expiry parity,
  machine-ceiling) are seeded into `docs/adr-conformance-enforced.tsv` yet, despite tests
  already existing and passing for each — low-effort follow-up.
