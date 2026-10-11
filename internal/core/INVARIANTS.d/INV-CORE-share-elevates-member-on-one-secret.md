- **INV-CORE-share-elevates-member-on-one-secret** A member's effective permission on a
  secret is max(role permission, active share permission) (#2941, Andrei's 2026-10-10
  decision). The share term lives in exactly one function, `sharePermissionFor`
  (`share_authz.go`), and both per-secret decision functions call it: `AuthorizeSecret` (the
  gate behind every per-secret REST route via `RequireScopedSecretPermission` /
  `RequireScopedSecretRefPermission`, every per-secret gRPC RPC via `authorizeSecretScoped`,
  and the core helpers that call `AuthorizeSecretPrincipal`) and `CheckSecretPermission` (the
  core `*WithPermissionCheck` / `EnforceSecret*Permission` paths). Limits, each enforced in
  that one function: (1) a share applies only while the recipient is a LIVE member of the
  secret's project (`IsProjectMember`, at access time — `RemoveProjectMember` deletes role
  grants and ACLs but not share rows); (2) an expired share grants nothing; a revoked share is
  a deleted row; (3) a share satisfies only `secrets.read` (read|write share) and, for a
  write share, `secrets.write` FOR AN ALLOWLISTED ACTION ONLY — `secretActionShareElevates`
  (Andrei, 2026-10-10 19:33: `secret.update` value+metadata, `secret.update_metadata`,
  `secret.rotate`), checked inside `sharePermissionFor`; every other `SecretAction`
  (suspend/resume, lifecycle = expiry/read limit, move, transfer, share, rollback, classify,
  auto-rotate, dependencies, version comments) and any decision that names no action is not
  elevated; never `secrets.delete`, `secrets.manage`, owner or the right to share; a stored
  level outside read|write grants nothing; (4) machine principals never take the share path.
  Every share-aware `secrets.write` gate names its action (HTTP `RequireScopedSecretPermission`
  third argument, gRPC `authorizeSecretScoped` sixth); core write paths a share may elevate
  call `EnforceSecretActionPermission`. (5) Audit: the share term runs only after ACL and role
  both denied; a grant is recorded on the request's `ShareElevationRecorder` and written as
  `share_access_elevated` (action, secret, share id, actor) by `CommitShareElevations` only
  when the action was performed (HTTP 2xx in the gate; gRPC nil error in
  `ShareElevationAuditInterceptor`) — never on a refusal, a failed request, or a decision the
  role made. A write elevation with no recorder on the context is refused (fail closed). Share mutations are owner-only through
  `requireShareAuthority`, whose typed refusals (`ErrShareOwnerNotMember`,
  `ErrShareRecipientNotMember`, ...) transports turn into the same user-facing reason via
  `ShareRefusalMessage` (#2976). Why: #2941 (a `write` share let nothing happen because the
  role-only route gates refused first, and the gRPC gate was role-only too), #2976 (bare 403).
  Guard: `share_authz_guard_test.go` (`TestShareTerm_DecisionFunctionsConsultIt`,
  structural; `TestShareTerm_AuthorizeSecret_MaxOfRoleAndShare`,
  `TestShareTerm_CheckSecretPermission_NonMemberShareGrantsNothing`, behavioural with real
  storage); transport halves `server/http/share_authz_route_guard_test.go`
  (`TestEveryPerSecretRoute_UsesShareAwareGate` over router.go's AST inventory,
  `TestSecretGates_CallShareAwareCheck`) and
  `server/grpc/services/share_authz_rpc_guard_test.go` (`TestEverySecretRPC_UsesShareAwareGate`
  over `pb.SecretService_ServiceDesc`, `TestAuthorizeSecretScoped_CallsShareAwareCheck`);
  end-to-end `server/http/share_elevation_2941_test.go`,
  `server/grpc/services/share_elevation_2941_test.go`. Allowlist (#3001 follow-up):
  `share_action_allowlist_guard_test.go` (every action has an explicit decision; the elevated
  set is exactly the decision; only the share term reaches the raw share lookup; per-action
  behaviour; record-then-commit audit), `TestShareAwareWriteRoutes_NameTheirAction`,
  `TestSecretsWriteRPCs_NameTheirAction`, `TestServerChain_HasShareElevationAuditInterceptor`,
  and the per-route matrices `server/http/share_write_allowlist_test.go` (every secrets.write
  REST route from router.go's AST) and `server/grpc/services/share_write_allowlist_test.go`
  (every secrets.write RPC from the package source). All default-ci.
  **Not covered**: a core function that authorizes one secret by calling the role-only
  `AuthorizePrincipal` at the secret's scope instead of `AuthorizeSecretPrincipal` would
  bypass the share term without tripping these guards (it would under-grant, never
  over-grant).
