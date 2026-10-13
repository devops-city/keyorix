- **INV-CORE-break-glass-list-own-only** Listing a project's break-glass activations
  (`GET /api/v1/projects/{id}/break-glass`, `BreakGlassService.ListBreakGlassActivations`)
  has ONE authorization decision, `ListBreakGlassActivationsForCaller`, used by both
  transports: (1) roles.read at the project through `AuthorizePrincipal` (PAT restriction,
  admin bypass, machine roles) returns every activation of the project, scope "project";
  (2) otherwise a USER principal (actor type user, principal id == authenticated user id,
  non-zero) who is a member of the project NOW (`IsProjectMember`) and whose PAT
  restriction allows roles.read at the project gets only the rows whose
  `UserID` is theirs, scope "own", nothing about other users' rows (not even a count); (3)
  everything else is `ErrBreakGlassListForbidden` (the old roles.read gate's 403 /
  PermissionDenied): a non-member (the same answer for every project id, existing or not,
  so the MFA check after it can never tell a non-member that a project exists or requires
  MFA), a machine identity without roles.read, a restricted PAT outside the project, and a
  FAILED authorization or membership read, which never falls back to the own view. The per-project MFA
  policy applies to both views (handlers). The own view is redacted in ONE place,
  `redactBreakGlassForOwnView` (FIX-3184, Andrei 2026-10-13): `ReviewNote`, `ReviewedBy`,
  `RevokedBy` and `RevokedByMachineIdentityID` are zeroed (omitted on the wire) on a copy,
  keyed on the scope the authorization returned, never on client input; state and the
  `revoked_at` / `reviewed_at` timestamps stay as the reviewed / revoked status. A new
  admin identity or note field must be cleared there
  (`TestBreakGlassOwnView_RedactsEveryAdminField`). Listing writes no audit event, as before. Why:
  BREAKGLASS-OWN-1 (Andrei 2026-10-13: a member lists their own activations; #2981 made the
  CLI refuse honestly instead). Guard: `server/http/break_glass_own_list_test.go` (real
  router: member A vs B, cross-project, outsider vs unknown project answer identically (also on an MFA project),
  revoked/expired, machine with and without roles.read, PAT restrictions, project MFA, no
  audit), `server/grpc/services/break_glass_own_list_test.go`,
  `internal/core/break_glass_own_list_test.go` (authz-error fail-closed, principal/user
  mismatch, non-member and membership-error refusal, PAT restriction), `scripts/e2e/journeys/journey9_break_glass_test.go` (real CLI
  and server), and `server/http/permission_sweep_test.go`'s `noPermissionGateAllowlist`
  entry for the now-ungated route. All default-ci except journey9 (e2e tag).
