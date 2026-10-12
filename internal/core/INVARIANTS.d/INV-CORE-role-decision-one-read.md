- **INV-CORE-role-decision-one-read** `Authorize` (and `principalHasScopedPermission`,
  through `userHasScopedPermission`) and `AuthorizePrincipal`'s machine branch take a
  principal's role ids, admin-bypass flag and permission answer from ONE storage call
  (`ResolveUserPermissionAt` / `ResolveMachinePermissionAt`) and decide exactly as before:
  PAT restriction first; no roles -> deny; a user role set carrying the ADR-084 flag ->
  allow (INV-CORE-18's structural flag, never a name); a machine never bypasses; otherwise
  the role set's permission answer. Any storage error, or a nil result, denies with the
  error (INV-CORE-19's stance). A Storage wrapper that overrides one of the per-statement
  role reads (the way a test injects an authorization fault) must also override the
  combined read it feeds, forwarding it to `storage.Compose*PermissionAt` over itself, or
  the override never reaches the decision. Why: PERF-FIX-6 (collapse C4). Guard:
  `TestAuthorizeRoleResolution_Equivalence` (decisions recorded on the code before the
  change, SQLite and Postgres, cold and warm, second replica), `_MutationsSeenOnNextCall`,
  `_CrossReplica` (two Postgres pools; grant/revoke and permission add/remove racing
  decisions), `_OneStatement`; `TestRoleReadWrappersForwardTheCombinedRoleRead` (AST scan of
  every Go file for a wrapper missing the forward, with calibration).
