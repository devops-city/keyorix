- **INV-STORE-principal-permission-one-snapshot** `ResolveUserPermissionAt` answers exactly
  what `GetUserRoleIDsAt` ∪ `GetUserGroupRoleIDsAt`, `RoleSetBypassesPermissionChecks` and
  `RoleSetHasPermission` answer for the same user, scope and permission
  (`storage.ComposeUserPermissionAt`), and `ResolveMachinePermissionAt` what
  `GetMachineRoleIDsAt` + `RoleSetHasPermission` answer (`ComposeMachinePermissionAt`; the
  bypass flag is never read for a machine). The role ids (same WHERE clauses), the bypass
  flag and the role->permission cache generation come from ONE statement, so the generation
  that validates a cached answer is never older than the role set. The cache is then used
  with `RoleSetHasPermission`'s rules: a hit needs exactly that generation; a miss runs the
  live join and publishes under the generation read BEFORE it; a transaction-scoped store
  neither reads nor publishes. Role membership is never cached. If the combined statement
  fails, the answer comes from the per-statement reads (`Compose*PermissionAt` over the
  store), so every failure mode answers as before (role/bypass read errors returned, a
  failed generation read only skips the cache). Why: PERF-FIX-6 (collapse C4) — a role
  decision issued 2-4 statements. Guard: `internal/storage/store`
  `TestResolvePrincipalPermission_EquivalentToClassicMethods`, `_OneStatementAndSharedCache`,
  `_GenerationReadBeforeTheJoin`, `_TransactionScopedStoreNeverUsesTheCache` (SQLite and
  Postgres). **Not covered**: a new grant table (another way to hold a role) must be added
  to both the per-statement methods and the combined statement; nothing derives one from the
  other.
