- **INV-CORE-role-grant-scope-valid-for-role** No role grant (user, group or machine identity)
  is written at a scope the role is not meaningful at: an ADR-021 project-tier built-in role
  (`project_admin`/`project_developer`/`project_viewer`/`project_auditor`, exact names, not a
  prefix) is never granted at the global scope (project 0), and an environment scope always
  names its own project's environment (`{0, X}` and `{P, env of Q}` are refused). Enforced in
  core at every storage grant write (`requireScopeValidForRole`, `role_scope_guard.go`), so
  every transport is covered; transports map `ErrRoleScopeInvalid` to HTTP 400 / gRPC
  InvalidArgument. Grants written before #3546 are not changed; the startup notice
  (`server/wire_global_project_roles.go`) lists them for review. Why: #3546 (DEMO-WALK-4: a
  group grant of project_developer with no project_id applied in every project).
  Guard: `role_scope_guard_registry_test.go` `TestEveryRoleGrantWriteChecksRoleScope` (AST:
  every function calling a storage grant writer calls the check or has a reasoned exemption;
  self-test `TestRoleScopeRegistryScanCatchesSyntheticShapes`), `role_scope_guard_test.go`
  `TestEveryRoleGrantEntryPointRefusesProjectRoleAtGlobalScope` (+ `_Postgres`; asserts no row
  written), `server/http/user_roles_env_scoped_global_project_test.go`.
  **Not covered**: custom roles have no assignable scope until Phase 2 (a custom role meant
  for projects can still be granted globally); a grant write outside internal/core is not
  scanned (transports reach storage only through core, see the registry test's header).
