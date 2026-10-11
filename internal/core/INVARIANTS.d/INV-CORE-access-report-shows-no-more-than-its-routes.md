- **INV-CORE-access-report-shows-no-more-than-its-routes** `ListSecretAccessors`
  (`GET /secrets/{id}/access`, `keyorix secret access`) never shows a caller more than the
  routes it summarises would: project roles (role-only members and every `role:` grant) only
  when the caller holds `users.read` at the project (the gate of `GET /projects/{id}/members`),
  per-secret ACL holders and every `acl:` grant only when the caller passes `secrets.manage` on
  the secret through `AuthorizeSecret` (the gate of `GET /secrets/{id}/acl`). A withheld part is
  neither evaluated nor reported, and the result is flagged `Degraded` with a `project_members` /
  `secret_acls` reason. Owner level is granted only through `requireLiveOwnerAuthority`, as
  enforcement does (RBAC-001). Why: #3020 review — the report listed ACL holders to any
  secrets.read caller and role levels to callers without users.read.
  Guard: `secret_access_list_test.go` `TestListSecretAccessors_ACLHoldersNeedSecretsManage`,
  `TestListSecretAccessors_NoRoleGrantsWithoutRoster`, `TestListSecretAccessors_RosterNeedsUsersRead`,
  `TestListSecretAccessors_OwnerNeedsLiveMembership`.
  **Not covered**: share recipients are listed to any caller who can read the secret (the same
  data as the share list); a new term added to `effectiveSecretAccess` needs its own gate here.
