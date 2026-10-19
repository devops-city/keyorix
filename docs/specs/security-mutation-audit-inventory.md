# Security mutations and where their audit row is written

AUDIT-TX-2 (follow-up to AUDIT-MUTATION-TX-1, #3297, which did this for secret
mutations). REVIEW-1 found that `AssignUserRole` committed the grant and only then
appended its `role.assigned` row. A crash or a refused append between the two left
a grant with no audit record.

This document lists every security-relevant mutation in `internal/core` (and the
transport-side audits for project, environment and user create). For each, it gives
where the audit row is written, whether it is written in the mutation's own
transaction, and why. The machine check is
`TestSecurityMutationAudit_RowExistsIffMutationCommitted` (`internal/core`) and
`TestSecurityMutationAuditFailure_FailsClosedChangesNothing` (`server/faultops`).
This table is the reviewed list behind them, not a guard of its own.

## The rule

- **Grant-shaped mutations** fail closed. They add access, a credential, a principal
  or a control change. Their audit rows are the last statements of the mutation's
  own transaction (`withAuditedMutation`, `internal/core/mutation_audit_tx.go`). A
  refused or panicking append returns `ErrMutationAuditUnavailable`, and the
  transaction rolls back.
- **Revocations** never block on the audit log (Andrei 2026-10-14). They keep their
  best-effort audit after the commit. #3345 (owed-audit record plus backfill) is
  not merged, so these paths have no backfill yet. When it merges, revocations
  should record their row through `commitOwingAudit`, as plain suspend does there.
- **Updates classified per call** (REVIEW-2 on #3367). `UpdateRole` and
  `UpdateSharePermission` can widen access or narrow it. They decide from what the
  update actually changes, read inside its own transaction
  (`withDirectedAuditedMutation`): one that grants anything, including a mixed one
  that also removes, is grant-shaped and fails closed; one that only narrows
  (removes permissions, write→read, sets or shortens an expiry) or changes no
  access is a revocation or neutral, commits without an audit write in its
  transaction, and writes the same rows best-effort after the commit. The web role
  editor (`PUT /api/v1/roles/{id}`) can therefore strip a permission during an
  audit outage. Guards: `TestSecurityMutationAudit_UpdateRole_ByDirection`,
  `TestSecurityMutationAudit_UpdateSharePermission_ByDirection` (`internal/core`,
  SQLite and PostgreSQL), `TestRoleEditorUpdate_AuditFailure_ByDirection`,
  `TestShareUpdate_AuditFailure_ByDirection` (`server/faultops`, REST and gRPC).
  - **The classification must hold until the write** (SHARE-CAS-1). A
    classification is only true if no other writer can change what it read before
    the update writes. `UpdateSharePermission` reads the share with
    `LockShareRecordForUpdate` (`SELECT … FOR UPDATE` on PostgreSQL), so a
    concurrent update or revoke of the share waits for its commit. A preserved
    expiry and the "expired share" check use the same locked row. Before this, on
    PostgreSQL READ COMMITTED, a narrowing committing between the read and the
    UPDATE turned an update classified neutral into write over read (or a stale
    expiry over a shortened one) with only a best-effort row. SQLite needs no lock:
    its write transactions are `BEGIN IMMEDIATE`. `UpdateRole` has no such window:
    it classifies from its own writes (a permission it inserted), not from a read,
    and a permission another transaction adds in between is audited by that
    transaction. Group shares go through `UpdateSharePermission` too; a re-share
    of an existing share (`ShareSecret`'s upsert) is not classified (always fail
    closed). Guards (pg-gated, two replicas on their own connections):
    `TestCTAReview_UpdateSharePermission_NeutralVsConcurrentNarrowing_CrossReplicaPostgres`,
    `TestCTAReview_UpdateSharePermission_PreservedExpiryVsConcurrentShortening_CrossReplicaPostgres`;
    default CI: `TestUpdateSharePermission_ClassifiesFromALockedRead`,
    `TestLockShareRecordForUpdate_DialectMatchedLocking`.
- **External side effects** (notifications, setup-link email, upstream lease
  revocation) stay after the commit and after the audit row.

"Before" means the mutation committed first and the row was appended after the
commit, through `c.storage` or by the transport. "In tx" means the row is written
through the transaction handle and commits together with the mutation.

## Grant-shaped: now in the mutation's transaction (fail closed)

| Operation | Core function | Audit row | Before | Now |
|---|---|---|---|---|
| Direct role grant | `AssignUserRole` → `grantUserRoleAudited` | `role.assigned` | after commit | in tx |
| SSO group-mapped grant | `assignUserRoleSystemGrant` | `role.assigned` | after commit | in tx |
| Baseline role backfill | `grantBaselineRoleBackfill` | `role.assigned` (backfill) | after commit | in tx |
| JIT user grant | `AssignUserRoleWithExpiry` | `role.assigned` | after commit | in tx |
| Group role grant (permanent, JIT) | `AssignRoleToGroup`, `AssignGroupRoleWithExpiry` → `grantGroupRoleAudited` | `role.group_assigned` | after commit | in tx |
| Permission into role | `AssignPermissionToRole` | `permission.assigned` | after commit | in tx |
| Role create | `CreateRole` | `role.created` + `permission.assigned`×n | after commit | in tx |
| Role update (incl. permission set) | `UpdateRole` | `role.updated` + `permission.removed/assigned`×n | after commit | in tx when it assigns any permission (mixed included); after commit, best-effort, when it only removes permissions or changes the description (see "Updates classified per call"); classified from its own inserts, so no row lock is needed (SHARE-CAS-1) |
| Group membership add | `AddUserToGroup` | `group.member_added` | after commit | in tx |
| Project member add | `AddProjectMember` → `AssignUserRole` | `role.assigned` | after commit | in tx |
| Access-request approval grant | `finalizeAccessRequestApproval` | `role.assigned` + `access_request.approved` | after commit | in tx |
| Break-glass activation | `activateBreakGlassLocked` | `role.assigned` + `break_glass.activated` | after commit (activated: outside the lock) | in tx |
| Share create (user, group) | `ShareSecret`, `ShareSecretWithGroup` | `share_created` / `group_share_created` | after commit | in tx |
| Share update | `UpdateSharePermission` | `share_updated` / `group_share_updated` | after commit | in tx when it widens (read→write, later expiry, expiry cleared; mixed included); after commit, best-effort, when it only narrows or changes nothing (see "Updates classified per call"); classified from the share row read under `FOR UPDATE` (SHARE-CAS-1) |
| Secret ACL grant | `GrantSecretACL` | `secret.acl_granted` | after commit | in tx |
| Machine identity create | `CreateMachineIdentity` | `machine_identity.created` | after commit | in tx |
| Machine token issue / rotate | `IssueMachineToken` | `machine_identity.token_issued` / `token_rotated` | after commit | in tx |
| Machine role grant | `AssignMachineRole` | `machine_identity.role_granted` | after commit | in tx |
| PAT create | `CreateOwnPAT` | `pat.created` | after commit | in tx |
| User create with assignments | `CreateUserWithAssignments` | `user.created` | after commit | in tx |
| User create (admin, setup link, one-time password) | `CreateUserAudited` | `user.created` | transport / caller, after commit | in tx |
| Project create | `CreateProject`, `CreateProjectWithEnvs` with `WithMutationAuditActor` | `project.created` | transport, after commit | in tx |
| Environment create | `CreateEnvironment` with `WithMutationAuditActor` | `environment.created` | transport, after commit | in tx |
| SoD policy create / delete | `CreateSoDPolicy`, `DeleteSoDPolicy` | `sod.policy_created` / `sod.policy_deleted` | after commit | in tx |
| Secret create/update/rotate/rollback/delete | (#3297) | `secret.*` | – | in tx (already) |

Risk closed: a crash or a refused append after the commit left these changes with
no audit record. That includes an emergency self-elevation (break-glass), a new
credential (PAT, machine token), and a new admin-capable principal (user create
with assignments).

## Revocations: best-effort after the commit (by design, unchanged)

| Operation | Core function | Audit row | In tx? | Note |
|---|---|---|---|---|
| Role removal (all scopes) | `RemoveUserRole` | `role.removed` | no | revocation |
| Group role removal | `RemoveRoleFromGroup` | `role.group_removed` | no | revocation |
| Permission removal | `RemovePermissionFromRole` | `permission.removed` | no | revocation |
| Role delete | `DeleteRole` | `role.deleted` | no | cascades grants away |
| Group member removal, group delete | `RemoveUserFromGroup`, `DeleteGroup` | `group.member_removed`, `group.deleted` | no | revocation |
| Project member removal | `RemoveProjectMember` | `role.removed`×n | no | revocation |
| Share revoke, self-removal, expiry sweep | `RevokeShare`, `RemoveSelfFromShare`, `RemoveExpiredShares` | `share_revoked`… | no | revocation |
| Secret ACL revoke | `RevokeSecretACL` | `secret.acl_revoked` | no | revocation |
| Machine suspend / revoke | `TransitionMachineIdentity` | `machine_identity.*` | no | revocation |
| Machine token revoke, machine role removal | `RevokeMachineToken`, `RemoveMachineRole` | … | no | revocation |
| PAT revoke (own, admin, expiry) | `RevokeOwnPAT`, … | `pat.revoked` | no | revocation |
| Session revoke (own, admin) | `RevokeUserSessions`, `RevokeOwnSession` | session revoke rows | no | revocation |
| User suspend / deactivate / delete | `setAccountState`, `UpdateUser`, `DeleteUser` | `user.*` | no | revocation |
| Break-glass revoke | `RevokeBreakGlassActivationAtomic` | `role.removed` + `break_glass.revoked` | no | revocation |
| JIT expiry sweep | `RemoveExpiredRoleGrants` | `role.expired` | no | revocation |
| Access review revoke decision | `DecideAccessReviewItem` | `access_review.revoked` | yes, best-effort | already in tx (#2676), still never blocked |

## Not covered by this change (follow-ups)

These are not access grants, or their transaction shape needs its own change.
Each still writes its row after the commit:

- **Project/environment delete**: transport audit after commit. `DeleteEnvironment`
  takes its own named lock inside storage, so it cannot run inside a transaction.
  `DeleteProject` revokes dynamic-secret leases upstream.
- **Project update; group create/update/restore; user update (non-deactivate),
  restore, reactivate; admin OTP reissue; SCIM user/group provisioning**. SCIM is
  driven by the IdP and already transactional for the write itself.
- **Machine/token classification**.
- **Config changes**: rotation policies, risk exceptions, legal hold,
  notification channels, alert escalation, anomaly config.
- **Access request create/partial approval/reject/withdraw; invitations; access
  review campaign open/close and attest**.
- **`SetUserRoles`**: a compensated sequence of single grants and removals. Each
  grant inside it is now in-tx; each removal is a revocation.
- **Login, MFA, WebAuthn, setup consume, step-up, impersonation**: out of scope
  for this session (FIX-3277 / AUTH-2).

Found while inventorying (not fixed here): `UpdateUser`'s deactivation branch calls
`writeAuditEventFailed` through `c.storage` from inside its own `WithTransaction`
(`internal/core/users.go`). That is the same self-deadlock shape the project seed
path avoids on SQLite.
