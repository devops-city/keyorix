# Security mutations and where their audit row is written

AUDIT-TX-2 (follow-up to AUDIT-MUTATION-TX-1, #3297, which did this for secret
mutations) moved the grant-shaped mutations. AUDIT-TX-3 finished the list: the
mutations that were "not covered yet", and the revocations' owed-audit wiring.
REVIEW-1 found that `AssignUserRole` committed the grant and only then appended its
`role.assigned` row. A crash or a refused append between the two left a grant with
no audit record.

This document lists every security-relevant mutation in `internal/core` (and the
transport-side audits for project, environment and user create). For each, it gives
where the audit row is written, whether it is written in the mutation's own
transaction, and why. Every row is covered or has a stated reason in the last
section. The machine checks are `TestSecurityMutationAudit_RowExistsIffMutationCommitted`,
`TestSecurityMutationAudit3_RowExistsIffMutationCommitted` and
`TestRevocationAudit_EffectCommitsAndRowIsOwedNeverLost` (`internal/core`) and
`TestSecurityMutationAuditFailure_FailsClosedChangesNothing`,
`TestAuditTx3Mutation_AuditFailureFailsClosedChangesNothing` and
`TestAuditTx3Revocation_AuditFailureDoesNotBlockAndRowIsOwed` (`server/faultops`).
This table is the reviewed list behind them, not a guard of its own.

## The rule

- **Grant-shaped mutations** fail closed. They add access, a credential, a principal
  or a control change, or they change configuration whose silent change would blind
  or relax a control. Their audit rows are the last statements of the mutation's
  own transaction (`withAuditedMutation`, `internal/core/mutation_audit_tx.go`). A
  refused or panicking append returns `ErrMutationAuditUnavailable`, and the
  transaction rolls back.
- **Revocations** never block on the audit log (Andrei 2026-10-14) and never lose
  their row (AUDIT-TX-3). They go through `withOwedAuditMutation` /
  `runOwedAuditMutation` (`internal/core/audit_owed.go`): the audit writers inside
  the transaction record a `pending_audit_events` row instead of appending, so the
  change and the record of the row it owes commit together. After the commit (and
  after any auth-cache eviction, so the audit log never delays a revocation taking
  effect) each owed row is appended and its record claimed in one transaction. A
  refused append leaves the record for `BackfillPendingAuditEvents`, loudly (#3345:
  `SECURITY:` log line, `audit_owed_failures`, the pending count in
  `GET /api/v1/system/info`). If even the record cannot be written, the revocation
  still commits and the row is attempted directly (logged as NOT queued if that
  fails too). A crash between the commit and the append loses nothing: the record
  committed with the effect.
- **Updates classified per call** (REVIEW-2 on #3367). `UpdateRole` and
  `UpdateSharePermission` can widen access or narrow it. They decide from what the
  update actually changes, read inside its own transaction: one that only grants is
  grant-shaped and fails closed; one that only narrows (removes permissions,
  write→read, sets or shortens an expiry) or changes no access is a revocation or
  neutral, never blocked by the audit log, its rows owed (`withOwedAuditMutation`);
  one that does both is split, the narrowing first (MERGE-FIX-3482K, see "Mixed
  requests"). The web role editor (`PUT /api/v1/roles/{id}`) can therefore strip a
  permission during an audit outage. Guards:
  `TestSecurityMutationAudit_UpdateRole_ByDirection`,
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
    its write transactions are `BEGIN IMMEDIATE`. A split share update locks again
    in its second commit. `UpdateRole` classifies from the permission set it reads
    and changes in the same transaction; its second commit (a mixed update) reads
    the set again and also removes what a concurrent writer added since, fail
    closed. Group shares go through `UpdateSharePermission` too; a re-share
    of an existing share (`ShareSecret`'s upsert) is not classified (always fail
    closed). Guards (pg-gated, two replicas on their own connections):
    `TestCTAReview_UpdateSharePermission_NeutralVsConcurrentNarrowing_CrossReplicaPostgres`,
    `TestCTAReview_UpdateSharePermission_PreservedExpiryVsConcurrentShortening_CrossReplicaPostgres`;
    default CI: `TestUpdateSharePermission_ClassifiesFromALockedRead`,
    `TestLockShareRecordForUpdate_DialectMatchedLocking`.
- **State transitions with a known direction** pick the rule from the target state
  (`auditedByDirection`): account state into suspended/deprovisioned/restricted and
  machine suspend/revoke are revocations; back to active is a grant. `UpdateUser`
  deactivating is a revocation unless the same request changes the username or
  email (then it widens, so it fails closed), every other `UpdateUser` is fail
  closed. A SCIM user update that deactivates a user who is active, with no email
  change in the request, is a revocation; any other (a reactivation, an email
  change, `active=false` on a user already inactive) fails closed. A SCIM group
  change that only removes members is a revocation; one that adds a member or
  renames the group fails closed.
- **External side effects** (notifications, setup-link email, upstream lease
  revocation) stay after the commit and after the audit row.

"Before" means the mutation committed first and the row was appended after the
commit, through `c.storage` or by the transport. "In tx" means the row is written
through the transaction handle and commits together with the mutation. "Owed" means
the revocation commits with a pending-audit record of its row (above).

Project, environment, and alert-escalation-policy rows are written by core only when
the transport tagged the request context with `WithMutationAuditActor`; the HTTP and
gRPC handlers do and no longer write them. An untagged internal caller writes no row
from core, as before, so there are no duplicates.

## Grant-shaped: in the mutation's transaction (fail closed)

| Operation | Core function | Audit row | Before | Now |
|---|---|---|---|---|
| Direct role grant | `AssignUserRole` → `grantUserRoleAudited` | `role.assigned` | after commit | in tx (AUDIT-TX-2) |
| SSO group-mapped grant | `assignUserRoleSystemGrant` | `role.assigned` | after commit | in tx |
| Baseline role backfill | `grantBaselineRoleBackfill` | `role.assigned` (backfill) | after commit | in tx |
| JIT user grant | `AssignUserRoleWithExpiry` | `role.assigned` | after commit | in tx |
| Group role grant (permanent, JIT) | `AssignRoleToGroup`, `AssignGroupRoleWithExpiry` → `grantGroupRoleAudited` | `role.group_assigned` | after commit | in tx |
| Permission into role | `AssignPermissionToRole` | `permission.assigned` | after commit | in tx |
| Role create | `CreateRole` | `role.created` + `permission.assigned`×n | after commit | in tx |
| Role update (incl. permission set) | `UpdateRole` | `role.updated` + `permission.removed/assigned`×n | after commit | in tx when it only assigns; owed when it only removes permissions or changes the description; removals owed then additions in tx when it does both (see "Updates classified per call", "Mixed requests"); classified from the permission set read in the same transaction (SHARE-CAS-1) |
| Group membership add | `AddUserToGroup` | `group.member_added` | after commit | in tx |
| Project member add | `AddProjectMember` → `AssignUserRole` | `role.assigned` | after commit | in tx |
| Access-request approval grant | `finalizeAccessRequestApproval` | `role.assigned` + `access_request.approved` | after commit | in tx |
| Break-glass activation | `activateBreakGlassLocked` | `role.assigned` + `break_glass.activated` | after commit (activated: outside the lock) | in tx; when only the append fails, degraded with owed records in the same tx (BREAKGLASS-OWED-1, `activateBreakGlassDegraded`) |
| Share create (user, group) | `ShareSecret`, `ShareSecretWithGroup` | `share_created` / `group_share_created` | after commit | in tx |
| Share update | `UpdateSharePermission` | `share_updated` / `group_share_updated` | after commit | in tx when it only widens (read→write, later expiry, expiry cleared); owed when it only narrows or changes nothing; narrowing owed then the rest in tx when it does both (see "Updates classified per call", "Mixed requests"); classified from the share row read under `FOR UPDATE` in each transaction (SHARE-CAS-1) |
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
| **Project update** (incl. turning the MFA requirement off) | `UpdateProject` | `project.updated`, `project.mfa_requirement_enabled/disabled` | transport / after commit | in tx (AUDIT-TX-3); the MFA row is written for every caller, `project.updated` for a tagged one. Turning the MFA requirement ON restricts access and is owed instead (Revocations table); with a rename in the same call it is split ("Mixed requests") |
| **Project restore** | `RestoreProject` | `project.restored` + `machine_identity.activated`×n | after commit | in tx |
| **Environment restore** | `RestoreEnvironment` | `environment.restored` | after commit | in tx |
| **Group create / update** | `CreateGroup`, `UpdateGroup` | `group.created` / `group.updated` | after commit | in tx |
| **Group restore** | `RestoreGroup` | `group.restored` | after commit | in tx |
| **User update** (anything but a deactivation that leaves username and email alone: profile, email, username, re-activate flag; a deactivation that also changes the username or email) | `UpdateUser` (also `UpdateOwnProfile`) | `user.updated` | after commit | in tx |
| **User reactivate** | `ReactivateUser` → `setAccountState` (to active) | `account.reactivated` | after commit | in tx |
| **User restore** | `RestoreUser` | `user.restored` | after commit | in tx |
| **OTP reissue** (the credential half) | `ReissueOneTimePassword` | `user.one_time_password_reissued` | after commit | in tx, after the owed narrowing commit ("Mixed requests") |
| **SCIM user provision** | `ProvisionSCIMUser` | `scim.user_provisioned` | after commit | in tx |
| **SCIM user update** (anything but deactivating an active user without an email change: includes active=false on an inactive user and active=false with an email change) | `UpdateSCIMUser` | `scim.user_updated` | after commit | in tx |
| **SCIM group provision / replace / patch** (adds a member or renames) | `ProvisionSCIMGroup`, `ReplaceSCIMGroup`, `PatchSCIMGroup` | `scim.group_provisioned` / `scim.group_updated` | after commit; rename a separate commit | in tx; the rename moved into the membership transaction |
| **Invitation create** (project, global, with or without link) | `InviteToProject[WithLink]`, `InviteGlobal[WithLink]` | `invitation.created` | after commit | in tx (the setup-link variants: in the invitation + token transaction) |
| **Access request create** (project, secret) | `RequestProjectAccess`, `RequestSecretAccess` | `access_request.created` / `.secret_created` | after commit | in tx |
| **Access request partial approval** | `recordPartialApproval` | `access_request.approval_recorded` | after commit | in tx |
| **Secret access request approval** | `ApproveSecretAccessRequest` | `access_request.secret_approved` | after commit | in tx |
| **Notification channel create / update / delete** | `CreateNotificationChannel`, `UpdateNotificationChannel`, `DeleteNotificationChannel` | `notification_channel.*` | after commit | in tx |
| **Notification channel retry policy** | `SetNotificationRetryPolicy` | `notification_channel.retry_policy_updated` | after commit | in tx |
| **Anomaly config** | `UpdateAnomalyConfig` | `anomaly_config.updated` | after commit | in tx |
| **Rotation policy create / update / delete** | `CreateRotationPolicy`, `UpdateRotationPolicy`, `DeleteRotationPolicy` | `rotation_policy.*` | after commit | in tx |
| **Alert escalation policy create / update / delete** | `CreateAlertEscalationPolicy`, `UpdateAlertEscalationPolicy`, `DeleteAlertEscalationPolicy` | `alert_escalation_policy.*` | transport, after commit | in tx (tagged) |
| **Risk exception create / approve** | `CreateRiskException`, `ApproveRiskException` | `risk.exception_created` / `.exception_approved` | after commit | in tx |
| **Legal hold place / lift** | `PlaceLegalHold`, `LiftLegalHold` | `data.legal_hold_placed` / `.legal_hold_lifted` | after commit | in tx |
| **Machine / token classification** | `ClassifyMachineIdentity`, `ClassifyMachineToken` | `machine_identity.classified` / `.token_classified` | after commit | in tx |
| **Access review campaign open / close** | `OpenAccessReviewCampaign`, `CloseAccessReviewCampaign` | `access_review.campaign_opened` / `.campaign_closed` | after commit | in tx |

Risk closed: a crash or a refused append after the commit left these changes with
no audit record. That includes an emergency self-elevation (break-glass), a new
credential (PAT, machine token), a new admin-capable principal (user create with
assignments), a changed account email (the password-reset anchor), a silently
repointed or disabled alert channel, a relaxed rotation policy or a lifted legal
hold.

## Mixed requests: two commits, narrowing first (MERGE-FIX-3482G)

A request that narrows access AND widens it (Andrei 2026-10-20, ask
3482-mixed-request-rule (a); INV-CORE-mixed-request-split, `audit_split.go`) commits
the narrowing alone first (owed, never blocked by the audit log) and the rest second
(fail closed). Each part's direction is decided against the row read under the
call's lock. If the second commit fails the narrowing stays and the answer is HTTP
503 / SCIM 503 / gRPC Unavailable with `code: mutation_partially_applied`,
`revocation_applied: true`, `remainder_applied: false`; a retry is safe.

| Request | Core function | Commit 1 (owed) | Commit 2 (fail closed) |
|---|---|---|---|
| Deactivate + username/email change | `UpdateUser` | deactivation, `user.updated` "deactivated user …" | identity change, `user.updated` |
| SCIM active=false (active user) + email change | `UpdateSCIMUser` | deactivation, `scim.user_updated` "SCIM deactivated user …" | email/displayName, `scim.user_updated` |
| SCIM PATCH removals (current members) + adds/rename | `PatchSCIMGroup` | removals, `scim.group_updated` "(-n members)" | rename + adds, `scim.group_updated` "(+n members)" |
| SCIM PUT removals (current members) + adds/rename | `ReplaceSCIMGroup` | removals, `scim.group_updated` | rename + adds, `scim.group_updated` "(members=n)" |
| MFA requirement on + rename/description | `UpdateProject` (`updateProjectSplit`) | `project.mfa_requirement_enabled` | rename, `project.updated` (tagged caller) |
| OTP reissue | `ReissueOneTimePassword` | restricted state + sessions ended, `user.one_time_password_reissue_restricted` | password, expiry, lockout reset, `user.one_time_password_reissued` |
| Machine token rotation (`replace_credential_id`) | `IssueMachineToken` → `rotateMachineToken` | old credential revoked (and evicted), `machine_identity.token_revoked` | new credential, `machine_identity.token_rotated` |
| Role update: permissions removed + added (MERGE-FIX-3482K) | `UpdateRole` | removals, `permission.removed`×n | description + additions, `role.updated` + `permission.assigned`×n |
| Share update: lower permission + later/cleared expiry, or the reverse (MERGE-FIX-3482K) | `UpdateSharePermission` | the narrower value of each part, `share_updated` / `group_share_updated` | the requested share, `share_updated` / `group_share_updated` |

## Revocations: never blocked, row owed in the same transaction (AUDIT-TX-3)

All of these commit with a `pending_audit_events` record of the row they owe, then
append it after the commit and any cache eviction (`withOwedAuditMutation`,
`runOwedAuditMutation`). Before AUDIT-TX-3 they wrote a plain best-effort row after
the commit with no record: a refused append or a crash lost the row for good.

| Operation | Core function | Audit row |
|---|---|---|
| Role removal (global admin path included) | `RemoveUserRole` → `removeUserRoleUnguarded`, `removeGlobalAdminRoleIfApplicable` | `role.removed` |
| Group role removal | `RemoveRoleFromGroup` | `role.group_removed` |
| Permission removal | `RemovePermissionFromRole` | `permission.removed` |
| Role delete | `DeleteRole` | `role.deleted` |
| Group member removal, group delete (incl. SCIM group delete) | `RemoveUserFromGroup`, `DeleteGroup`, `DeprovisionSCIMGroup` | `group.member_removed`, `group.deleted`, `scim.group_deprovisioned` |
| Project member removal | `RemoveProjectMember` | `role.removed`×n |
| Share revoke, self-removal, expiry sweep | `RevokeShare`, `RemoveSelfFromShare`, `RemoveExpiredShares` | `share_revoked`, `share_self_removed`, `share.expired` |
| Secret ACL revoke | `RevokeSecretACL` | `secret.acl_revoked` |
| Machine suspend / revoke | `TransitionMachineIdentity` (to suspended/revoked; to active is a grant, fail closed) | `machine_identity.suspended/revoked` |
| Machine token revoke, machine role removal | `RevokeMachineToken`, `RemoveMachineRole` | `machine_identity.token_revoked`, `.role_removed` |
| PAT revoke (own, admin bulk, expired bulk) | `RevokeOwnPAT`, `RevokeAllPersonalAccessTokensForUser`, `BulkRevokeExpiredOwnPATs` | `pat.revoked`, `user.credentials_revoked` |
| Session revoke (own, admin, bulk) | `RevokeOwnSession`, `RevokeUserSessions`, `DeleteSessionsForUserExcept` | `session.revoked`, `account.sessions_revoked`, `user.credentials_revoked` |
| User suspend / restrict | `setAccountState` (to suspended, deprovisioned, password-reset-required) | `account.suspended`, … |
| User deactivate (with a username/email change: split, "Mixed requests"), delete | `UpdateUser` (deactivating branch), `DeleteUser` | `user.updated`, `user.deleted` |
| SCIM user deactivate (active user; with an email change: split), deprovision | `UpdateSCIMUser` (active=false), `DeprovisionSCIMUser` | `scim.user_updated`, `scim.user_deprovisioned` |
| Project delete (cascade, machine-identity suspension) | `DeleteProject` | `project.deleted` + `machine_identity.suspended`×n (the cascade events are owed for every caller, `project.deleted` for a tagged one) |
| Environment delete | `DeleteEnvironment` (tagged) | `environment.deleted`; the secret-guard named lock is taken around the transaction and the row is settled after it is released |
| Project MFA requirement turned on (with a rename: split) | `UpdateProject` | `project.mfa_requirement_enabled` (+ `project.updated` for a tagged caller when nothing else changes) |
| Break-glass revoke | `RevokeBreakGlassActivationAtomic` | `role.removed` + `break_glass.revoked` |
| JIT expiry sweep (roles) | `RemoveExpiredRoleGrants` | `role.expired` |
| Invitation revoke, access request withdraw and reject (a narrowing decision is never blocked, ask 3482-reject-access-request-direction) | `RevokeInvitation`, `WithdrawAccessRequest`, `RejectAccessRequest` | `invitation.revoked`, `access_request.withdrawn`, `access_request.rejected` |
| Risk exception revoke | `RevokeRiskException` | `risk.exception_revoked` |
| Access review revoke decision | `DecideAccessReviewItem` | `access_review.revoked`: already in tx (#2676) with a best-effort sink, still never blocked; unchanged |

The `UpdateUser` deactivation branch used to write its failure audit from inside its
own transaction, which could deadlock on SQLite (DEADLOCK-SHAPE-1: the
write gate the transaction holds). That is fixed on main
(`TestUpdateUser_DeactivationCleanupFailure_AuditedAfterCommit`); AUDIT-TX-3 moves
its `user.updated` row to the owed record and adds
`TestUpdateUser_DeactivateAuditInOwnTransaction_NoSQLiteDeadlock` for the shape.

## Remaining, with the reason each is not in a fail-closed or owed transaction

- **`SetUserRoles`**: a compensated sequence of single grants and removals. Each
  grant inside it is in-tx, each removal is owed; the sequence as a whole is not one
  transaction by design (the compensation logic reverts partial progress).
- **Setup-token issuance (`setup_token.issued`) and invitation accept
  (`invitation.accepted`)**: `setup_token.go` / `setup_consume.go` belong to the
  login/setup flow another session owns (FIX-3277). Their rows stay after the commit.
- **`ChangePassword`, login, MFA, WebAuthn, step-up, impersonation, session create**:
  authentication, not administrative mutation; the same session owns them.
- **Bulk access request approve/reject summaries**
  (`access_request.bulk_approve_attempted` / `bulk_reject_attempted`): a summary
  record of per-request operations that are each audited in their own transaction
  above; the summary itself changes nothing.
- **Access-review revoke proxy (`AuditCampaignCreated`)**: the `/system` proxy path
  scheduled for deletion under ADR-108; the human path above is covered.
- **Operator-configured startup settings** (`SetPasswordPolicy`, `SetSessionTTLs`, …)
  and **the security-posture snapshot diff**: process configuration read at start,
  not runtime mutations; `security.posture_setting_changed` already records a change
  between starts.
- **Dynamic-secret config enable/disable, lease revoke**: audited by the dynamic
  secrets engine in its own transaction family (`dynamic_secrets.go`), outside this
  inventory's scope.
- **`user.deactivation_cleanup_failed`**: a diagnostic failure record written after
  the deactivation commits; losing it loses no security-relevant fact (the
  deactivation row itself is owed).
