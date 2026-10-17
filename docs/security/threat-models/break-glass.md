# Threat Model: Break-glass (self-service emergency access)

> Part of [`docs/security/threat-models/`](README.md). Narrows
> [`../threat-model.md`](../threat-model.md) to the self-service,
> time-bound emergency role grant (`POST /projects/{id}/break-glass`,
> ADR-112). This is *not* the offline admin recovery path
> (`keyorix-server admin recover-admin`, boundary B8), which is covered as
> AUTH-9 in [authentication.md](authentication.md).
>
> Evidence cells name a function or file and the test that proves it. A
> mitigation with no proving test on `main` is written as a **GAP**.
> `TestThreatModelEvidence_CitedFilesAndTestsExist` (`internal/docsdrift`)
> checks that every cited path and `Test` function exists; it does not
> check that the test proves the mitigation.

## 1. System context

Break-glass is off by default (`break_glass.enabled: false`). When on, a
member of a project can grant themselves one configured, contained
emergency role on that project, for a bounded time, with a written
justification. It is deliberately not gated by RBAC (the point is access
the caller lacks), so the controls are configuration, membership,
containment of the role, justification, audit, alert, expiry and an
independent after-the-fact review.

```mermaid
flowchart TB
    USER["Project member\n(session or unrestricted PAT)"]
    GATES["Refusals before any write:\nrestricted PAT, disabled, short justification,\nnot a project member, already active,\nemergency role is admin-bypass or carries roles.assign"]
    LOCK["Named lock projectAdminGuardLockKey\n(same lock as revoke)"]
    TX[("One transaction:\nBreakGlassActivation row (partial unique index,\none active per project+user)\n+ AssignRoleWithExpiry(expires_at)")]
    AUDIT["break_glass.activated audit event\n(written AFTER commit, best-effort on main)"]
    NOTIFY["Alert to project approver-role members\nand install-wide admins\n(best-effort, panic-recovered)"]
    EXPIRE["Role grant expires at expires_at\n(authorization ignores expired grants)"]
    REVIEW["ReviewBreakGlass by a different human,\nafter the activation is no longer active"]
    POSTURE["Unreviewed past window:\nposture deviation, SECURITY log,\nbreak_glass.review_overdue event,\nrepeat notification"]
    REVOKE["RevokeBreakGlass (roles.assign)\nrole removal + record revoked in one tx"]

    USER --> GATES --> LOCK --> TX --> AUDIT --> NOTIFY
    TX --> EXPIRE
    EXPIRE --> REVIEW
    REVOKE --> REVIEW
    REVIEW -. none within window .-> POSTURE
    REVOKE -. early end .-> TX
```

## 2. Trust boundaries

| Boundary | What crosses it | Enforcement |
|---|---|---|
| Member → emergency role | A role the caller does not hold, on one project | Policy gates in `ActivateBreakGlass`; role must not be an admin-bypass role and must not carry `roles.assign` |
| Impersonation session → grant | A durable, time-bound grant attributed to the impersonated user | `BlockWhenImpersonating` on activation and review routes |
| Restricted PAT → owner's privileges | A token narrowed below its owner escalating the owner | `ErrRestrictedPATCannotBreakGlass`, checked first in core |
| Activator → reviewer | The record that proves the activation was checked | `ReviewBreakGlass`: human, not the activator, not still active, once |
| Core → audit log / notifier | The evidence that the grant happened | Audit write after commit; notification fan-out; both best-effort on `main` |

## 3. Threat table

| ID | STRIDE | Description | Mitigation | Evidence link | Residual risk / GAP |
|---|---|---|---|---|---|
| BG-1 | Elevation of privilege | Break-glass is enabled by accident or used when it is off. | Disabled by default; `ActivateBreakGlass` refuses with a typed `ErrBreakGlassDisabled` (HTTP 403 `BreakGlassDisabled`) and says which key turns it on. A justification of at least 10 characters after trimming is required. | `internal/core/break_glass.go` `ActivateBreakGlass`; `TestActivateBreakGlass_DisabledAndJustificationRequired`; `TestActivateBreakGlass_RejectsWhitespaceOnlyAndTooShortJustification`; `TestActivateBreakGlass_DisabledCarriesTypedCode` | The justification is free text; its length is checked, not its truth. The review (BG-7) is the control for that. |
| BG-2 | Elevation of privilege | A user who is not on the project (for example one holding only the install-wide baseline role) grants themselves the emergency role on any project. | Eligibility is `IsProjectMember`, which requires a role scoped to this project (directly or via a group) and excludes global roles. | `internal/core/break_glass.go` `ActivateBreakGlass`; `TestActivateBreakGlass_RejectsNonMember`; `TestActivateBreakGlass_RejectsGlobalOnlyAffiliation` | There is no minimum tenure: a user added to the project seconds ago can activate (noted in the code). Accepted: an emergency path that waits fails when it is needed. |
| BG-3 | Elevation of privilege | The emergency role is itself a vehicle for permanent or install-wide access: it is an admin-bypass role, or it carries `roles.assign` (which also gates machine-token issuance), so the holder mints access that outlives the expiry. | The role is resolved by name and refused if it is flagged admin-bypass (structural flag, not a name list) or if its permission set contains `roles.assign`. | `internal/core/break_glass.go` `ActivateBreakGlass`; `TestActivateBreakGlass_RejectsRoleAssignEmergencyRole`; `TestActivateBreakGlass_RejectsInstallAdminEmergencyRole` | The check runs at activation. A role's permissions can be edited afterwards by someone who can already edit roles, and a live grant then carries the new permission until it expires. Accepted: that editor is an administrator. Revoke re-runs the last-admin guard (BG-9). |
| BG-4 | Elevation of privilege / persistence | The grant never expires, is renewed indefinitely, or two activations race and the second keeps the role. | Expiry is `expires_at` on the role grant itself, capped at the effective ceiling (`MaxTTL`, falling back to the default TTL when unset, so an unconfigured ceiling cannot make an unbounded grant). One active activation per (project, user) is enforced by a partial unique index; a TTL-lapsed row is reconciled before a new insert. An expired grant denies authorization. | `internal/core/break_glass.go` `breakGlassTTLs`; `TestActivateBreakGlass_CapsTTL`; `TestActivateBreakGlass_UnsetMaxTTLFloorsToDefault`; `TestBreakGlass_ExpiredGrantDeniesAuthorization`; `TestActivateBreakGlass_RejectsConcurrentReactivation`; `TestCreateBreakGlassActivation_ConcurrentRaceYieldsExactlyOneWinner`; `TestBreakGlassActiveIndex_CreatedByMigration` | A member can re-activate once the previous grant has expired or been revoked; the number of activations is bounded only by the review process (BG-7), not by a rate. |
| BG-5 | Tampering | Activation and revoke interleave so the emergency role stays live while the record reads `revoked` (or the record exists with no role). | Record insert and role grant run in one transaction under the same named lock the revoke takes; revoke removes the role and marks the record in one transaction under that lock, and an "already gone" role removal is not an error. | `internal/core/break_glass.go` `activateBreakGlassLocked`, `RevokeBreakGlassActivationAtomic`; `TestActivateBreakGlass_InsertAndGrantShareTheRevokeLock`; `TestRevokeBreakGlass_StillTakesTheSameLock`; `TestActivateBreakGlass_FailedGrantLeavesNoActivationRecord`; `TestCTAReview_BreakGlassActivate_vs_Revoke_CrossReplicaPostgres` (Postgres-gated); `TestRevokeBreakGlassActivationAtomic_PostgresTransaction_GenuineFailureRollsBackBoth` (Postgres-gated) | None identified on the grant / record pair. |
| BG-6 | Repudiation | **Audit.** An activation is not recorded, or the record is lost when the audit subsystem is failing at the moment of activation. | Two records exist: the `BreakGlassActivation` row (durable, committed with the grant, queryable per project) and the `break_glass.activated` audit event (hash-chained, written after the commit). An audit write failure is logged at error level with a `SECURITY:` prefix (`logAuditEmitFailure`) and does not roll the grant back (code behaviour; no break-glass-specific test asserts it, see the GAP). | `internal/core/break_glass.go` `ActivateBreakGlass`; `TestActivateBreakGlass_GrantsTimeBoundRole`; `TestActivateBreakGlass_StillAuditedWithGlobalAdminAlert` | **GAP TM2-GAP-3 (fix owned by BREAKGLASS-OWED-1, queued).** On `main` the audit event is written after the commit and its failure is not durable: if the audit append fails, the grant stays live with an activation row, a log line and no audit event, and nothing backfills it. AUDIT-TX-2 (#3367, open) and BREAKGLASS-OWED-1 change this (owed-audit record in the same transaction, degraded short-expiry mode, backfill); the owed-audit mechanism on `main` today (`internal/core/audit_owed.go`) covers plain secret suspend only. No test on `main` asserts the failure-path behaviour for break-glass, so none is cited. Update this row when BREAKGLASS-OWED-1 merges. |
| BG-7 | Repudiation / elevation of privilege | The activator closes out their own activation, or a puppet identity does, so no independent person ever looks at it. | `ReviewBreakGlass` refuses: an unattributable reviewer (machine, local CLI), the activator, a still-active activation, a note under 10 or over 2000 characters, a second review. The review route requires `roles.assign` and is blocked while impersonating. Overdue reviews are a posture deviation (`emergency-access` control goes to Gap), a periodic `SECURITY:` log line, one `break_glass.review_overdue` audit event per pass and a repeated notification to the project's admins. Activation is never blocked by a pending review (decided). | `internal/core/break_glass.go` `ReviewBreakGlass`, `RunBreakGlassReviewReminder`; `TestReviewBreakGlass_RefusesSelfReview`; `TestReviewBreakGlass_RefusesUnattributableReviewer`; `TestReviewBreakGlass_RefusesWhileStillActive`; `TestBreakGlassActivation_HasNoApproverField`; `TestImpersonation_BreakGlassReviewBlocked`; `TestRunBreakGlassReviewReminder_WarnsAndAuditsOncePerPass`; `TestAccumulateBreakGlassPosture_CountsUnreviewedPastTheWindow` | **Single-administrator deployments cannot have an independent review**: the posture report flags it (`TestAccumulateBreakGlassPosture_SingleAdminDeploymentFlagsIndependentReviewImpossible`) but cannot fix it. A reviewer who is a colluding second person is out of scope. |
| BG-8 | Spoofing / elevation of privilege | **Notification recipients.** The alert reaches nobody, the wrong people, or is lost silently. | `projectAdminRecipients` resolves project approver-role members **and** install-wide admins (user grants and group-inherited grants, de-duplicated, active accounts only). A failure to list members is returned and logged as `SECURITY:`; recipients that were resolved are still notified; a panic in the fan-out is recovered and audited as `break_glass.notify_panicked`. A notification failure never fails the activation. | `internal/core/notifications.go` `projectAdminRecipients`; `TestActivateBreakGlass_NotifiesGlobalAdmin`; `TestActivateBreakGlass_NotifiesGroupInheritedGlobalAdmin`; `TestActivateBreakGlass_DedupesAdminWithBothScopes`; `TestNotifyBreakGlassAdmins_PanicInNotifyFanOut_StillReturnsNilAndAudits`; `TestNotifierRecipients_NoDirectProjectMemberFanOut` | Delivery is best-effort: a notifier outage is a detection-latency gap, not a control failure, because the grant is audited and listed regardless (subject to BG-6). A project with no approver-role member and no install-wide admin alerts nobody. |
| BG-9 | Denial of service / tampering | Revoking an emergency grant strips the project of its last administrator, or a TTL-lapsed row blocks a legitimate revoke. | `RevokeBreakGlassActivationAtomic` runs the last-project-admin guard and the removal under the same named lock; revoke is refused only for an already-revoked row, never because of a clock-derived `expired` state; a genuine role-removal failure aborts the revoke rather than recording it as done. | `internal/core/break_glass.go` `RevokeBreakGlass`; `TestRevokeBreakGlass_NotBlockedByExpiredState`; `TestRevokeBreakGlass_GenuineRoleRemovalFailureAbortsRevoke`; `TestRevokeBreakGlass_ConcurrentRevokesOnlyOneWins`; `TestConcurrency_RevokeBreakGlassActivationAtomic_TOCTOU_Deterministic` | None identified. |
| BG-10 | Elevation of privilege | **PAT-restricted callers.** A PAT created with a permission or project restriction activates break-glass and so escalates its owner beyond the restriction. | `ActivateBreakGlass` checks the PAT restriction first, before configuration or membership, and refuses with `ErrRestrictedPATCannotBreakGlass` on any restricted PAT. Listing is also filtered: a restricted PAT sees its owner's own rows only when it could have `roles.read` on the project. | `internal/core/break_glass.go` `ActivateBreakGlass`; `TestPATRestriction_RestrictedPATCannotActivateBreakGlass`; `TestListBreakGlassActivationsForCaller_PATRestriction`; `TestBreakGlassOwnList_PATRestriction` | None identified. An unrestricted PAT can activate on behalf of its owner, as the owner's session can. |
| BG-11 | Elevation of privilege | An admin impersonating a user activates break-glass, minting a durable grant attributed to the impersonated user that outlives the impersonation. | `BlockWhenImpersonating` on both the activation and the review routes. | `server/http/router.go` break-glass routes; `TestImpersonation_BreakGlassBlocked`; `TestImpersonation_BreakGlassReviewBlocked` | None identified. |
| BG-12 | Information disclosure | A member listing their own activations learns who reviewed or revoked them, the reviewer's note, or other members' activations. | `ListBreakGlassActivationsForCaller` returns the whole project only to a `roles.read` holder; otherwise only the caller's own rows with the reviewer, note and revoker identities stripped (`redactBreakGlassForOwnView`); a non-member, a machine without `roles.read`, and an authorization lookup failure all get the same refusal. | `internal/core/break_glass.go` `ListBreakGlassActivationsForCaller`; `TestListBreakGlassActivationsForCaller_OwnViewRedactsAdminFields`; `TestBreakGlassOwnView_RedactsEveryAdminField`; `TestBreakGlassOwnList_CrossProjectAndOutsiders` | None identified. |

## 4. Residual risks specific to this component

- **The audit event can be lost on `main` (BG-6).** The grant is
  recorded in the `BreakGlassActivation` table either way, so the
  activation is never invisible, but the hash-chained audit event is
  best-effort until BREAKGLASS-OWED-1 merges. If the audit database is
  the thing that is broken, the offline `recover-admin` path (AUTH-9) is
  the documented last resort.
- **One person can activate and the review is after the fact.** This is
  the ADR-112 design (an emergency path that needs a second person fails
  exactly when it is needed). A deployment with one administrator has no
  independent reviewer; the posture report says so.
- **Containment is checked at activation, not continuously (BG-3).**
- System-wide residuals (the authentication cache window, clock skew
  across replicas for `expires_at`) are not re-derived; see
  [authentication.md](authentication.md) and [ha-consistency.md](ha-consistency.md).
