# Open-issue triage, 2026-10-17

Scope: every open issue numbered below #2910 (68 issues) plus the flake #2945, checked against
`main` @ `726861f36`. Four issues just above the line (#2914, #2923, #2925, #2934) were looked at on
the way and are in the table too, marked "(extra)". Nothing here was taken from an issue title: a
FIXED verdict names the test that proves it (found by grepping tests and `docs/security-closures.d/`
for the symbol), and a STILL REAL verdict was confirmed by running a reproducing test (the probes are
not committed; see "Probes" below). No production code was changed. #3413 merged after the check
and fixed #2431, #2868 and #2945; those three rows are updated to FIXED (re-checked on main).

## Verdicts

In scope (69 issues):

| Verdict | Count | Meaning |
|---|---|---|
| FIXED | 46 | Fixed on main; the proving test passes. Close the issue. 38 have a closure row (16 existed, 22 are added by this PR); 4 are proven by a JS/e2e test and cannot carry a Go row (#2450, #2552, #2782, #2823); 1 has a row in the ADR-conformance ledger (#2424); 3 (#2431, #2868, #2945) are proven by tests that came with #3413. |
| STILL REAL | 14 | Reproduced, or, where the gap is a missing guard, shown absent. Needs a fix. |
| DECISION | 8 | Needs a maintainer decision, or is a roadmap item rather than a defect. |
| STALE / NOT-A-BUG | 1 | Decided by design (#2880). |

Extras (#2914 STILL REAL, #2923 DECISION, #2925 FIXED, #2934 FIXED) are not counted above.

How the closure rows were checked: `scripts/check-closures.sh` over the whole ledger with a real
Postgres so pg-gated rows run instead of skipping. Every row passed except two that cannot pass
with a non-superuser database role, not because of a regression: `role-permission-cache-direct-sql-001`
(#3259) and `secret-node-cache-replication-role-001` (#3361) run `SET session_replication_role`, which
such a role is refused (`permission denied to set parameter "session_replication_role"`). They pass in
CI's superuser Postgres. The 24 fragments added here were verified on their own with the same
Postgres: `ok: 23 closure claim(s) verified` (the 24th, `triage-2839-...`, was run directly with
`go test` and passes).

## Table

Size: S under a day, M a few days, L needs a spec first. Model: the recommended model for the
follow-up work; "none" where the only step is closing the issue.

| Issue | Verdict | Evidence | Suggested next step | Size | Model |
|---|---|---|---|---|---|
| #2407 access-request approval partial commit | FIXED | row `access-request-approval-partial-commit-001` (`TestFinalizeAccessRequestApproval_ApprovalRecordFailureRevertsGrant`), passes | close | S | none |
| #2424 boot check that the key-file set is consistent | FIXED | `internal/keyfiles/consistency.go` `VerifyKeySetConsistency`, called from `server/main.go:2413`; conformance row `ADR-112-KEYFILE-SET-PARTIAL-REFUSES-BOOT`. The stronger manifest is #2900 | close | S | none |
| #2425 EnforceSessionLimit panic after login | FIXED | row `mfa-verify-enforcesessionlimit-panic-001` (`TestLogin_EnforceSessionLimitPanic_StillSucceeds`), passes | close | S | none |
| #2431 `fuzzutil.Guard` per-call goroutine + watchdog | FIXED | #3413: `Guard` runs `fn` on a pooled runner goroutine with a pooled timer (`internal/fuzzutil/guard.go`); `TestGuard_ReturnsWhenFnFinishes`, `TestGuard_ReportsHang`, `TestGuard_ReuseAfterSlowButInTimeCall`, `BenchmarkGuard` | close | S | none |
| #2433 NotificationChannel.URL stored unencrypted | FIXED | URL is AAD-bound ciphertext (`URLEnc`/`URLMeta`), startup backfill `MigrateNotificationChannelURLsToEncrypted`; `TestGetNotificationChannel_CrossRowCiphertextSwapRefused`, `TestNotificationChannelURL_EncryptionOffThenOn` pass. Fragment `triage-2433-...` | close | S | none |
| #2449 gRPC CreateUser project-count panic | FIXED | row `grpc-createuser-projectcounts-panic-001` (`TestCreateUser_ProjectCountsPanicDoesNotMaskSuccess`), passes | close | S | none |
| #2450 revealing a secret crashes the page (atob) | FIXED | `web/src/features/secrets/useSecretReveal.ts:19` no longer decodes a field the API never returns; `useSecretReveal.test.ts`, `services/__tests__/secrets.test.ts`, real-backend spec `web/e2e/real/secrets-crud.spec.ts` | close (JS proof, no Go closure row possible) | S | none |
| #2455 RestoreGroup admin-reinstate TOCTOU | FIXED | row `restoregroup-admin-reinstate-toctou-001` (`TestConcurrency_RestoreGroup_AdminGrantRace_CrossReplicaPostgres`), pg-gated, passes on Postgres | close | S | none |
| #2500 INV-CORE-34: no structural guard that best-effort post-commit calls recover a panic | STILL REAL | `internal/core/INVARIANTS.md:254-270` says "UNGUARDED as a class"; recovery exists only as per-site point fixes | AST sweep like `atomicity_guard_test.go`: every discarded/deferred post-commit call must run under `besteffort.Run` or be on a reviewed allowlist | M | Opus |
| #2506 INV-STORAGE-31: ADR-103 Postgres RLS has no implementation | DECISION | `internal/storage/INVARIANTS.md:287-293`: design only, zero `ROW LEVEL SECURITY` references | Maintainer: schedule or park ADR-103; this is a roadmap item, not a defect | L | Opus |
| #2507 INV-STORAGE-32: exported LocalStorage methods need a threaded `context.Context` | DECISION | same file, `:295-299`; prerequisite of #2506 | decide together with #2506; if ADR-103 is parked, close | L | Opus |
| #2541 purge legacy APIClient/APIToken rows and drop the models | DECISION | models still present (`internal/storage/models/models.go`, `all_models.go`); ADR-113 accepts the retirement and says "once verified empty" | Maintainer: when to run the verification and the drop (it is a destructive migration) | M | Opus |
| #2542 keyorix-migrate: no path for Vault policies/auth methods/tokens | DECISION | ADR-114 (Accepted) chose assisted mapping; `migrate/cmd/vaultplanaccess.go`, `vaultapplyaccess.go`, `migrate/internal/accessplan/` exist. The real-Vault equivalence check is an e2e that needs a real Vault and was not run | Maintainer: confirm which of the three "not supported" rows remain (Vault tokens are out of ADR-114's scope), then close or re-scope | M | Sonnet |
| #2552 TOTP enrolment 400s on `/auth/mfa/activate` | FIXED | `web/src/services/mfa.ts:36` sends `{code, password}`; `services/__tests__/mfa.test.ts:34-38`; `docs/demo/GOLDEN-PATH.md:383` lists it fixed. `scripts/e2e/journeys/journey16_golden_path_test.go:23` still calls it open (stale comment) | close; refresh the journey-16 comment | S | none |
| #2567 MFA verify: CreateSession error burns the TOTP code | FIXED | `TestVerifyMFALogin_MintFailureAfterConsume_FailsClosed` retries the same code after the fault clears. Fragment `triage-2567-...` | close | S | none |
| #2646 ShareSecret vs DeleteSecret | FIXED | row `CTA-PARENT-2646`, pg-gated, passes on Postgres | close | S | none |
| #2647 ShareSecretWithGroup vs DeleteSecret | FIXED | row `CTA-PARENT-2647`, pg-gated, passes | close | S | none |
| #2649 GrantSecretACL vs DeleteSecret | FIXED | row `CTA-PARENT-2649`, pg-gated, passes | close | S | none |
| #2652 IssueLease vs DeleteProject | FIXED | row `CTA-PARENT-2652`, pg-gated, passes | close | S | none |
| #2653 UpdateUser reverts a concurrent SuspendUser | FIXED | row `stale-user-profile-write-001` (+ `-003` column-scoped), passes | close | S | none |
| #2654 UpdateOwnProfile reverts a concurrent password change | FIXED | row `stale-user-profile-write-002`, pg-gated, passes | close | S | none |
| #2656 RestoreEnvironment vs DeleteProject | FIXED | row `CTA-PARENT-2656`, pg-gated, passes | close | S | none |
| #2677 core.DeleteUser persists a stale user row | STILL REAL | `internal/core/users.go:790` reads the user outside the lock, `:813` `tx.UpdateUser` is the full-row `Save` (`internal/storage/store/local_users.go:201`). Probe: a password change committed between the read and the write is reverted; the row ends with the OLD hash, so `RestoreUser` lets the old password back in. `docs/full-row-write-exempt.tsv` lists it UNSAFE-OPEN | write only the deactivation columns (`UpdateUserIfActiveStateMatches`-style conditional write) under the user row lock; remove the exempt row | S | Sonnet |
| #2685 declared WithNamedLock order enforced in test builds | FIXED | `internal/core/storage/named_lock_order.go`; `TestCheckNamedLockOrder`, `TestNamedLockOrder_EveryCallSiteKeyHasAFamily`. Fragment `triage-2685-...` | close | S | none |
| #2687 UpdateGroup stale Save | FIXED | `UpdateGroupFields` is conditional and column-scoped (`local_users.go:586`); `UpdateGroup` is gone. `TestCTAReview_UpdateGroup_vs_DeleteGroup_CrossReplicaPostgres` (row `stale-group-project-save-001`, #2697). Fragment `triage-2687-...` | close | S | none |
| #2688 UpdateProject stale Save | FIXED | `UpdateProjectFields` (`local_secrets.go:176`); `TestCTAReview_UpdateProject_vs_DeleteProject_CrossReplicaPostgres`, `..._vs_SetRequireMFA_...`. Fragment `triage-2688-...` | close | S | none |
| #2689 UpdateSecret stale Save / TransitionSecretStatus `Select("*")` | FIXED | `TestUpdateSecret_HasNoProductionCallerBeyond2668` (empty allowlist); `TransitionSecretStatus` writes `Status, SuspendClearSyncedCopies, UpdatedAt` only (`local_secrets.go:895-909`). Fragment `triage-2689-...` | close | S | none |
| #2690 ClassifyMachineToken stale Save | FIXED | `TestClassifyMachineToken_IsColumnScoped`, `TestCTAReview_ClassifyMachineToken_vs_RevokeMachineToken_CrossReplicaPostgres` (rows `classify-machine-token-un-revoke-*`, #2696). Fragment `triage-2690-...` | close | S | none |
| #2691 ClassifyDynamicSecretConfig stale Save | FIXED | `internal/core/dynamic_secrets.go:430` uses `SetDynamicSecretConfigClassification`; storage `UpdateDynamicSecretConfig` has no production caller. Row `dynamic-secret-kill-switch-revert-001` (#2698). Fragment `triage-2691-...`. `docs/full-row-write-exempt.tsv:39` still says UNSAFE-OPEN (stale row) | close; refresh the exempt row | S | none |
| #2692 BeginMFAEnrollment's late upsert replaces an activated TOTP secret | STILL REAL | `internal/core/mfa.go:101-116`: `MFAEnabled` is read at `:105`, then `UpsertMFASecret` (`local_mfa.go:17`, `OnConflict{UpdateAll}`) overwrites unconditionally. Probe: an `ActivateMFA` committed between the read and the upsert leaves `Activated=false` and a new seed; login verification does not look at `Activated`, and the new seed was returned to the enrolling caller | make the upsert conditional on "no activated row" (insert-or-replace-only-pending, or lock the user row and re-read `MFAEnabled`); add the cross-replica test | S | Sonnet |
| #2693 bring `docs/atomicity-exempt.tsv` under the exemption-review rule | DECISION | `internal/core/exempt_ledger_review_test.go:81` lists it as pending: "needs an independent review recorded in a sidecar" | someone other than the row authors reviews the rows (a maintainer or an independent reviewer); then drop it from the pending list | M | none (human review) |
| #2694 lock-order check does not cover in-process mutexes under named locks | STILL REAL | `internal/core/storage/named_lock_order.go:62` states "Not covered: locks other than WithNamedLock" | extend the order check (or a vet-style rule) to `sync.Mutex` fields taken inside `WithNamedLock` | M | Opus |
| #2699 resolveSSOUser's full-row UpdateUser resurrects a deleted user | FIXED | row `sso-first-federation-resurrect-001` (pg-gated, passes) and `-002` (`TestResolveSSOUser_ClaimIsColumnScopedAndReReads`) | close | S | none |
| #2701 PAT/session created during a concurrent suspend survives | FIXED | rows `credential-under-suspend-001..006`; `-001` pg-gated passes, `TestCredentialInsertsRecheckOwnerLiveness` passes | close | S | none |
| #2703 assorted lifecycle gaps (umbrella) | STILL REAL | of its 9 items: 3, 6, 9 are fixed (#2796/#2887, #2799, #2803); 7 (`revertFailedActivation`) restores both stamps now (`membership_lifecycle.go:539-540`); items 1, 2, 4, 5, 8 are open as #2794, #2795, #2797, #2798, #2801 | keep open as the tracker until those five land, or close it and rely on them | S | none |
| #2704 structural guard: no stale full-row write of a security-state model | FIXED | `TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels` and `_NoUnexemptedCallerOfFullRowWriter`. Fragment `triage-2704-...` | close | S | none |
| #2705 registry test: child insert re-checks its soft-deletable parent | FIXED | `TestChildParentLiveness_EveryChildInsertLocksItsParent` (+ `_EveryIDFieldClassified`, `_NoRawSQLInserts`). Fragment `triage-2705-...` | close | S | none |
| #2707 process guard: exemption rows reviewed by someone other than the author | FIXED | `TestExemptLedgers_EveryRowIndependentlyReviewed` with calibration and a pending list that cannot merge. Fragment `triage-2707-...` | close (the remaining pending ledger is #2693) | S | none |
| #2734 no isolated execution boundary for connector/rotation code | DECISION | `docs/security/threat-models/connectors.md`: scoping and SSRF guards exist, no process sandbox | Maintainer: is process-level isolation on the roadmap? design item, not a defect | L | Opus |
| #2747 WebAuthn login/passwordless: CreateSession failure burns the ceremony | DECISION | `internal/core/consume_first_fails_closed_test.go:170` pins consume-first on purpose; the issue itself asks for an explicit decision | Maintainer: accept "re-tap the passkey" as by design (recommended; close with the test as the record) or fund a transactional redesign | M | Opus |
| #2782 mfa-login.spec.ts setup flake (fixture password has no digit) | FIXED | `web/e2e/real/mfa-login.spec.ts:56-96` uses `compliantPassword`, with a test that 100s of generated passwords satisfy the policy | close | S | none |
| #2794 ResumeSecret reactivates a suspended secret inside a deleted environment | STILL REAL | `DeleteEnvironment` counts `status='active'` only (`local_secrets.go:523`); `ResumeSecret` (`internal/core/secret_suspend.go:346-372`) never checks the environment. Probe: suspend, delete the environment (succeeds), resume: the secret ends ACTIVE in a deleted environment | count suspended secrets in `DeleteEnvironment` (or refuse resume under a deleted environment, under the environment lock) | S | Sonnet |
| #2795 PurgeDeletedProjectsBefore leaves `machine_identity_roles` | STILL REAL | `local_purge.go:160-165` deletes `UserRole`/`GroupRole` only. Probe: the machine role row for the purged project remains; `GetMachineRoleIDsAt`'s `LEFT JOIN projects` reads the missing project as live (`local_machine_credentials.go:249-250`). Reachable only if a project id is reused (SQLite) | delete the project's (and its environments') machine roles in the purge; make the JOIN treat a missing project as dead | S | Sonnet |
| #2796 DeleteProjectIfEmpty counts without locking the project row | FIXED | `local_secrets.go:372` locks first. `TestConcurrency_DeleteProjectIfEmpty_LockFirstPreventsOrphanedDelete`, pg-gated, passes. Fragment `triage-2796-...` | close | S | none |
| #2797 DeleteSecret does not sweep approved secret-scoped AccessRequests | STILL REAL | `local_secrets.go:1010-1034` sweeps shares and ACLs only; `hasApprovedSecretAccessRequest` matches on state alone. Probe: an `approved` request with `secret_id` survives delete + restore | sweep (or terminally resolve) the secret's requests in the same transaction, in `DeleteSecret` and in `deleteProjectCascade`; family test over "every per-secret grant table" | S | Sonnet |
| #2798 deleteProjectCascade revokes ShareRecords but not SecretACLs | STILL REAL | `local_secrets.go:204-288`: the cascade revokes shares (`:243`) and nothing else per secret. Probe: an ACL grant survives `DeleteProject` + `RestoreProject` | revoke `SecretACL` for the project's secrets in the cascade (mirror `DeleteSecret`); same family test as #2797 | S | Sonnet |
| #2799 DeprovisionSCIMUser revokes sessions but not PATs | FIXED | fixed by #2855; `TestDeprovisionSCIMUser_RevokesSessionAndPAT`, `_RestoreDoesNotHandBackPATs` (rows `scim-deprovision-pat-revoke-*`, issue column holds the PR number). Fragment `triage-2799-...` | close | S | none |
| #2801 CreateShareRecord fallback drops the caller's ExpiresAt | STILL REAL | `local_sharing.go:138-140`: the unique-violation fallback sets `Permission` and `UpdatedAt` only. Probe: a 1h share that loses the create race comes back permanent | assign `ExpiresAt` in the fallback; better, one shared apply-fields helper for both paths (and see #2802) | S | Sonnet |
| #2802 CreateShareRecord still uses the full-row `Save` upsert | STILL REAL | `local_sharing.go:115` and `:140` `tx.Save(&existing)`. Probe: a revoke committed between the read and the `Save` is undone (same row id live again, with the re-share's permission) | replace both `Save`s with the conditional column-scoped write `UpdateShareRecord` uses, failing closed when it matches no row; combine with #2801 | S | Sonnet |
| #2803 RevertAccessReviewItemClaim has no campaign-is-open condition | FIXED | the revoke is one transaction now (`ar-revoke-atomic-001..004`, #2676); `RevertAccessReviewItemClaim` has no production caller. Fragment `triage-2803-...` | close; delete the dead storage method (S cleanup) | S | none |
| #2807 WebAuthn finish: post-verdict GetUserRoles error leaves a grant behind | FIXED | `TestFinishWebAuthnLogin_IdentityReadFailureLeavesNoSessionOrGrant` (#2841). The slot kept after a post-verdict fault is the decided behaviour of #2880. Fragment `triage-2807-...` | close | S | none |
| #2812 migrate-from-user: SetAccountState error reports failure with the identity kept | FIXED | `MigrateUserToMachine` is one transaction (`TestMigrateUserToMachine_FaultedSuspendRollsBackTheIdentity`), so the partial state is gone. The best-effort entry `post_projects_id_machine_identities_migrate_from_user_setaccountstate` in `server/faultops` is dead. Fragment `triage-2812-...` | close; remove the dead faultops entry | S | none |
| #2823 secrets-crud.spec.ts recycle-bin step flaky | FIXED | `web/e2e/real/secrets-crud.spec.ts:186-192` targets the heading by role (#2788). The residual question the issue raises (React Query `staleTime` on the settings query) was never filed | close; file the staleTime question only if the flake recurs | S | none |
| #2835 failed keep-session lookup silently widens the purge | FIXED | row `keep-session-lookup-silent-widen-001`, passes | close | S | none |
| #2839 SAML ACS leaves a JIT user + roles on a mintSession failure | FIXED | The maintainer's decision (class C) is implemented: no session is minted over a failed reconcile (#2903, #2907), oracle rule `TestSSOClassCRule_*` (`server/faultops/zz_sso_class_c_oracle_test.go`). Fragment `triage-2839-...` | close | S | none |
| #2842 oracle (a) flags RotateSecret's non-transactional version write | FIXED | AUDIT-MUTATION-TX-1: a rotation with no backend, and every rollback, is one transaction; the tolerance was removed. `TestSecretMutationAudit_RowExistsIffMutationCommitted`. Fragment `triage-2842-...` | close | S | none |
| #2844 FuzzStorageFaultOperations: webauthn/register/finish DeleteSessionsForUserExcept | FIXED | rows `KEEP-SESSION-LOOKUP-PANIC-2844`, `LOGIN-UNDELIVERED-SESSION-2844` and `keep-session-lookup-silent-widen-001`, all pass; the named finding is closed. The issue's second half (an ongoing backlog of fresh fuzz findings) is a moving target, not one defect | close; file fresh fuzz findings as their own issues | S | none |
| #2854 admin migrate runs migrations without `cfg.Validate()` | STILL REAL | `server/admin/admin.go:107-131` `loadConfig` never validates (`server/main.go:181` does); `server/admin/migrate.go:44` opens storage, which migrates. Probe: a postgres `ssl_mode: verify-full` config with no root cert is rejected by `Validate()` and accepted by `loadConfig()` | call `cfg.Validate()` in `loadConfig` (check which admin commands must tolerate an invalid config, e.g. `validate` itself) | S | Sonnet |
| #2857 global-admin holder counts disagree on `{ProjectID:0, EnvironmentID:X}` | STILL REAL | `ListProjectRoleAssignments` filters `project_id` only (`local_rbac.go:463-471`); `ListGlobalAdminAssignmentsForUpdate` also requires `environment_id = 0` (`:541`); documented in `internal/core/INVARIANTS.md:113`. Probe: a `{0, env 3}` grant is returned. Reachability through an API path is still unestablished | add `environment_id = 0` for the global call path, plus a test that the assignment paths reject `{0, X}`; low priority | S | Sonnet |
| #2868 openapiDrift allow-exemptions silence every check on a path | FIXED | #3413: exemptions are keyed on `allowKey(path, kind)` (`<path>#<kind>`) and `used` is tracked per pair (`web/src/types/__tests__/openapiDriftLib.ts`), so an exemption silences exactly the message it names; covered in `openapiDrift.engine.test.ts` | close | S | none |
| #2873 RotateSecret commits a version before the row update | FIXED | for a secret with no rotation backend the version, timestamp and audit row are one transaction (`internal/core/secrets.go` `rotateSecret`, `oneTx`); a backend-bound rotation stays two-step by design (documented there). New test `TestRotateSecret_ConcurrentDelete_LeavesNoOrphanVersion` (committed here; red with `oneTx` forced false, green on main). Fragment `triage-2873-...` | close | S | none |
| #2879 WebAuthn finish: PANIC keeps a per-IP slot | FIXED | `TestFinishWebAuthnLogin_PanicInsideCore_ReleasesTheSlotAndRePanicsUnchanged`, `TestFinishWebAuthnLogin_PanicKeepsTheSlotOnlyAfterTheVerdict`. Fragment `triage-2879-...` | close | S | none |
| #2880 WebAuthn finish: should a post-assertion storage fault consume a slot? | STALE / NOT-A-BUG | decided: "auth owner's decision: a post-verdict storage fault keeps the slot" (`server/faultops/oracle_a_by_design_entry_post_auth_webauthn_login_finish_{createsession,getuserroles}_test.go`), pinned by `TestFinishWebAuthnLogin_PanicKeepsTheSlotOnlyAfterTheVerdict` | close with the decision record | S | none |
| #2887 DeleteProjectIfEmpty counts secrets before the project lock | FIXED | fixed by `eb15ff85`; row `delete-project-if-empty-lock-order-001` passes on Postgres | close | S | none |
| #2888 login reveals a correct password during DB faults | FIXED | all four listed sites: `handlers/auth.go:236-257` answers the wrong-credential response and counts toward lockout; `TestLogin_CreateMFAChallengeFaultCostsTheSameAsAWrongPassword`, `TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode`, `TestReauthEndpoints_PreVerdictStorageFaultIsIdenticalToAWrongCode`. Fragment `triage-2888-...` | close | S | none |
| #2892 ADR-115: fold #2628's improvements into an amendment | DECISION | ADR-115 is `Parked (2026-10-13)`; the issue itself says "after demo" | Maintainer: leave parked, or schedule after the demo | S | Sonnet |
| #2895 14 insecure settings that cannot be renamed mechanically | FIXED | all 14 are rows of `config.InsecureSettingsRegistry`; `TestInsecureSettingsRegistry_EveryIssue2895RowIsRegistered`. Fragment `triage-2895-...` | close | S | none |
| #2900 key-set manifest (generation id + per-file hash) | STILL REAL | `internal/keyfiles/consistency.go:20-43`: only the presence check and a 24h mtime heuristic exist; the file says the real fix is #2900 | spec first (manifest format, atomic write, boot verification, upgrade path), then implement | L | Opus |
| #2914 (extra) posture: warn when the only administrator is SSO-managed | STILL REAL | no SSO-managed check in `server/admin/posture.go` or `internal/core/admin_posture.go` | add a posture finding (counted) in `collectAdminMFAPosture`'s holder resolution | S | Sonnet |
| #2923 (extra) ADR-112: when does the `require_mfa` upgrade grace period end | DECISION | `server/admin/posture.go:529` calls it out as untracked; product decision | Maintainer: define the end condition (recommended: first admin enrolment, or N days) | M | Opus |
| #2925 (extra) posture: a deprecated name is labelled shipped-default | FIXED | `config.ExplicitlySetPaths` records the current name for a deprecated alias the file writes; `TestCollectInsecureSettingsPosture_InEffectSettingIsADeviation` runs both spellings and passes. Fragment `triage-2925-...` | close | S | none |
| #2934 (extra) SAML ACS oracle false positive + SSO sessions record RemoteAddr | FIXED | both halves: `handlers/saml.go:80`, `sso.go:138` pass `clientIP(r)` (`TestCompleteSAML_SessionRecordsCanonicalClientIP`); the oracle half no longer reproduces (the fixture subject is `fuzz-saml-user`; with `fullOracle: true` for the SAML case `TestPostCommitDiscardedWritePanic_IsNotReportedAsFailure` passes). Fragment `triage-2934-...` | close; flip the stale `fullOracle` flag in `besteffort_discarded_write_panic_test.go` (S) | S | none |
| #2945 auth interceptor tests fail under `-count>1` | FIXED | #3413: `isolateGRPCAuthFailureLimiter` (`server/grpc/interceptors/auth_test.go`) gives each test its own per-IP failed-auth limiter and restores the production one in cleanup; no assertion was loosened. Before the fix, `-count=20` gave 217 failures of 3300 (the shared throttle answered ResourceExhausted instead of Unauthenticated) | close | S | none |

## Close these

FIXED, proven by a passing test: 2407 2424 2425 2431 2433 2449 2455 2567 2646 2647 2649 2652 2653 2654
2656 2685 2687 2688 2689 2690 2691 2699 2701 2704 2705 2707 2796 2799 2803 2807 2812 2835 2839 2842
2844 2868 2873 2879 2887 2888 2895 2925 2934 2945.
FIXED, proven by a JS/e2e test (no Go closure row possible): 2450 2552 2782 2823.
STALE / NOT-A-BUG: 2880.
Needs a maintainer decision: 2747 (recommend close as by design).

## STILL REAL, ranked

In priority order: #2692, #2802, #2677, #2798, #2797, #2794, #2854, #2795, #2801, #2857, then backlog
items #2500, #2694, #2900 and #2914. #2703 stays open as the tracker for #2794/#2795/#2797/#2798/#2801.

## Housekeeping found on the way

- `docs/full-row-write-exempt.tsv` rows for `UpdateDynamicSecretConfig` (#2691), `UpdateSecret` (#2689)
  and the `UpdateUser` row's #2699 half are stale: those are fixed. Only #2677 and #2692 remain
  UNSAFE-OPEN. (Not edited here: a guard test reads that file and its owner should refresh it.)
- `RevertAccessReviewItemClaim` is dead code (no production caller); delete it with its interface entry.
- `server/faultops` entry `post_projects_id_machine_identities_migrate_from_user_setaccountstate` is dead
  after the atomic `MigrateUserToMachine`.
- `scripts/e2e/journeys/journey16_golden_path_test.go:23` still calls #2552 open.
- `besteffort_discarded_write_panic_test.go` keeps `fullOracle` off for the SAML case for a reason that
  no longer holds.

## Probes

The reproducing tests for the STILL REAL rows were run against main and are not committed, so those
verdicts cannot be re-run from this repository alone. Each probe asserted the CORRECT behaviour, so a
failure was the open bug. The "Evidence" column names the code location and the observed behaviour; a
fix PR for any of these rows should add its own regression test.
