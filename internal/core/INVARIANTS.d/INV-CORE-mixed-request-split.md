- **INV-CORE-mixed-request-split** A request that narrows access AND, in the same call, widens it
  is applied as two commits, narrowing first (`audit_split.go`; Andrei 2026-10-20, ask
  3482-mixed-request-rule (a)). Commit 1 holds only the narrowing part and runs through
  `runOwedAuditMutation`: never blocked by the audit log, its row owed
  (INV-CORE-revocation-audit-owed), settled after the auth-cache eviction and after any named
  lock. Commit 2 holds the rest and is fail closed (`commitSplitRemainder` →
  `withAuditedMutation`, INV-CORE-security-mutation-audit-same-tx). Each part's direction is
  decided against the row read under the call's lock, never from the request alone, and no
  mixed request is rejected up front. Sites: `UpdateUser` (deactivate + username/email, decided
  on `LockUserForUpdate`), `UpdateSCIMUser` (active=false of an active user + email change, read
  under `lastAdminGuardLockKey` + `accountStateMu`), `PatchSCIMGroup` / `ReplaceSCIMGroup`
  (removals of current members, read under the guard locks, + adds or a rename),
  `UpdateProject` (MFA requirement on + rename/description, `updateProjectSplit`, decided on the
  row read in commit 1), `ReissueOneTimePassword` (account restricted + sessions ended, then the
  credential), `IssueMachineToken` with `ReplaceCredentialID` (`rotateMachineToken`: the old
  credential revoked and evicted, then the new one issued; ask
  perf-cred-lookup-1-rotation-audit-gated (b)), `UpdateRole` (permissions removed + added: the
  removals alone, then the description and the additions, decided on the permission set read in
  each transaction), `UpdateSharePermission` (a lower permission + a later or cleared expiry, or
  the reverse: the narrower value of each part, then the requested share, decided on
  `LockShareRecordForUpdate`; MERGE-FIX-3482K, ask 3482-mixed-update-role-share (a)). If commit 2 fails, commit 1 stays and the call returns `*PartialMutationError`
  (`errors.Is` `ErrMutationPartiallyApplied`; it unwraps to the cause), which the transports
  answer with HTTP 503 (error `MutationPartiallyApplied`, `details` {code
  `mutation_partially_applied`, revocation_applied true, remainder_applied false, applied,
  not_applied, retry_safe true}), SCIM 503 (RFC 7644 error schema plus the
  `urn:keyorix:params:scim:api:messages:2.0:PartialMutation` extension) or gRPC Unavailable
  (`google.rpc.ErrorInfo` reason `MutationPartiallyApplied`, domain `keyorix.audit`). A retry of
  the same request is safe: commit 1 is idempotent. The one retry that cannot complete by itself
  is MFA-on + rename by an actor without a second factor: the new requirement gates the actor
  (`ProjectMFARequired`) and the refused retry changes nothing. If BOTH the owed record and the
  append of commit 1's row fail, the narrowing still applies and the row is the loud "NOT queued
  for backfill" gap: a violation, never accepted as complete (Andrei 2026-10-20).
  Why: a mixed request used to fail closed as a whole, so an audit outage rolled its revocation
  back (REVIEW-3482 F1); owing the whole call instead could commit a widening with no row.
  Guard: `internal/core` `TestMixedRequestSplit_NarrowingNeverBlockedRemainderFailsClosed` (11 mixed requests
  x success / audit outage + backfill + retry / commit-2 append error, effect-then-error, panic /
  crash after commit 1 / owed record refused / record AND append refused, SQLite and PostgreSQL;
  every case reads the database), `TestMixedRequestSplit_RetryAfterPartialIsIdempotent`,
  `TestSecurityMutationAudit_UpdateRole_ByDirection` / `_UpdateSharePermission_ByDirection`
  (pure narrowing owed, pure widening fail closed, mixed partial);
  `server/faultops` `TestOwedAuditSplit_SweepEverySplitOp` (the same sites over the real HTTP,
  SCIM and gRPC stack, LogAuditEvent#1..n, pinned `owedAuditSplitExpectedOwedTypes`),
  `TestOwedAuditSplit_Calibration` (red/green of `owedAuditSplitVerdict`),
  `TestRoleEditorUpdate_AuditFailure_ByDirection`, `TestShareUpdate_AuditFailure_ByDirection`.
  Not covered: no static guard detects a new mixed request that is not split. The share
  scenarios' expiry is invisible to the faultops state comparison (every `time.Time` is
  excluded); there the second commit is told apart by its row, and the core tests read the expiry.
