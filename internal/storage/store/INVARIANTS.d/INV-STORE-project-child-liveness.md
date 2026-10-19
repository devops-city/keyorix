- **INV-STORE-project-child-liveness** Every writer that can make a row LIVE in one of the
  three tables `deleteProjectCascade` sweeps does its write and a project re-check inside ONE
  transaction, write first, and rolls back when the project is gone. This is
  `INV-STORE-21`'s child/parent rule (see `INVARIANTS.md`) applied to the project as parent;
  the mechanism, its ordering requirement, and the precondition that the delete side
  row-locks the parent BEFORE sweeping are all stated there and not repeated. What is
  specific to the project: the re-check is reachable from `internal/core` through
  `Storage.LockLiveProject`, so a core-layer writer already inside `WithTransaction` can
  apply it without the store growing a bespoke combined method; `LockLiveProject` is a thin
  specialisation of `lockLiveParent` and must stay one (a plain unlocked re-read answers the
  same question and serializes against nothing).
  **The six writers, and how that list was derived rather than asserted**: the cascade
  sweeps `secret_nodes`, `environments`, and `dynamic_secret_configs`. For `secret_nodes`:
  `core.CreateSecret`, `core.CreateFolder`, `LocalStorage.RestoreSecret` (there is no
  `RestoreFolder` — a folder is a `SecretNode` and is restored through `RestoreSecret`), and
  `core.ResumeSecret` (#2794: `DeleteEnvironment` counts only ACTIVE secrets, so a suspended
  one is deletable-around, and resuming it afterwards made it live inside a deleted
  environment; `ResumeSecret` takes `withEnvironmentSecretGuard` and does its status write and
  a `LockLiveProject` re-read in one transaction, pg-gated guard
  `internal/core/cta_review_resume_secret_postgres_test.go`). For
  `environments`: `core.CreateEnvironment` and `LocalStorage.RestoreEnvironment`;
  `seedProjectEnvironment` is excluded because it runs inside the transaction that just
  created the project, so no deleted-parent window exists. `dynamic_secret_configs` is
  excluded **deliberately**: the cascade DISABLES rather than deletes, and
  `IssueLease`/`RenewLease` refuse against a disabled config, so a config created in the
  window is inert rather than live under a dead parent — if the cascade ever starts
  soft-deleting them, `CreateDynamicSecretConfig` joins this list.
  Why: #2702/#2710/#2711/#2712 — all four serialized only against a concurrent
  `DeleteEnvironment` (the `EnvironmentSecretGuardLockKey` named lock plus an in-lock
  existence check) and `deleteProjectCascade` takes no such named lock, so the legitimate
  order "cascade locks the project, sweeps the children that exist, commits; the writer then
  writes anyway" left a live child under a deleted project. Reachable, not merely untidy:
  `GetSecret` and `AuthorizeSecret` do not check project liveness, so a global-scope role or
  an ACL grant still reaches the value, and the purge only ever collects soft-deleted rows,
  so the orphan outlives the project purge. Same end state as #2656, which fixed
  `RestoreEnvironment` alone.
  Guard: pg-gated, two replicas —
  `internal/core/concurrency_child_under_deleted_project_postgres_test.go`
  (`TestCTAReview_CreateSecret_vs_DeleteProject_CrossReplicaPostgres`,
  `_CreateFolder_`, `_CreateEnvironment_`, `_RestoreSecret_`) — each asserts the count of
  live children under the deleted project, not the writer's returned error, because the
  writer may legitimately fail OR be swept; what it may not do is leave a live child.
  Structural, default-ci: `internal/core/guards/project_child_liveness_guard_test.go`
  (`TestProjectChildWrites_RecheckProjectLivenessInATransaction`, with the derivation above
  written into the list it iterates, and `TestLockLiveProject_GoesThroughLockLiveParent`).
  **Not covered**: the opposite interleaving, where the writer's `FOR SHARE` lands first and
  the cascade blocks on it. `lockLiveParent`'s doc argues that order is safe; the
  `beforeA` hook these tests use can only produce the order that caused the bug.
  `RestoreProject` racing a re-issued `DeleteProject` is a different shape (the cascade's
  `FOR UPDATE` matches nothing once the project row is already deleted) and is #2723/#2724,
  still open.
