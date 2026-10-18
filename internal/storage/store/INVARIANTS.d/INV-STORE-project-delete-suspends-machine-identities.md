- **INV-STORE-project-delete-suspends-machine-identities** A project soft-delete leaves no
  ACTIVE machine identity whose only live roles were in that project, and a project restore
  re-activates exactly the identities that delete suspended. "Belongs to the project" is
  the home project or a `machine_identity_roles` row there; "a live role elsewhere" is a
  role at project 0 or in another project that exists and is not soft-deleted (a role in an
  already-deleted project does not keep an identity alive). The suspension
  (`SuspendMachineIdentitiesForDeletedProject`) runs in the cascade's transaction, after
  `DeleteProject`/`DeleteProjectIfEmpty`. It stamps `cascade_suspended_project_id` and
  `cascade_suspended_at`, and sets `updated_at` to the project's `deleted_at`, copied by the
  UPDATE itself (never round-tripped through Go). The re-activation
  (`ReactivateMachineIdentitiesForRestoredProject`) runs in the restore's transaction,
  BEFORE `RestoreProject` clears `deleted_at`, and requires all of: suspended, marker naming
  this project, `cascade_suspended_at` equal to the project's current `deleted_at`, and
  `updated_at` still equal to it. Every core transition clears the marker
  (`transitionMachineInTx`); any other write moves `updated_at`, which also covers an
  epoch-3 binary that does not know the columns. Both methods row-lock the project first,
  unscoped, then the identities they change (Postgres `FOR UPDATE`; SQLite's
  `_txlock=immediate` serializes the transaction), so the rows they return, and that core
  audits in the same transaction, are the rows they wrote.
  Why: #3433 (AUTHZ-WALKS-HTTP-1's dead-credential walk), a machine token of a soft-deleted
  project kept authenticating, cold and warm; decision 2026-10-17 option (a).
  Guard: `internal/core/project_delete_machine_suspend_test.go`
  (`TestDeleteProject_SuspendsMachineIdentitiesHeldOnlyThere`, ten identity cases plus a
  bystander project's restore and a second round trip; `_NonForce_SuspendsOnlyWhenDeleted`;
  `_MachineSuspendStepIsAtomicWithTheCascade`; SQLite always, Postgres when
  `KEYORIX_TEST_PG_DSN` is set), and route-wide
  `server/http/dead_credentials_walk_test.go` (`machine_token_project_deleted`, cold and
  warm on a replica with no cache invalidator). Mutation-checked: dropping the `updated_at`
  condition, the transition's marker clear, or the "live role elsewhere" clause each turns
  the core test red.
  Not covered: two projects deleted with the same stored `deleted_at` (the project-id match
  in the marker is the guard there, with no test); writers that make a machine identity
  active, or mint it a token, under an already-deleted project (`CreateMachineIdentity`,
  `TransitionMachineIdentity` to active, `IssueMachineToken`): they do not re-check project
  liveness.
