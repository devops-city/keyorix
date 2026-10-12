- **INV-CORE-break-glass-activate-serialized-with-revoke** `ActivateBreakGlass`'s activation
  insert and its emergency-role grant happen inside ONE acquisition of
  `projectAdminGuardLockKey(projectID)` — the same key `RevokeBreakGlassActivationAtomic`
  takes — so the two can never interleave. This is the activation-side counterpart to
  `INV-CORE-26`, which covers the revoke's own atomicity; both are needed, and neither
  implies the other. Why: #2722 — the two writes were separate storage operations with no
  shared transaction, and the revoke deliberately TOLERATES `ErrRoleNotAssigned` ("already
  gone — proceed to reconcile the record"), so a revoke landing between them removed
  nothing, set the record to `revoked`, audited success, and the activation then granted the
  role anyway. End state: a self-granted, SoD-bypassing role live for its full TTL while the
  record every reviewer and the UI reads says revoked, which nobody revisits because the
  admin's revoke reported success; `ReconcileExpired` only touches `active` rows so it never
  cleans it up, and the freed partial-unique-index slot allows a second activation.
  **Why not `lockLiveParent`**, which is how every other fix in this class is built and what
  #2722 itself suggested: `lockLiveParent` requires the delete side to row-lock the PARENT
  before touching the children (its own doc comment names that exclusion), and this revoke
  does the opposite — `tx.RemoveRole` runs BEFORE `tx.RevokeBreakGlassActivation` — so a
  `FOR SHARE` on the activation row is read only after the revoke has already looked for and
  not found the grant. The race would have survived that fix.
  **The precondition this rests on**: the revoke must keep taking this same key. If it stops,
  the two no longer exclude each other and nothing else goes red, so the precondition is
  guarded directly rather than assumed (`TestRevokeBreakGlass_StillTakesTheSameLock`).
  Lock-order safety: a single acquisition at `storage.NamedLockOrder` rank 3
  (`project-admin-guard`) with nothing nested inside — the grant (`tx.AssignRoleWithExpiry`)
  takes no named lock, deliberately.
  **Atomic (#3109)**: the insert and the grant are also ONE `WithTransaction`, so a failed
  grant rolls the record back with it — no `revoked` row behind an error, no `active` row
  without its role in between, no audit/notification before commit, and no stuck
  unique-index slot if a compensating write were to fail. Guard:
  `TestActivateBreakGlass_FailedGrantLeavesNoActivationRecord` and the one-transaction
  assertion in the structural test below.
  Guard: `break_glass_lock_guard_test.go`
  (`TestActivateBreakGlass_InsertAndGrantShareTheRevokeLock`, structural, default-ci — it
  asserts the two writes live in `activateBreakGlassLocked` AND that `ActivateBreakGlass`
  performs neither directly, so moving one back outside the callback is red even though the
  `WithNamedLock` call still exists; plus the precondition test above). Behavioural, pg-gated:
  `concurrency_break_glass_activate_vs_revoke_postgres_test.go`
  (`TestCTAReview_BreakGlassActivate_WaitsForTheRevokeLock_Postgres` for the mutual
  exclusion, and `TestCTAReview_BreakGlassActivate_vs_Revoke_CrossReplicaPostgres` for the
  end-state invariant).
  **Not covered**: the `ctaReview` `beforeA` hook cannot be used for this invariant at all —
  it runs replica B synchronously inside replica A's callback, so with A holding the lock B
  blocks inside A's own call stack and the test hangs instead of failing. That is why the
  concurrent test is probabilistic, and why it carries a floor requiring at least half its
  iterations to have produced a successfully-revoked activation.
