- **INV-CORE-no-outer-storage-in-transaction-closure** A transaction closure uses only its own `tx`
  handle. It never reaches the receiver's outer storage handle (`c.storage`) and never calls an
  audit, log or notify helper that writes through it (`c.writeAudit*`, `c.Log<Upper>*`,
  `c.notify*`, `c.emitAudit*`, `c.auditNow()`). On SQLite the open transaction holds the single
  write gate, so such a call is a second writer queued behind its own caller: a self-deadlock until
  the gate's bounded wait gives up, after which the audit row is silently lost. On Postgres it takes
  a second pool connection and is not rolled back with the transaction. A result that must be
  reported is recorded inside the closure and written AFTER the commit (`UpdateUser`'s deactivation
  records the PAT/session cleanup errors in the closure and writes
  `user.deactivation_cleanup_failed` once the transaction has committed; the deactivation itself
  stays successful). The `...On` helpers (`writeAuditEventFullOn`, `emitAuditOn`, ...) are the
  correct in-transaction form and are fine with `auditInto(tx, sink)`; `auditNow()` is the outer
  target and is reported wherever it appears in a closure.
  Why: DEADLOCK-SHAPE-1, found by AUDIT-TX-2. `TestAtomicityGuard_TransactionEscape` (INV-CORE-36)
  only saw the literal `c.storage.X(...)` form, not `c.writeAuditEventFailed(...)`, which writes
  through `c.storage` one call deeper.
  Guard: `guards/tx_closure_outer_storage_guard_test.go` (`TestNoOuterStorageInTransactionClosure`, an AST
  scan of every non-test file in `internal/core` with an allowlist whose entries each carry a reason
  and fail the test once stale; `TestTxClosureGuard_SelfTest`, which plants each violation form and
  each corrected form). Behaviour: `update_user_deactivation_cleanup_tx_test.go`
  (`TestUpdateUser_DeactivationCleanupFailure_AuditedAfterCommit`, a write-gated SQLite store built
  through the storage factory plus faultstorage on `RevokeAllPersonalAccessTokensForUser` and
  `DeleteSessionsForUserExcept`; Postgres leg pg-gated).
  Closure recognition (the idioms the guard knows): a function literal passed as the last argument
  of any `<x>.WithTransaction` call, and ANY function literal whose first parameter is typed
  `storage.Storage` (this also covers `commitOwingAudit`'s `effect` and the `inTx` callbacks of
  `storeNextSecretVersion` / `updateSecretWithNewVersion`); a non-literal closure argument is
  reported as `OPAQUE`.
  Not covered: a helper method that reaches `c.storage` on its own (`c.someHelper(ctx)` called inside
  a closure), an outer handle aliased before the closure (`st := c.storage`), and a writer reached
  through another struct's field. The sweep behind this entry ran a transitive pass over the
  receiver's methods for the first form and found only the three `...On` helpers, which all receive
  `auditInto(tx, sink)`; that pass is not part of the guard.
