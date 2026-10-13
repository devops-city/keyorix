- **INV-STORE-audit-batch-insert-values-order** The audit flusher's multi-row INSERT
  (`commitBatchAttempt`) stores a batch exactly as the per-item path would: hashes are
  computed item by item before the insert, each item's row gets an id greater than the
  previous item's (VALUES order), the id GORM writes back onto each item is that item's own
  row (on Postgres the event ids are assigned before the INSERT instead, see
  `INV-STORE-audit-pipelined-commit`), and the id-DESC chain head is the batch's last item. `checkAuditInsertIDOrder` re-checks
  the returned ids on every attempt and fails the attempt closed (into `commitAuditBatch`'s
  bisection) if they do not ascend. A bad row fails the whole statement, and the bisection
  still confines the error to its own caller; every other caller gets nil only after its
  rows commit. Each INSERT stays under SQLite's bind-variable limit (`auditInsertMaxBindVars`),
  and a full `auditFlusherMaxBatch` batch is one statement per table. Why: PERF-FIX-2 replaced
  one statement per item with one per batch; VerifyAuditChain walks id ASC, so an id order
  that differed from the hash order would read as tampering.
  Guard: `internal/storage/store` `TestCommitBatchAttempt_MultiRowMatchesPerRow_SQLite`/`_Postgres`
  (pg-gated), `TestCommitAuditBatch_RealDBErrorOnOneRowIsolated_SQLite`/`_Postgres`,
  `TestLogAuditEvent_FlusherPoisonedCallerIsolated_SQLite`/`_Postgres`,
  `TestCommitBatchAttempt_ChunksAtVariableLimitBoundary_SQLite`/`_Postgres`,
  `TestAuditInsertRowsPerStatement_SQLiteVariableLimitIsReal`,
  `TestAuditInsertRowsPerStatement_CoversAFullFlusherBatch`, `TestCheckAuditInsertIDOrder`.
