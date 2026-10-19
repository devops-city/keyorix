- **INV-STORE-audit-flusher-no-stranded-submission** The batching audit flusher never stops while
  a submission that read its queue is still on its way to it: every submission registers
  (`auditFlusherState.pending`) under `mu` before it releases the lock and sends, the flusher
  lowers the count when it takes the items, and the idle exit clears `running` only under `mu`
  with `pending == 0`. On Postgres the idle exit first waits for every pipelined batch in flight
  (`auditBatchPipeline.drain`), so a run never ends with a batch whose items have no result yet. So every queued audit row has a committer, and no read waits out its
  audit deadline (and fails closed) because its row sat in a channel nobody reads. Why: the
  idle exit introduced with the group commit (#2420) checked only that the queue was empty,
  which a submission between its unlock and its send does not show (PERF-LOWCONC-1). Guard:
  `local_audit_flusher_strand_test.go` (`TestAuditFlusher_SlowSendIsNotStrandedByIdleExit`: a send
  held past `auditFlusherIdleTimeout` by `auditBeforeQueueSendHook` still commits within 2 s, red
  with the old exit; `TestAuditFlusher_ConcurrentSubmissionsNoneStranded`: 32x25 concurrent
  submissions all return, chain verifies, batched, nothing left registered).
