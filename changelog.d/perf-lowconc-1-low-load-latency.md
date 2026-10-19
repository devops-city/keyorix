### Fixed
- **A secret read can no longer stall for its whole audit deadline when it lands on the audit flusher's idle exit.**
  The batching flusher stopped after 200 ms without work if its queue was empty, even when a read had already picked
  up the queue and was about to hand over its audit row; that row then waited in a queue nobody read until its 10 s
  deadline and the read failed with "Failed to record audit trail". Rows now register before they are handed over,
  and the flusher stops only when none is on its way. Guarded by `TestAuditFlusher_SlowSendIsNotStrandedByIdleExit`.

### Internal
- The audit commit resolves the audit table name once per store instead of on every batch (less CPU per audited
  read). Design note for the low-concurrency read path: `docs/specs/low-concurrency-read-path.md`.
