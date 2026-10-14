- **INV-SW-memo-only-while-vouched** The folded credential statement's answer is served from memory only
  while `swstate.Get()` is authoritative and `Valid(gen)` holds for the generation it was filled at (no
  fenced write in flight, none finished since). A fill that overlapped a write is not stored. Every table
  the statement reads is fenced. A write through this server (core call or its own pool) is seen on the very
  next request, and no request that starts after the revoking call returned is served the old answer.
  Why: docs/specs/single-writer-cache.md §1.5. Guard: `server/http`
  `TestSingleWriter_ServerPathRevocationIsImmediate` (14 end-of-access paths; red with the tracker's
  generation bump removed, and with the memo hit's validity check removed),
  `TestSingleWriter_RevocationRacingReaders`, `TestSingleWriter_LostLockConfirmsAgain`,
  `TestSingleWriter_ExpiryByTimeAloneIsSeenOnAMemoHit`, `TestSingleWriter_WarmMachineReadRunsNoConfirmingStatement`;
  `internal/storage/store` `TestFoldedCredentialSQL_ReadsOnlyFencedTables` (red with a read table unfenced).
