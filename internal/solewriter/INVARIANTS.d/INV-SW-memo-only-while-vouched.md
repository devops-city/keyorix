- **INV-SW-memo-only-while-vouched** The folded credential statement's answer is served from memory only
  while `swstate.Get()` is authoritative and `Valid(gen)` holds for the generation it was filled at (no
  fenced write in flight, none finished since). A fill that overlapped a write is not stored. Every table
  the statement reads is fenced. A write through this server (core call or its own pool) is seen on the very
  next request, and no request that starts after the revoking call returned is served the old answer.
  A write from outside this server that reaches a fenced table (a copied tag; anything the fence lets
  through) is not seen by the tracker: it is served stale until the next poll sees the epoch move and
  flushes, at most one poll interval (250 ms) while polls succeed, and at most the 1 s lease when they
  fail (the guard then stops vouching). Each entry is handed out as a deep copy.
  Why: docs/specs/single-writer-cache.md §1.5. Guard: `server/http`
  `TestSingleWriter_ServerPathRevocationIsImmediate` (14 end-of-access paths; red with the tracker's
  generation bump removed, and with the memo hit's validity check removed),
  `TestSingleWriter_RevocationRacingReaders`, `TestSingleWriter_RevocationRacingReaders_ThroughTheServerPool`
  (no per-site cache eviction on that path, so only the tracker and the validity check answer; red with
  either removed; the `token-revoked-on-server-pool` case likewise), `TestSingleWriter_LostLockConfirmsAgain`,
  `TestSingleWriter_ExpiryByTimeAloneIsSeenOnAMemoHit`, `TestSingleWriter_WarmMachineReadRunsNoConfirmingStatement`;
  `internal/storage/store` `TestFoldedCredentialSQL_ReadsOnlyFencedTables` (red with a read table unfenced),
  `TestFoldMemo_HitIsADeepCopy` (red with a shallow copy; every pointer field by reflection).
