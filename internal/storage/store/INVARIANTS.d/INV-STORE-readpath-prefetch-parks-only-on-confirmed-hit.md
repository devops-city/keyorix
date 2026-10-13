- **INV-STORE-readpath-prefetch-parks-only-on-confirmed-hit** When a request declares a
  `storage.ReadPathPrefetch`, the node-stamp statement (`readNodeStampPrefetching`) also reads
  the machine's roles at the cached node's scope and, on a latest-version value read, the
  schedule row and versions generation. Those answers are parked on the carrier only when the
  node cache hit is confirmed in that same statement (row found, `cache_epoch` trigger proven
  present and enabled, stamp equal to the cached generation); they are taken at most once, only
  for the same machine and scope (or the same secret), and the gate drops an unconsumed one
  after its decision. Every fact is still read live on every request, and the trigger proof
  stays in the stamp statement (`nodeTriggerExistsExpr`), not in a cache. If the combined
  statement errors, the classic `readLiveNodeStamp` runs and nothing is parked.
  Why: fewer round trips on the machine secret read path without a window where a stale or
  contested node lends its scope to a permission read, or a dropped trigger is served from cache.
  Guard: `TestReadPathPrefetch_OneStatementSameAnswers`, `_RevokedRoleIsSeenOnTheNextRequest`,
  `_StaleNodeParksNothing`, `_NotServedToAnotherPrincipalOrScope`,
  `_TriggerDroppedWhileWarmIsAMissNotAStaleHit` (SQLite and Postgres legs).
