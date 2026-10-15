- **INV-STORE-audit-chain-segment-same-rules** `VerifyAuditChainSegment` applies exactly the
  full walk's per-row rules (`verifyBatchEvents`, the same retention-anchor rule at the chain
  start). `VerifyAuditChain` is its zero segment, so the incremental modes and the full walk
  cannot drift apart. A segment with a seed pins the seed row (it exists, has the certified
  hash, and recomputes) before it walks on, and reports `Truncated` when its row cap left rows
  unwalked. Guard: `local_audit_chain_segment_test.go`
  (`TestVerifyAuditChainSegment_ZeroSegmentIsFullWalk`, `_PinnedBoundedAndCapped`,
  `_SeedPinning`) and the core incremental tests.
