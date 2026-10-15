- **INV-CORE-refused-value-read-is-audited** A refused native secret-value read
  writes a `secret.read` row with `Success=false` and a closed `reason=` class
  (`SecretReadDenialReasons`), at both `insecure_audit_skip_reads` settings
  (#3273, ADR-112 Amendment 4). The write goes through
  `recordSecretReadDenial` (`secret_read_denial.go`) and is best-effort: a
  failure is logged and the read stays refused. A refusal before
  authorization (`forbidden`, `not_found`, `internal_error`) puts no
  `SecretNodeID` and no `ProjectID` on the row, so a caller-visible surface
  cannot tell "missing" from "forbidden". Rows are aggregated per (principal,
  reason, path, target): the first refusal of a window is written at once,
  and at most one summary row per key per window follows. Why: probing must
  leave a trace, but must not become an existence oracle or a write-amplification
  DoS on the hash chain. Guard: `secret_read_denial_test.go`
  (`TestSecretReadDenial_BurstIsAggregatedFirstImmediateCountCorrect`,
  `_DistinctTargetFloodIsBoundedPerPrincipal`,
  `_ForbiddenAndNotFoundRowsAreNotAnOracle`,
  `_AuditWriteFailureKeepsTheRefusal`, `_WrittenAtBothSkipReadsSettings`) and
  `server/http/secret_value_read_denial_audit_test.go`.
