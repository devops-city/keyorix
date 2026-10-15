- **INV-CORE-skip-reads-skips-only-successful-value-reads** With
  `storage.database.insecure_audit_skip_reads` on (ADR-112 Amendment 4), the
  only audit writes dropped are `secret.read` and `connect.secret_read` with
  `Success=true` (`successfulValueReadEventTypes`, `audit_skip_reads.go`). The
  drop happens at the three emit choke points (`emitAudit`, `emitAuditOn`,
  `emitAuditWithAccessLog`) before any storage call, so a skipped read opens
  no transaction. Every other event, every `Success=false` event and every
  event with a nil `Success` is still written. With the setting off, nothing
  is dropped. Why: a denied read, a write or a permission change must never go
  unaudited because reads are. Guard: `audit_skip_reads_test.go`
  (`TestInsecureAuditSkipReads_SkipSetIsExactlyTheSuccessfulValueReads`,
  `_SuccessfulReadWritesNothingAndOpensNoTransaction`,
  `_DeniedReadIsStillAudited`, `_EveryOtherEventClassStillAudited`).
