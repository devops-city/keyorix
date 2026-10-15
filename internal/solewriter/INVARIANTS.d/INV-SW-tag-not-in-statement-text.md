- **INV-SW-tag-not-in-statement-text** The server's per-boot session tag is sent as a bind parameter
  (`SELECT pg_catalog.set_config($1, $2, false)`), never in statement text, so it does not appear in
  `pg_stat_activity.query` or `pg_stat_statements`. Statement logs with parameter logging still
  record it (docs/single-writer.md "Residual risks"). Why: REVIEW-SINGLE-WRITER-1 F2. Guard:
  `TestSessionTag_NotInStatementText` (red with the literal `SET`).
