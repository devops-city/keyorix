### Security
- **A plain suspend's audit row is never silently lost.** Suspending a secret (without
  clearing synced copies) still blocks reads at once and is never blocked by the audit log.
  When the audit log refuses the `secret.suspended` row, the server now logs a `SECURITY:`
  line with the details, counts it, reports it to administrators in
  `GET /api/v1/system/info` (`security.audit_owed`), shows a warning bar in the web UI, and
  writes the row (exactly once, also across replicas) as soon as the audit log accepts writes
  again (`audit_owed_backfill` job, every minute). Upgrade note: adds the
  `pending_audit_events` table (schema epoch 3; an epoch-2 binary can still start).
