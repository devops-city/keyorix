### Added
- **Web UI: a persistent "Secret reads are not audited" banner** on every page while the server runs with `storage.database.insecure_audit_skip_reads: true` (ADR-112 Amendment 4), read from `security.audit_reads_skipped` in `GET /api/v1/system/info`. It cannot be dismissed.
