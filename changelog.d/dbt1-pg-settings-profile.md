### Added
- **Helm: `postgresql.settings` for the bundled PostgreSQL.** Extra server settings, rendered as `postgres -c key=value` alongside the secure-baseline TLS args. Empty by default (rendered output unchanged). `synchronous_commit`, `fsync` and `full_page_writes` accept only durable values (an allow-list), and settings that would override the secure-baseline TLS/auth args or run commands (`ssl`, `ssl_*`, `hba_file`, `listen_addresses`, `password_encryption`, `archive_command`, and others) are refused. Guarded by `TestHelmPostgresSettings`.

### Documentation
- **docs/PERFORMANCE.md: a production PostgreSQL profile** (memory, WAL compression, checkpoint spacing; durability left on), with what it measurably changes (WAL volume) and what it does not (read throughput, `commit_delay`). The SQLite advice now says the server's own settings are complete: the cache/mmap/temp_store PRAGMAs it used to recommend made no measurable difference.
