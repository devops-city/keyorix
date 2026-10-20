### Fixed
- **`admin restore` reported INDETERMINATE for every database that had ever been through an audit retention purge.** Its automatic `verify-audit` was not given the checkpoint signing key it had just unwrapped, so the purge's signed re-anchor could not be authenticated, although `admin verify-audit --checkpoint-key-file` on the same data said VALID. Restore now derives the key from the restored key files and passes it (SQLite and PostgreSQL). Guarded by `TestAdminRestore_PurgedAuditChain_ReportsValid_SQLite` / `_Postgres`.
- **A restore turned SQL NULL in JSON columns into the text `null`.** The backup archive writes NULL as JSON null and `models.JSON` kept the four bytes, so e.g. `secret_nodes.metadata` came back as `'null'` after a SQLite to PostgreSQL move. The restore codec now gives null back as NULL. Guarded by `TestRowCodec_NullJSONColumnRestoresAsNull`.

### Documentation
- **Moving from SQLite to PostgreSQL: the verified procedure** in `docs/SELF_HOSTING.md` (steps, what was checked, what is deliberately not carried over, what an interrupted restore leaves behind and how to restart it, rollback), plus `docs/operator/drill-sqlite-to-postgres.md`. Corrected the recovery-point text: the `admin.backup_created` event is written to the source after the archive, it is not in it.

### Testing
- **`scripts/migrate/sqlite-to-pg-check.sh`**: seeds a SQLite instance (more than 10,000 audit events, a retention purge, MFA users, deleted and suspended secrets, machine tokens, a dynamic-secret config, break-glass history), migrates it with `admin backup` / `admin restore`, compares every table by row count and checksum, and exercises logins, decryption, the audit chain and `kill -9` of a restore at two points.
