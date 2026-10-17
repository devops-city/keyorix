### Security
- **Role-permission cache: the generation proof now requires triggers that fire for every writer.** On PostgreSQL the role->permission cache trusted its generation while a generation trigger was ENABLE REPLICA or an ordinary trigger (which a writer in `session_replication_role = replica` skips), and on a reading connection in replica role. A permission removed by direct SQL in those states kept authorizing from a warm cache. The proof now uses the secret-node cache-epoch condition: ENABLE ALWAYS on a connection in `origin`. The next migration re-issues ENABLE ALWAYS. Guarded by the pg-gated `TestRolePermissionGeneration_*_Postgres` tests in `internal/storage/store`.

### Testing
- **No new hand-written shared-cache SQLite DSNs.** The remaining `cache=shared` literals in internal/storage, internal/config and internal/core tests now use `internal/testutil/sqlitetest`, and `TestNoNewSharedCacheLiterals` fails `go test` on any new one outside its allowlist.
