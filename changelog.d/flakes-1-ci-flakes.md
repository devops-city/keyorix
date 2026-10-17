### Testing
- **Postgres tests that take a database-wide advisory lock run on their own database.** The audit list plan test (#3295), core's audit page test and the KEYAUDIT purge test used schemas of the shared CI database, where another package's test could hold the same lock. Lock-holder counts on `pg_locks` are scoped to the test's database. `TestSharedDatabaseLockGuard` keeps both from coming back.
- **The Postgres savepoint tests no longer lose log lines to each other** (#2870): their capture of the global logger is serialized.
