- **INV-STORE-native-read-pool** On Postgres the hottest read-path statements (the machine
  credential lookup, the folded credential + node read, the node-stamp read) run on a pgxpool
  (`SetNativeReadPool`, `native_reads.go`), and nothing else changes: the same SQL text (gorm's
  `?` numbered `$1..$n` exactly as gorm's Postgres dialector renders it), the same binds in the
  same order, the same scan functions and destinations, pgx's default statement cache as on the
  request pool, and a no-row lookup still wraps `sql.ErrNoRows` (never `pgx.ErrNoRows`). The gorm
  Row callbacks on `ls.db` still see the folded and node-stamp statements (fired in dry-run mode
  before the native query, same SQL and binds), so statement counters and fault-injecting
  callbacks behave as before; an error a callback sets fails the statement. The dry run is
  skipped only while the Row callback chain is the one `SetNativeReadPool` recorded (nothing
  registered, replaced or removed since); an unreadable chain means always observed. Only the root
  LocalStorage the factory built has the pool: a transaction-scoped or derived store reads
  through its transaction, and SQLite has none. The pool is opened from the same
  `config.ResolvePostgresConnConfig` result as every other pool (password on the parsed config,
  TLS check, time-zone setup), capped at `storage.NativeReadPoolMaxSize` (never above the request
  pool's cap), counted in the headroom warning, and closed by `LocalStorage.Close`. Why:
  PGX-NATIVE-1, the stdlib driver's per-column conversion and reflection on every row of the
  statements every machine read runs. Guard: `native_reads_test.go`
  (`TestNativeReads_CredentialLookupMatchesDatabaseSQL`, `_NodeStampMatchesGorm`,
  `_FoldedCredentialMatchesGorm`: native vs database/sql/gorm, reflect.DeepEqual over every row
  shape, NULLs and missing rows, distinct ids per table so a misplaced bind reads another row;
  `_GormCallbacksSeeTheStatement`; `_NeverInsideATransaction`; all pg-gated;
  `_DryRunOnlyWhenACallbackWasRegistered` (default CI);
  `TestNativeSQL_NumbersEveryPlaceholder`, default CI); `internal/storage`
  `TestNativeReadPool_UsesTheResolvedConnConfig`, `TestPostgresPoolHeadroomWarning`,
  `TestPostgresStorage_Close_ReleasesEveryPool` (pg-gated). The Postgres legs of this package's
  read-path tests (`newPrincipalPermStorage`) and the factory-built server tests run on the pool.
