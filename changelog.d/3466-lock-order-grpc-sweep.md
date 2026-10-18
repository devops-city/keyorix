### Fixed
- **Restoring a secret no longer runs without its environment lock when the first read fails.**
  `RestoreSecret` reads the secret to learn its environment, takes that environment's lock and
  then opens the restore transaction. If the read failed, it carried on with no lock, and the
  storage restore took the lock inside the transaction instead: the lock-inside-transaction
  order that can stall writers on SQLite and pin a request connection on Postgres. A failed read
  now fails the restore and changes nothing; a missing secret still reports "not found". (#2694)
- **The gRPC failed-authentication limiter no longer scans its whole table on every failed
  token.** It now clears idle source IPs once every 1000 failures, like its HTTP twin and the
  per-principal gRPC limiter. Limits and idle timeout are unchanged. (#3429)

### Testing
- **One declared lock order, checked statically over every call site.** A new test in
  `internal/core` follows `internal/core`, `internal/core/storage` and `internal/storage/store`
  call by call. It covers in-process mutexes, `sync.Once`/singleflight waits, named-lock
  families, transactions and the scheduler, bootstrap and checkpoint locks, and fails on any
  acquisition that goes against the declared table, including a mutex/named-lock ABBA. The
  named-lock runtime order check now also runs in the `server/http`, `server/http/handlers`,
  `server/grpc` and `server/grpc/services` suites. A parity test keeps the gRPC limiters' sweep
  interval and idle timeout equal to the HTTP limiters'. (#2694, #2685, #3429)
