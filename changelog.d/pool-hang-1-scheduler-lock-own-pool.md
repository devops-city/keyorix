### Fixed
- **A small Postgres pool no longer hangs the server under load at startup.** Background
  scheduler jobs took their cross-replica lock on a connection from the request pool and then
  waited for a second one, so with a small `storage.database.max_open_conns` (e.g. 5) and
  traffic right after boot every connection could end up held by a waiting job, and all
  requests timed out until restart. The scheduler lock now uses its own small pool (at most 4
  extra Postgres connections per process, closed when idle), and the startup headroom warning
  counts them. Single-runner-per-replica behaviour is unchanged.
