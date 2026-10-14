### Fixed
- **Concurrent writes on a small Postgres pool no longer hang the server.** Operations that take a
  cross-replica named lock (creating secrets per environment, membership and role changes, ...)
  held that lock on a request-pool connection and then waited for a second one, so with as many
  different environments/projects being written at once as `storage.database.max_open_conns`, every
  connection could end up waiting and all requests timed out until restart. Named locks now use
  their own small pool (at most 8 extra Postgres connections per process, closed when idle), and the
  startup headroom warning counts it. Locking behaviour across replicas is unchanged.
