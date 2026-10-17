### Added
- **`storage.database.native_read_pool_max` sets the size of the Postgres native read pool.** The pool the machine credential lookup and the node-stamp read run on stays at 8 connections unless you set it (1 to 1000, never more than `max_open_conns`; Postgres only, refused elsewhere). The boot-time connection headroom warning counts the configured size. See `docs/CONFIGURATION.md`.
