### Changed
- **Startup refuses an audit id sequence with `CACHE` > 1 on Postgres.** The pipelined audit commit needs `audit_events` ids handed out in lock order; the boot-time check fails with `ALTER SEQUENCE ... CACHE 1` as the fix instead of failing every audit write later.

### Testing
- Commit-time failure of the pipelined audit commit, and a disabled cache-epoch trigger on the combined secret read path, are now covered against real Postgres.
