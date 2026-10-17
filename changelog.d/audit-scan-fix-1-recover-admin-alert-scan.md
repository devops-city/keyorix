### Fixed
- **The recover-admin alert job no longer re-reads the whole audit table on every run.** It
  runs at start-up and every 10 minutes and filters on the unindexed `event_type`; its stored
  high-water mark only moved when an event matched, so an install that never used
  `recover-admin` scanned all of `audit_events` each time (seconds at a million rows, and on
  SQLite the open read snapshot kept the WAL from checkpointing, slowing every concurrent
  write). The mark is now the highest audit id examined, and each run scans only the primary-key
  range added since the previous one. Every recover-admin use still alerts exactly once. No
  schema change.
