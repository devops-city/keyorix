- **INV-STORE-schedule-and-latest-version-one-snapshot** `GetSecretScheduleAndLatestVersion`
  answers exactly what `GetSecretAccessSchedule` + `GetLatestSecretVersion` answer for the
  same secret, from ONE statement: the versions aggregate (`count, max(version_number),
  sum(read_count), sum(cache_epoch)`, the same generation `liveVersionsGeneration` reads;
  see INV-STORE-version-cache-sees-ciphertext-rewrite) LEFT JOIN the
  schedule row. The version row is read only on a version-cache miss, after the
  generation, and published under it (`readLatestSecretVersionRow`, shared with
  `GetLatestSecretVersion`). The schedule is read live in full and published/evicted with
  `GetSecretAccessSchedule`'s rules (its own generation from the same statement; a missing
  row evicts), so the two classic methods find the cache in a state they accept. Nothing
  is published from a transaction-scoped store. Why: PERF-FIX-4 (collapse C5) — a
  latest-version value read issued two statements on the same secret.
  Guard: `internal/storage/store` `TestGetSecretScheduleAndLatestVersion_EquivalentToThePair`,
  `_OneStatementAndSharedCaches`, `_TransactionScopedStoreNeverPublishes`,
  `_ReadsEveryScheduleColumn` (SQLite and Postgres). **Not covered**: a new column on
  `secret_versions` is not part of the generation (same as `liveVersionsGeneration`).
