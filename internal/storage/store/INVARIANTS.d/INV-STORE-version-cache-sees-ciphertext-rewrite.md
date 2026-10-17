- **INV-STORE-version-cache-sees-ciphertext-rewrite** A warm latest-version cache entry
  never outlives an in-place rewrite of its ciphertext. The generation that validates it
  is `(count, max(version_number), sum(read_count), sum(cache_epoch))` over the secret's
  versions (`versionsAggregateSQL`, the one select list behind `liveVersionsGeneration`,
  `scheduleAndVersionsSQL` and the read-path prefetch statements), and the only code that
  rewrites `secret_versions.encrypted_value` in place, the DEK-rotation sweep
  (`internal/encryption/sweep.go`), raises `secret_versions.cache_epoch` for every row it
  rewrites, in the same transaction. The signal is read from the database, so every
  replica, not only the process that swept, misses on its next hit; it adds a term to the
  aggregate each hit already issues, not a statement. A decrypt failure after a sweep
  stays an error: nothing here falls back to the pre-sweep copy or to a retry under
  another key. Why: DEK-SWEEP-CACHE-1, the gap named since #2764. The sweep moved none of
  the other three terms, so a warm entry kept serving ciphertext under the retired DEK:
  the same plaintext while the process still held the old key, a decrypt error once it
  held only the new one.
  Guard: `internal/storage/store` `TestDEKSweepCache_OldKeyRetained`,
  `TestDEKSweepCache_OldKeyDestroyed` (SQLite and Postgres, two replicas),
  `internal/solewriter` `TestSingleWriter_DEKSweepVsLatestVersionCache`,
  `internal/storage` `TestSecretVersionCacheEpoch_FreshInstallAndUpgrade_{SQLite,Postgres}`;
  family guard `TestSecretVersionCiphertextWriters_AreOnlyTheSweep` (fails on a second
  writer of the ciphertext columns, or when the sweep stops raising the epoch).
  **Not covered**: an `admin encryption rotate` run from a release older than this one
  rewrites ciphertext without raising the epoch (a warm entry then lives at most
  `secretMetaCacheTTL`, as before); a ciphertext writer in SQL outside Go files; and the
  other DEK-encrypted tables, which have no read-path value cache in this package.
