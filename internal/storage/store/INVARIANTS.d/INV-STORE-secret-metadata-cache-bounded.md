- **INV-STORE-secret-metadata-cache-bounded** The secret read-path cache
  (`secretMetadataCache`) is bounded on both axes: each of its three maps holds at most
  `secretMetaCacheMaxEntries` entries (`makeRoom` evicts before an insert of a new key),
  and an entry older than `secretMetaCacheTTL` is a miss that is deleted on read. The
  versions map necessarily holds `EncryptedValue` ciphertext (every
  `GetLatestSecretVersion` caller consumes it), so the cap and TTL are what limit the
  ciphertext's residence in process memory. The TTL is a memory/exposure bound only:
  correctness never depends on it, every hit is still validated against its live
  generation. Why: #2764 review — three plain maps for the process lifetime grew with
  vault size and kept every secret ever read resident as ciphertext.
  Guard: `internal/storage/store` `TestSecretMetadataCache_SizeIsCapped`,
  `_CapDoesNotEvictAnOverwrittenKey`, `_EntriesExpire`, `_BoundHoldsUnderConcurrency`.
