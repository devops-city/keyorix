### Fixed
- **Deactivating a user no longer stalls on SQLite when credential cleanup fails.** `UpdateUser`'s
  deactivation wrote the `user.deactivation_cleanup_failed` audit event from inside its own
  transaction, a second writer behind the SQLite write gate that transaction holds. The event is now
  written after the commit; the deactivation itself still succeeds. Guarded by
  `TestNoOuterStorageInTransactionClosure` (INV-CORE-no-outer-storage-in-transaction-closure).
