- **INV-STORE-named-lock-nested-no-queue** No `WithNamedLock` caller ever waits in the per-key
  in-process queue while it holds a named-lock session. A nested call under a different key (the
  call chain already holds a lock session, `namedLockConnCtxKey`) skips the in-process queue and
  waits in Postgres on that session (`pg_advisory_lock`, still exclusive against every other
  holder); only top-level calls, which hold nothing, queue in-process before taking a session.
  Why: #3358 (REVIEW-1, introduced by #3235). A nested call queued in-process while holding a
  session, and the top-level owner of that key in-process waited for a session; with every session
  of the named-lock pool (`storage.NamedLockPoolSize`) held that way, nothing moved until the
  contexts ended, and every other named lock in the process (CreateSecret's
  `environment-secret-guard` included) waited for a session as well. SQLite is unaffected (no
  sessions; nested calls still queue in-process, ordered by `storage.NamedLockOrder`). Guard:
  `TestWithNamedLock_NestedCallerHoldingEveryLockSession_DoesNotDeadlock` (pool of 8, 8 nested
  holders + a top-level owner + an unrelated key; red on the base: context deadline exceeded) and
  `TestWithNamedLock_NestedCallerSkipsQueue_StillSerializesWithTopLevelHolder` (exclusion kept),
  both pg-gated in `local_named_lock_nested_pool_postgres_test.go`.
