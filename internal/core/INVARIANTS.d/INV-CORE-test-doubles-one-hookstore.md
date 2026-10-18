- **INV-CORE-test-doubles-one-hookstore** Test doubles of `storage.Storage` in `internal/core`
  (package `core`) test files are built with `hooked(inner, &storeHooks{...})`; exactly one type,
  `hookStore`, embeds the whole interface. No other struct embeds `storage.Storage`,
  `*store.LocalStorage`, `MockStorage` or `hookStore`, directly or through another such struct. Why:
  Go emits a value and a pointer wrapper for every promoted method of every embedding type whether
  or not it is called; at ~1,090 methods that is ~2.6 MB of object code per double, and 123 doubles
  made the `[internal/core.test]` archive 326-434 MB (CORE-MOCKS-SLIM-1, CACHE-SHAPE-1). An
  un-hooked method delegates to the inner store; on a nil inner store (a pure spy) it panics, so a
  test never silently reaches a method nobody faked. `hookStore` composes the three combined reads
  (`ResolveUserPermissionAt`, `ResolveMachinePermissionAt`, `GetSessionAuthLiveness`) over itself
  when a feeding read is hooked, which is the PERF-FIX-6/7 forwarding rule. Guard:
  `TestNoWholeStorageEmbeddingInCoreTests` (AST scan, with `_Calibration`),
  `TestHookStore_*` (delegation, nil-inner panic, transaction handling, combined reads). Not
  covered: the external `core_test` package, which has its own archive and its own doubles.
