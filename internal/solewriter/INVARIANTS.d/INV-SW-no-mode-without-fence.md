- **INV-SW-no-mode-without-fence** A single-writer server never runs without its write fence:
  `InstallFence` creates or converges every trigger `triggerSpecs` derives from `FencedTables`, makes
  each `ENABLE ALWAYS`, verifies count, enabled state and definition in the same transaction, and any
  failure is fatal at boot (`server/main.go`). Why: Andrei 2026-10-15, decision 2. Guard:
  `TestInstallFence_RefusesWhenATableIsMissing`, `server` `TestSingleWriter_Postgres_OperatorJourney`.
