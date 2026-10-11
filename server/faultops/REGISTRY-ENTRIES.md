# Registry tables: one file per entry; never append to a shared list.

The exemption tables of the storage-fault fuzzer are populated by one Go test
file per row, each registering itself from `init()`. Two PRs that each add a row
touch two different files, so they never conflict. Full explanation:
`registry_entries_test.go`.

| Table | New row = a new file | Register function |
|---|---|---|
| `knownOpenTolerances` | `known_open_tolerances_entry_<slug>_test.go` | `registerKnownOpenTolerance` |
| `opScopedBestEffortTables` | `op_scoped_best_effort_entry_<slug>_test.go` | `registerOpScopedBestEffort` |
| `effectThenErrorExtraExclusions` | `effect_then_error_exclusion_entry_<slug>_test.go` | `registerEffectThenErrorExclusion` |
| `bestEffortTables` | `best_effort_tables_entry_<method>_test.go` | `registerBestEffortTable` |
| `nonLoadBearingAuthzReadExceptions` | `non_load_bearing_authz_read_entry_<slug>_test.go` | `registerNonLoadBearingAuthzRead` |
| `multiStepAmbiguousCommitExceptions` | `multi_step_ambiguous_commit_entry_<slug>_test.go` | `registerMultiStepAmbiguousCommit` |
| `oracleAByDesignErrors` | `oracle_a_by_design_entry_<slug>_test.go` | `registerOracleAByDesign` |
| `toleranceDeadPendingTriage` | `tolerance_dead_pending_triage_entry_<slug>_test.go` | `registerToleranceDeadPendingTriage` |
| `toleranceStalenessUndrivable` | `tolerance_staleness_undrivable_entry_<slug>_test.go` | `registerToleranceStalenessUndrivable` |

Put the row's reasoning comment above the `register…` call, in that file. Do not
add a row to the table's declaration (those literals are empty on purpose). A
duplicate `<slug>` panics at package init.
