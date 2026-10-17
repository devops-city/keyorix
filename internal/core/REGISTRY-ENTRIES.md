# Registry tables: one file per entry; never append to a shared list.

Guard tables in this package that every security PR used to append to are
populated by one Go test file per row, each registering itself from `init()`.
Two PRs that each add a row touch two different files, so they never conflict.
Full explanation: `registry_entries_test.go`.

| Table | New row = a new file | Register function |
|---|---|---|
| `mfaStepUpPurposeAllowlist` | `mfa_stepup_purpose_allow_entry_<slug>_test.go` | `registerMFAStepUpPurposeAllow` |
| `g4FuzzSeedPrograms` (FuzzCrossReplicaInvariants seeds) | `cross_replica_seed_entry_<issue>_test.go` | `registerG4FuzzSeed` |
| `bestEffortCallAllowlist` (INV-CORE-34 call-site guard) | `besteffort_callsite_allow_entry_<slug>_test.go` | `registerBestEffortCallAllow` |
| `pendingSeedFix` | `pending_seed_fix_entry_<issue>_test.go` | `registerPendingSeedFix` |

Put the row's reasoning comment above the `register…` call, in that file. Do not
add a row to the table's declaration (those literals are empty on purpose). A
duplicate name or key panics at package init.

New cross-replica check-then-act review tests (`TestCTAReview_*`) go in their OWN
`cta_review_<name>_postgres_test.go` file, reusing the `newCTAReview` fixture, not
at the end of `concurrency_check_then_act_exempt_review_postgres_test.go`.
