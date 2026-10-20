# Registry tables in `server/`: one file per entry

Like `server/faultops/REGISTRY-ENTRIES.md`: each row is its own `_test.go` file
registering itself from `init()`, so two PRs adding a row never touch the same
file. Do not add rows to the table's declaration (it is empty on purpose). A
duplicate key panics at package init.

| Table | New row = a new file | Register function |
|---|---|---|
| `schedulerAuditReads` | `scheduler_audit_read_entry_<job>_test.go` | `registerSchedulerAuditRead` |

## `schedulerAuditReads`: scheduler jobs that read an audit-sized table

`TestSchedulerAuditReads_EveryJobThatReadsAnAuditTableDeclaresItsBound`
(`scheduler_audit_read_registry_test.go`) derives, from the code, every
`runScheduler`/`runSchedulerAfter` job that can reach a read of `audit_events`
or `secret_access_logs` (`scheduler_audit_reader_analysis_test.go` says how, and
what it does not see). Each such job needs an entry naming the tables and the
bound that keeps one run's read from growing with the table's history:

- `high-water mark`: a persisted mark of the last row examined;
- `time window`: an indexed time range;
- `id window`: an id range per run (a segment, a tail);
- `full walk, conditional`: in a configuration the entry names, one full walk
  per run in bounded statements (no snapshot held across it).

The test fails on a job without an entry, an entry whose tables differ from what
the job reaches, and an entry for a job that reads none (or no longer exists).
Reads of the audit append path itself (chain-head point reads, reached by every
job that writes an audit event) are listed once in `auditAppendPathReads`.
