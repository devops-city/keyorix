# Rolling upgrades and added columns

Status: in force since the release containing QUERYFIELDS-1.
Invariant: `INV-STORE-explicit-column-reads` (`internal/storage/store/INVARIANTS.d/`).

## The problem

With more than one replica, an upgrade replaces them one at a time, so for a while
release N-1 and release N run against the same database. Release N's migration has
already added a column. A release N-1 replica that reads a table with `SELECT *`
(GORM's default) now gets a row shape it was not built for:

- on PostgreSQL, a connection that already holds a prepared plan for that statement
  fails it with SQLSTATE 0A000 ("cached plan must not change result type"), once per
  cached statement per connection, which the client sees as an HTTP 500;
- on any backend, positional scans and strict struct mapping see columns they do not know.

HA-READY-1 measured the first one in the mixed-version test.

## What changed

`storage.gormConfig()` sets `QueryFields: true` for both backends, so every GORM read
names its columns. The few hand-written queries that used `alias.*` build the column list
from the scanning model (`modelColumns` in `internal/storage/store/explicit_columns.go`).
An added column is then invisible to a replica that does not know it.

Cost: the statement text is longer. The number of statements per operation does not change
(the statement-count tests are unchanged and pass).

## What it enables, and what it does not

It enables, for HA-READY-1's mixed-version test (`scripts/e2e/mixed_version_test.go`):

- once the N-1 binary is a release that contains this change, the test can assert that an
  added column causes no request failure at all, instead of asserting that the failure
  window closes;
- until then the old binary still reads with `*`, so the 0A000 window remains for the
  first upgrade that crosses this change. Treat that one upgrade as the last one that needs
  the pooled-connection retry allowance.

It does not cover:

- dropping or renaming a column, or changing its type: N-1 still names the old column;
- a new `NOT NULL` column without a default: N-1's inserts omit it and fail. Add columns
  as nullable or with a default, and tighten in a later release;
- new config keys (N-1 rejects unknown keys); those go in a second rollout.

## Rules for contributors

- Do not write `SELECT *` or `alias.*`. Use GORM's model reads, or `modelColumns`.
- `Select("*")` is fine on `Updates` (it names every column on purpose).
- `TestNoStarSelectInProductionSQL` fails on a new star select. An allowlist entry needs a
  reason and a removal condition.
- Check a change against a schema one release ahead:
  `go test -tags nplus1 ./internal/storage/... ./internal/core/...` (add
  `KEYORIX_TEST_PG_DSN` for Postgres).
