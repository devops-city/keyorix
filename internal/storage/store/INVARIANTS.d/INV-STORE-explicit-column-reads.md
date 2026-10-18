- **INV-STORE-explicit-column-reads** No production query lets the database expand `*` or
  `alias.*` into its result columns. gorm reads name their columns because every
  `gorm.Open` in `internal/storage` uses `gormConfig()` (`QueryFields: true`); hand-written
  SQL and `Select("alias.*, ...")` strings build the list from the scanning model with
  `modelColumns` (`explicit_columns.go`). Why: during a rolling upgrade release N has
  already added a column while release N-1 replicas keep running; N-1's pooled connections
  hold plans for the old column list, and a star-expanded statement then fails once per
  plan (Postgres SQLSTATE 0A000, "cached plan must not change result type"). Named columns
  make an added column invisible to N-1. Applies from the first release that contains this
  invariant: a replica older than that still reads with `*`. Guard: `internal/storage`
  `TestNoStarSelectInProductionSQL` (static, every Go string literal under `internal/` and
  `server/`; one allowlist entry per exception, each with a removal condition),
  `TestQueryFields_PlansSurviveAColumnAddedByTheNextRelease_Postgres` (pg-gated; runs a
  `SELECT *` control that must hit 0A000, then every model read must not), and the
  behavioural run `go test -tags nplus1 ./internal/storage/... ./internal/core/...`
  (`factory_nplus1_hook.go` adds a NOT NULL DEFAULT column to every table after migration;
  `TestNPlusOneHook_AddsTheExtraColumnToEveryTable` proves the hook fires). **Not covered**:
  a SQL string assembled at run time from pieces, `Select("*")` (legitimate on
  `Updates`, so the static guard skips it), and any change that is not an added column
  (drop, rename, type change, a NOT NULL column without a default breaks N-1 inserts).
