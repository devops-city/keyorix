### Changed
- **Database reads now name their columns.** GORM `QueryFields` is on for both backends, and the few raw `alias.*` queries list their columns. A column added by the next release no longer makes this release's replicas fail (Postgres "cached plan must not change result type", HTTP 500) during a rolling upgrade. This protects upgrades from this release onward; see `docs/rolling-upgrade-columns.md`.

### Testing
- **Guards for explicit column reads.** `TestNoStarSelectInProductionSQL` rejects a new `SELECT *`; a Postgres test reproduces the cached-plan failure and proves model reads survive an added column; `go test -tags nplus1` runs the storage and core suites against a schema with an extra column on every table.
