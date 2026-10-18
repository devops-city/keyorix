### Fixed

- Operational drills (`scripts/drills`) no longer report a valid `verify-audit` (or other matched output) as a failure at random: `echo "$out" | grep -q` under `pipefail` died of SIGPIPE (exit 141); all such sites now use here-strings. `totp_fresh` keeps the last consumed code per account, so two accounts no longer replay a code. `scripts/drills/selftest.sh` (run by `go test ./internal/statemap`) proves both and fails on any new `echo | grep -q`.

### Changed

- `docs/state-map/entrypoints.tsv` regenerated, and `go test ./internal/statemap` now fails when `docs/state-map/{entrypoints,stores}.tsv` differ from what `go run ./cmd/statemapgen` generates (`statemapgen` gained `-out <dir>`).
