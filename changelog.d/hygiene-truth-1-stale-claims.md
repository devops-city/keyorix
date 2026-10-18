### Fixed

- The web "SDKs & CLI" page and `docs/MIGRATION.md` no longer teach `keyorix connect`, `keyorix auth login`, `--password` or `--value`; they show `keyorix login --server …` (password prompted) and `keyorix secret create --from-file`. A new vitest guard fails on any `keyorix <unknown subcommand>` or `--password`/`--value`/`--mfa-code` in web string literals, with the command list derived from `cli/cmd`.
- `docs/state-map/entrypoints.tsv` no longer carries a line-number column, which went stale on every unrelated edit (102 rows had drifted unnoticed). A new `cmd/statemapgen` test regenerates both state-map TSVs into a temp dir and fails on any differing row.
