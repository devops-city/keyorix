### Fixed
- **The audit CSV export names the machine identity on machine rows.** `GET /api/v1/audit/export.csv`
  left the `actor` column blank for a row written by a machine identity, and the JSON feed
  `GET /api/v1/audit/export` (rendered by `keyorix audit export --csv`) left `actor` empty too.
  Both now carry the identity's name (e.g. `ci-app`), with `actor_type` `machine_identity`, as the
  audit list and search already do. Names only; no token or secret material is added. The stored,
  hash-covered fields of the export are unchanged, so off-box chain verification is unaffected.
