### Changed
- **Less CPU per machine secret read.** The combined node-stamp/roles/schedule statement on the read path is scanned into named variables instead of through gorm's reflection scan, which also re-rendered the statement text (regexp) on every call. Results are identical; `TestReadPathPrefetchScan_MatchesGormScan` compares both scans row for row on SQLite and Postgres.
