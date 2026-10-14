### Changed
- **Less CPU per machine-token request.** The credential lookup scans its time columns through `sql.NullTime`, which avoids a per-row reflection check of `time.Time`'s method set in the Postgres driver. Results are identical; `TestCredentialLookupRaw_TimesMatchDirectScan` compares with the previous scan on SQLite and Postgres.
