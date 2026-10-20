### Documentation
- **Six new per-component threat models** in `docs/security/threat-models/`, in the existing format (DFD, trust boundaries, threat table with Evidence and Residual-or-GAP columns): sharing and secret ACLs, break-glass, SCIM and SSO-managed accounts, dynamic secrets and leases, notifications and webhooks, and rate limits and login lockout. Every mitigation names a function and a test that exists on `main`; where none does, the row is a GAP with an issue number. The README indexes them and lists the eleven gaps filed (#3418, #3419, #3420, #3422–#3429).

### Testing
- **Threat-model Evidence cells are machine-checked.** `go test ./internal/threatmodelcheck` fails when a cell cites a file, a `Test`/`Fuzz` function or an identifier that does not exist, when a threat-model document is not indexed in the README, and, for new documents, when a row cites no test. It checks existence only; it does not check that the cited test proves the mitigation.
