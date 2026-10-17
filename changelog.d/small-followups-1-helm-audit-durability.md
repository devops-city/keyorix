### Added
- **Helm: `auditDurability`.** Sets the server's `storage.database.audit_durability` (`strict` or `standard`; empty keeps the backend default). Any other value is rejected by `values.schema.json` and the template. Guarded by `deploy/helm_audit_durability_test.go`.
