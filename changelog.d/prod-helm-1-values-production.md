### Added
- Helm chart: `values-production.yaml`, a documented production example (external PostgreSQL with `verify-full` TLS, credentials from `auth.existingSecret`, ingress TLS, secure baseline, `audit_durability: strict`), rendered by a test. New `server.auditDurability` (`strict` | `standard`) renders `storage.database.audit_durability`.
