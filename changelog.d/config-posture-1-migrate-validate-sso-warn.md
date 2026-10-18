### Security
- **`admin migrate` refuses a config that `serve` refuses (#2854).** `keyorix-server admin migrate` now runs `Config.Validate()` before it opens the database and fails with the same `Configuration is invalid: ...` message `serve` prints, so a config that cannot boot no longer gets its schema migrated. Guarded by `TestAdminMigrate_RefusesConfigThatValidateRejects` (asserts the database file is never created).

### Added
- **`admin validate --posture` warns when every administrator is IdP-managed (#2914).** A new WARN section (printed, not counted toward the exit code) appears when every global administrator was created by SSO or SCIM; the remediation is a local break-glass administrator and the local recovery procedure. See `docs/security/hardening-guide.md`.

### Testing
- **OpenAPI drift exemptions are narrowed to (path, message kind) (#2868).** An `ALLOW` entry used to silence every check on its path; it now silences only the one message kind it names, and an exemption that matched nothing, or matched a different message, fails the test.
