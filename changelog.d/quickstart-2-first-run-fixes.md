### Fixed
- **`keyorix-server admin` commands refuse a too-open secret file.** A `*_FILE` secret (for example `KEYORIX_DB_PASSWORD_FILE`) with mode 0644 was accepted by every admin command and then refused by the server at start. The admin commands now apply the server's check (`config.Config.EnforceSecretFilePermissions`) and fail early with the same `secret file security: ...` message. Guarded by `TestLoadConfig_RefusesTooOpenSecretFile`.

### Documentation
- **QUICK_START, README, pilot-install and quickstart-60s corrected** after a native first-run walk: release downloads for macOS and all four platforms, the generated bootstrap token cannot be exported (use `KEYORIX_BOOTSTRAP_TOKEN_FILE` / `admin generate-secrets`), the audit event is `share_revoked`, there is no `keyorix doctor` (use `keyorix status` / `admin diagnose`), the credentials path per OS, and the Sharing example now creates the recipient first.
