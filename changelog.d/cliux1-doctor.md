### Added
- **`keyorix doctor`: a read-only health checklist for the CLI's connection to the server.** It checks the configuration in use (server URL, token and CA file, and where each came from), that the server answers `/health`, the TLS chain and its expiry (against `--ca-file` or the system roots), API/minimum-CLI-version compatibility, clock skew against the server (TOTP codes and sessions break when a clock drifts), that the stored token is accepted and by whom, and the audit chain's integrity. Every problem prints the next step; checks that depend on an earlier failure are skipped, not failed. `-o json|yaml` for scripts; non-zero exit when any check fails (warnings do not fail it). It only sends GET requests and never starts the long full audit walk.

### Documentation
- **`docs/REMOTE_CLI_TROUBLESHOOTING.md`** now starts with `keyorix doctor` and no longer lists `keyorix config status` / `keyorix auth status`, which do not exist.
