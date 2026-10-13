### Security
- **Shell scripts no longer put secrets on a command line.** `scripts/smoke.sh`, `scripts/release-qa/*`, `scripts/k8s-e2e/run.sh`, `scripts/demo/vault-migration-demo.sh` and `scripts/demo-keyorix.sh` passed admin/login passwords, MFA codes, bootstrap tokens, secret values and Vault/PAT tokens as flags (visible in `ps` and CI logs). They now use `KEYORIX_*` environment variables, `--from-file`, a stdin pipe, `keyorix-migrate`'s `VAULT_TOKEN`/`KEYORIX_TOKEN`, curl `-H @file` / `--data-binary @-`, `docker --env-file`, and helm `-f` values files. `TestDocsShowNoLiteralSecretOnCommandLine` now also scans `scripts/**/*.sh` and `deploy/**/*.sh` (no allowlist), so a secret flag in a script fails CI.

### Added
- **`keyorix login`, `mfa activate` and `mfa step-up` take their secrets from the environment.** `KEYORIX_PASSWORD` and `KEYORIX_MFA_CODE` (each also as `*_FILE`, same rules as `KEYORIX_ADMIN_PASSWORD_FILE`) work without a terminal. Precedence is flag (still warned), then environment, then prompt. Before this, an MFA-enabled login without a TTY could only succeed with `--mfa-code` on the command line.

### Fixed
- **`scripts/demo/vault-migration-demo.sh` runs again.** It stopped at `project create` ("requires multi-factor authentication") since `security.require_mfa` became the default; it now enrols the demo admin's MFA through `scripts/demo/lib.sh`. `lib.sh`'s `demo_api` also reads the bearer token from a 0600 header file, and its login/activate JSON builders read the password from the environment instead of `python3`'s argv.
