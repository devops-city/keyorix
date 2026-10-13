# AGENTS.md

Instructions for AI agents (coding assistants, local models) working with Keyorix.

## Installing Keyorix

Follow [INSTALL-WITH-AI.md](INSTALL-WITH-AI.md) step by step. For an air-gapped host
or when you can only run a script, use
[docs/install/offline-install.sh](docs/install/offline-install.sh).

## Handling secrets (always)

- Never read, print, copy, encode or search the contents of `secrets/`, `keys/`,
  `certs/*.key`, `*.age`, the database file, or the keyorix CLI credential file.
- Never put a secret in a command-line flag, a log, a commit, or the chat. Pass
  secrets by path: `KEYORIX_MASTER_PASSWORD_FILE`, `KEYORIX_BOOTSTRAP_TOKEN_FILE`,
  `KEYORIX_ADMIN_PASSWORD_FILE`. `keyorix-server admin generate-secrets` creates
  those files (0600) without printing them.
- Never ask a person to paste a password, token, key, TOTP secret, MFA code or
  recovery code. Commands that print one (`keyorix mfa enroll`, `keyorix mfa activate`,
  `keyorix-server admin recovery-key rotate` without `--recipient`) are run by the
  person in their own terminal.
- Never relax a security setting (`security.require_mfa`, TLS, file-permission
  checks, `insecure_*` keys) to get past an error. Stop and report the error.

## Changing this repository

Read [CLAUDE.md](CLAUDE.md) (applies to every agent, not only Claude) and
[CONTRIBUTING.md](CONTRIBUTING.md). In short:

- Before editing a package, read its `INVARIANTS.md`; keep every invariant listed.
- Add a `changelog.d/<PR-number>-<slug>.md` fragment; never edit `CHANGELOG.md`.
- A security fix ships with a test that fails without the fix.
- Build with `make build`; run `go test` on the packages you touched, plus `gofmt`,
  `go vet` and `golangci-lint`.
