# Bootstrap token

The token that authorises claiming the first admin over `POST /system/init`. See
`docs/security/production-hardening-matrix.md` for the row rules; the guessing budget
on `/system/init` is in `rate-limits.md`.

| Control | Where | Setting | Default | Test |
|---|---|---|---|---|
| A pinned token shorter than 32 characters refuses to start, without echoing it | `server/main.go` `resolveBootstrapToken` | `KEYORIX_BOOTSTRAP_TOKEN` / `_FILE` | unset: server generates a 256-bit token | `server/secret_file_test.go:TestResolveBootstrapToken_ShortPinnedTokenRefused`, `scripts/e2e/bootstrap_token_strength_test.go:TestBootstrapTokenStrength_SQLite` |
| Both env and file set, or an unreadable file, refuses to start (never falls back to a generated token) | `resolveBootstrapToken` | as above | — | `server/secret_file_test.go:TestResolveBootstrapToken_BothSetRefuses`, `server/secret_file_test.go:TestResolveBootstrapToken_UnreadableFileRefuses` |
| A wrong token is refused; an unset server token disables API bootstrap | `internal/core` `bootstrapSystemLocked` | — | — | `internal/core/auth_bootstrap_token_test.go:TestBootstrapSystem_TokenGate` |
| A generated token is long and unique | `core.GenerateBootstrapToken` | — | — | `internal/core/core_s23_test.go:TestGenerateBootstrapToken_MinLength` |
