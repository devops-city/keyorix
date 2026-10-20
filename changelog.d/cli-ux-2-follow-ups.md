### Security
- **Webhook URLs are secrets in the CLI and the web form (CLI-UX-2).** `keyorix notification channel add|update` take the URL with `--url-file <path>` or `--url-file -` (stdin); `--url` is refused like the other secret flags (`KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1` warns instead). `channel get` says the URL shown is masked. The web form uses a password-type field, and an existing channel shows its masked URL with a "Replace URL" button. The server side (create-only full URL, encrypted at rest with a startup backfill) was already in #3438; see `docs/UPGRADING.md` 6j.

### Added
- **`KEYORIX_TOKEN_FILE`** (mode 0600/0400, or 0440 for a mounted Secret) as the file form of `KEYORIX_TOKEN`; a bad file is an error naming it, never a fallback. `keyorix doctor` names the token source.
- **`keyorix machine token issue --output-file <path>`** writes the token to a new 0600 file (refuses to overwrite; created before the token is minted) so it never passes through terminal scrollback.

### Changed
- **Refused secret flags and a bad `keyorix doctor --output` exit 2** (usage error); `doctor` is in the exit-code table of `--help` (exit 1 when a check failed). `doctor`'s `reachable` check shows the same plain-language transport description as every other command. Help examples use `-o json`, and a guard fails on any example that teaches a deprecated flag.
- **Dynamic-secret create/issue against a private-network target** answers with what was refused and which setting allows it (`dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets`) instead of "an internal error occurred". The address a hostname resolved to and the DSN's credentials are not in the response.

### Fixed
- **Operator messages named commands that do not exist** (`keyorix encryption rotate --confirm`, `keyorix system init --database`, `keyorix encryption migrate-provider`, `keyorix encryption shamir-split`). They now name `keyorix-server admin ...`; `TestEveryCommandNamedInAMessageExists` (CLI) and `TestEveryServerCommandNamedInAMessageExists` (server) fail for any quoted command in a Go string literal that is not in the command tree.
