# Pointing the CLI at a server

The `keyorix` CLI always talks to a `keyorix-server` over its REST API, even when the
server runs on the same machine. It has no local-database mode and no `storage.type:
remote` setting (that value exists for internal use only, and the server refuses to
start on it, ADR-083). Everything that must run on the server host (config and key
setup, backup, restore, key rotation, lost-admin recovery) is `keyorix-server admin ...`;
see [QUICK_START.md](../QUICK_START.md) and the other pages in [README.md](README.md).

This page used to describe a CLI "local mode" and `keyorix config set-remote`. Neither
exists any more; the commands below are checked against the CLI's `--help`.

## Log in

```bash
keyorix login --server https://keyorix.example.com --username alice
# Password: (typed at the no-echo prompt)
```

`login` stores the server URL and the session token in
`os.UserConfigDir()/keyorix/credentials.yaml` (mode 0600; on Linux
`~/.config/keyorix/credentials.yaml`, on macOS
`~/Library/Application Support/keyorix/credentials.yaml`). If the account has MFA
enrolled it asks for an authenticator code (or an unused recovery code) after the
password; `--mfa-code` supplies it non-interactively. Prefer the prompts over
`--password` on a command line, where it is visible in `ps` and shell history.

`keyorix logout` revokes the stored session and forgets it. `keyorix status` shows the
configured server, whether you are logged in, and the server/CLI version-skew check.

## Non-interactive use (CI, scripts, applications)

Do not script a user's password. Use a token:

- A personal access token: `keyorix pat create --name ci --scope secrets.read
  --project-id <id> --expires 2027-01-01` prints the token once.
- A machine identity token: `keyorix machine token issue <name>` (see
  [operator/demo.md](operator/demo.md) step 5).

Then set the environment for the process: `KEYORIX_SERVER=https://...` and
`KEYORIX_TOKEN=<token>` (read the token from a secret store or a 0600 file; do not put it
on a command line). `keyorix run --env production --var NAME=secret-ref -- cmd` injects
secrets into a child process.

## Trusting the server's certificate

By default the CLI trusts only the operating system's CA store. For a server with a
private CA or the self-signed certificate `keyorix-server admin init` generates, name the
certificate with one of:

```bash
keyorix config set ca_file /path/to/server.crt   # stored with your credentials
export KEYORIX_CA_FILE=/path/to/server.crt         # one shell
keyorix --ca-file /path/to/server.crt status       # one command
```

`ca_file` is the only setting `keyorix config` manages (`get`, `set`, `unset`). The CLI
then trusts exactly that file's certificates, on every platform. Always use `https://` for a
server that is not on this machine; the CLI does not add TLS for you.

## Which commands need the server host

| You want to | Run |
|---|---|
| store, read, share, rotate secrets; manage users, roles, projects | `keyorix ...` (over the API) |
| first admin and default workspace | `keyorix system init --server <url>` (needs the bootstrap token) |
| create config, keys and database; migrate | `keyorix-server admin init`, `admin encryption init`, `admin migrate` |
| back up, restore, rotate keys | `keyorix-server admin backup`, `admin restore`, `admin encryption rotate` |
| regain a locked-out admin | `keyorix-server admin recover-admin` |

Troubleshooting a failing login or connection: [REMOTE_CLI_TROUBLESHOOTING.md](REMOTE_CLI_TROUBLESHOOTING.md).
