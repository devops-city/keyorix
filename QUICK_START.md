# Keyorix — Quick Start

A secrets manager you can run on one machine, in an air-gapped network, or for a
team. This page gets you from a clone to a stored secret. Every `keyorix ...`
command below is checked against the CLI's own flag definitions by
`cli/cmd/quickstart_commands_test.go`; every `keyorix-server admin ...` command is
checked the same way by `server/admin/quickstart_commands_test.go`.

Installing with an AI assistant, or want no secret ever typed or shown? Follow
[INSTALL-WITH-AI.md](INSTALL-WITH-AI.md) instead: the same install, with every
secret generated into a 0600 file (`keyorix-server admin generate-secrets`) and
passed by path.

## Get the binaries

**From a release (no toolchain needed).** Each GitHub release publishes bare
binaries, not tarballs: `keyorix-server_linux_amd64` (API server),
`keyorix_linux_amd64` (CLI), the `-airgap` server variant, and `checksums.txt`
(signed: `checksums.txt.sig` / `.pem`, verify with `cosign`). `install.sh` from the
README installs only the CLI. For the server:

```bash
V=v0.96.0   # the release you want (this one has `admin generate-secrets` and `mfa enroll`)
curl -fsSLO https://github.com/keyorixhq/keyorix/releases/download/$V/keyorix-server_linux_amd64
curl -fsSLO https://github.com/keyorixhq/keyorix/releases/download/$V/checksums.txt
sha256sum -c --ignore-missing checksums.txt && chmod +x keyorix-server_linux_amd64
```

A release binary is the release's own behaviour: this page tracks `main`, so a
command below can be newer than the release (for example `keyorix mfa enroll`
does not exist in v0.95.3). `keyorix-server --version` (or `keyorix-server admin version`)
prints the version, commit, build date and Go version. The server itself has no
`--config` flag (it reads `KEYORIX_CONFIG_PATH`, else `./keyorix.yaml`; only the
`keyorix-server admin ...` subcommands take `--config`); the CLI has
`keyorix version`.

**From source.**

```bash
make build
```

Produces `./bin/keyorix` (CLI) and `./bin/keyorix-server` (API server).
Go 1.27+ (see `go.mod`) is the only requirement: the SQLite driver is pure Go
(`modernc.org/sqlite`), so no C toolchain is needed and `CGO_ENABLED=0` builds work.

`make build` does **not** include the web UI: the server then logs
`Web UI not bundled in this build; serving API only` and shows a placeholder page
at `/`. To get the UI, build it first (needs Node and `pnpm`) and then build
again:

```bash
make build-ui
make build
```

Everything below works with the CLI alone. The Docker demo (`scripts/demo/up.sh`)
already bundles the UI.

## Initialise the server host

`keyorix-server admin init` writes a config file, and creates the encryption key
directories and an empty database file, on THIS host. Run it once, before
starting the server:

```bash
export KEYORIX_MASTER_PASSWORD='choose-a-strong-passphrase'
./bin/keyorix-server admin init --config ./keyorix.yaml
./bin/keyorix-server admin encryption init --config ./keyorix.yaml
./bin/keyorix-server admin migrate --config ./keyorix.yaml
./bin/keyorix-server admin validate --posture --config ./keyorix.yaml   # "No deviations found."
```

The generated config is the secure baseline (ADR-112): TLS on and required, API
rate limiting on, and `/metrics` behind a token. `admin init` generates the files
it needs, all mode `0600`, and never prints their contents:

- `certs/server.crt` and `certs/server.key`: a self-signed TLS certificate for
  `localhost`, this host's name, `127.0.0.1` and `::1`. Replace it with a
  CA-issued certificate (same paths) before other machines connect.
- `secrets/metrics_token`: the bearer token `GET /metrics` requires
  (`Authorization: Bearer <contents>`).

Tell the CLI to trust that certificate. `admin init` prints this exact line with
the absolute path:

```bash
./bin/keyorix config set ca_file "$PWD/certs/server.crt"
```

(`--ca-file <path>` or `KEYORIX_CA_FILE=<path>` do the same for one command or
one shell.)

Only for a throwaway local demo, `admin init --dev` writes the old relaxed config
instead: no TLS, no rate limit, open `/metrics`. Its first line says DEV-ONLY and
`admin validate --posture` reports all three. Never use it on a network.

`admin init` only creates the encryption key *directories* — it does not generate
key material. `admin encryption init` generates the actual KEK/DEK pair; the
server refuses to start without it.

`KEYORIX_MASTER_PASSWORD` is not optional. With the default passphrase provider
the key-encryption key is derived from it plus the on-disk salt, so the server
refuses to start without it. Set it in your shell profile, a systemd unit, or a
secrets file your init system reads — anywhere but a committed file.

Keep `keys/` and the database file together and back them up together. Losing
`keys/kek.salt` means losing every secret in the database; there is no recovery
path, by design.

### Generate the admin recovery key

If every admin account is ever locked out (lost password, lost MFA device), the
only way back in is `keyorix-server admin recover-admin` on this host — and by
default it also requires an admin recovery key. No key exists until you
generate one, so do it now, while the server is not running yet:

```bash
./bin/keyorix-server admin recovery-key rotate --config ./keyorix.yaml
```

It prints a 256-bit key **exactly once**. Store it offline and away from this
host (a password manager, a sealed envelope) — not next to the database or
`keys/`. Only a one-way verifier is stored server-side, so a lost key cannot be
recovered: run the command again to replace it (the old key stops working
immediately). It needs the database to itself and refuses while the server is
running — to rotate the key later, stop the server, run it, then start the
server again. `--recipient <age1...>`
prints it age-encrypted instead of in plaintext; see
`docs/design-b2-recover-admin.md` for the design.

## Start the server and bootstrap the admin account

The CLI is REST-only — it always talks to a running `keyorix-server` over the
network, even on a single machine. Start the server, then bootstrap the first
admin account and default workspace with `keyorix system init --server`:

```bash
mkdir -p -m 700 secrets
(umask 077 && openssl rand -hex 32 > secrets/bootstrap_token)
export KEYORIX_BOOTSTRAP_TOKEN_FILE="$PWD/secrets/bootstrap_token"
KEYORIX_CONFIG_PATH=./keyorix.yaml ./bin/keyorix-server &

# The admin password comes from the environment (or, if KEYORIX_ADMIN_PASSWORD
# is unset, an interactive prompt) and the bootstrap token from the 0600 file
# above (the server refuses a token shorter than 32 characters) — never from flags.
read -r -s -p 'Admin password: ' KEYORIX_ADMIN_PASSWORD; echo
export KEYORIX_ADMIN_PASSWORD
./bin/keyorix system init --server https://localhost:8080 \
  --admin-username admin --admin-email admin@keyorix.local
```

> **Why no `--admin-password` / `--password` / `--value` flags?** Anything on a
> command line is visible to other local users (`ps`, `/proc`) and saved in shell
> history, so the CLI refuses a secret given as a flag and tells you the safe form
> (a hidden prompt, a `KEYORIX_*` environment variable or `KEYORIX_*_FILE`, a
> file, or stdin). The examples here use those. A script that cannot be moved yet
> can set `KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1` to get the old warning instead.

Two things about this command are not obvious from `--help` alone:

- **Pass `--admin-email` explicitly.** The flag's own default (`admin@localhost`)
  fails the server's email validation (no dot after `@`), so omitting it makes
  bootstrap fail with a confusing `Validation error: Validation error: Email`.
- **Pick a password with an uppercase letter, a digit, and that does not contain
  the username.** `Correct-Horse-Battery9` above satisfies all three.

`system init --server` is safe to run more than once — it is idempotent, and
reports `already_initialized` on every call after the first. It creates the
admin user, default RBAC roles, and a default workspace (a project with three
seeded environments — development, staging, production — as IDs 1/2/3) in one
call. Without `KEYORIX_BOOTSTRAP_TOKEN` (or `KEYORIX_BOOTSTRAP_TOKEN_FILE`) set
before the server starts, the server generates a random token and logs only a
masked form of it (first 8 and last 4 characters), so pin your own as shown above.

- Health: <https://localhost:8080/health>
- OpenAPI spec: <https://localhost:8080/openapi.yaml> — only when
  `server.http.swagger_enabled: true` in `keyorix.yaml` (otherwise it returns 404)
- Swagger UI: <https://localhost:8080/swagger/> — same setting

The server speaks TLS from the first start, with the certificate `admin init`
generated. `curl` needs to be told about it too:
`curl --cacert certs/server.crt https://localhost:8080/health`. A browser shows
a warning for a self-signed certificate until you install a CA-issued one.

`keyorix-server admin validate --posture` reports zero deviations on the
generated config (like every `admin` command it needs the database to itself:
**stop the server first**, run it, then start the server again). A `--dev`
config is the relaxed one: TLS, API rate limiting and the `/metrics` token are
off, so it reports three deviations;
[docs/CONFIGURATION.md](docs/CONFIGURATION.md#hardening-an-older-config-clearing-the-posture-report)
lists the keys that clear them.

**CLI against a TLS server with a private CA or self-signed certificate.** By
default the CLI trusts the OS store only. Name the CA (or the self-signed server
certificate) with `keyorix config set ca_file <path>` (stored with your
credentials), `KEYORIX_CA_FILE=<path>`, or `--ca-file <path>`. The CLI then
trusts exactly that file's certificates, on every platform. `SSL_CERT_FILE`
works on Linux only: on macOS Go verifies through the system keychain and
ignores it. For the bundled Caddy `tls` profile the CA is
`docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt`.

What you will see on first start, and what it means:

- **`WARNING: HTTP protocol_versions is set but NOT honored`.** Informational:
  the TLS 1.2 minimum is fixed in code. (A `--dev` config also prints cleartext
  and `trusted_proxies` warnings: TLS is off there.)
- **`Automatic file-permission fixing is on (security.auto_fix_file_permissions ...)`.**
  Informational. The generated config turns the setting on, so it is printed on
  every start. A permission change is reported separately as `[FIXED] <path>`; if
  there is no such line, nothing was changed. Set the option to `false` in
  `keyorix.yaml` to silence it.
- **`storage: opening existing SQLite database ...` several times** from every
  `admin` command. Harmless, including after a brand-new `admin init`.

For Postgres instead of SQLite, `docker compose up -d postgres` starts one, and
`configs/dev.yaml` shows the connection block.

## Log in

```bash
./bin/keyorix login --server https://localhost:8080 --username admin
# Password: (typed at the no-echo prompt)
```

Stores the session token (and server URL) at the CLI's one credential-file
location — see `keyorix status --help`. Every command below reads it from there;
none of them take `--server` again.

## Enrol MFA (required on first login)

`security.require_mfa` defaults on (ADR-112): until the admin enrols a second
factor, this session can only reach the enrolment endpoints — every command in
"Use it" below returns `This deployment requires multi-factor authentication`.
Enrol once, right after the first login:

```bash
./bin/keyorix mfa enroll        # prints an otpauth:// URI (QR) and a base32 secret
./bin/keyorix mfa activate      # prompts for the code your authenticator app shows, then your password
```

In the web UI the same step is Profile → Security → Enable (TOTP) or a passkey.

Save the recovery codes `mfa activate` prints — they are shown once. The session
you activated from stays signed in (every *other* session is signed out), so the
commands below work immediately; the next `login` asks for a code after the
password; type the authenticator code there (an unused recovery code works too).
Either is used for that one request: only the session token is stored. For
non-interactive use, log in once and use a personal access token
(`KEYORIX_TOKEN`) instead of scripting the password and code. An account whose
only second factor is a WebAuthn passkey cannot complete a CLI login — sign in
with the web UI and use a personal access token for CLI work.

(To opt out, set `security.require_mfa: false` explicitly in the config.)

## Use it

Secrets live in a project and an environment. `system init --server` already
seeded project `1` with environments `1`/`2`/`3` above, so new secrets can be
created right away:

```bash
./bin/keyorix secret create --name "stripe-api-key" --interactive   # value typed at a hidden prompt
./bin/keyorix secret create --name "deploy-key" --from-file ./deploy_key   # relative path; absolute paths and symlinks are refused
./bin/keyorix secret list
./bin/keyorix secret get --id 1               # metadata only
./bin/keyorix secret get --id 1 --show-value  # decrypted value
```

`--from-file` reads a file from the current directory (copy the key there first),
so delete that copy once the secret is stored: `shred -u ./deploy_key` on Linux,
`rm -P ./deploy_key` on macOS, or `rm` on a disk you trust to be encrypted.

New secrets default to project `1`, environment `1`. Create another project for
anything that needs its own environments. Every project gets its **own** three
environments with new IDs (project 2's are 4/5/6, not 1/2/3), and using another
project's environment ID fails with a bare `HTTP 422`, so list them first:

```bash
./bin/keyorix project create --name "my-project"
./bin/keyorix project env list --project 2     # development 4, staging 5, production 6

./bin/keyorix secret create --name "db-password" --interactive \
  --project 2 --environment 6 --description "primary read-write user"

# Or address one by reference instead of ID
./bin/keyorix secret get --ref my-project/production/db-password
```

Useful on create: `--max-reads N` (burn after N reads), `--expires` (RFC3339),
`--type`, `--description`, `--interactive` (hidden-prompt value) and
`--from-file` (a relative path, or `-` to read the value from stdin: `printf %s "$VALUE" | keyorix secret create ... --from-file -`) — `--value` is refused, since it puts the secret on the command line.

Export everything in a project/environment at once — the same call the
[GitHub Action](integrations/github-action/README.md) makes:

```bash
./bin/keyorix secret export --project 1 --env 1 --format json
```

## Sharing

Shares are granted to a **user or group ID**, not an email address. Before you
can share anything, both you (the owner) and the recipient need an explicit
role in the project the secret lives in — holding the global `admin` role from
bootstrap is not enough:

```bash
./bin/keyorix rbac assign-role --user admin@keyorix.local --role project_admin --project default
./bin/keyorix rbac assign-role --user alice@keyorix.local --role project_viewer --project default

./bin/keyorix user list                       # find the recipient's ID
./bin/keyorix share create --secret-id 1 --recipient-id 42 --permission read
./bin/keyorix share create --secret-id 1 --recipient-id 7 --is-group --ttl 24h
./bin/keyorix share list --secret-id 1
```

Skipping the two `rbac assign-role` lines and going straight to `share create`
is refused with the reason: the owner (or the recipient) is not a member of
the secret's project. A share only applies to project members, and for them
it can lift access on that one secret: a `project_viewer` shared with `write`
can update its value and metadata and rotate it (nothing else: suspend, move,
expiry changes and the like still need a project role), and revoking the share
takes exactly that away again. See
[the sharing guide](docs/SECRET_SHARING_USER_GUIDE.md#how-a-share-combines-with-a-project-role).

`--ttl` (a Go duration) and `--expires` (RFC3339) are mutually exclusive; either
makes the share time-bound, which is usually what you want for access granted
during an incident.

### A share does not override the recipient's role

Access to a secret is the **union** of every way the user has it: owner, a direct
share, a group share, a per-secret ACL, or a role on the secret's project. A share
adds a path; revoking it removes only that path.

Because the recipient must already hold a role in the project to receive a share
(above), a recipient with `project_viewer` can read every secret in the project
through that role. So `share revoke` removes the share record — `share list` and
the audit log (`share.revoked`) show it — but **alice keeps read access** until her
role is removed too (`rbac remove-role`). Do not rely on a `write` share to let a
read-only role edit a secret: when tried (`share create --permission write`, then
`secret update` as a `project_viewer`) the update was still refused (#2941).

To demonstrate access actually disappearing, remove the role:

```bash
./bin/keyorix rbac remove-role --user alice@keyorix.local --role project_viewer --project default
```

`secret access --id 1` lists each user's effective level, including access that
comes from a role, with a GRANTS column naming every grant they hold.

## Giving a machine (CI/app) access

```bash
./bin/keyorix machine create --name my-ci-app --project default --type ci
```

Issuing that machine a bearer token takes one more command
(`keyorix machine token issue <name>`, see
[`docs/operator/demo.md`](docs/operator/demo.md) step 5 for the full worked
example). Grant it access to a project with `machine grant-role`:

```bash
./bin/keyorix machine grant-role my-ci-app --project default --role project_viewer
```

The machine's token can now read secrets in that project with the granted
role's permissions. Revoke just the role grant (leaving the machine identity
itself intact) with `machine revoke-role`, or list what it currently holds
with `machine roles`:

```bash
./bin/keyorix machine roles my-ci-app --project default
./bin/keyorix machine revoke-role my-ci-app --project default --role project_viewer
```

See [`docs/operator/demo.md`](docs/operator/demo.md) for the full worked
example including revocation.

## Known gaps

- **Sharing requires an explicit project role on both owner and recipient**
  (see "Sharing" above) — holding the global `admin` role is not enough. The
  refusal says which of the two is missing.

## What else is there

`./bin/keyorix --help` lists every command group. Beyond secrets and sharing,
the ones people reach for first are `rbac`, `project`, `user`, `group`, `audit`,
`rotation`, and `machine` (machine identities for CI). Host-side operations —
encryption key rotation, config/database maintenance — are
`keyorix-server admin --help`, not the CLI: see
[`docs/cli-migration.md`](docs/cli-migration.md) for the full old-command ->
new-command table.

- **Configuration reference:** [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)
- **Deployment:** [`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md) (Docker Compose
  + Postgres, TLS, backup/restore, upgrades), and `server/config/production.yaml`
  as a starting config
- **API:** [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)
- **Security model:** [`docs/SECURITY.md`](docs/SECURITY.md)
- **Migrating from the old CLI:** [`docs/cli-migration.md`](docs/cli-migration.md)

The CLI speaks five languages (de, en, es, fr, ru); set `locale.language`.

If something here does not work as written, that is a bug in this page and worth
an issue — the commands are meant to be copy-pasteable.
