# Keyorix

**Lightweight secrets management for teams that can't use SaaS.**

On-premise. Air-gapped ready. Single binary. No Vault admin required.

---

## Why Keyorix?

| | Vault | Doppler | Keyorix |
|---|---|---|---|
| On-premise | Yes | No | **Yes** |
| Air-gapped¹ | Yes | No | **Yes** |
| Simple ops | No | Yes | **Yes** |
| EU company | No | No | **Yes** |
| Open source | BSL | No | **AGPL** |
| Single binary | Yes | N/A | **Yes** |

¹ The core product needs no internet access. Optional integrations that delegate to
an external identity provider — OIDC machine-identity federation, SSO login — need
network reachability to that provider (which can itself live entirely inside a
private network with no internet egress). See [Configuration](docs/CONFIGURATION.md#oidc)
for what's required.

Vault is powerful but requires a dedicated admin. Doppler is simple but SaaS-only. Keyorix is both simple and runs entirely in your infrastructure.

---

## Install

```bash
curl -L https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh
```

That installs the `keyorix` **CLI** only. The server (`keyorix-server`) is a
separate release asset (`keyorix-server_linux_amd64`, plus an `-airgap` variant,
with `checksums.txt`) — see [QUICK_START.md](QUICK_START.md#get-the-binaries) — or a
container image (`ghcr.io/keyorixhq/keyorix-server`).

Or build from source:

```bash
git clone https://github.com/keyorixhq/keyorix
cd keyorix && make install
```

---

## Quick Start

**Self-host the full stack (web UI + API + PostgreSQL) with Docker Compose:**

```bash
cp .env.example .env   # set KEYORIX_DB_PASSWORD, KEYORIX_MASTER_PASSWORD, admin creds
docker compose up -d   # open http://localhost:8088
```

See [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) for production setup (TLS,
backups, upgrades, and the all-important encryption-key handling), and
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the full `keyorix.yaml`
reference (encryption/KEK providers, MFA, WebAuthn, dynamic secrets, OIDC, …).

**Or start just the server binary:**

```bash
KEYORIX_MASTER_PASSWORD=yourpassword keyorix-server
```

**Log in with the CLI:**

```bash
keyorix login --server http://localhost:8080 --username admin
# Password: (typed at the no-echo prompt)
```

With an authenticator app enrolled, `login` prompts for a code after the
password (an unused recovery code works too).

**Create and use secrets** (passwords and values are prompted or read from a file, not passed as flags, because command-line arguments are visible via `ps` and saved in shell history):

```bash
keyorix secret create --name db-password --interactive   # value typed at a hidden prompt
keyorix run --env production --var DATABASE_URL=db-password -- node app.js
keyorix run --env production --var DATABASE_URL=db-password -- flask run
keyorix run --env production --var DATABASE_URL=db-password -- ./myapp
```

Secrets are injected as environment variables under the name YOU choose with
`--var NAME=secret-ref` (repeatable). The old behavior — auto-deriving the env
var name from the secret's own name (`db-password` becoming `DB_PASSWORD`) — is
still available via the deprecated `--derive-names` flag, but is no longer the
default: it let whoever names a secret also choose the env var it becomes.

---

## Migrate from Vault

```bash
# From Vault (Medusa YAML export)
keyorix secret import --file vault-export.yaml --format vault --project 1 --env 1

# From .env files
keyorix secret import --file .env --format dotenv --project 1 --env 1

# Preview before importing
keyorix secret import --file vault-export.yaml --format vault --project 1 --env 1 --dry-run
```

For a **live** Vault/OpenBao instance (rather than a static export file) —
including AWS/Azure/GCP secret managers — use `keyorix-migrate`, a separate
release binary (`keyorix-migrate_<os>_<arch>`) that connects directly and
imports over the Keyorix REST API. See
[docs/migrate-from-vault.md](docs/migrate-from-vault.md) and
[docs/migrate-from-cloud.md](docs/migrate-from-cloud.md).

---

## SDKs

Fetch secrets directly from your application at startup. Zero hardcoded credentials.
Go, Python, Node.js, and Java SDKs live together in
[keyorixhq/keyorix-sdks](https://github.com/keyorixhq/keyorix-sdks)
(`github.com/keyorixhq/keyorix-go` is archived — superseded by the `go/`
directory there). Recommended for an app running unattended: authenticate
with a machine identity token (`keyorix machine token issue <name|id>`),
not a user's password — see [docs/sdks.md](docs/sdks.md) for the full
picture, including PATs, error handling, and TLS with a private CA.

**Go**
```bash
go get github.com/keyorixhq/keyorix-sdks/go
```
```go
client, _ := keyorix.New("https://your-server:8443", os.Getenv("KEYORIX_TOKEN"))
dbPassword, _ := client.GetSecretScoped(ctx, "db-password",
    keyorix.ProjectByName("my-project"), keyorix.EnvironmentByName("production"))
```

**Python**
```bash
pip install keyorix
```
```python
client = keyorix.Client("https://your-server:8443", os.environ["KEYORIX_TOKEN"])
db_password = client.get_secret_scoped("db-password", "my-project", "production")
```

**Node.js**
```bash
npm install @keyorixhq/sdk
```
```javascript
const client = new keyorix.Client("https://your-server:8443", process.env.KEYORIX_TOKEN);
const dbPassword = await client.getSecretScoped("db-password", "my-project", "production");
```

**Java**
```xml
<dependency>
    <groupId>com.keyorix</groupId>
    <artifactId>keyorix-sdk</artifactId>
    <version>0.3.0</version>
</dependency>
```
```java
KeyorixClient client = Keyorix.newClient("https://your-server:8443", System.getenv("KEYORIX_TOKEN"));
String dbPassword = client.getSecretScoped("db-password", "my-project", "production");
```

Each language's `examples/petstore/` directory in
[keyorix-sdks](https://github.com/keyorixhq/keyorix-sdks) has a full
working demo with Docker Compose. No release has been tagged for
`keyorix-sdks` yet — see that repo's own `COMPATIBILITY.md` for the
current verified-compatible state.

---

## Core Features

**Secrets management**
- Create, read, update, delete secrets with full versioning
- Environment separation: development, staging, production
- Secret sharing between users and groups

**Access control**
- Role-based access control (RBAC)
- Group-based permissions
- Service tokens for CI/CD and automation
- Dynamic secrets — on-demand credential generation with TTL

**Audit and compliance**
- Every access logged: who, what, when, from where
- Two audit layers: `audit_events` and `secret_access_logs`
- NIS2 / DORA alignment for European compliance requirements
- Dashboard expiry alerts for secrets approaching rotation deadlines
- ML-based access anomaly detection and alerting

**Developer experience**
- `keyorix run` — inject secrets into any process
- `keyorix secret import` — migrate from Vault, .env files, JSON
- `keyorix login` — single command server authentication
- MCP server for AI-assistant integration — read-only (`keyorix_get_secret`,
  `keyorix_list_secrets`), no write/rotate/delete tools (ADR-061)
- Web dashboard for teams who prefer a UI

---

## Architecture

Two binaries: a thin `keyorix` CLI that only ever talks REST to a server, and the
`keyorix-server` binary itself (HTTP REST + gRPC APIs, port 8080 by default). Web UI on
port 3000. The CLI has no local database mode and cannot bypass the server's own
authorization/audit — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full
picture, including `keyorix-server admin`'s offline, host-side operations (recover a
locked-out admin, offline backup/restore, independent audit-chain verification).

SQLite for development and small teams. PostgreSQL for production.

Air-gapped deployment: copy the `keyorix-server` binary and run — no internet required,
and an air-gapped build profile excludes every cloud-SDK dependency entirely (see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#full-vs-air-gapped-build-profiles)).
(Optional features that delegate to an external identity provider — OIDC federation, SSO
login — need network reachability to that provider; see
[Configuration](docs/CONFIGURATION.md#oidc).)

---

## Security

- AES-256-GCM encryption for all secret values
- Envelope encryption: passphrase → PBKDF2 → KEK (memory only) → wrapped DEK
- Constant-time token comparison (timing attack prevention)
- Secrets never logged or exposed in error messages

Security issues: security@keyorix.com

---

## Roadmap

- Kubernetes service account authentication
- Java SDK

---

## License

AGPL-3.0. Commercial licensing available for enterprise deployments.

Contact: hello@keyorix.com

---

## About

Built by Andrei Beshkov, ex-Microsoft Security PM, Valencia, Spain.

Keyorix SL — your data stays in your infrastructure.
