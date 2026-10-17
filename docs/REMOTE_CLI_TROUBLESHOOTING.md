# CLI connection and login troubleshooting

For setup see [REMOTE_CLI_SETUP.md](REMOTE_CLI_SETUP.md). The CLI always connects to a
server over HTTPS/HTTP; there is no local mode to fall back to.

## Quick Diagnostics

Start with `keyorix doctor`. It is read-only and checks, in order: the configuration the CLI
would use, that the server answers, the TLS chain and its expiry, version compatibility, clock
skew against the server, that your token is accepted, and the audit chain's integrity. Each
problem comes with the next step:

```bash
keyorix doctor
keyorix doctor -o json    # for scripts; exits non-zero if any check failed
```

For a short look at just the server URL and login state:

```bash
keyorix status        # configured server, logged in or not, version-skew check
```

If `status` cannot reach the server, check the server from the machine the CLI runs on
(`curl --cacert certs/server.crt https://<host>:8080/health`), then the symptoms below.

| Symptom | Cause and fix |
|---|---|
| `no server configured: run "keyorix login" first, or set KEYORIX_SERVER` | No stored credentials and no `KEYORIX_SERVER`. Run `keyorix login --server <url>`, or set `KEYORIX_SERVER` and `KEYORIX_TOKEN`. |
| `x509: certificate signed by unknown authority` | The server's certificate is private or self-signed. Trust it: `keyorix config set ca_file <path-to-server.crt>`, `KEYORIX_CA_FILE`, or `--ca-file`. A config written by `keyorix-server admin init` generates `certs/server.crt`. |
| `x509: certificate has expired` | The certificate `admin init` generates is valid for 397 days and the server does not warn before it expires. Replace it (same paths) with a new or CA-issued one and restart the server. Check with `openssl x509 -in certs/server.crt -noout -dates`. |
| `x509: certificate is valid for ..., not <host>` | You are connecting by a name the certificate does not list. Use a listed name, or issue a certificate that includes yours. |
| `connection refused` / timeout | The server is not running, listens on another address (`server.http.host` defaults to `127.0.0.1`), or a firewall is in between. |
| `HTTP 401` | The session expired or was revoked, or the token is wrong. `keyorix login` again; for scripts, mint a new PAT or machine token. |
| `This deployment requires multi-factor authentication` / `HTTP 403` on every command | The account has not enrolled a second factor and `security.require_mfa` is on (the default). `keyorix mfa enroll`, then `keyorix mfa activate` ([QUICK_START.md](../QUICK_START.md#enrol-mfa-required-on-first-login)). |
| `Too many login attempts` (`HTTP 429`) | The per-IP failed-login budget is used up. Wait for the window, or clear it on the server host: `keyorix-server admin clear-login-lockout --ip <addr>` ([SELF_HOSTING.md](SELF_HOSTING.md)). |
| An account is locked after failed attempts | `keyorix-server admin clear-login-lockout --user <id or email>`, or `POST /api/v1/users/{id}/unlock` as an admin. |
| Locked out of every admin account | [operator/j5-lost-admin.md](operator/j5-lost-admin.md). |
| `HTTP 422` creating a secret with `--environment <id>` | The environment id belongs to a different project. List them: `keyorix project env list --project <id>`. |
| A passkey-only account cannot log in from the CLI | A WebAuthn passkey cannot complete a CLI login. Sign in with the web UI and create a personal access token (`keyorix pat create`) for CLI work. |

`keyorix version` prints the CLI version and the API version it targets; if `status`
reports a version-skew problem, upgrade the older side
([UPGRADING.md](UPGRADING.md)).
