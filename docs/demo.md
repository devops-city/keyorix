# Demo guide and talk track

How to run the Keyorix demo and what to say. Two ways to bring it up, one seed, one set of
scenario scripts.

| | Command | Needs | Verified |
|---|---|---|---|
| Native (host binaries) | `scripts/demo/native-up.sh` | Go, python3, openssl; `pnpm` for the web UI | SQLite and PostgreSQL |
| Container (air-gapped image) | `scripts/demo/up.sh` | Docker | not re-run in this change (pending e2e VM) |

Both seed the same calm org through the public API and CLI only (`scripts/demo/seed.sh`). The
step-by-step presenter walk through the UI is `docs/demo/GOLDEN-PATH.md`; this page adds the live
anomaly demo and the scenario catalogue.

## 1. Bring it up

```sh
scripts/demo/native-up.sh              # SQLite, http://127.0.0.1:18490
```

For PostgreSQL give the server a database (the DSN travels in the environment, never on a command
line; in a sandbox `kpg dsn <name>` prints one):

```sh
export KEYORIX_DEMO_PG_DSN='<postgres dsn>'
scripts/demo/native-up.sh
```

To serve the dashboard from the same process build it in first (`make build-ui`, needs `pnpm`);
without it the server answers API-only and says so in its log.

What the script does: builds the server, CLI and helpers into `bin/`, creates `.demo-native/`
(gitignored: config, keys, SQLite file, server log, `state.env` with the demo logins at mode
0600), starts the server, enrols MFA for the three seeded accounts, seeds, then waits for the
first anomaly-detection pass and acknowledges the low-severity "first observed access" alerts the
seed itself caused. The bootstrap token is generated per demo (`openssl rand -hex 32`) into a
0600 file; it is never a fixed value and never on a command line.

It is idempotent. Run again with the demo up and it reprints the logins; with the data present and
the server stopped it restarts the server without reseeding. Stop with
`scripts/demo/native-down.sh`, add `--wipe` to delete the demo. `KEYORIX_DEMO_FOREGROUND=1` keeps
the script attached and stops the server on Ctrl-C.

Demo-only settings the script writes to the demo's own config: the anomaly detector runs every 15
seconds instead of hourly, loopback is a trusted proxy (so a script can present another client
address), break-glass is on, a local stand-in CI issuer is trusted for the OIDC scenario, and the
dynamic-secret sweeper runs every 10 seconds. None of this is a production recommendation.

### Seeding a server you started yourself (hosted demo kits)

`scripts/demo/seed-demo.sh STATE_DIR` is the seed on its own. It is what `native-up.sh` calls, and
what a kit that starts the server itself can pass as its seed script.

- **Non-interactive, one argument.** The server URL comes from `$KEYORIX_SERVER`, else
  `STATE_DIR/server.url`, else `http://127.0.0.1:18490`.
- **Idempotent.** With `STATE_DIR/state.env` present and the admin able to log in with the stored
  TOTP key it does nothing and exits 0. It never re-enrols an enrolled admin, so the authenticator
  entry stays valid for as long as the data lives.
- **MFA stays on.** The seed enrols TOTP for the demo admin itself, through the real API, and
  writes the setup key, the otpauth URI and the recovery codes to `STATE_DIR/admin-mfa` (mode 0600).
  Nothing secret is printed or passed on a command line; the presenter adds the key to an
  authenticator once, from that file. Limit: the server generates the TOTP secret when the admin
  enrols (the API cannot be given one), so a demo whose database was wiped and re-seeded gets a new
  key, written over `admin-mfa`; "reuse the same key on reset" holds only while the data persists.
- **Bootstrap token.** Read from `STATE_DIR/bootstrap-token` (mode 0600), generated with
  `openssl rand -hex 32` if missing. Start the server with `KEYORIX_BOOTSTRAP_TOKEN` set to that
  file's content before seeding. The server refuses a pinned token shorter than 32 characters, and
  no script in `scripts/demo` uses a fixed one (`up.sh` generates its own the same way).
- Writes `STATE_DIR/state.env` (0600): the seeded accounts' logins and TOTP keys and the CI
  machine token, which the scenario scripts read.

## 2. The calm baseline

A fresh demo shows no unexplained red: the dashboard Alerts tile, Compliance and Anomalies are
clean. There is exactly one deliberate, explainable gap:

> "One production secret, the payments webhook secret, has no rotation policy. That is the
> control the Compliance page flags, and the one we fix live." (`GOLDEN-PATH.md` section 1b)

`scripts/demo/trigger-anomaly.sh status` prints `calm: 0 open anomalies`.

## 3. Anomaly detection, live

**Talk track: calm baseline, run a scenario, the anomaly + the audit trail + the alert appear,
investigate.**

Say: "Everything is quiet. Now an identity does something it has never done." Run one scenario in
a second terminal and switch to the Anomalies page. The alert is there within one detection pass
(the demo's cadence is 15 seconds; typically a few seconds to under half a minute). Then
investigate: open the alert (who, which secret, from where, when), open the audit log for the same
actor (the reads behind it), and note that the detection is metadata-only: secret values are never
examined.

```sh
scripts/demo/trigger-anomaly.sh list        # the scenarios
scripts/demo/trigger-anomaly.sh bulk-read   # run one
scripts/demo/trigger-anomaly.sh reset       # back to calm
```

Every scenario makes ordinary, authorised API calls that one of the product's existing detectors
flags. Nothing is faked or inserted.

| Scenario | What happens | Detector | Threshold | Shows as |
|---|---|---|---|---|
| `bulk-read` | A new machine identity reads 13 secrets it has never read | `principal_breadth` | 5 or more never-read secrets in the scan window (10 or more is high) | high, plus a low "first observed" alert per secret |
| `read-burst` | The CI identity reads one secret 25 times in a few seconds | `frequency_spike`, `cumulative_rate` | 10 or more reads in the window and over 3 times the hourly baseline; over 20 reads in 24 h on a secret averaging under 1 per day | medium, one each |
| `off-hours` | The off-hours band is moved over "now", then a secret is read | `off_hours` | a read inside the configured band (default UTC 22:00 to 06:00) | medium |
| `new-source` | The CI identity reads from a client address never seen | `new_ip` | first access from an address outside the 24-hour-quarantined baseline | low on a fresh demo (no history to compare), high once a secret has history |
| `login-burst` | Six wrong passwords against a throwaway account from one address | none (audit only) | the account locks after the fifth failure | audit rows `auth.login_failed`, `account.locked` |
| `probe` | alice, a viewer on one project, tries secrets outside her grant | none (audit only) | each refused value read is audited | audit rows `secret.read` with `outcome=denied` |

Two honest notes for the presenter. First, a failed-login burst and refused-read probing are not
anomaly alerts today: they leave audit rows and (for logins) a lockout, but the Anomalies page
stays empty for them. Say "audit trail", not "alert". Second, the detector de-duplicates an
equivalent alert (same secret, type, accessor and address) for one hour even after it is
acknowledged, so each run uses a fresh actor, a fresh source address or the next secret in a
rotation; the scenarios handle this and `reset` is permanent (the alert is not re-raised).

`reset` acknowledges every open alert (they stay in history and in the audit trail), restores the
off-hours setting, and revokes or deletes the actors the scenarios created.

Check it works: `scripts/demo/anomaly-check.sh` asserts that the seed is calm, that each scenario
produces its evidence, and that each reset returns to zero open anomalies.

## 4. Scenario catalogue

Each scenario is a repeatable script (`scripts/demo/scenario-<name>.sh`, secrets never on a command
line) with a short talk track. They share the native demo's state file; run them in any order.
Afterwards `trigger-anomaly.sh reset` clears the low "first observed" alerts they cause.

**1. Tamper-evident audit** (`scenario-tamper-audit.sh`). "An insider with database access edits
one audit row. The chain breaks at exactly that row, the posture control turns to a gap, and
restoring the row makes it valid again." The script rewrites a row directly in the database,
runs `keyorix audit verify --full` (BROKEN, first broken id), shows the Compliance control, and
restores it.

**2. Vault migration** (`scenario-vault-import.sh`). "Import from Vault with a dry run first. The
plan shows every source path and what it becomes; apply it; the application reads the same values
from Keyorix; run it again and nothing changes." The source is a Vault export file served by a
protocol stand-in; the real-Vault container walk is `vault-migration-demo.sh` (Docker).

**3. Install in under a minute** (`scenario-install-60s.sh`). "From the binary to a healthy server
with an admin account in five commands." The script times it and asserts under 60 seconds. The
container one-liner and the air-gapped bundle are written out in the script (`--docker`,
`--airgap`) but not run here.

**4. `keyorix run`** (`scenario-run.sh`). "The application is unmodified: Keyorix puts the secret
in its environment when it starts. Rotate the secret and the next start gets the new value." A
running process keeps the value it started with; restart after a rotation.

**5. CI without stored secrets** (`scenario-oidc-federation.sh`). "The pipeline presents the
five-minute token its platform issues. Keyorix checks the signature against the platform's keys,
maps issuer and subject to a machine identity, and audits the read against it. Another repo, an
expired token or a token for another audience gets a 401." The CI platform is a local stand-in.

**6. Dynamic database credentials** (`scenario-dynamic-credentials.sh`). "Keyorix creates a real
database role on demand. It works, it stops working when the lease ends, and a second lease is
revoked on the spot." Needs a PostgreSQL to hand roles out in
(`KEYORIX_DEMO_DYNAMIC_ADMIN_DSN`, or the Postgres demo's own database).

**7. Break-glass** (`scenario-break-glass.sh`). "alice is read-only. In an incident she activates
break-glass with a written reason, gets developer rights for thirty seconds, makes the change, and
the grant expires by itself. The activation is audited, admins are notified, and a second
administrator reviews it."

**8. Access request, approval and review** (`scenario-access-governance.sh`). "alice asks for
access to a project; an administrator approves it for four hours. At the next recertification the
independent reviewer revokes it. The completed cycle is the evidence the Compliance page reads
(ISO 27001 A.5.18; NIS2 Art. 21(2)(i); DORA Art. 9)."

**9. Compliance evidence** (`scenario-compliance-evidence.sh`). "One command produces a signed
evidence pack: the posture plus the records behind it. The auditor verifies it against the
deployment, and changing one byte makes verification fail."

**10. AI assistant over MCP** (`scenario-mcp-readonly.sh`). "The assistant gets a least-privilege
identity and a read-only tool surface: read one allowed secret and nothing else. There is no
write, rotate or delete tool, a secret outside its allow-list is refused, and the same token cannot
write through the API either. Every read is audited as the assistant."

**11. Kubernetes sync** (`scenario-k8s-sync.sh`). Written, not run here (needs Docker and kind):
"rotate the secret in Keyorix and the Kubernetes Secret follows; a restarted pod sees the new
value." Run it on the e2e VM after `KEEP=1 make k8s-e2e`.

**12. Share with expiry and revoke** (`scenario-share-expiry.sh`). "The owner lets alice rotate
one secret for twenty-five seconds. The share expires by itself; a second share is revoked by hand
and takes effect immediately. No role change, nothing to remember to undo."

## 5. Not covered here (pending e2e VM)

The container image path (`up.sh`), the browser walk of the UI, the real Vault and OpenBao
containers, Kubernetes with kind, and the docker one-liner and air-gapped installs were not run in
this environment. Everything above that says "verified" ran against the native server on SQLite
and PostgreSQL.
