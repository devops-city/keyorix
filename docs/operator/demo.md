# Keyorix in 10 minutes

A copy-paste demo script for a newcomer on a fresh machine: install, store a
secret, give an app access to it and revoke that access, then prove a backup
actually restores. Every command below was run for real against a fresh
SQLite install while writing this page — the expected output shown is what
you should actually see, not a paraphrase.

A few of the steps below work around gaps that are still open in the CLI
(tracked in the UX track's report); they're called out inline so you know
they're deliberate, not a typo.

## 0. Build (1 min)

```bash
make build
```

Produces `./bin/keyorix` (CLI) and `./bin/keyorix-server`.

## 1. Initialise the host (2 min)

```bash
export KEYORIX_MASTER_PASSWORD='choose-a-strong-passphrase'
./bin/keyorix-server admin init --config ./keyorix.yaml
./bin/keyorix-server admin encryption init --config ./keyorix.yaml
./bin/keyorix-server admin migrate --config ./keyorix.yaml
```

Expected: each command prints its own success banner. `admin init`'s config
file is created at `./keyorix.yaml`; `admin encryption init` generates
`keys/dek.key` and prints a key version; `admin migrate` reports the database
migrated successfully.

## 2. Start the server and bootstrap the admin account (2 min)

```bash
export KEYORIX_CONFIG_PATH=./keyorix.yaml
export KEYORIX_BOOTSTRAP_TOKEN='choose-a-bootstrap-token'
./bin/keyorix-server &

./bin/keyorix system init --server http://localhost:8080 \
  --admin-username admin \
  --admin-email admin@keyorix.local \
  --bootstrap-token "$KEYORIX_BOOTSTRAP_TOKEN"
```

Omitting `--admin-password` makes the CLI prompt for it interactively
(hidden input) instead of putting it on the command line, where it would be
visible to other local users via `ps`/`/proc` and saved in shell history.
The rest of this page assumes you entered `Correct-Horse-Battery9` at the
prompt — use that value (or substitute your own, and adjust the later
steps) so the commands below still match.

Expected: `Keyorix initialised successfully`, plus a seeded `default` project
with `development`/`staging`/`production` environments (IDs 1/2/3).

Two things about this command are not obvious from `--help` alone, so they're
spelled out here rather than left for you to discover the hard way:

- **Pass `--admin-email` explicitly.** The flag's own default
  (`admin@localhost`) fails the server's email validation (no dot after
  `@`), so omitting it makes bootstrap fail with a confusing
  `Validation error: Validation error: Email`.
- **Pick a password with an uppercase letter, a digit, and that does not
  contain the username.** `Correct-Horse-Battery9` above satisfies all
  three; something like `admin-password1` will not, because it contains
  `admin`.

This page uses `http://localhost:8080` throughout because it's genuinely
local — the server and client are the same machine. Talking to a real,
non-local server should always use `https://`; the CLI does not add TLS for
you.

## 3. Log in and store your first secret (1 min)

```bash
./bin/keyorix login --server http://localhost:8080 --username admin
```

Enter `Correct-Horse-Battery9` (or whatever you chose in step 2) at the
`Password:` prompt — same reasoning as above: omitting `--password` keeps it
out of shell history and process listings.

```bash
./bin/keyorix secret create --name my-first-secret --value "hello"
./bin/keyorix secret get --id 1 --show-value
```

Expected: `Logged in to http://localhost:8080 as admin.`, then a created-secret
confirmation with `ID: 1`, then `Decrypted Value` / `hello`.

Open <http://localhost:8080> in a browser and log in with the same
credentials to see the same secret in the dashboard.

## 4. Share it with a teammate (2 min)

```bash
./bin/keyorix user create --username alice --email alice@keyorix.local --one-time-password
```

This prints a one-time password — relay it to alice; she'll be forced to
change it on first login.

Before you can share anything, both you (the owner) and alice (the
recipient) need an explicit role in the project the secret lives in —
holding the global `admin` role from bootstrap is not enough:

```bash
./bin/keyorix rbac assign-role --user admin@keyorix.local --role project_admin --project default
./bin/keyorix rbac assign-role --user alice@keyorix.local --role project_viewer --project default

./bin/keyorix share create --secret-id 1 --recipient-id 2 --permission read
./bin/keyorix share list --secret-id 1
```

Expected: `✅ Secret shared successfully!`, then a one-row share list showing
alice (recipient ID 2) with `read` permission.

**What the share does — and what revoking shows.** alice must already hold a
project role to receive a share, and with `project_viewer` she can read the
secret through that role. Access is the union of owner, shares, ACLs and roles, so
the share is an *additional* path:

```bash
./bin/keyorix share revoke --share-id 1     # the share record is gone (share list is empty)
# alice can STILL read secret 1: her project_viewer role grants it.
./bin/keyorix rbac remove-role --user alice@keyorix.local --role project_viewer --project default
# NOW alice's access is gone.
```

Demo it in that order: share → `share list` → revoke (the record and the
`share.revoked` audit event are the visible effect) → remove the role to show
access actually ending. Do not present "revoke the share" alone as the moment alice
loses access. (A recipient with no project role cannot be shared to at all:
`share create` is refused until they are a member of the secret's project.)

(Skipping the two `rbac assign-role` lines and going straight to
`share create` is what QUICK_START.md's own sharing example currently shows
— it fails with a bare `HTTP 403` and no explanation. Filed for a fix; use
the four commands above until it lands.)

## 5. Give an app access, then revoke it (2 min)

```bash
./bin/keyorix machine create --name my-ci-app --project default --type ci
./bin/keyorix machine token issue my-ci-app --name ci-token-1 --project default --expires-in-days 30
```

Expected: a machine identity (`id=1`), then a bearer token printed once —
copy it now.

Grant the machine a project role with `machine grant-role`:

```bash
./bin/keyorix machine grant-role my-ci-app --project default --role project_viewer
```

Expected: `Granted role 'project_viewer' to machine identity 'my-ci-app'`.
Check what it holds with `machine roles`:

```bash
./bin/keyorix machine roles my-ci-app --project default
```

Expected:
```
ID    NAME
----- ----------------
9     project_viewer
```

Now the app can read the secret with its own token:

```bash
export APP_TOKEN='<the machine token from machine token issue, above>'
curl -s "http://localhost:8080/api/v1/secrets/1?include_value=true" \
  -H "Authorization: Bearer $APP_TOKEN"
```

Expected: a JSON body ending in `"value":"hello"`.

Revoke just the role grant (the machine identity itself stays active):

```bash
./bin/keyorix machine revoke-role my-ci-app --project default --role project_viewer
```

Expected: `Revoked role 'project_viewer' from machine identity 'my-ci-app'`.
Re-run the same `curl` from above: expect `403` this time — the app is
denied immediately.

To revoke the whole machine identity instead (irreversible — asks you to type
the name back to confirm):

```bash
./bin/keyorix machine revoke my-ci-app --project default
```

## 6. Back it up, wipe it, restore it (2 min)

```bash
kill %1                                         # stop the server (job from step 2)
./bin/keyorix-server admin backup --config ./keyorix.yaml --output ./backup1.kxbak
```

Expected: `Backup written to ./backup1.kxbak (database N bytes, 2 key file(s))`
plus a reminder to store the archive off this host.

Simulate a wiped host — a fresh directory with only the server binary, the
same config, and the backup archive:

```bash
mkdir /tmp/keyorix-restore-demo && cd /tmp/keyorix-restore-demo
cp /path/to/keyorix-server /path/to/keyorix.yaml /path/to/backup1.kxbak .

export KEYORIX_MASTER_PASSWORD='choose-a-strong-passphrase'
./keyorix-server admin restore --config ./keyorix.yaml --input ./backup1.kxbak
```

Expected: migrations applied, `Restored database (N bytes) and 2 key file(s)`,
and — automatically, as part of the same command — `verify-audit on the
restored database: VALID`. That last line is the actual proof the restore is
trustworthy, not just present: it re-walks the tamper-evident audit hash
chain on the restored data, not merely a file checksum.

Start the server against the restored data and confirm the secret is still
there:

```bash
KEYORIX_CONFIG_PATH=./keyorix.yaml ./keyorix-server &
./keyorix login --server http://localhost:8080 --username admin
./keyorix secret get --id 1 --show-value
```

(Enter your password at the prompt, same as step 3.)

Expected: `Decrypted Value` / `hello` — the same value from step 3.

## That's the demo

You've installed Keyorix, stored a secret, shared it with a teammate, given
an app access and revoked it, and proved a backup restores cleanly with its
integrity verified. For anything past this — key rotation, Kubernetes,
Postgres, disaster recovery of a lost admin password — see
[`QUICK_START.md`](../../QUICK_START.md) and the other pages under
`docs/operator/`.
