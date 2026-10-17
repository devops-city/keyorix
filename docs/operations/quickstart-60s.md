# Quick start in about a minute: download to first secret read

The shortest honest path from "nothing on the machine" to reading back a secret you
stored, using the published release binaries: **one node, SQLite, no Docker, no
compiler**. It is for trying Keyorix, not for running it. For a deployment you keep, use
[SELF_HOSTING.md](../SELF_HOSTING.md) and [QUICK_START.md](../../QUICK_START.md).

"Honest" means every step a secure install needs is here. Nothing is skipped by weakening a
default: TLS is on (self-signed certificate), MFA is required for the admin, and the
secrets (master passphrase, bootstrap token, admin password) are generated into `0600` files
rather than typed.

The macOS (Apple silicon) commands are shown, with `P=darwin_arm64`. Set `P` to
`darwin_amd64` (Intel Mac), `linux_amd64` or `linux_arm64` for another platform, and use
`sha256sum -c` instead of `shasum -a 256 -c` on Linux. The release assets
are listed on the [releases page](https://github.com/keyorixhq/keyorix/releases).

## The steps

Work in an empty directory; everything is created in it.

```bash
V=v0.96.1   # the release you want; this one has `admin generate-secrets` and `mfa enroll`
P=darwin_arm64   # your platform
BASE=https://github.com/keyorixhq/keyorix/releases/download/$V
curl -fsSLO $BASE/keyorix-server_$P
curl -fsSLO $BASE/keyorix_$P
curl -fsSLO $BASE/checksums.txt
shasum -a 256 -c --ignore-missing checksums.txt   # both lines must say OK
mv keyorix-server_$P keyorix-server && mv keyorix_$P keyorix
chmod +x keyorix-server keyorix
```

Create the secrets, then the config, keys and schema. The `*_FILE` variables make every
`keyorix-server` command read the secret from its file. The files must be `0600` (or
`0400`): `generate-secrets` creates them that way, and the server refuses to start with a
more open file. The `admin` commands of the v0.96.1 release accept such a file and only the
server then refuses it; on `main` they refuse it first, with the same message. The server also
generates its own one-time bootstrap token if you give it none, but logs it masked, so it
cannot be exported: keep using the file.

```bash
./keyorix-server admin generate-secrets
export KEYORIX_MASTER_PASSWORD_FILE=$PWD/secrets/master_password
export KEYORIX_BOOTSTRAP_TOKEN_FILE=$PWD/secrets/bootstrap_token
./keyorix-server admin init
./keyorix-server admin encryption init
./keyorix-server admin migrate
./keyorix-server admin recovery-key rotate   # prints the recovery key ONCE: store it offline
```

Start the server in a second terminal (same directory and same two `export` lines):

```bash
export KEYORIX_MASTER_PASSWORD_FILE=$PWD/secrets/master_password
export KEYORIX_BOOTSTRAP_TOKEN_FILE=$PWD/secrets/bootstrap_token
./keyorix-server
```

Back in the first terminal, create the first admin, log in, enrol the second factor and
store and read a secret. `admin init` generated a self-signed certificate; tell the CLI to
trust it:

```bash
export KEYORIX_CA_FILE=$PWD/certs/server.crt
export KEYORIX_ADMIN_PASSWORD_FILE=$PWD/secrets/admin_password
./keyorix system init --server https://localhost:8080 --admin-username admin --admin-email admin@keyorix.local
./keyorix login --server https://localhost:8080 --username admin   # password: the contents of secrets/admin_password
./keyorix mfa enroll      # add the printed secret to an authenticator app
./keyorix mfa activate    # prompts for the app's 6-digit code, then the password; save the recovery codes
printf 'my first secret' > first.txt
./keyorix secret create --name first --from-file ./first.txt
rm -P first.txt
./keyorix secret get --id 1 --show-value
./keyorix status          # server, logged in, health, version compatibility (there is no `keyorix doctor`)
```

The `secret get` command prints `my first secret`. That is the first secret read.
`keyorix status` is the connection check; for host-side checks stop the server and run
`./keyorix-server admin diagnose`.

Two details of the **released** v0.96.1 CLI that cost a first-time user a minute each:

- `login` and `mfa activate` have no `KEYORIX_PASSWORD_FILE` / `KEYORIX_MFA_CODE` form in
  that release (main has them). You type the password at the prompt; open
  `secrets/admin_password` in an editor to copy it. Do not pass it with `--password`: that
  puts it in `ps` and your shell history.
- `mfa enroll` prints an `otpauth://` link and the secret, not a QR code. Enter the secret
  by hand in the authenticator app.

## What was measured

Measured on one Mac, not a performance claim. Machine time for the commands above, run by a script on one Apple silicon MacBook Air
(macOS, loopback network, release `v0.96.1`, a real download from GitHub each time, empty
directory each time). The script supplied the password and the 6-digit code itself with the
`--password`/`--code` flags, because a script has no one to type them.

| Run | Includes `recovery-key rotate` | Total |
|---|---|---|
| 1 | no | 6.6 s |
| 2 | no | 6.0 s |
| 3 | yes | 18.6 s |
| 4 | yes | 25.3 s |
| 5 | yes | 22.0 s |

Runs 3 to 5 are slower in every command, not in one step, and the machine was shared with
other jobs at the time; load was not controlled or measured, so treat that as the likely
cause, not a finding. The honest statement is: **on this one machine, the commands took
between 6 and 25 seconds.** A person adds the time to copy a password, open an authenticator
app and type a code, which was not measured. Nothing here says how long it takes on another
machine, another network, or with a different release.

## What this path does not give you

- No web UI check was made on these binaries.
- The certificate is self-signed and only the CLI on this host trusts it.
- SQLite, one node, no backup. Back up `keys/` and `keyorix.db` together before you rely on
  anything stored (see [SELF_HOSTING.md](../SELF_HOSTING.md)).
- On a fresh SQLite install the server started and served requests when `admin migrate` was
  skipped (observed once, v0.96.1, not investigated). The documented sequence keeps it,
  because it also applies pending migrations on later upgrades.
