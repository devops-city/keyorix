# Hosted demo kit (DEMO-HOSTED-1, phase 1)

One small VM that runs Keyorix + PostgreSQL through the **production compose path**
(`docker-compose.yml`, `tls` profile) behind Caddy with an automatic Let's Encrypt
certificate. Phase 1 is a **private link used only during scheduled calls**; phase 2
(a public demo with guided "try it" buttons) comes later and will need more than this kit
(per-visitor accounts, WAF, uptime alert).

Everything here is fake data on a throwaway VM. The kit never needs, stores or asks for a
cloud account, an API token or a DNS credential: you create the VM and the DNS record
yourself, the installer only runs on the VM.

| File | What it is |
|---|---|
| `install.sh` | idempotent installer (Ubuntu/Debian, as root) |
| `democtl.sh` | installed as `/usr/local/sbin/keyorix-demo`: up, down, status, reset, seed, idle-check, destroy |
| `docker-compose.demo.yml` | small overlay on the production compose file (see "What the overlay changes") |
| `Caddyfile.demo` | TLS, security headers, the gate, access log |
| `systemd/` | boot start, nightly reset timer, idle-check timer |
| `demo_hosted_test.go` | the offline checks for all of the above |

## VM size

Recommended: **2 vCPU, 4 GB RAM, 40 GB disk**, Ubuntu 24.04 LTS (or Debian 12), in an EU region.
That is a sizing recommendation, not a measurement: the stack is four small containers plus
Postgres and no load beyond a presenter and a few prospects. Watch `free -m` on the first
call and go down to 1 vCPU / 2 GB only if it stays comfortable. Public IPv4 required
(ACME validation needs ports 80/443 reachable).

## Ports

| Port | Direction | Who | Why |
|---|---|---|---|
| 443/tcp | in | everyone (behind the gate) | the demo |
| 80/tcp | in | everyone | Let's Encrypt HTTP validation and redirect to HTTPS |
| 22/tcp | in | only `--ssh-allow` addresses | administration; `--harden-ssh` makes it key-only |
| 8088/tcp | loopback only | the VM itself | plain-HTTP web, used by the seed hook and for SSH tunnels |
| 5432, 8080 | not published | the compose network only | Postgres and the API server |

Outbound: 443 to Let's Encrypt, `ghcr.io` (images) and the Docker/apt mirrors during install.
Restricting egress further is **not** done by this kit (phase 2 item).

With `--no-firewall` the kit does not touch ufw and you must close everything else in the
cloud provider's firewall. Docker publishes only Caddy's 80/443 to the world, because
Docker-published ports bypass ufw: that is why the overlay moves web's 8088 to the loopback.

## Install

1. Create the VM, add your SSH key, note its public IP.
2. Create the **DNS** record (next section).
3. On the VM, get the repository at a **release tag** (the compose file pins that release's
   images, and the seed scripts must match it):

   ```
   sudo git clone --branch v0.96.0 https://github.com/keyorixhq/keyorix.git /opt/keyorix
   cd /opt/keyorix
   sudo deploy/demo-hosted/install.sh \
     --hostname demo.example.com --acme-email you@example.com \
     --ssh-allow 203.0.113.7/32 \
     --acme-ca staging          # rehearse first; re-run with --acme-ca production when it works
   ```

   Keep the checkout where it is: the installed commands use it. Re-running `install.sh` is
   safe; it re-applies everything, never regenerates an existing secret, and remembers the
   options of the previous run (so `install.sh --idle-minutes 90` changes only that).
4. Open `https://demo.example.com`. The gate asks for the basic-auth user `demo` and the
   password in `/var/lib/keyorix-demo/gate_password`; the first admin's password is in
   `/var/lib/keyorix-demo/secrets/admin_password`. Neither is ever printed.

### Options

| Option | Meaning |
|---|---|
| `--hostname FQDN` | public name (required the first time) |
| `--acme-email ADDRESS` | Let's Encrypt contact (required the first time) |
| `--acme-ca staging\|production` | staging rehearses without production rate limits (default production) |
| `--gate basic\|ip\|both\|none` | what stands in front of the login page; default `basic`; `none` is open to the internet |
| `--allow-ip CIDR[,CIDR]` | addresses that pass the IP gate (required for `ip` and `both`) |
| `--ssh-allow CIDR[,CIDR]\|any` | who may reach port 22 (required unless `--no-firewall`) |
| `--no-firewall` | leave ufw alone (you close the cloud firewall) |
| `--harden-ssh` | key-only SSH; refuses if no authorized key exists, so it cannot lock you out |
| `--idle-action stop\|poweroff\|none` | what to do when idle (default `poweroff`) |
| `--idle-minutes N` | minutes without use before that (default 45, minimum 5) |
| `--grace-minutes N` | a freshly started or reset stack cannot be judged idle for this long (default 30) |
| `--reset-time HH:MM` | nightly reset, UTC (default 03:30) |
| `--seed-script PATH` | repo-relative seed/scenario script run after every reset; repeatable, in order |
| `--require-seed` | a reset fails when no seed script is configured |
| `--no-start` | install but do not start |
| `--render-only` | write the config, secrets and gate into `--state-dir`/`--conf-dir` and stop (tests, dry look) |
| `--state-dir DIR` | default `/var/lib/keyorix-demo` |
| `--conf-dir DIR` | default `/etc/keyorix-demo` |

The ufw rules are rebuilt from scratch on every run (`ufw reset`, then the rules above), so
changing `--ssh-allow` really tightens SSH. The VM is dedicated; do not keep other ufw rules on it.

## DNS: how Andrei points the name at the VM

At the DNS provider of `keyorix.com` (or any domain you control) create:

| Type | Name | Value | TTL |
|---|---|---|---|
| `A` | `demo` (for `demo.keyorix.com`) | the VM's public IPv4 | 300 |
| `AAAA` | `demo` | the VM's public IPv6, **only if** you also allow 80/443 on IPv6 | 300 |

Create it **before** the first `install.sh` run (the installer warns if the name does not
resolve to this VM) and wait until `getent hosts demo.example.com` on the VM shows the IP.
Caddy asks Let's Encrypt for the certificate on the first request and renews it on its own;
the certificate lives in the `keyorix-demo_caddy_data` volume and survives resets. If you
destroy and recreate the VM many times for the same name, remember Let's Encrypt allows only
a handful of duplicate certificates per week: rehearse with `--acme-ca staging`.

IP gating caveat: `--allow-ip` matches the address Caddy sees. IPv4 through Docker's NAT keeps
the client address; if you enable IPv6 on Docker, test the gate from a blocked address before
you rely on it.

## What the overlay changes

`docker-compose.demo.yml` is applied on top of the unmodified production `docker-compose.yml`
(images, Docker-secrets files, read-only root filesystems, dropped capabilities and the TLS
links between the containers are inherited). It changes only:

- project name `keyorix-demo`;
- web published on `127.0.0.1:8088` instead of every interface;
- the server reads the generated `keyorix.demo.yaml`: the shipped `keyorix.docker.yaml` plus
  `storage.database.audit_durability: strict`;
- Caddy runs `Caddyfile.demo` for a hostname that **must** be set.

Applied from the hardening guide (`docs/security/hardening-guide.md`): TLS on every hop and
required (`security.require_transport_tls`), strict audit commit (5a), secret reads audited
(`insecure_audit_skip_reads` stays unset), rate limiting on, Postgres over TLS with
`verify-full`, HSTS/nosniff/frame/referrer/permissions headers at the TLS terminator (the web
container already sends the CSP), no default passwords (every secret is generated per
install), a 0600 bootstrap token, a firewall, key-only SSH on request.

## Safety

- **Fake data only.** Nothing here connects to a real system; do not put a real secret in the demo.
- **Its own KEK.** `master_password` is generated on the VM by `scripts/selfhost/init-secrets.sh`
  (the production path), unique per install, never printed, never shared with anything. Back
  nothing up: the demo is rebuilt from the seed. `install.sh` hands every file in `secrets/` to
  `root:<KEYORIX_SECRETS_GID>` after generating it (the server refuses a secret file owned by any
  other account), except the bootstrap token below.
- **Bootstrap token:** a random value of at least 32 characters in
  `/var/lib/keyorix-demo/secrets/bootstrap_token`, mode `0600`, owned by the server's uid (1001),
  read through `KEYORIX_BOOTSTRAP_TOKEN_FILE`. It is never on a command line.
- **Gate:** basic auth with a generated password and/or an IP allow-list in front of everything,
  including the API. A missing `gate.caddy` stops Caddy rather than serving open.
- **Reset:** see below. If a reset fails after the wipe, Caddy is stopped so nobody meets a
  half-seeded demo.
- **Idle:** see below.
- Not in phase 1: WAF, fail2ban, restricted egress, uptime alert, per-visitor accounts.

## Seed and scenario scripts (placeholder until DEMO-LOCAL-2 merges)

After every reset `keyorix-demo` runs the scripts listed with `--seed-script` (repo-relative
paths, in order), as separate processes, with these variables (paths and names only; the
password and the token are **files** the script reads):

`KEYORIX_DEMO_URL` (`http://127.0.0.1:8088`), `KEYORIX_DEMO_ADMIN_USERNAME`,
`KEYORIX_DEMO_ADMIN_PASSWORD_FILE`, `KEYORIX_DEMO_BOOTSTRAP_TOKEN_FILE`.

DEMO-LOCAL-2 owns the real seed and scenario scripts and this kit neither copies nor edits them.
**At the time this kit was written they were not merged, so the hook is a PLACEHOLDER:** with
no `--seed-script` a reset logs a loud warning and leaves the bootstrap admin only.
When they land:

```
sudo deploy/demo-hosted/install.sh --seed-script scripts/demo/<seed> --seed-script scripts/demo/<scenario> --require-seed
```

Open point for DEMO-LOCAL-2: Keyorix ships with MFA required (ADR-112). Today's `scripts/demo/up.sh`
enrols TOTP for the admin itself and prints the secret for the presenter; the hosted seed has to
do the same (or the presenter enrols on first login), and must not need a pinned weak token.

## Reset

`sudo keyorix-demo reset` is the **full reset back to the seed**: stop the stack, delete the
`keyorix-demo_postgres_data` and `keyorix-demo_keyorix_keys` volumes (the database and the
encryption key files; the master password file is kept, so the new keys are wrapped with this
VM's same KEK secret), start again (the bootstrap admin is recreated from the same secret
files), wait for health, run the seed hook. The issued certificate is **not** touched.

The same command runs nightly from `keyorix-demo-reset.timer` (03:30 UTC by default,
`--reset-time`). The timer is `Persistent=true`: a VM that was powered off at 03:30 resets as
soon as it boots, so the call starts from the calm seed. Start the VM about ten minutes before
a call; the reset takes a couple of minutes.

## Idle shutdown

`keyorix-demo-idle.timer` runs `keyorix-demo idle-check` every 5 minutes. It looks at Caddy's
access log: no successful (2xx/3xx) request for `--idle-minutes`, ignoring `/health`, means
idle; gate rejections and scanners do not count as use. Then it runs `--idle-action`:
`poweroff` (the VM shuts down), `stop` (the containers stop, the VM stays) or `none`. A
freshly booted, started or reset stack is exempt for `--grace-minutes`.

Cost: most providers keep billing a powered-off server for its disk and reserved resources.
`poweroff` saves nothing there; it only limits the exposure window. To stop paying, **destroy**
the VM between call campaigns and rebuild it from this kit (the demo is rebuilt from the seed
anyway, so nothing is lost; use `--acme-ca staging` to rehearse so the real name does not run
into certificate limits).

## Day 2

```
sudo keyorix-demo status        # containers, last reset, gate, idle settings
sudo keyorix-demo reset         # full reset now
sudo keyorix-demo seed          # run the seed hook only, without wiping
sudo keyorix-demo down          # stop the stack, keep data
sudo keyorix-demo up            # start it again
sudo keyorix-demo idle-check    # what the timer runs
sudo keyorix-demo compose logs caddy      # any docker compose command with this install's files
```

## Destroy

```
sudo keyorix-demo destroy --yes
```

removes the containers, **all** volumes (including the certificate), the secrets, the state
and the systemd units. Then, at the provider: delete the VM and its disk, delete the DNS
record, and delete the firewall group if you created one. The repository checkout and
`/usr/local/sbin/keyorix-demo` are left; `rm` them if the VM stays.

## Cost target

A proposed ceiling of **about 10-15 EUR per month while the VM exists** (one small VM, no
managed services, no backups, no load balancer). Prices were not checked for this kit: compare
the provider's current list for the size above before creating the VM. The lever that
actually saves money is destroying the VM when no calls are scheduled.

## Validation status (pending e2e VM)

Offline, in this repository (`go test ./deploy/demo-hosted/`): the overlay and Caddyfile are
parsed and checked against the production compose file (only Caddy publishes publicly; headers;
gate imported by exact name; required hostname; no localhost fallback); `install.sh
--render-only` is run for real (config equals the shipped one plus strict audit, secrets are
generated, a bootstrap token is at least 32 characters and 0600, no secret value is printed,
the gate for every mode, idempotent re-runs, bad input rejected before any change); the reset
and idle logic, the systemd units and this README are checked; `bash -n` and `shellcheck`.

**Pending the real VM** (none of this has run yet): `docker compose config` on the merged
files, Caddy accepting the Caddyfile and issuing the certificate, the containers reading the
0600 token owned by uid 1001, `ufw` and SSH hardening, systemd timers, a real reset with the
seed. First-boot checklist:

1. `sudo keyorix-demo compose config -q` is silent.
2. `curl -sI https://demo.example.com` shows `401` (basic) or `403` (IP), and `strict-transport-security`.
3. With the gate password: the login page loads, the admin logs in.
4. `sudo keyorix-demo reset`, then `sudo keyorix-demo status` shows a fresh "last reset".
5. `sudo systemctl list-timers 'keyorix-demo*'` shows both timers.
6. From an address that is not in `--ssh-allow`: `ssh` times out.
