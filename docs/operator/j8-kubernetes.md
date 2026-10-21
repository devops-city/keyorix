# Deploying on Kubernetes

Installing the Helm chart with defaults, checking it is healthy, and upgrading. The
chart's own reference is [`deploy/helm/keyorix/README.md`](../../deploy/helm/keyorix/README.md);
this page is the short path. Not re-run on a cluster for this revision (kind needs the
e2e VM); `scripts/k8s-e2e/run.sh` is the automated journey that installs the chart this
way.

## 1. Install with defaults

Never pass a password on the command line (`--set auth.masterPassword=...`,
`kubectl create secret --from-literal=...`): while the command runs, every local
user can read its arguments (`ps`), and afterwards they stay in shell history and
CI logs. Put each secret in an owner-only file, create the Secret from the files,
and point the chart at it with `auth.existingSecret` (same steps as the chart
README's "Quick start"). The admin password must meet the bootstrap policy: at
least 16 characters, with upper and lower case, a digit and a special character.

```bash
umask 077                      # new files: owner-only (0600 / 0700)
mkdir keyorix-secrets
# `read -s` does not echo (bash and zsh), and printf is a shell builtin, so no
# secret reaches a process's argv. The file name is the key in the Secret.
printf 'Master password (keep it, it derives the KEK): '; read -r -s v; echo
printf '%s' "$v" > keyorix-secrets/KEYORIX_MASTER_PASSWORD
printf 'Database password: '; read -r -s v; echo
printf '%s' "$v" > keyorix-secrets/KEYORIX_DB_PASSWORD
printf 'Admin password: '; read -r -s v; echo
printf '%s' "$v" > keyorix-secrets/KEYORIX_ADMIN_PASSWORD
unset v
# The bootstrap token is required whenever an admin password is set. Generated into the file,
# so it never appears in a command line.
LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32 > keyorix-secrets/KEYORIX_BOOTSTRAP_TOKEN

kubectl create secret generic keyorix-auth --from-file=keyorix-secrets/
helm install keyorix ./deploy/helm/keyorix --set auth.existingSecret=keyorix-auth

# Once the master password is in your password manager:
rm -r keyorix-secrets
```

The credentials that matter (the Secret's keys, `KEYORIX_*`; the chart's equivalent
values are `auth.masterPassword`, `auth.adminPassword` and `postgresql.auth.password`):

- `KEYORIX_MASTER_PASSWORD` (`auth.masterPassword`): derives the encryption key. Set it once and keep it; changing
  it after first boot makes every stored secret undecryptable. Keep the
  `keyorix-auth` Secret's source files somewhere safe and offline.
- `KEYORIX_ADMIN_PASSWORD` (`auth.adminPassword`): the first admin is created at first boot. It must be at least
  16 characters with an uppercase letter, a lowercase letter, a digit and a special
  character, and must not contain the admin username, the email's local part or
  "Administrator". The chart refuses to render a shorter password or one containing the
  username; the other rules are checked by the server at first boot (the pod exits with
  the reason in its log). Leave it empty to run `keyorix system init` yourself.
- `KEYORIX_DB_PASSWORD` (`postgresql.auth.password`): the bundled PostgreSQL password.

`KEYORIX_BOOTSTRAP_TOKEN` is required in the Secret when `KEYORIX_ADMIN_PASSWORD` is set (without it the server
pod exits at first boot and restarts in a loop; the reason is in `kubectl logs`). Put it in the Secret before
`helm install`: the chart reads the Secret at install and upgrade time.

The install prints next steps (`NOTES.txt`), including how to reach the UI and the
warning to back up the encryption-keys volume.

## 2. Check pod health

```bash
kubectl get pods -l app.kubernetes.io/instance=keyorix -w
```

`postgresql`, `server` and `web` should reach `1/1 Running`. The server's first boot runs
migrations and key derivation, so give it a few minutes before reading anything into a
restart. If `server` does not become ready:

```bash
kubectl logs deploy/keyorix-keyorix-server
kubectl logs deploy/keyorix-keyorix-server --previous
```

(The Deployment name is `<release>-keyorix-server` for a release named `keyorix`.) An
admin password the policy refuses shows up here as `admin password rejected: <reason>`;
fix the value and run `helm upgrade`, a rejected password writes nothing.

## 3. Reach the UI

```bash
kubectl port-forward svc/keyorix-keyorix-web 8080:80
```

Open <http://localhost:8080> and log in as `admin` with the password you set. The first
login is confined to MFA enrolment (`security.require_mfa` defaults on).

With the secure baseline on (the default), the server itself speaks TLS only. To use the
CLI against it directly, trust its certificate as `NOTES.txt` shows.

## 4. Upgrade

The passwords stay in the `keyorix-auth` Secret, so the upgrade passes none:

```bash
helm upgrade keyorix ./deploy/helm/keyorix \
  --set auth.existingSecret=keyorix-auth \
  --set web.replicaCount=2
```

Read the chart README's "Upgrading: egress NetworkPolicy" section and
[UPGRADING.md](../UPGRADING.md) section 5 (Helm-specific steps, including the
bundled-PostgreSQL ownership change) before your first upgrade of an existing install.
Take a backup first ([SELF_HOSTING.md](../SELF_HOSTING.md) section 5).
