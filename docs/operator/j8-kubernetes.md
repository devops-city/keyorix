# Deploying on Kubernetes

Installing the Helm chart with defaults, checking it is healthy, and upgrading. The
chart's own reference is [`deploy/helm/keyorix/README.md`](../../deploy/helm/keyorix/README.md);
this page is the short path. Not re-run on a cluster for this revision (kind needs the
e2e VM); `scripts/k8s-e2e/run.sh` is the automated journey that installs the chart this
way.

## 1. Install with defaults

Keep the credentials in a file with mode 0600 and pass it with `-f`, never with `--set`
(a `--set` value is visible in `ps` and shell history):

```bash
umask 077
printf 'auth:\n  masterPassword: "%s"\n  adminPassword: "%s"\npostgresql:\n  auth:\n    password: "%s"\n' \
  "$(openssl rand -base64 32)" "$(openssl rand -base64 18)-Aa1!" "$(openssl rand -hex 24)" \
  > keyorix-values.yaml

helm install keyorix ./deploy/helm/keyorix -f keyorix-values.yaml
```

The values that matter:

- `auth.masterPassword`: derives the encryption key. Set it once and keep it; changing
  it after first boot makes every stored secret undecryptable. Store `keyorix-values.yaml`
  (or the Secret it creates) somewhere safe and offline.
- `auth.adminPassword`: the first admin is created at first boot. It must be at least
  16 characters with an uppercase letter, a lowercase letter, a digit and a special
  character, and must not contain the admin username, the email's local part or
  "Administrator". The chart refuses to render a shorter password or one containing the
  username; the other rules are checked by the server at first boot (the pod exits with
  the reason in its log). Leave it empty to run `keyorix system init` yourself.
- `postgresql.auth.password`: the bundled PostgreSQL password.

To keep the credentials in a Secret you manage, set `auth.existingSecret` instead (keys
`KEYORIX_MASTER_PASSWORD`, `KEYORIX_DB_PASSWORD`, optionally `KEYORIX_ADMIN_PASSWORD` and
`KEYORIX_BOOTSTRAP_TOKEN`).

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

```bash
helm upgrade keyorix ./deploy/helm/keyorix -f keyorix-values.yaml --reset-then-reuse-values
```

Read the chart README's "Upgrading: egress NetworkPolicy" section and
[UPGRADING.md](../UPGRADING.md) section 5 (Helm-specific steps, including the
bundled-PostgreSQL ownership change) before your first upgrade of an existing install.
Take a backup first ([SELF_HOSTING.md](../SELF_HOSTING.md) section 5).
