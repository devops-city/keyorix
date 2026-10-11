# Keyorix Helm chart

Deploy the self-hosted [Keyorix](https://github.com/keyorixhq/keyorix) secrets
manager — API server + web UI + PostgreSQL — to Kubernetes. It mirrors the
docker-compose stack: a single-instance server holding the encryption keys on a
persistent volume, the web UI proxying to it, and a bundled (or external) Postgres.

## Quick start

From a published release (the chart is pushed to GHCR as an OCI artifact on each
`vX.Y.Z` tag):

```sh
helm install keyorix oci://ghcr.io/keyorixhq/charts/keyorix \
  --set auth.masterPassword='change-me-and-keep-it' \
  --set postgresql.auth.password='a-strong-db-password' \
  --set auth.adminPassword='S3cure-Passphrase!9'
```

> `auth.adminPassword` must satisfy the server's own admin-bootstrap password
> policy (`POST /system/init`): **at least 16 characters, with an uppercase
> letter, a lowercase letter, a digit, and a special character — and it must
> not contain the admin username, email, or display name as a substring**
> (the default username is literally `admin`, so a password like
> `Admin-Something123!` fails this even though it looks strong). The chart
> fails the render early (a clear `helm install`/`template` error) if it's
> under 16 characters; the other rules aren't chart-checkable — get those
> wrong and the first-boot bootstrap fails instead (the pod comes up,
> `helm install`/`helm test` succeed, but no admin user is ever created —
> see `kubectl logs` for the server pod for the actual reason). First-boot
> bootstrap is atomic and retryable: a rejected password writes nothing, so
> simply retrying `keyorix system init` (or `helm upgrade` with a corrected
> `auth.adminPassword`, since bootstrap re-runs on every restart until the
> install is initialised) with a compliant password completes the install —
> no DB wipe needed.

Or from a source checkout, swap the chart reference for `./deploy/helm/keyorix`.

Then follow the printed NOTES (port-forward the web service and log in). After
install you can smoke-test the deployment:

```sh
helm test keyorix
```

> ⚠️ **`auth.masterPassword` derives the encryption KEK.** Set it once and keep it
> — changing it, or losing the server's keys PVC, makes every stored secret
> undecryptable. For production, supply it via `auth.existingSecret` and back up
> the `*-server-keys` PVC.

## Key values

| Value | Default | Notes |
|-------|---------|-------|
| `auth.masterPassword` | — | **Required** (or `auth.existingSecret`). KEK passphrase. |
| `auth.existingSecret` | — | Bring your own Secret (`KEYORIX_MASTER_PASSWORD`, `KEYORIX_DB_PASSWORD`, opt. `KEYORIX_ADMIN_PASSWORD`). |
| `auth.adminPassword` | — | Optional first-boot admin bootstrap (idempotent). ≥16 chars, upper+lower+digit+special — see quick start note above. |
| `server.image.tag` | chart `appVersion` | Server image tag (empty pins to the chart's own `appVersion`; `server.image.digest` takes precedence if set). |
| `web.image.tag` | chart `appVersion` | Web UI image tag (same default/precedence as `server.image.tag`). |
| `server.keysPersistence.*` | 1Gi RWO | The encryption-keys PVC (`resource-policy: keep`). |
| `web.enabled` | `true` | Deploy the UI (with a k8s-adapted nginx that proxies to the server Service). |
| `ingress.*` | disabled | Ingress for the web UI. |
| `postgresql.enabled` | `true` | Bundled Postgres for evaluation. |
| `postgresql.auth.password` | — | Required when bundled DB is enabled. |
| `externalDatabase.*` | — | Used when `postgresql.enabled=false` (managed/HA Postgres). |
| `secureBaseline.enabled` | `false` | ADR-112 secure baseline: server TLS (Helm-generated certificate, verified by the web pod), rate limiting, `/metrics` token, bundled Postgres over TLS, runtime files 0600. `admin validate --posture` then reports zero deviations. **Needs a server image newer than v0.95.3**; becomes the default with the next release. See below. |

## Upgrading: egress NetworkPolicy

`networkPolicy.egress.enabled` (default `true`) makes every pod's OUTBOUND
traffic default-deny — previously it was unrestricted (any pod could reach
anything the cluster network permits). Read this before your next
`helm upgrade` on an existing install.

**What the default rules allow:**

- `web`: DNS (UDP/TCP 53) + the `server` Service on its ClusterIP, port
  `server.service.port` (default `8080`). Nothing else.
- `postgresql` (when bundled): no egress at all — it never initiates an
  outbound connection of its own.
- `server`: DNS (UDP/TCP 53) + the bundled `postgresql` Service on `5432`
  (only when `postgresql.enabled: true`). `server` gets no other egress by
  default — see below.

**Features that dial OUT from `server` and will silently stop working** the
moment egress restriction is on, unless you add an `extraRules` entry for
them:

- SMTP (email notifications / credential rotation over SMTP)
- Syslog/SIEM audit-event forwarding (`siem.push` in `keyorix.yaml`)
- LDAP (identity/auth backend)
- A checkpoint notary / TSA (RFC 3161 timestamp authority) endpoint
- Secret-rotation backends (Vault, Azure, AWS, custom KMS) on whatever port
  they listen on
- Webhook notification sinks
- `externalDatabase.host` (when `postgresql.enabled: false`), especially on a
  non-default (non-`5432`) port
- Any SSO/OIDC/SAML identity provider

**Add an `extraRules` entry per destination** — e.g. an external Postgres on a
non-default port, plus an SMTP relay:

```yaml
networkPolicy:
  egress:
    extraRules:
      - to:
          - ipBlock: { cidr: 10.0.5.10/32 }
        ports:
          - protocol: TCP
            port: 5433
      - to:
          - ipBlock: { cidr: 10.0.9.0/24 }
        ports:
          - protocol: TCP
            port: 587
```

(`to` accepts `ipBlock`, `podSelector`, and `namespaceSelector` — the same
shape as a raw Kubernetes `NetworkPolicyEgressRule`.)

**To turn egress restriction off entirely:**

```yaml
networkPolicy:
  egress:
    enabled: false
```

> ⚠️ This removes ALL egress restriction on every pod in this chart — a
> compromised pod can then reach anything the cluster network permits,
> including other namespaces and any cloud metadata endpoint. Prefer
> `extraRules` over disabling this outright.

**Troubleshooting:** an egress `NetworkPolicy` drops packets silently — the
symptom is a **connection timeout**, never "connection refused" (refused
means a packet reached the destination and got a TCP RST back; a
NetworkPolicy drop means it never left the pod's network namespace). If a
feature that used to work stops working right after this upgrade:

```sh
kubectl -n <namespace> describe networkpolicy <release>-keyorix-server
```

and confirm the destination/port you need is covered by an existing rule or
your own `extraRules`.

## Production notes

- **External database:** set `postgresql.enabled=false` and `externalDatabase.host`
  (+ `externalDatabase.password` via `auth.existingSecret`), pointing at a managed
  or HA PostgreSQL. The bundled Postgres is single-instance, for evaluation.
- **Single server instance:** the server is pinned to 1 replica — it owns the
  ReadWriteOnce keys volume and a per-instance KEK; it is not horizontally scalable.
- **Backups:** back up both the database and the `*-server-keys` PVC. You need
  both (plus the master password) to recover.
- **TLS:** terminate at the ingress (`ingress.tls` + cert-manager annotations).
- **Secure baseline (`secureBaseline.enabled=true`):** Helm generates a
  `<fullname>-secure-baseline` Secret (e.g. `kx-keyorix-secure-baseline`) on first install, kept across upgrades:
  the server's self-signed certificate for its Service names, the `/metrics`
  token, and a certificate for the bundled Postgres. The server serves and
  requires TLS; the web pod's nginx verifies exactly that certificate; the
  server connects to the bundled Postgres with `ssl_mode: require`; an
  initContainer copies the config, certificate, key and token into a memory
  emptyDir at 0600 owned by the server's uid (#2922). Give Prometheus the token
  (`kubectl get secret <fullname>-secure-baseline -o jsonpath='{.data.metrics_token}' | base64 -d`).
  To rotate the certificates or token, delete that Secret and `helm upgrade`,
  then restart the pods. Verified on kind: posture `No deviations found.`,
  server-to-Postgres TLS 1.3, `helm test` and a CLI journey through the web
  Service.
- **Swap:** run the nodes backing this deployment with swap disabled (the
  Kubernetes default). Decrypted secret memory is not locked against swap
  in-process (see `docs/adr-100-mlockall-removal-deployment-swap-control.md`
  for why an in-process lock was tried and removed) — this is now a
  deployment-level control, not something the chart or server configures for
  you.

## Image pinning

`server.image.digest`/`web.image.digest` (empty by default; see their own
`values.yaml` comments) take precedence over `.tag` and pin the exact image
content, immune to a tag being retargeted after the fact — set these for
production. The default (tag-based, pinned to this chart's own `appVersion`,
never `latest`) is not currently auto-populated with the real digest at
release time: `release.yml`'s `helm package` step and `docker-publish.yml`'s
image build+push+cosign-sign step are separate, parallel jobs on the same
`v*` tag push with no data flow between them, so the digest
`docker-publish.yml` captures (`steps.build.outputs.digest`) never reaches
the packaged chart's `values.yaml`. Wiring that (with the resolved tag kept
as an adjacent comment for auditability) needs a change to `release.yml`/
`docker-publish.yml` themselves, not this chart — outside `deploy/helm/**`.

## Versioning

`version` and `appVersion` in `Chart.yaml` are release.yml-overridden at
publish time (`helm package --version/--app-version`, derived from the `v*`
git tag), so the OCI chart published to `ghcr.io/keyorixhq/charts/keyorix` is
always correct regardless of what's committed. The committed value still
matters for a LOCAL `helm install ./deploy/helm/keyorix` without an explicit
`--set`/`--version` override — it's what picks `server.image.tag` and
`web.image.tag`'s default (`default .Chart.AppVersion .Values.X.image.tag` in
`_helpers.tpl`). This has drifted stale — pointing at an older image tag than
what's actually being released — **twice** now (last confirmed 2026-09-25,
0.88.0 committed vs. 0.89.0 actually published). **Policy: bump this chart's
`version`/`appVersion` (and `deploy/helm/keyorix-k8s-sync` and
`deploy/helm/keyorix-operator`'s, in lockstep, since all three publish
alongside the main server/web images on the same release tag) as part of any
PR that changes `deploy/helm/**` content meaningfully, and independently as
part of cutting every release** — don't rely on remembering to do this only
at release time. No CI check enforces this today (a machine check would need
to compare the committed value against the actual latest published tag,
which isn't something PR-time CI can safely query against a moving target);
treat this section as the explicit, considered "declining to enforce
mechanically" this repo's own engineering practice calls for when a real
check isn't a good fit.
