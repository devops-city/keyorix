# keyorix-k8s-sync Helm chart

Deploys the [Keyorix Kubernetes sync agent](../../../docs/k8s-sync.md): it
materialises selected Keyorix secrets into native Kubernetes Secrets and refreshes
them as the upstream values rotate.

## Install

First create a Secret holding the agent's Keyorix machine-identity token:

```sh
kubectl -n keyorix create secret generic keyorix-token --from-literal=token=<TOKEN>
```

Then install with your mappings — from the published OCI chart:

```sh
helm install kx-sync oci://ghcr.io/keyorixhq/charts/keyorix-k8s-sync --version <release> \
```

…or from this repo checkout:

```sh
helm install kx-sync deploy/helm/keyorix-k8s-sync \
  --namespace keyorix --create-namespace \
  --set keyorix.url=https://keyorix.internal \
  --set keyorix.projectID=42 \
  --set keyorix.tokenSecret.name=keyorix-token \
  --set 'mappings[0].ref=production/db-password' \
  --set 'mappings[0].namespace=app' \
  --set 'mappings[0].name=db-creds' \
  --set 'mappings[0].key=DB_PASSWORD' \
  --set 'targetNamespaces={app}'
```

## Values

| Key | Description |
| --- | --- |
| `keyorix.url` | Keyorix server base URL (**required**) |
| `keyorix.projectID` | Numeric id of the Keyorix project the token's machine identity belongs to (**required**) — every `mappings[].ref` names only an environment and secret, never a project, since environment names are unique per-project, not globally |
| `keyorix.interval` | Reconcile cadence (Go duration; default `5m`) |
| `cleanup` | Reap orphaned owned Secrets when a mapping is removed (default `false`) |
| `onSuspend` | What happens to a target Secret while its Keyorix source is suspended: `retain` (default) keeps that source's key as is (the other keys keep syncing), `clear` empties that source's key (never deletes the Secret). An expired source's key is always retained. See [Suspended and expired sources](../../../docs/k8s-sync.md#suspended-and-expired-sources) |
| `pruneOnRevoke` | Actually delete/trim a Secret when its upstream Keyorix reference is confirmed gone or access is revoked, instead of leaving the last-known value untouched (default `true` — the secure default; bounded by the mass-revocation circuit breaker, see [Failure modes](#failure-modes)) |
| `massPruneAck` | RFC3339 timestamp acknowledging a suspected mass revocation, valid for 1 hour (default empty — see [Failure modes](#failure-modes)) |
| `keyorix.tokenSecret.name` | Existing Secret holding the Keyorix token (**required**) |
| `keyorix.tokenSecret.key` | Key within that Secret (default `token`) |
| `mappings` | List of `{ref, namespace, name, key}` — Keyorix secret → Kubernetes Secret key |
| `targetNamespaces` | Namespaces the agent may write Secrets in (RoleBinding per ns); defaults to the release namespace |
| `image.repository` / `image.tag` | Agent image (tag defaults to the chart's appVersion) |
| `serviceAccount.create` / `serviceAccount.name` | ServiceAccount control |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations` | Standard pod scheduling/resourcing |

## Upgrading: egress NetworkPolicy

`networkPolicy.egress.enabled` (default `true`) makes the agent's OUTBOUND
traffic default-deny — previously it was unrestricted. Read this before your
next `helm upgrade` on an existing install.

**What the default rules allow:** DNS (UDP/TCP 53), plus TCP `443` and TCP
`6443` to ANY destination — by port only, not by destination, since neither
the Kubernetes API server nor `keyorix.url` is a `podSelector`-able target.
This covers the two ports a Kubernetes API server and an https Keyorix server
overwhelmingly listen on.

**Will silently stop working** if your `keyorix.url` or your cluster's API
server listens on a different port — the agent stops reconciling with no
clear error (see Troubleshooting below), just a growing gap since its last
successful sync.

**Add an `extraRules` entry** for a non-standard port — e.g. a Keyorix server
on `:8443`:

```yaml
networkPolicy:
  egress:
    extraRules:
      - ports:
          - protocol: TCP
            port: 8443
```

**To turn egress restriction off entirely:**

```yaml
networkPolicy:
  egress:
    enabled: false
```

> ⚠️ This removes ALL egress restriction on the agent pod — a compromised pod
> can then reach anything the cluster network permits. Prefer `extraRules`
> over disabling this outright.

**Troubleshooting:** an egress `NetworkPolicy` drops packets silently — the
symptom is a **connection timeout**, never "connection refused". If reconciles
stop working right after this upgrade:

```sh
kubectl -n <namespace> describe networkpolicy <release>-keyorix-k8s-sync
```

## Failure modes

- **Keyorix unreachable, or returns a 5xx:** treated as transient. The target
  Secret(s) affected are skipped for that pass — left completely untouched,
  never written with a missing/partial value — and retried at the next pass
  (see "Retry cadence" below for the backoff this now applies on repeated
  failure).
- **A specific secret is deleted upstream, or a token is revoked/expired:**
  detected (Keyorix returns 401/403/404). By default (`pruneOnRevoke: true`
  — the secure default) the target Secret is actively wiped/trimmed the
  moment its reference is confirmed gone/revoked, counted as `revoked` —
  visible via `/status`'s `revoked` field and the
  `keyorix_k8s_sync_secrets_total{outcome="revoked"}` metric. Set
  `pruneOnRevoke: false` to opt OUT and leave the target Secret's last-known
  value untouched instead, for deployments that prefer availability over
  immediate reap.
- **Mass-revocation circuit breaker:** a revoked or expired agent token reads
  as the exact same failure on *every* mapping's fetch, not just one — with
  `pruneOnRevoke` on by default, an unconditional wipe would otherwise delete
  or trim every Secret the agent manages in a single pass, triggered by
  nothing more than a routine credential rotation. When a SINGLE reconcile
  pass would wipe more than one target AND more than 20% of everything this
  agent manages, none of them are wiped: the pass instead reports "MASS
  REVOCATION SUSPECTED" — visible via `/status`'s `suspected` field and the
  `keyorix_k8s_sync_secrets_total{outcome="mass_revocation_suspected"}`
  metric — until acknowledged via `massPruneAck` (an RFC3339 timestamp,
  valid for 1 hour after it's set). A single revocation is unaffected by the
  breaker and always wipes immediately, regardless of what fraction of a
  very small mapping set it represents.
- **Retry cadence:** the agent's default poll interval (`keyorix.interval`,
  5m) applies as long as every pass is clean. After a pass with any failed or
  revoked target, the next pass's delay backs off exponentially (bounded at
  8x the configured interval) with up to ±20% jitter, resetting to the plain
  interval the moment a pass is fully clean again — so a sustained outage or
  revocation doesn't retry at the same cadence as healthy operation
  indefinitely, and multiple agent replicas recovering from a shared outage
  don't all retry in lockstep.

## Versioning

`Chart.yaml`'s `version`/`appVersion` are release.yml-overridden at publish
time and picks `image.tag`'s default for a local `helm install` otherwise —
this chart's committed value must be bumped in lockstep with
`deploy/helm/keyorix` and `deploy/helm/keyorix-operator` (all three publish
alongside the same release tag). See
[`deploy/helm/keyorix`'s own "Versioning" section](../keyorix/README.md#versioning)
for the full policy — this chart was found 3 releases behind by that same
drift (confirmed live against `ghcr.io/keyorixhq/keyorix-k8s-sync`, not
assumed) and bumped alongside it.

## RBAC

The chart creates a `ClusterRole` (`secrets`: `get`/`list`/`create`/`patch`/`delete`)
and a namespaced `RoleBinding` in each `targetNamespaces` entry — least privilege, no
cluster-wide Secret access. `get`/`patch`/`delete` are further scoped with
`resourceNames` to exactly the Secret names in `mappings`, so the ClusterRole cannot
touch any Secret this release doesn't manage; `create` and `list` cannot be
`resourceNames`-scoped (a Kubernetes RBAC limitation, not an oversight — see the
comment in `templates/rbac.yaml`) and so remain granted on the `secrets` resource type
as a whole. The agent uses Server-Side Apply (field manager `keyorix-sync`), so it
owns the Secret `data` it writes and prunes keys it no longer maps. `list`/`delete`
are exercised only when `cleanup: true` (orphan reaping); see
[docs/k8s-sync.md](../../../docs/k8s-sync.md#orphan-cleanup-cleanup).
