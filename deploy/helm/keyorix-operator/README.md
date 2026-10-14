# keyorix-operator Helm chart

Deploys the Keyorix Kubernetes **operator** — a controller that reconciles
`KeyorixSecret` custom resources into native Kubernetes Secrets and keeps them current as
upstream values rotate. See [docs/k8s-operator.md](../../../docs/k8s-operator.md).

The chart installs the `KeyorixSecret` CRD (from `crds/`), the controller Deployment, its
ServiceAccount, and RBAC. Each `KeyorixSecret` names its own Keyorix server and a
machine-identity token Secret, so no credentials live in this chart.

```sh
helm install keyorix-operator deploy/helm/keyorix-operator -n keyorix-system --create-namespace
```

## Values

| Key | Description |
| --- | --- |
| `allowedServers` | Trusted Keyorix base URLs a `KeyorixSecret`'s `spec.server` must match (**required to sync anything** — empty rejects every CR, fail closed) |
| `image.repository` / `image.tag` | Operator image (tag defaults to the chart's appVersion) |
| `imagePullSecrets` | Names of existing `docker-registry` Secrets to pull the operator image from a private/mirrored registry — see [Private registries](#private-registries) |
| `replicas` | Manager replicas (keep at 1 unless `leaderElection` is on) |
| `leaderElection` | Run >1 replica safely via a lease in the release namespace (default `false`) |
| `metricsPort` / `healthPort` | Manager metrics (`/metrics`) and probe (`/healthz`,`/readyz`) ports |
| `serviceAccount.create` / `serviceAccount.name` | ServiceAccount control |
| `watchNamespaces` | Restrict this instance (and its RBAC) to these namespaces instead of just its own — see [RBAC](#rbac) |
| `rbac.clusterScoped` | `true` for a genuinely cluster-wide instance (default `false`) — see [RBAC](#rbac) |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations` | Standard pod scheduling/resourcing |

## Failure modes

- **Keyorix unreachable, times out, or returns a 5xx:** treated as transient.
  `Ready` goes `False` with its unchanged reason `SyncError` and a message
  starting `KeyorixUnreachable:`, one Warning Event `KeyorixUnreachable` is
  emitted when the state is entered,
  `keyorix_operator_fetch_errors_total{reason}` counts each failed reconcile,
  and a Normal `KeyorixRecovered` Event follows the first successful read. The
  target Secret is left
  completely untouched and retried on the next reconcile, which
  controller-runtime backs off exponentially (bounded, per-`KeyorixSecret`)
  after a non-nil `Reconcile` error — see [Upgrading: egress
  NetworkPolicy](#upgrading-egress-networkpolicy) above for what "retried"
  actually needs egress for.
- **The operator's own token is rejected (401):** every synced Secret is kept
  untouched, whatever `spec.prunePolicy` says. `Ready` goes `False` with
  reason `UpstreamAccessRevoked` (the historical reason, kept so existing alerts
  keep firing; the message starts with `KeyorixAuthFailed:`), a Warning Event
  `KeyorixAuthFailed` is emitted,
  `keyorix_operator_auth_failures_total` counts it, and the controller retries
  with backoff; fixing the token Secret resumes normal syncing.
- **A referenced secret is deleted upstream, or access to it is revoked:**
  detected (Keyorix returns 404/403) and always
  surfaced distinctly on the `Ready` condition (`reason` `UpstreamSecretGone`). By default (`spec.prunePolicy: Delete` — the
  secure default) the operator actively reaps the target Secret the moment
  its reference is confirmed gone/revoked. Set `spec.prunePolicy: Keep`
  per-CR to opt OUT and leave the target Secret's last-known value untouched
  instead, for deployments that prefer availability over immediate reap —
  see the field's own CRD description.
- **A referenced secret is suspended or expired:** never a reason to delete.
  Only that reference's keys are affected: they are retained by default
  (`spec.onSuspend: Retain`, never overwritten or deleted) while the other keys of
  the same Secret keep syncing; with `spec.onSuspend: Clear` the suspended
  reference's keys are emptied (also while a sibling is expired) and the Secret
  itself stays. A suspension can also ask, for itself, to clear the synced copies
  (the "Also clear copies synced to Kubernetes clusters" choice, a compromise
  response): that reference is then cleared whatever `spec.onSuspend` says, until
  the secret is resumed. An expired source's keys are always retained. Either way the
  `SourceSecretHealthy` condition goes `False` (reason `SourceSecretSuspended` /
  `SourceSecretExpired`), a Warning Event is emitted, and the
  `keyorix_operator_source_secrets{state}` gauge counts it; resuming restores
  the data on the next reconcile and clears all three. Warnings also fire 30, 7
  and 1 days ahead of an expiry (`SourceSecretExpiring`). See
  [docs/k8s-operator.md](../../../docs/k8s-operator.md#suspended-and-expired-secrets).
- **Mass-revocation circuit breaker:** `tokenSecretRef` is commonly *shared*
  across several `KeyorixSecret`s, so a single credential rotation or
  revocation event reads as a simultaneous 404/403 on
  every `KeyorixSecret` that references it, not just one (a rotated credential
  reads as 401, which never wipes) — with
  `prunePolicy: Delete` on by default, an unconditional wipe would otherwise
  delete every target Secret backed by that token, triggered by nothing more
  than a routine credential rotation. Before wiping, the operator checks
  every OTHER `KeyorixSecret` sharing the same `tokenSecretRef`: if more than
  one AND more than 20% of that group are confirmed gone/revoked at once,
  none of them are wiped — the `Ready` condition instead reads
  `MassRevocationSuspected`, a Warning Event is emitted, and the
  `keyorix_operator_mass_revocation_suspected_total` metric increments. A
  single revocation is unaffected and always wipes immediately. To
  acknowledge a suspected mass revocation you've confirmed is intentional
  (e.g. a planned rotation) and proceed with the wipe, annotate the affected
  CR(s) with `keyorix.io/confirm-prune=<RFC3339 timestamp>` (valid for 1 hour
  after it's set) — see the [example](examples/keyorixsecret.yaml).

## Versioning

`Chart.yaml`'s `version`/`appVersion` are release.yml-overridden at publish
time and picks `image.tag`'s default for a local `helm install` otherwise —
this chart's committed value must be bumped in lockstep with
`deploy/helm/keyorix` and `deploy/helm/keyorix-k8s-sync` (all three publish
alongside the same release tag). See
[`deploy/helm/keyorix`'s own "Versioning" section](../keyorix/README.md#versioning)
for the full policy — this chart was found 3 releases behind by that same
drift (confirmed live against `ghcr.io/keyorixhq/keyorix-operator`, not
assumed) and bumped alongside it.

## RBAC

A `ClusterRole` grants read on `keyorixsecrets` (+ status) and
get/list/watch/create/update/patch/delete on `secrets` (`delete` is used only to remove the
target Secret once the upstream Keyorix reference is confirmed gone). A namespaced `Role`
grants the lease + event access leader election needs. The operator reads secret **values**
only through the Keyorix API (with each `KeyorixSecret`'s machine token) — never from the
cluster.

**By default (ADR-076) a single operator instance watches `KeyorixSecret` CRs in its own
release namespace only**, and the `ClusterRole` above is bound via a namespace-scoped
`RoleBinding` in that namespace — an unmodified `helm install` never grants access outside
where you installed it. Two opt-in modes, mutually exclusive with each other (setting both
makes the chart refuse to render, naming both values in the error):

- **`watchNamespaces: [team-a, team-b]`** — one instance managing a bounded, known set of
  namespaces. Binds a `RoleBinding` in each listed namespace.
- **`rbac.clusterScoped: true`** — one instance managing every namespace in the cluster,
  with no static list (the only way to reach this; it is no longer the default). Binds a
  cluster-wide `ClusterRoleBinding`.

```sh
# Bounded multi-namespace
helm install keyorix-operator-team-a deploy/helm/keyorix-operator -n team-a \
  --set 'watchNamespaces={team-a}'

# Cluster-wide (preserves the pre-ADR-076 default; see the CHANGELOG's BREAKING entry
# if you're upgrading an existing install that relied on it)
helm install keyorix-operator deploy/helm/keyorix-operator -n keyorix-system \
  --create-namespace --set rbac.clusterScoped=true
```

Both values feed a single named template (`_helpers.tpl`'s `kxop.scope`) that both
`rbac.yaml` and `deployment.yaml` render from, so the RBAC binding and the manager's own
`-watch-namespaces`/`-all-namespaces` flag can't drift apart — the same `ClusterRole`
object always exists (a Kubernetes RBAC object type, needed for manifest reusability
across modes), but what it's actually *bound* to is what determines real access. Do not
deploy more than one instance watching the same namespace with different configs.

## Upgrading: egress NetworkPolicy

`networkPolicy.egress.enabled` (default `true`) makes the manager's OUTBOUND
traffic default-deny — previously it was unrestricted. Read this before your
next `helm upgrade` on an existing install.

**What the default rules allow:** DNS (UDP/TCP 53), plus TCP `443` and TCP
`6443` to ANY destination — by port only, not by destination, since neither
the Kubernetes API server nor a `KeyorixSecret`'s `spec.server` is a
`podSelector`-able target. This covers the two ports a Kubernetes API server
and an https Keyorix server overwhelmingly listen on.

**Will silently stop working** if the Kubernetes API server or any
`KeyorixSecret`'s `spec.server` listens on a different port — reconciliation
of that CR stops with no clear error (see Troubleshooting below). This is
separate from, and on top of, `allowedServers`: a `spec.server` not in
`allowedServers` is rejected outright by the controller (a fast, explicit
error in `.status`); a `spec.server` that IS allowed but listens on a
non-standard port is instead silently dropped at the network layer.

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

> ⚠️ This removes ALL egress restriction on the manager pod — a compromised
> pod can then reach anything the cluster network permits. Prefer
> `extraRules` over disabling this outright.

**Troubleshooting:** an egress `NetworkPolicy` drops packets silently — the
symptom is a **connection timeout**, never "connection refused". If a
`KeyorixSecret` stops syncing right after this upgrade:

```sh
kubectl -n <namespace> describe networkpolicy <release>-keyorix-operator-metrics
```

## Private registries

For an air-gapped deployment that mirrors `keyorix-operator`'s image to a private,
authenticated registry, create a `docker-registry` Secret in the release namespace and
reference it via `imagePullSecrets`:

```sh
kubectl create secret docker-registry my-registry-cred \
  -n keyorix-system \
  --docker-server=my-mirror.example.com \
  --docker-username=... --docker-password=...

helm install keyorix-operator deploy/helm/keyorix-operator -n keyorix-system \
  --set image.repository=my-mirror.example.com/keyorix-operator \
  --set 'imagePullSecrets[0].name=my-registry-cred'
```

## Uninstalling

`helm uninstall` removes the controller and RBAC. Helm does **not** remove CRDs it
installed from `crds/`; delete the CRD manually if you want the `KeyorixSecret` type gone
(this also deletes all `KeyorixSecret` objects and the Secrets they own):

```sh
kubectl delete crd keyorixsecrets.secrets.keyorix.io
```
