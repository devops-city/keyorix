# Keyorix Kubernetes operator

The Keyorix operator reconciles **`KeyorixSecret`** custom resources into native
Kubernetes Secrets and keeps them current as upstream values rotate. It is the
`kubectl apply`-able, per-object-status delivery model — an alternative to the
[sync agent](k8s-sync.md) and the [External Secrets Operator](k8s-eso.md) integration.

| | Operator (this page) | [sync agent](k8s-sync.md) | [ESO](k8s-eso.md) |
|---|---|---|---|
| API | `KeyorixSecret` CRD | Agent config (Helm values) | `ExternalSecret` CRD |
| Reference by | `project/environment/name` | `environment/name` | `project/environment/name` |
| Per-object status | ✅ `Ready` condition | ✗ (one agent status) | ✅ |
| Orphan cleanup | Owner-reference GC | `cleanup: true` (ADR-057) | `creationPolicy: Owner` |
| Best when | You want a native CR | A self-contained agent | You standardise on ESO |

All three read over the same authorized Keyorix API (scoped `secrets.read`, `max_reads`,
suspension, audit) and never log values.

## How it works

For each `KeyorixSecret`, the controller reads the machine-identity token from the
referenced Secret, fetches each value through the by-reference read endpoint
(`GET /api/v1/secrets/value?ref=…`, ADR-059), and creates/updates the target Secret —
**owned by the `KeyorixSecret`**, so deleting the CR garbage-collects the Secret. It then
sets a `Ready` condition and requeues after `refreshInterval`.

A fetch failure is handled differently depending on what it means:

- **Keyorix cannot answer** (server unreachable, timeout, 5xx): the target Secret is left
  completely untouched — no partial write, no wipe. `Ready` goes `False` with its
  historical reason `SyncError` (unchanged, so existing alerts keep firing); the detail is
  in the message, which starts with `KeyorixUnreachable:`; one Warning Event
  `KeyorixUnreachable` is raised when the state is entered (not on every retry),
  `keyorix_operator_fetch_errors_total{reason="unreachable|timeout|server_error"}` counts
  each failed reconcile, and the controller backs off and retries. The first successful
  read raises a Normal Event `KeyorixRecovered` and `Ready` returns to `True`. Other
  failures (token Secret missing or unlabelled, server not in `allowedServers`, a
  Kubernetes API error while applying) are also `SyncError`: `Ready=False`, no
  `KeyorixUnreachable` message prefix, no Event, no dedicated counter.
- **The operator's own credential is rejected** (Keyorix returns **401**: the token in
  `tokenSecretRef` is invalid, expired or rotated): every synced Secret is **kept
  untouched**, whatever `spec.prunePolicy` says. A 401 is about the operator's credential,
  not about this workload's grant, so it is never grounds to wipe. `Ready` goes `False`
  with reason `UpstreamAccessRevoked` (the reason this path has always used, kept so
  existing alerts keep firing even though the Secret is no longer wiped) and a message that
  starts with `KeyorixAuthFailed:`; one Warning Event `KeyorixAuthFailed` is raised when the
  state is entered, `keyorix_operator_auth_failures_total` counts each failed reconcile, and
  the controller retries with backoff. Fix or rotate the token Secret and the next retry
  syncs normally.
- **Affirmatively gone or revoked** (Keyorix returns 404/403 — the referenced secret no
  longer exists, or this workload's access to it was removed): the target Secret is
  **wiped** per `spec.prunePolicy` (`Ready` goes `False` with reason
  `UpstreamSecretGone`), subject to the mass-revocation circuit breaker. This is
  deliberate — leaving a previously-synced plaintext value sitting in the cluster
  indefinitely after access was deliberately cut would be a worse outcome than a workload
  losing the Secret it depends on.

## Suspended and expired secrets

A Keyorix secret can be *suspended* (an operator's "block value reads" switch; the
server answers `409 SecretSuspended`) or *expire* (`409 SecretExpired`). Neither is a
revoked grant, so neither deletes the target Secret. What happens, by cause:

| Cause | Target Secret | `Ready` | Also raised |
| --- | --- | --- | --- |
| Server **unreachable, timeout, 5xx** | **Never modified or deleted.** Retried with backoff; syncs normally once Keyorix answers | `False`, reason `SyncError` (unchanged), message `KeyorixUnreachable: …` | Warning Event `KeyorixUnreachable` (once on entry), counter `keyorix_operator_fetch_errors_total{reason="unreachable\|timeout\|server_error"}`, Normal Event `KeyorixRecovered` on recovery |
| Token Secret missing / unlabelled, apply error | **Never modified or deleted.** Retried with backoff | `False`, reason `SyncError` | — |
| **401** — the operator's own credential rejected | **Kept** (never wiped, whatever `prunePolicy` is). Retried with backoff; syncs normally once the token is fixed | `False`, reason `UpstreamAccessRevoked` (historical reason, kept for alerts), message `KeyorixAuthFailed: …` | Warning Event `KeyorixAuthFailed`, counter `keyorix_operator_auth_failures_total` |
| **403 / 404** — grant revoked / secret deleted | **Pruned per `spec.prunePolicy`** (Delete by default; Keep leaves it), behind the mass-revocation circuit breaker | `False`, reason `UpstreamSecretGone` | — |
| Referenced secret **expired** | **Only that ref's keys are retained** (last value kept, never overwritten or deleted); the other refs' keys in the same Secret keep syncing in the same single update. When every ref is held nothing is written | `False`, reason `SourceSecretExpired` (the message names the held keys) | `SourceSecretHealthy=False`, Warning Event `SourceSecretExpired`, gauge `expired` |
| Referenced secret **suspended**, `spec.onSuspend: Retain` (default) | **Only that ref's keys are retained**, as above | `False`, reason `SourceSecretSuspended` | `SourceSecretHealthy=False`, Warning Event `SourceSecretSuspended`, gauge `suspended` |
| Referenced secret **suspended**, `spec.onSuspend: Clear` | The keys of suspended refs are **emptied** (also while another ref of the same target is expired: that one's keys are held, only the suspended ref's keys are cleared); keys of readable refs stay current. The Secret object is never deleted, and a Secret the operator does not own is never touched | `True` (the rest synced) | as above |
| Within **30, 7 or 1 days** of expiring | Syncs normally | `True` | `SourceSecretHealthy=False` reason `SourceSecretExpiring`, Warning Event when each window is first entered, gauge `expiring` |
| Resumed / extended | Next reconcile (within `spec.refreshInterval`) **restores** the data under the same name, labels and owner | `True` | condition removed, Normal Event `SourceSecretRecovered`, gauge back down |

A confirmed 404/403 is a different signal and still follows `spec.prunePolicy` (see
"How it works"); a 401 never wipes. The state-based reconcile above does not back off: it requeues at
`refreshInterval`, so a resume is picked up within one interval.

**What running workloads see.** The operator only changes the Secret object:

- Pods that took the value as **environment variables** keep what they started with until
  they restart — the environment of a running container never changes.
- Pods that **mount the Secret as a volume** follow the Secret: with `Retain` the files
  stay; with `Clear` the files disappear (after the kubelet's sync delay, typically up to a
  minute) and reappear after the resume. Mounts with `subPath` never update.
- **New pods** that need a key `Clear` removed fail with `CreateContainerConfigError`
  (a `secretKeyRef` to a missing key, or a Secret volume without `optional: true` whose
  Secret has no such item) until the secret is resumed. With `Retain`, new pods start with
  the retained value.

Metric: `keyorix_operator_source_secrets{state="suspended|expired|expiring"}` is the number
of `KeyorixSecret`s currently in each state.

## Install

The operator ships as a Helm chart that installs the CRD, controller, ServiceAccount, and
RBAC:

```sh
helm install keyorix-operator deploy/helm/keyorix-operator \
  -n keyorix-system --create-namespace \
  --set allowedServers[0]=https://keyorix.internal
kubectl -n keyorix-system rollout status deploy/keyorix-operator-keyorix-operator
```

**`allowedServers` is required to sync anything.** It's the confused-deputy control: a
`KeyorixSecret`'s `spec.server` must match one of these trusted base URLs, or the
reconciler rejects the CR outright (fail closed) — without it, the controller starts
fine (`helm install` succeeds, the pod goes `Ready`) but every `KeyorixSecret` fails
with `Ready=False`/`SyncError` and a "server not in allowedServers" message, which is
easy to miss since nothing about the install itself looks broken. Set it to every
Keyorix base URL (`https://host`, no path) a `KeyorixSecret` in this cluster is allowed
to point at.

For HA, run multiple replicas with leader election (only one is active):

```sh
helm upgrade keyorix-operator deploy/helm/keyorix-operator -n keyorix-system \
  --set replicas=2 --set leaderElection=true
```

### Choosing a namespace scope (ADR-076)

**By default, a single operator instance watches `KeyorixSecret` CRs in its own release
namespace only** — its RBAC (a `Role`/`RoleBinding` pair) is scoped accordingly, and the
manager itself defaults to the same namespace (read from `POD_NAMESPACE`, set via the
Downward API). This is the least-privilege choice: an unmodified `helm install` never
grants the operator access to Secrets outside the namespace you installed it into.

Two opt-in modes cover broader deployments, both resolved from the same two values so they
can never disagree with each other (`_helpers.tpl`'s `kxop.scope` — see the chart's
[README](../deploy/helm/keyorix-operator/README.md#rbac) for the underlying mechanism):

- **Bounded multi-namespace** — one operator instance managing a known, fixed set of
  namespaces (e.g. all of one team's tenants). Set `watchNamespaces`:

  ```sh
  helm install keyorix-operator-team-a deploy/helm/keyorix-operator -n team-a \
    --set 'watchNamespaces={team-a,team-b}'
  ```

  RBAC is bound via a namespace-scoped `RoleBinding` in each listed namespace; the manager
  watches exactly those namespaces.

- **Cluster-wide** — one operator instance managing `KeyorixSecret` CRs in *every*
  namespace, with no static list. Set `rbac.clusterScoped: true` explicitly:

  ```sh
  helm install keyorix-operator deploy/helm/keyorix-operator -n keyorix-system \
    --create-namespace --set rbac.clusterScoped=true
  ```

  RBAC is bound via a cluster-wide `ClusterRoleBinding` — this is now the **only** way to
  get that grant; it is no longer the default. `watchNamespaces` and
  `rbac.clusterScoped: true` are mutually exclusive — setting both makes the chart refuse
  to render (`helm template`/`helm install` fails with an error naming both values), rather
  than silently picking one.

**Upgrading from a chart version older than this default change?** Two scenarios:

- **You relied on the old cluster-wide default (neither value set).** Add
  `--set rbac.clusterScoped=true` to your `helm upgrade` to preserve that behavior across
  the upgrade. Without it, the operator narrows to its own release namespace only, which
  may stop it from reconciling `KeyorixSecret` CRs in other namespaces it previously
  watched.
- **You already set `watchNamespaces`.** `rbac.clusterScoped` defaulted to `true` before
  this release, and a plain `helm upgrade` (without `--reset-values`) carries forward a
  release's previously-recorded values by default — so your install is very likely already
  in the now-rejected combination (`rbac.clusterScoped=true` + `watchNamespaces` set). The
  upgrade will refuse to render at all, with an error containing:
  `rbac.clusterScoped=true and watchNamespaces=[...] are both set -- these are mutually
  exclusive (ADR-076)`. This is a hard block on the upgrade itself, not a permissions
  change — add `--set rbac.clusterScoped=false` explicitly to your `helm upgrade` (or the
  equivalent in your values file) to clear it.

See the CHANGELOG's `BREAKING` entry for this release for the full detail.

For an air-gapped install that mirrors the operator image to a private, authenticated
registry, set `image.repository` to the mirror and `imagePullSecrets` to a
`docker-registry` Secret in the release namespace — see the chart's
[README](../deploy/helm/keyorix-operator/README.md#private-registries).

For an air-gapped install that mirrors the operator image to a private, authenticated
registry, set `image.repository` to the mirror and `imagePullSecrets` to a
`docker-registry` Secret in the release namespace — see the chart's
[README](../deploy/helm/keyorix-operator/README.md#private-registries).

## Usage

1. Create a least-privilege machine-identity token (ADR-030) Secret in your app
   namespace — give the identity `secrets.read` only for the secrets it will sync:

   ```sh
   kubectl -n app create secret generic keyorix-token \
     --from-literal=token="$KEYORIX_MACHINE_TOKEN"
   ```

2. Apply a `KeyorixSecret` (see
   [`examples/keyorixsecret.yaml`](../deploy/helm/keyorix-operator/examples/keyorixsecret.yaml)):

   ```yaml
   apiVersion: secrets.keyorix.io/v1alpha1
   kind: KeyorixSecret
   metadata:
     name: db-creds
     namespace: app
   spec:
     server: https://keyorix.internal
     tokenSecretRef: { name: keyorix-token, key: token }
     refreshInterval: 5m
     target: { name: db-creds, type: Opaque }
     data:
       - secretKey: DB_PASSWORD
         ref: app/production/db-password   # project/environment/name
       - secretKey: API_KEY
         ref: app/production/api-key
   ```

3. Watch it reconcile and consume the Secret as usual:

   ```sh
   kubectl get keyorixsecret -n app          # READY=True, LAST SYNC=…
   kubectl get secret db-creds -n app
   ```

   ```yaml
   envFrom:
     - secretRef: { name: db-creds }
   ```

Deleting the `KeyorixSecret` removes the `db-creds` Secret it created (owner reference).

## Spec reference

| Field | Description |
|---|---|
| `spec.server` | Keyorix base URL (`https://…`). |
| `spec.tokenSecretRef.name` / `.key` | Secret holding the machine token (`key` defaults to `token`). |
| `spec.refreshInterval` | Re-read cadence (default `5m`). |
| `spec.target.name` / `.type` | Target Secret name (defaults to the CR name) and type (default `Opaque`). |
| `spec.data[].secretKey` | Key to set in the target Secret. Must be unique across entries: the CRD rejects duplicates, and a stored CR that still has one is refused by the controller (`Ready=False`, reason `InvalidSpec`, Warning Event `InvalidSpec`, nothing read or written) until it is fixed. |
| `spec.data[].ref` | Keyorix `project/environment/name` reference to read. |

## Status & observability

- `status.conditions[Ready]` — `True` when the target Secret is up to date; `False` on
  failure, with the cause in the message and one of these reasons: `SyncError`
  (any other failure, and also unreachable / timeout / 5xx, where the message starts with
  `KeyorixUnreachable:` — target Secret kept), `InvalidSpec` (duplicate `spec.data[].secretKey`
  — nothing read or written), `UpstreamAccessRevoked` (401 — target Secret kept; the message starts with
  `KeyorixAuthFailed:`), `SourceSecretExpired` / `SourceSecretSuspended` (held keys kept, the
  other keys synced), or `UpstreamSecretGone` (404/403 — wipes the target Secret per `prunePolicy`, see "How
  it works" above).
- `status.lastSyncTime`, `status.syncedHash`, `status.observedGeneration`.
- The manager serves Prometheus metrics on `:8080/metrics` and health probes on
  `:8081/healthz`,`/readyz` (the chart wires both).

## Security

- **Least-privilege token per KeyorixSecret.** Each resource names its own token Secret;
  scope the identity to exactly the secrets it syncs.
- **Token stays in a Secret.** It is read from `tokenSecretRef`, never inlined in the CR.
- **Keyorix-side controls apply.** Every read goes through scoped `secrets.read`,
  `max_reads`, suspension, and audit — avoid pointing the operator at a tight `max_reads`
  secret, since each refresh counts as a read.
- The controller image is a distroless non-root static binary with a read-only root
  filesystem and all capabilities dropped.

## Uninstalling

`helm uninstall` removes the controller and RBAC. Helm does not delete CRDs it installed;
remove the type explicitly when you want it gone (this also deletes every `KeyorixSecret`
and the Secrets they own):

```sh
kubectl delete crd keyorixsecrets.secrets.keyorix.io
```
