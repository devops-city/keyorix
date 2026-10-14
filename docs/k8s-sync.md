# Keyorix Kubernetes sync agent

`keyorix-k8s-sync` materialises selected Keyorix secrets into native **Kubernetes
Secrets** and keeps them current as the upstream values rotate. Workloads consume the
synced Secret the usual way (env var or mounted file) — they never talk to Keyorix
directly.

> Prefer the [External Secrets Operator](k8s-eso.md)? Keyorix also works as an ESO
> Webhook provider — no agent to run if you already operate ESO.

It runs **in-cluster** as a small Deployment:

- authenticates to Keyorix with a **machine-identity token** (`KEYORIX_TOKEN_FILE`,
  or `KEYORIX_TOKEN`),
- writes Secrets via the Kubernetes API using its mounted **service-account**
  credentials (no `client-go` — a thin REST client, so the image stays tiny),
- reconciles on an interval, creating/updating a target Secret **only when its data
  changes** and never writing a Secret partially if any value fails to fetch.

## Configuration

A YAML file (default `/etc/keyorix/k8s-sync.yaml`, override with `-config` or
`KEYORIX_K8S_SYNC_CONFIG`):

```yaml
keyorix_url: https://keyorix.internal   # the Keyorix server base URL
project_id: 42                          # the Keyorix project the token's machine identity belongs to
interval: 5m                            # reconcile interval (Go duration; default 5m)
cleanup: false                          # reap orphaned owned Secrets (see below; default off)
mappings:
  # Each mapping copies one Keyorix secret into one key of one Kubernetes Secret.
  # Several mappings may target the same Secret with different keys.
  - ref: production/db-password         # "<environment>/<name>" in Keyorix
    namespace: app                      # target Kubernetes namespace
    name: db-creds                      # target Kubernetes Secret name
    key: DB_PASSWORD                    # key within that Secret's data
  - ref: production/api-key
    namespace: app
    name: db-creds
    key: API_KEY
```

The Keyorix auth token is **not** in this file. Prefer `KEYORIX_TOKEN_FILE`
(a path to a mounted Secret volume — this repo's own Helm chart mounts it this way
by default) over `KEYORIX_TOKEN` (a plain env var, still supported for backward
compatibility): a mounted, read-only file never appears in the pod spec itself,
unlike an env var sourced from a `secretKeyRef`, which the Kubernetes API still
returns verbatim to anyone who can read the pod (e.g. `kubectl get pod -o yaml`).
`KEYORIX_TOKEN_FILE` takes precedence when both are set. Give that token a
least-privilege machine identity that can read only the referenced secrets.

`project_id` is required: a mapping's `ref` names only an environment and a secret
(`<environment>/<name>`), never a project, because environment names are unique
per-project, not globally — two different projects can each have a `production`
environment. `project_id` pins every secret lookup this agent performs to the one
project its token belongs to (a machine identity, and so its tokens, always belongs to
exactly one project), so a same-named secret in a *different* project can never be
resolved instead of the intended one.

## Kubernetes RBAC

The agent's service account needs to read and write Secrets in each target namespace:

```
verbs:     [get, list, create, patch, delete]
resources: [secrets]
```

`list` is used **only** by orphan cleanup (below) — with `cleanup` off, the agent never
lists. `delete` is used by orphan cleanup **and** by `pruneOnRevoke` (default **true** —
see "Fetch failures" below) whenever every mapping for a target is confirmed gone or
revoked at once, so a default install (`cleanup` off, `pruneOnRevoke` on) still needs
it — only `get`, `create`, `patch` are guaranteed with BOTH features off. Bind a `Role`
with these permissions in every target namespace (or a `ClusterRole` with
namespace-scoped `RoleBinding`s). The Helm chart further restricts `get`/`patch`/`delete`
with `resourceNames` to exactly the Secret names in `mappings` — `create` and `list`
can't be `resourceNames`-scoped (a Kubernetes RBAC limitation: those verbs don't target
a single named object), so they remain granted on the `secrets` resource type as a
whole. The agent uses Server-Side Apply with the field manager `keyorix-sync`, so it
owns the `data` it writes and prunes keys it no longer maps.

## Fetch failures: transient vs. confirmed gone/revoked (`pruneOnRevoke`)

A **transient** failure (network error, timeout, 5xx from Keyorix) leaves the target
Secret completely untouched — every key it currently holds, not just the one that
failed to fetch — and retries next pass. This is always true, regardless of
`pruneOnRevoke` below. The target is counted `failed` and `keyorix_unreachable` (the log
line says `KeyorixUnreachable` with the reason `unreachable`, `timeout` or `server_error`;
the operator's counterpart is `KeyorixUnreachable` plus
`keyorix_operator_fetch_errors_total{reason}`).

A **401** (Keyorix rejected the agent's *own* token: invalid, expired or rotated) never
prunes either, whatever `pruneOnRevoke` says: every synced Secret is kept, the target is
counted `failed` and `auth_failed` (the log line says `KeyorixAuthFailed`), and the loop
backs off until the token is fixed, after which the next pass syncs normally.

A **confirmed** gone-or-revoked result (Keyorix returns 404/403 — the secret was
deleted or this agent's access to it was removed) is a different signal: the upstream has
*affirmatively* said this value is no longer available, not just "ask again later."
`pruneOnRevoke` (default **`true`** — the secure default, since a confirmed-gone or
confirmed-revoked value must not stay readable in the cluster indefinitely) acts on it:

- If some but not all of a target's mappings are confirmed gone/revoked, the affected
  key(s) are dropped from the target Secret; keys that still fetched fine stay.
- If *every* mapping for a target is confirmed gone/revoked, the whole target Secret is
  removed.
- **Mass-revocation circuit breaker**: if more than one target AND more than 20% of
  every target this agent manages are confirmed gone/revoked in the *same* pass, none
  of them are pruned — this looks like one shared event (e.g. a shared grant removed),
  not N independent per-secret revocations. The pass instead reports `MASS REVOCATION SUSPECTED` (see `/status` and
  the `keyorix_k8s_sync_secrets_total{outcome="mass_revocation_suspected"}` metric).
  Acknowledge an expected event (a planned credential rotation) by setting
  `massPruneAck` to an RFC3339 timestamp (valid for 1 hour) to let the next pass
  proceed; a permanently-set `massPruneAck` defeats the breaker for every future
  incident, not just the one you're acknowledging.
- Set `pruneOnRevoke: false` to opt out entirely: a confirmed gone/revoked reference is
  still surfaced (as a `revoked` count/metric) but never acted on — the target Secret's
  last-known value is always left untouched, favoring availability over immediate reap.

`pruneOnRevoke`'s delete path needs `delete` RBAC on the target Secret names, which the
chart grants whenever `cleanup` **or** `pruneOnRevoke` is enabled (see below) — since
`pruneOnRevoke` defaults on, a default install already has it.

## Suspended and expired sources

A Keyorix secret can be *suspended* (an operator's "block value reads" switch; the server
answers `409 SecretSuspended`) or *expire* (`409 SecretExpired`). Neither is a revoked
grant, so neither deletes the target Secret, and neither counts as a failure or a
revocation (the loop keeps its normal interval, so a resume is picked up within one
interval). The setting is `onSuspend: retain|clear` in the Helm values, `on_suspend` in the
agent's config file. By cause:

| Cause | Target Secret | Logged / counted |
| --- | --- | --- |
| Server **unreachable, timeout, 5xx** | **Never modified or deleted**; counted `failed`, retried with backoff; syncs normally once Keyorix answers | `KeyorixUnreachable (unreachable\|timeout\|server_error)` in the pass log, outcome `keyorix_unreachable` |
| **401** — the agent's own token rejected | **Kept** (never pruned, whatever `pruneOnRevoke` is); counted `failed`, retried with backoff; syncs normally once the token is fixed | `KeyorixAuthFailed` in the pass log, outcome `auth_failed` |
| **403 / 404** — grant revoked / secret deleted | **Pruned** when `pruneOnRevoke` is true (default), behind the mass-revocation circuit breaker; kept when false | outcome `revoked` (or `mass_revocation_suspected`) |
| Source **expired** | **Only that mapping's key is retained** (never overwritten or deleted); the target's other keys keep syncing in the same Apply. When every mapping is held nothing is written | `WARNING SourceSecretExpired`, outcome `source_expired` |
| Source **suspended**, `onSuspend: retain` (default) | **Only that mapping's key is retained**, as above | `WARNING SourceSecretSuspended`, outcome `source_suspended` |
| Source **suspended**, `onSuspend: clear` | The suspended mapping's key is **emptied** (also while another mapping of the same target is expired: that key is held); other keys stay current. The Secret is never deleted, and a Secret the agent does not own is never touched | as above |
| Source **suspended with "also clear copies synced to Kubernetes clusters"** (chosen by whoever suspended it), any `onSuspend` | Treated as `onSuspend: clear` **for that mapping and that suspension**, even under `retain`: its key is **emptied** with exactly the clear semantics above (the Secret is never deleted, a Secret the agent does not own is never touched) | `WARNING SourceSecretSuspended ... requests clearing the synced copies`, outcome `source_suspended` |
| Within **30, 7 or 1 days** of expiring | Syncs normally | `WARNING SourceSecretExpiring` when each window is first entered, outcome `source_expiring` |
| Resumed / extended | The next pass **restores** the data: same name, labels and values | "readable again" line |

The per-suspension row is the same override the operator honours (`docs/k8s-operator.md`,
"Clearing copies for one suspension"): the server's `409 SecretSuspended` carries
`details.clear_synced_copies=true`, the agent empties that mapping's key on its next pass,
and resuming restores it. An agent that predates the field follows `onSuspend`.

The lines are logged when a source *enters or leaves* a state, not every pass; the
`keyorix_k8s_sync_secrets_total{outcome=…}` counters (and `/status`) count the targets
observed in each state per pass. A target that also has a confirmed-revoked mapping still
takes the `pruneOnRevoke` path above; retained keys are carried over unchanged.

**What running workloads see** — same as for the operator (`docs/k8s-operator.md`):
environment variables of running containers stay fixed until restart; volume-mounted
files follow the Secret (`retain` keeps them, `clear` removes them until the resume);
new pods fail with `CreateContainerConfigError` only if `clear` removed a key they need.

## Orphan cleanup (`cleanup`)

`pruneOnRevoke` above handles a target whose *upstream* secret became inaccessible.
This is a different case: removing a mapping from the *agent's own config* (the ref is
still perfectly valid in Keyorix, you just stopped syncing it here) leaves the whole
Secret behind if it was the target's last remaining mapping — the agent simply stops
reconciling it, and its now-stale values linger forever. (A single key within a
still-referenced Secret is unaffected by this — the agent owns the Secret's `data` via
Server-Side Apply, so a no-longer-mapped key on an otherwise-still-mapped target is
pruned on the very next pass, same as `pruneOnRevoke`'s per-key case above.)

Set `cleanup: true` (or pass `-cleanup`) to reap these orphans. Every Secret the agent
creates is stamped `app.kubernetes.io/managed-by: keyorix-sync`; after the apply phase,
cleanup lists Secrets carrying that label in each namespace the config still references
and **deletes those whose target is no longer mapped**. It is deliberately conservative:

- **Label-scoped** — it only ever lists and deletes Secrets carrying the managed-by
  label, so Secrets created by an operator or another tool are never touched.
- **Config-scoped** — it only scans namespaces still present in the config. Dropping a
  namespace from the config entirely leaves its Secrets unreaped (remove the mappings
  first, let one pass reap, then drop the namespace).
- **Off by default** — deleting Secrets is destructive, so cleanup must be opted into.
  (`pruneOnRevoke` above is the separate, default-on mechanism for an upstream secret
  that's actually gone or revoked, as opposed to a mapping simply removed from config.)

> Cleanup assumes a **single sync agent owns each managed namespace**. Do not point two
> agents with different mapping sets at the same namespace with cleanup on — each would
> treat the other's Secrets as orphans. Use `-cleanup -dry-run -once` to preview what
> would be deleted before enabling it for real.

## Running

```
keyorix-k8s-sync -config /etc/keyorix/k8s-sync.yaml
```

Logs are counts and target identities only — secret values are never logged.

### Flags

- `-once` — run a single reconcile pass and exit (no health server / loop). Exits
  non-zero if any target failed, so it works as a CI gate or a Kubernetes `Job`.
- `-dry-run` — report what *would* change (created/updated/unchanged/deleted counts)
  without writing any Secret. Combine with `-once` to validate config and preview a sync.
- `-cleanup` — delete orphaned owned Secrets whose mapping was removed (see *Orphan
  cleanup*). Equivalent to `cleanup: true` in the config; combine with `-dry-run` to
  preview deletions.

```
keyorix-k8s-sync -config ./k8s-sync.yaml -once -dry-run
```

## Health & probes

The agent serves probe endpoints on `health_port` (default `8080`):

- `GET /healthz` — liveness; always `200` while the process is responsive.
- `GET /readyz` — readiness; `503` until the first reconcile completes, then `200`.
- `GET /status` — JSON of the last pass (counts + timestamp + error count; no values).
- `GET /metrics` — Prometheus metrics: `keyorix_k8s_sync_reconcile_passes_total`,
  `keyorix_k8s_sync_secrets_total{outcome=…}` (`created`/`updated`/`unchanged`/`failed`/`deleted`),
  `keyorix_k8s_sync_last_run_timestamp_seconds`, and `keyorix_k8s_sync_last_failed`. The
  chart adds `prometheus.io/scrape` pod annotations.

The Helm chart wires `/healthz` and `/readyz` as the Deployment's liveness and
readiness probes.

`/metrics` is unauthenticated by default, like the other three endpoints — set
`-metrics-bearer-token` (or `KEYORIX_METRICS_TOKEN`; `metricsBearerToken` in the Helm
chart) to require a matching `Authorization: Bearer <token>` header on `/metrics`
specifically. `/healthz`, `/readyz`, and `/status` stay unauthenticated regardless —
Kubernetes' own kubelet has no way to supply a token, and none of the three expose
secret values. The chart also ships a `NetworkPolicy` (`networkPolicy.enabled`,
default on) restricting who can reach `health_port` at all.

> A Helm chart that deploys the agent with its RBAC and config ships separately
> (`deploy/helm/keyorix-k8s-sync`).
