# ADR-096: Anti-enumeration status-code convention — 403-for-both, not 404-for-both

## Status

**Accepted (2026-09-01).** #1645. This ADR documents the decision and the
migration mechanism; see the tracking issue for which call sites have moved
onto it as of any given date — the decision is final, the migration is
incremental.

## Summary

#1645 found two incompatible, undocumented conventions coexisting for how a
scoped-resource endpoint (a secret, project, user, role, dynamic-secret
config, ...) responds when the caller either lacks the permission or the
resource doesn't exist:

- **Convention A (403-for-both)**: the primary GET-by-ID routes
  (`server/middleware/auth.go`'s `handleScopeResolutionError`, used by
  `RequireScopedPermission`/`RequireScopedSecretPermission`). An unauthorized
  caller gets an identical 403 whether the target exists or not; only a
  caller who holds the permission **globally** gets a real 404.
- **Convention B (404-for-both)**: a separate, independently-invented idiom
  (tagged `#G14`/`#G85`/`TMPL-002` at each site) used by dynamic-secret
  config/lease routes, template-render secret-reference resolution, SCIM's
  per-record 404s, and gRPC's `GetSecret`/dynamic-secret RPCs. Denied and
  nonexistent both collapse to a uniform 404, **regardless of caller
  privilege** — there is no privileged-caller exception at all in this
  convention. (SCIM's is reviewed and excluded below, not migrated — see
  "Out of scope: SCIM provisioning".)

**Decision: Convention A (403-for-both) is the house standard.** Convention B
sites migrate to it. Not because A is the majority (that would be a weak
reason to standardize — if B were the better design it would be worth the
larger migration the other direction) — because of the threat model.

## Why 403, not 404

404-for-denied is a deliberate lie to an authenticated user already inside
the trust boundary. That's a reasonable trade for a product like GitHub,
whose threat model is anonymous scraping of private repos. It is not a
reasonable trade for an on-prem secrets tool used during incidents: an
operator who lacks a permission and is told "not found" concludes the secret
was deleted, or that they're pointed at the wrong server. That misdirection
has a real operational cost, and it buys very little against an attacker who
is already authenticated and knows the route shape.

## The convention, precisely

Four conditions. Without all four, "pick 403" is not actually a convention —
it's a status code with no enforcement, which is exactly how this repo ended
up with two conventions the first time.

### 1. The real-404 exception is narrow, and must stay narrow

A genuine 404 (not the collapsed one) is returned **only** when the caller
holds, **at global scope**, the **same permission** that would have granted
access to this specific resource had it existed. Not "any global
permission." Not "global read on some other resource type." That sentence is
the whole exception — a looser version (e.g. "any authenticated caller with
some admin-tier role") re-opens the oracle for a broader population than
intended.

`handleScopeResolutionError` implements this exactly today:

```go
func handleScopeResolutionError(w http.ResponseWriter, r *http.Request, cs *core.KeyorixCore, userCtx *UserContext, permission string, err error) {
	if errors.Is(err, errTargetNotFound) {
		if ok, aerr := cs.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permission, core.Scope{}); aerr == nil && ok {
			notFoundResponse(w, "Resource not found")
		} else {
			forbiddenResponse(w, "Insufficient permissions")
		}
		return
	}
	badRequestResponse(w, "Invalid target")
}
```

`core.Scope{}` here is the global scope — the check is literally "does this
caller hold `permission` with no project/environment restriction," which is
the precise exception, not an approximation of it.

### 2. The convention is the whole response, not just the status code

Identical body, identical error-code string, identical headers. Two handlers
both returning 403 with `{"error":"forbidden"}` vs
`{"error":"secret not found in project"}` leak exactly as much as
403-vs-404 did — the caller learns which case they hit either way. Every
site that adopts this convention must produce the SAME body shape
`handleScopeResolutionError`/`finishScopedPermissionRequest` already produce
for the "denied" branch (`forbiddenResponse(w, "Insufficient permissions")`)
— not a resource-specific message that happens to also be a 403.

### 3. Route through the shared mechanism, not a re-derived per-site check

`handleScopeResolutionError` already exists and is exercised by every
primary GET route today. The migration for a Convention-B site is "route
this resource's scope resolution through `RequireScopedPermission`/a new
`ScopeResolver`" — a mechanism fix, not writing the collapse logic again at
each call site. See "Migration mechanism" below for the concrete shape.

### 4. gRPC is specified here too, not left to be re-derived later

`secret_service.go`'s `GetSecret` is one of the divergent (Convention B)
sites, and gRPC has its own status codes (`PermissionDenied` vs `NotFound`,
not HTTP 403/404). A convention written only in HTTP terms leaves gRPC to
reinvent its own version later — which is how this repo ended up with two
conventions the first time. The gRPC-side rule is the identical shape:

- Denied or nonexistent, caller lacks the permission globally →
  `codes.PermissionDenied`, with the same message text regardless of which
  case actually happened.
- Nonexistent, caller holds the permission globally → `codes.NotFound`.

A shared Go function analogous to `handleScopeResolutionError` (gRPC has no
middleware chain equivalent to chi's, so this is a plain function called
from each RPC handler, not middleware) should back every gRPC RPC that
resolves a scoped resource by ID, for the same "one mechanism, not
per-RPC copies" reason.

## Scope: this is a full rule, not just a GET-by-ID rule

Two gaps the original recon didn't cover, closed here so the convention is
complete:

- **List endpoints** already comply by construction: they return 200 with
  the filtered result set (an empty list leaks nothing — it's the honest
  answer for "you have access to zero matching items," indistinguishable
  from "zero items exist"). No change needed; noted so a future audit
  doesn't have to re-derive this.
- **Write verbs** (PUT/PATCH/DELETE) on a resource the caller can't see
  follow the identical 403-for-both rule as GET. A write route that
  resolves scope via `RequireScopedPermission`/`RequireScopedSecretPermission`
  already gets this for free (the middleware doesn't distinguish HTTP
  method). A write route with its own hand-rolled existence check (matching
  the shape #1645 found on the read side) needs the same migration as any
  other Convention-B site — otherwise existence gets probed through DELETE
  instead of GET, which defeats the point.

## Out of scope: SCIM provisioning

`server/http/handlers/scim.go` and `scim_groups.go` (the #G85-tagged 404s
#1645 originally flagged) were reviewed against this convention and found
**not** to be a 403-for-both site — not an oversight, a deliberate exclusion,
recorded here so a future audit doesn't re-flag it.

The 403-for-both threat model is: an authenticated caller, inside the trust
boundary, who holds *some* permissions but not the ones needed for *this*
resource, and who could otherwise infer the resource's existence by comparing
responses across many resources. SCIM has no such caller. Every SCIM route is
gated by `customMiddleware.SCIMToken` (`server/middleware/scim.go`) — one
static bearer token per deployment, configured for a single IdP integration.
There is no authenticated-but-differently-privileged population to protect
from an oracle: the token either matches (and the caller can act on the
entire SCIM-managed namespace) or it doesn't (401, before any handler runs).
Migrating `GetUser`/`GetGroup`/etc. to `RequireScopedPermission` would be a
no-op that adds a resolver with nothing to resolve against.

What the #G85 404 actually reveals — whether an id belongs to a SCIM-managed
account versus a native one, or doesn't exist at all — is a narrower,
different question than the one this ADR answers, and is left as a separate,
not-yet-filed concern rather than folded into this migration. (SCIM's 409 on
`CreateUser`/`CreateGroup` duplicate-name collisions is unrelated to either
question — that's correct RFC 7644 create-collision behavior, not an
existence leak, and needs no change.)

## Migration mechanism

For an HTTP handler currently doing its own fetch-then-authorize-then-collapse
(the `loadAuthorizedConfig`/`loadAuthorizedLease` shape in
`server/http/handlers/dynamic_secrets.go` is the clearest example): write a
`ScopeResolver` (`server/middleware/auth.go`'s existing type) for the
resource, matching `ScopeFromSecretParam`'s shape —

```go
func ScopeFromDynamicSecretConfigParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		cfg, err := cs.GetDynamicSecretConfig(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: cfg.ProjectID, EnvironmentID: cfg.EnvironmentID}, nil
	}
}
```

— then wire the route through `RequireScopedPermission(perm,
ScopeFromDynamicSecretConfigParam("id"))` in `router.go` instead of calling
the handler-internal loader, and delete the handler-internal
fetch/authorize/collapse logic (the handler now runs only once already
authorized, and can fetch the row again cheaply, or the middleware can stash
it on the request context the way `RequireScopedSecretRefPermission` already
does for the by-ref read path, if avoiding a second fetch matters for that
route).

Where full middleware conversion is impractical for a specific call site
(e.g. a check embedded in a larger multi-step operation, or one target among
several references resolved inside a single request body — `secrets_render.go`'s
`RenderTemplate` is the worked example: the route-level project scope is
already gated through `RequireScopedPermission`, but each `${secret:...}`
reference inside the template body is a second, per-reference existence
check that can't be expressed as a single path-param `ScopeResolver`), the
same decision must still be made by ONE shared, exported function callable
from handler code — not re-derived inline. `handleScopeResolutionError`
itself is unexported (package `server/middleware`); export the decision as
`middleware.AuthorizedAtGlobalScope(ctx, cs, userCtx, permission) bool` so
handler packages can call the identical logic without a full route
restructure. `server/grpc/services/conversions.go`'s `authorizeScopedTarget`
is the gRPC equivalent, backing `authorizeSecretScoped`
(`secret_service.go`) and `loadConfigScoped`/`loadLeaseScoped`
(`dynamic_secret_service.go`).

## Out of scope: Connect (third convention, not a migration target)

**Added 2026-09-07**, before the Guard below was ever built — a 2026-09-07 ADR
review (Finding 1, `keyorix-private/adversarial-review/ADR-CORPUS-REVIEW-2026-
09-07.md`) found a **third** existence-collapse convention in production this
ADR's Summary never accounted for, on routes this ADR's own scope language
("a scoped-resource endpoint... a secret, project, user, role, dynamic-secret
config") is broad enough to cover. ADR-082 §E (Connect connector tenant
scoping, predates this ADR) has Connect's own convention: a read denied by
ownership returns the **exact same shape as an unknown connector**
(`ErrConnectUnknownConnector` — `502`/HTTP, `codes.FailedPrecondition`/gRPC,
identical message text) — always-collapse, with **no privilege-based
exception at all**, on a different status-code family than either Convention
A (403) or Convention B (404).

**Deliberately excluded from this ADR's migration, recorded here so the Guard
below enumerates three buckets, not two:**

- Connect's collapse is at least as conservative as this ADR's own
  403-for-both — it has no real-404-exception oracle to close, since it
  never grants a privileged caller a distinguishable "genuinely not found"
  response at all (unlike Convention A's narrow global-permission exception,
  see "The convention, precisely" §1 above). Migrating it to 403-for-both
  would be a status-code change with no security improvement.
- Convention A's exception logic (§1) does not apply to Connect's ownership
  model unchanged — Connect's wildcard/ownership resolution (ADR-082 §E) is
  its own mechanism, not `handleScopeResolutionError`, and forcing it through
  that function would need its own translation layer for no proven benefit.
- This is a **naming and enumeration gap in this ADR's Guard, not a live
  vulnerability** — ADR-082 §E's own text is explicit that the collapse is
  "a deliberate choice, not an oversight," made for the identical
  existence-hiding reason this ADR exists for.

**Consequence for the Guard below**: a route-enumeration guard built against
only two known conventions (403-via-shared-resolver, or an explicit
exception) would either misfire on every Connect route, or need a silent
third bucket discovered ad hoc — exactly the "enumeration is only as
complete as the idioms it knows about" failure mode this codebase's own
engineering notes name as a recurring defect class. Any future implementation
of the Guard below must enumerate Connect's `ErrConnectUnknownConnector`
collapse as its own named, explicit bucket from the start, not add it after
the guard already misfires once.

## Guard

An assertion that every handler touching a scoped resource returns denial
through the shared mechanism, not a hand-rolled status code, is required
once the migration lands — otherwise this drifts back to two conventions the
same way it happened the first time. `handleScopeResolutionError`/
`RequireScopedPermission` is the thing to grep for; a guard test enumerating
every route registered against a `{id}`-shaped scoped-resource path and
confirming it's wired through one of **three** buckets — a shared resolver
(Convention A), an explicit individually-justified exception (mirroring
`raw_storage_bypass_guard_test.go`'s own allowlist pattern), or Connect's own
`ErrConnectUnknownConnector` collapse (see "Out of scope: Connect" above) —
is the cheapest way to enforce this going forward. **This guard is not built
yet** (as of 2026-09-07) — the enumeration above is a precondition for
building it correctly the first time, not a description of an existing test.

## Explicitly deferred: timing side-channel

If the exists-but-denied path does a real lookup and the doesn't-exist path
returns early (or vice versa), response time can distinguish the two cases
regardless of what status code and body are returned. Routing every site
through one shared mechanism helps structurally (a single code path means a
single timing profile, rather than N independently-timed implementations),
but actually measuring and closing that gap is a separate pass — not
attempted as part of this ADR or its migration.

## Amendment 1 (2026-10-17): a zero-grant caller on a list route gets an empty 200

Decided by Andrei, 2026-10-17 (MACHINE-IDENT-DENY-1). It makes the
"List endpoints" bullet under "Scope" explicit for a caller holding no grant at
all, such as a machine identity created with no role. The SDK contract suites
expected 403 for this caller, and nothing written down said otherwise.

For an authenticated caller with no grant:

1. **A list route answers 200 with only the rows the caller may read**, which
   for this caller means none. A list is filtered by permission, not gated on
   it. This is the reasoning in #2780's code comments:
   `CatalogHandler.ListProjects` and `ListEnvironments`
   (`server/http/handlers/catalog.go`) and `internal/core/project_visibility.go`
   ("Why this exists (#2780)"). Those comments carry `ListSecrets`' existing
   behaviour over to the project and environment lists.
2. **A single-object read without a grant stays 403**, per the convention
   above.
3. **A bad token stays 401.** The empty 200 is only for a token that
   authenticates.

Guard, once #3403 merges: `server/http`
`TestZeroGrantMachine_ProjectListIsEmpty200` checks parts 1 and 2 for a fresh
machine identity on SQLite and Postgres.
`TestEveryGETRouteWithholdsDataFromZeroGrantCredentials` and
`TestZeroGrantAfterRevocation_CachedMachineTokenReadsNothing` check that every
GET route discloses nothing to such a caller, including just after its last
grant is revoked. They check what is disclosed, not which code a gated route
returns, so a route that hides a gated read behind an empty 200 would not fail
them. **Part 3 is not yet tested end to end.** The only 401 test,
`server/middleware` `TestHandleAuthRequest_NegativeCacheHit_Returns401`, seeds
the token cache directly. A follow-up adds a mangled-machine-token → 401
assertion on `GET /api/v1/projects` to `TestZeroGrantMachine_ProjectListIsEmpty200`.
