# ADR-042: Personal access token permission scoping (least privilege)

**Status:** Accepted
**Date:** 2026-06-12

## Context

A personal access token (PAT, ADR-027) authenticates an API request **as its
owning user**, inheriting that user's *full* permission set — there is no way to
mint a token that does less than its owner. In practice a PAT is most often handed
to automation: a CI job that only needs to **read** one project's secrets, a
backup script, a third-party integration. Giving each of those the owner's entire
authority — frequently a project- or system-admin's authority — is a textbook
least-privilege violation. If such a token leaks, the blast radius is the whole
account, not the one capability the job actually used.

Least privilege for non-interactive credentials is a core control in the
certification frames Keyorix targets — NIS2 Art. 21(2) (access control,
least-functionality), ISO 27001:2022 A.5.15 / A.5.18 / A.8.2 (access rights and
privileged access), ENS `op.acc.4` (least privilege). Machine identities (ADR-030)
already get bounded, explicitly-granted permissions with **no admin bypass**; PATs
were the remaining over-privileged credential.

## Decision

A PAT may carry an optional **least-privilege restriction** fixed at creation: a
**permission allowlist** and/or a **single-project confinement**. The restriction
is a **filter that only ever narrows** the token below its owner — it can never
grant a permission the owner does not hold, because the owner's live RBAC still
runs. An existing token, or one created without a restriction, is unaffected
(full inheritance — the back-compatible default).

- **Model** (`PersonalAccessToken`, additive columns, ADR-042):
  - `Scopes` — JSON-encoded `[]string` permission allowlist. Empty/null = inherit
    the owner's full set. An entry is an exact permission (`secrets.read`), the
    catch-all `*`, or a prefix wildcard (`secrets.*`).
  - `ProjectScope uint` — when non-zero, the token may act **only** within that
    project's scope; `0` = any scope the owner can reach (mirrors the `0 = global`
    sentinel used throughout RBAC). A project-scoped token is therefore denied at
    global/system scope — it is not a system-wide credential.
  - Defaults leave existing rows unrestricted. On an existing DB the columns are
    added via the GORM `Migrator` (never a full `AutoMigrate` on the live table —
    the same pgx prepared-statement hazard the invitations/notifications blocks
    avoid).

- **Enforcement is at the single authorization chokepoint, not the HTTP layer.**
  The restriction is carried on the request `context.Context`
  (`core.WithPATRestriction`, tagged in the auth middleware's
  `buildRequestContext` for PAT requests only) and read back inside
  **`core.Authorize` and `core.AuthorizePrincipal`** — the two functions every
  authorization decision funnels through (HTTP middleware `RequireScopedPermission`
  / `RequirePermission`, the in-handler authorizers for secret-create /
  dynamic-secrets / rotation-create, and gRPC). The filter is applied **first,
  before role resolution and before the admin bypass**, so it bounds even a
  global admin's own token. Because it sits at the chokepoint rather than at N
  call sites, every present and future authorization path is constrained
  automatically — there is no route to forget to wire (the failure mode ADR-037's
  pre-merge review caught for per-project MFA).

- **The two authz paths that do _not_ funnel through `Authorize` are guarded
  directly.** `core.IsGlobalAdmin` (used to short-circuit scope-filtered listing)
  and the role-based `middleware.RequireRole` gate resolve authorization without
  calling `Authorize`, so a PAT restriction would not reach them. Both now fail
  closed for a PAT-restricted request: `IsGlobalAdmin` returns false (a scoped
  token is never treated as an unrestricted global admin — callers fall back to the
  filtered path, which can only return a subset), and `RequireRole` denies outright
  (a deliberately-scoped token must not satisfy a role gate's full breadth). Neither
  is wired to a live route today; the guards close the gap pre-emptively so that
  enforcement genuinely holds at *every* path, as claimed above.

- **It is a filter, never an escalation.** `Authorize` still resolves the owner's
  live roles after the restriction passes. A token listing `secrets.write` whose
  owner has since lost that permission grants nothing. This is why creation does
  **not** need to validate that the requested scopes are a subset of the owner's
  permissions: the runtime intersection makes over-broad scopes harmless, and the
  owner's permission set is scope-dependent and changes over time anyway.

- **API.** `POST /api/v1/auth/tokens` accepts optional `scopes` (`[]string`) and
  `project_scope` (`uint`). The list/create DTO surfaces both read-only — a
  token's scope is immutable after creation (to change it, revoke and re-mint).
  The raw token is still returned exactly once.

## Consequences

- A user — including an admin — can mint a token that is strictly weaker than
  themselves: a CI read-only token for one project, a rotation-only token, etc.
  Leak blast radius shrinks to the granted capability.
- Enforcement is uniform and centrally provable: the four-case core test plus the
  real-RBAC end-to-end test show a `secrets.read`-scoped token on a **global
  admin** is denied `secrets.write`, and a project-3 token is denied in project 4
  and at global scope — surviving the real admin bypass.
- No behavioural change for existing tokens or unrestricted new ones.

## Alternatives considered

- **Enforce in HTTP middleware (like ADR-037 per-project MFA).** Rejected: PAT
  authority must hold for *every* authorization path including gRPC and in-handler
  authorizers; the ctx-at-the-chokepoint approach covers them all without
  per-site wiring. (Per-project MFA had to be at the HTTP layer because it keys on
  request interactivity, which `Authorize` cannot see; a PAT restriction is pure
  authorization data and belongs at the authorization function.)
- **Validate scopes ⊆ owner at creation.** Rejected as unnecessary: the runtime
  intersection already prevents escalation, and owner permissions are
  scope-dependent and mutable, so a creation-time check would be both
  redundant and frequently wrong later.
- **Separate scoped-credential type.** Rejected: machine identities (ADR-030)
  already serve the "first-class non-human principal" need; this is the lighter
  "narrow a token I already trust myself to hold" case.

## Addendum (2026-06-13): per-environment confinement

The scoping axes are now complete: a PAT may also be confined to a single
**environment** via `environment_scope` (a third optional dimension alongside the
permission allowlist and `project_scope`). `PATRestriction.EnvironmentID` denies
any check whose resolved scope is a different environment — or a project-level /
global scope (`environment 0`). Secret-level checks carry the secret's
environment, so this confines a token to that env's secrets (e.g. a staging-only
CI credential); broader project-level operations resolve `environment 0` and are
therefore denied for an environment-scoped token — correct least privilege.
Environment ids are globally unique, so confining to an environment also pins its
project. Additive `environment_scope` column (default 0 = any), enforced via the
same ctx-carried filter at the `Authorize`/`AuthorizePrincipal` chokepoint;
existing tokens are unaffected.

## Addendum (2026-06-13): PAT authentication over gRPC

PATs now authenticate over **gRPC**, not just HTTP. Previously the gRPC auth
interceptor validated only session tokens, so a `kx_pat_` token was rejected
outright (fail-closed, but an HTTP/gRPC parity gap — #136 had already made gRPC
*authorization* identical to HTTP). The unary and stream interceptors now route
the `kx_pat_` prefix to `ValidatePATToken` and, critically, carry the returned
restriction onto the handler context via `core.WithPATRestriction` — so the
least-privilege filter is enforced at the same `core.Authorize` chokepoint the
gRPC RPCs already funnel through, exactly as over HTTP. **Machine-identity tokens
over gRPC (ADR-030) shipped immediately after**: the interceptor routes the
`kx_machine_` prefix to `ValidateMachineToken`, builds a machine principal
(actor_type `machine_identity`, no owning user), and the gRPC service authz
helpers now call `AuthorizePrincipal(actorKind, principalID, …)` instead of
`Authorize(userID, …)` — identical to `Authorize` for users (so PAT and session
paths are unchanged) but resolving machine roles with **no admin bypass** for
machines. gRPC authentication now has full parity with HTTP: session, PAT, and
machine.

## Deferred

- **Frontend env dropdown** — the My Account scope picker (`web/`) offers the
  permission allowlist + project; an environment selector (cascading from the
  chosen project) is the remaining UI surface for `environment_scope`.
- **Scope presets** (e.g. a "read-only" macro expanding to the read permissions).
- ~~CLI flags on token creation~~ — **shipped**: `keyorix pat create --scope … --project-id … --environment-id …` (plus `pat list` / `pat revoke`).

## Addendum (2026-10-11): reads decided outside the chokepoint (PAT-GUARD-1)

"Every authorization path funnels through `Authorize`" held for permission
checks, not for every decision about what a token may see. Reads that decide
visibility themselves — the personal secret set (owned ∪ shared ∪ ACL-granted),
the notification feed, the secret access-request family (`requireAdminAuthorityAt`),
`CheckSecretPermission`'s owner/share/ACL paths — and PAT creation itself never
reached it, so a restricted token saw (and in two cases changed) data outside its
restriction. Each now applies the restriction at the row's own scope
(`internal/core/pat_restriction_listing.go`, `INV-CORE-pat-restriction-outside-authorize`),
and a restricted PAT cannot create a PAT. The claim is now machine-checked rather than
argued: `TestEveryGETRouteHonoursPATRestriction` (every GET route) and
`TestEveryGRPCReadHonoursPATRestriction` (every unary read RPC) call the whole read
surface with restricted tokens against a canary project and fail on any disclosure.

## Addendum (2026-10-11): self-service writes (PAT-GUARD-2)

Decided by Andrei on 2026-10-11, for the two ungated self-service writes the
PAT-GUARD-1 inventory reviewed and left open:

- **Break-glass activation is refused for a restricted PAT.** `POST
  /projects/{id}/break-glass` and gRPC `BreakGlassService.ActivateBreakGlass` are
  deliberately not RBAC-gated, so the restriction never reaches them through
  `Authorize`, and they grant the token's owner an emergency role at a project. A
  token confined below its owner must not be able to raise its owner's privileges,
  whatever the restriction's dimension (project, environment, permissions or CIDR).
  `ActivateBreakGlass` refuses any request carrying a restriction before any other
  check (`ErrRestrictedPATCannotBreakGlass`): HTTP 403, gRPC `PermissionDenied`, no
  activation recorded — the same shape as the PAT-mint refusal above. Sessions,
  machine tokens and unrestricted PATs are unchanged.
- **Revoking the owner's own tokens and sessions stays allowed for a restricted
  PAT.** `DELETE /auth/tokens/{id}` and `DELETE /auth/sessions/{id}` act on the
  caller's own credentials only (another user's id is a 404) and only ever reduce
  access; whoever holds a restricted token must be able to kill a leaked sibling
  credential with it. There is no gRPC equivalent.

Guarded by `server/http` `TestPATRestriction_RestrictedPATCannotActivateBreakGlass`
and `TestPATRestriction_RestrictedPATRevokesOnlyOwnTokensAndSessions`, and
`server/grpc` `TestGRPCPATRestriction_RestrictedPATCannotActivateBreakGlass`, over
every restricted persona of the PAT-GUARD-1 fixture (a project-only owner and the
global admin), with unrestricted controls. The other ungated self-service writes
(profile, password, MFA and WebAuthn enrolment, project access requests) are not
decided by this addendum.

## Addendum (2026-10-11): ungated writes, deny-by-default (PAT-GUARD-3)

Decided by Andrei on 2026-10-11, answering the open note PAT-GUARD-2 left on
#3071: a restricted PAT is **refused on every ungated write**, deny-by-default.
"Ungated" means no permission gate covers the write, so `Authorize` never sees it
and the restriction meant nothing there: the HTTP non-GET routes in
`noPermissionGateAllowlist` and the gRPC write RPCs whose handler makes no
authorization call. Unrestricted PATs, sessions and machine tokens are unchanged.

- **One table, both transports.** `internal/core/pat_restriction_writes.go`'s
  `restrictedPATUngatedWrites` gives every ungated write a policy whose zero value
  is "refused"; allowing one takes `Allowed` and a written `Reason`. The HTTP
  `/api/v1` group refuses from it (`RefuseRestrictedPATUngatedWrites`, after
  `Authentication`) and so do both gRPC auth interceptors. The refusal shape is
  #3062/#3071's: HTTP 403 with the sentinel text, gRPC `PermissionDenied` with the
  same text. The new sentinel is `ErrRestrictedPATSelfServiceWrite`; PAT creation
  and break-glass keep `ErrRestrictedPATCannotMintPAT` and
  `ErrRestrictedPATCannotBreakGlass`, and their core checks stay as defence in depth.
- **Refused:** profile, password change, MFA enrol/activate/disable/recovery-code
  regeneration and step-up, passkey register/delete and re-authentication, PAT
  creation, ending impersonation, marking notifications read, leaving a share
  (`DELETE /secrets/{id}/self-share`), project access requests (create, withdraw),
  secret access requests (create, withdraw), break-glass (HTTP and
  gRPC). A step-up grant belongs to the user, not the token: the owner opens it
  from a session and a restricted PAT then reads under it.
- **Allowed, each with its reason in the table:** revoking the owner's own PATs
  (one, or all expired ones) and sessions (#3071; it is also how a PAT logs
  itself out); the four creates authorized inside the handler through `Authorize`
  at the body's scope (`POST /secrets`, `/folders`, `/rotation-policies`,
  `/dynamic-secrets/configs`), where the restriction already applies and refusing
  would stop a restricted token creating anything inside its own restriction;
  deciding a secret access request (`PUT /secret-access-requests/{requestId}`,
  Andrei's follow-up decision of 2026-10-11), for parity with the gated sibling
  `PUT /projects/{id}/access-requests/{requestId}`: core applies the restriction
  (`roles.assign` at the request's own project) and then requires admin authority
  there (`requireAccessRequestAuthorityAt`), so a token without `roles.assign` at
  that project is refused by core and the request stays pending; and
  the pre-authentication and infrastructure routes outside `/api/v1`, which a PAT
  never authenticates.
- **Family-wide guard.** `server/http` `TestEveryUngatedWriteDeclaresRestrictedPATPolicy`
  derives every ungated route from `router.go`'s AST (the permission sweep's
  `scanRouter`) and `server/grpc` `TestEveryUngatedGRPCWriteDeclaresRestrictedPATPolicy`
  derives every ungated write RPC from the services' AST; each fails on an
  undeclared write or a stale entry, then checks every declaration behaviourally
  with #3062's restricted personas (two owners x five restrictions): a refused
  write answers 403/`PermissionDenied` with its sentinel while the unrestricted
  controls are not refused, an allowed one really succeeds (own revocations take
  effect, in-scope creates succeed and out-of-scope ones are refused by
  `Authorize`), and a pre-authentication route answers a restricted PAT exactly
  as it answers an unrestricted one.
