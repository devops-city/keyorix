# Threat Model: Authorization (scoped RBAC)

> Part of [`docs/security/threat-models/`](README.md). Derived from
> [`../threat-model.md`](../threat-model.md) and [`../architecture.md`](../architecture.md)
> §5. See [authentication.md](authentication.md) for *who* a caller is;
> this document covers *what they're allowed to do once identified*.

## 1. System context

Every authorization decision in this codebase — HTTP handler, gRPC
service, in-handler helper — funnels through one function. This
single-chokepoint design is the property that let one fix
(the PAT-restriction filter, §authentication.md) automatically bind
every present and future authorization path without re-implementing it
per transport.

```mermaid
flowchart LR
    subgraph Callers
        HTTP[HTTP handlers]
        GRPC[gRPC services]
        INH[In-handler helpers]
    end

    AUTHZ["core.Authorize /\ncore.AuthorizePrincipal\n(the one chokepoint)"]

    subgraph Decision["Decision inputs"]
        ROLE[Role grants:\nsystem / project / environment scope]
        BYPASS["BypassesPermissionChecks\n(structural field, ADR-084)"]
        PATR[PAT restriction filter\n(narrows below owner, pre-role)]
        CEIL[Privilege ceiling\n(derived from ACTOR, not target)]
    end

    ALLOW[Allow]
    DENY["Deny — 403, identical\nshape for 'no access' and\n'doesn't exist' (ADR-096)"]

    HTTP --> AUTHZ
    GRPC --> AUTHZ
    INH --> AUTHZ
    AUTHZ --> PATR --> ROLE --> BYPASS --> CEIL
    CEIL -->|granted| ALLOW
    CEIL -->|not granted| DENY
```

## 2. Trust boundaries

This component sits *inside* B3/B4 (it's the decision core those
boundaries call into) rather than defining a boundary of its own —
see [server-api.md](server-api.md) for the surrounding transport
boundaries.

## 3. Threat table

| ID | STRIDE | Description | Mitigation | Evidence link | Residual risk / GAP |
|---|---|---|---|---|---|
| AUTHZ-1 | Elevation of privilege | Renaming a role to match an admin-role name string grants it admin-bypass privilege. | `models.Role.BypassesPermissionChecks` is a structural field, written only by role seeding and a one-time migration snapshot — not derived from the role's name. `CreateRole`/`UpdateRole` never accept it from a request DTO on any transport. | ADR-084 | **Closed.** Replaced an earlier fixed-name lookup (`roleSetContainsAdmin`) at all 8 call sites. |
| AUTHZ-2 | Elevation of privilege | A privilege-ceiling check inspects only the *target*'s current privileges, letting a zero-standing attacker self-mint into an empty/attacker-controlled target and pass trivially. | Ceiling is derived from the **actor's own effective privileges**, checked at creation time, not only at credential-mint time. | `RequireMachinePrivilegeCeiling` | **Closed — was a real historical gap.** Checked only the target machine identity's roles until 2026-08-25. |
| AUTHZ-3 | Elevation of privilege | A nested-resource route (e.g. a child object under a project) is reachable by a caller authorized for a *different* project. | Every nested-resource route reconciles the child object's project against the caller's authorized project before acting. | 2026-09 security review, five lifecycle routes fixed | **Closed.** |
| AUTHZ-4 | Information disclosure | A 403-vs-404 (or similarly differentiated) error on an authorization check leaks whether a resource exists to a caller with no access to it. | The same 403 for "exists, no access" and "doesn't exist," verified by a call-site guard. | [ADR-096](../../adr-096-anti-enumeration-403-for-both.md) | None identified. |
| AUTHZ-5 | Tampering | A write path exists that bypasses the authorization chokepoint reads go through. | Every write path funnels through the same `core.Authorize` chokepoint as every read — there is no separate, less-guarded write path. | `internal/core/authz.go` | None identified. |

## 4. Residual risks specific to this component

- **CLI local mode (closed).** The CLI used to open the SQLite database
  directly and so never called `core.Authorize`. ADR-108 Decision A removed that
  mode: the CLI is a thin network client with no database access. See
  `../threat-model.md` §4 (B1/B2) and §5.2.
- No other residual risk specific to the authorization chokepoint
  itself is identified beyond what's listed above as closed.
