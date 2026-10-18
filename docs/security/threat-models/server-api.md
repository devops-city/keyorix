# Threat Model: Server API (REST + gRPC)

> Part of [`docs/security/threat-models/`](README.md). This is a
> per-component view derived from, and consistent with, the system-wide
> [`../threat-model.md`](../threat-model.md) (trust boundaries B3/B4) — it
> does not re-derive conclusions that document already reached, only
> narrows the focus to this one component with more operational detail
> and a dedicated data-flow diagram. Where the two ever disagree, treat
> that as a bug in this document and open an issue; `../threat-model.md`
> is the longer-standing, more-reviewed source.

## 1. System context

The server API is the single point every client goes through to reach
stored secrets and account data — there is no other path. As of this
writing: **343 files under `server/http/handlers/`** implementing the
REST surface, and **55 files under `server/grpc/services/`** implementing
a partial (data-plane-focused), 86-RPC subset of the same surface
([ADR-105](../../adr-105-grpc-scope-and-parity.md)). Every one of those
~400 implementation files reaches the same single authorization
chokepoint — this is the property the rest of this document is about.

```mermaid
flowchart LR
    subgraph Clients
        WEB[Web UI]
        CLI[CLI, remote mode]
        GRPC[gRPC clients /\nk8s delivery / SDKs]
        API3P[Third-party API clients]
    end

    subgraph Edge["server/middleware"]
        TLS[TLS termination]
        RL[Rate limiting /\nbody-size caps]
        SESS[Session / PAT / machine\ntoken validation]
        CSRF[CSRF double-submit\n(cookie clients only)]
    end

    subgraph Core["core.Authorize chokepoint"]
        AUTHZ[Scoped RBAC check\n(system/project/environment)]
    end

    subgraph Handlers
        HTTP[server/http/handlers\n(343 files)]
        GRPCSVC[server/grpc/services\n(55 files)]
    end

    DB[(Storage layer:\nSQLite / PostgreSQL)]
    AUDIT[(audit_events,\nhash-chained)]

    WEB --> TLS
    CLI --> TLS
    API3P --> TLS
    TLS --> RL --> SESS --> CSRF --> HTTP
    GRPC --> GRPCSVC
    HTTP --> AUTHZ
    GRPCSVC --> AUTHZ
    AUTHZ --> DB
    AUTHZ -. best-effort\nasync .-> AUDIT
    AUTHZ -. audit-before-disclosure\n(secret VALUE reads only) .-> AUDIT
```

## 2. Trust boundaries in scope

| Boundary (from `../threat-model.md` §3) | What crosses it here |
|---|---|
| B3 — REST API | Every human- and machine-facing HTTP request |
| B4 — gRPC API | The 86-RPC data-plane subset, same authorization chokepoint |

B1/B2 (CLI local vs. remote mode), B5 (web UI specifically), and B6 (k8s
delivery specifically) are covered in their own component documents —
this one covers what's common to every caller once a request lands at
the HTTP or gRPC edge.

## 3. Threat table

| ID | STRIDE | Description | Mitigation | Evidence link | Residual risk / GAP |
|---|---|---|---|---|---|
| API-1 | Spoofing | A forged or guessed session/PAT/machine token lets an attacker act as the token's owner. | Tokens are 256-bit `crypto/rand` values; reusable ones are SHA-256-hashed and looked up by hash, never compared in plaintext. | [`authentication.md`](authentication.md) (full mechanism) | A leaked raw token is valid until revoked/expired — mitigated by short session TTLs and an absolute lifetime ceiling refresh cannot extend. |
| API-2 | Tampering | A write request bypasses authorization and mutates data the caller shouldn't be able to touch. | Every write path funnels through `core.Authorize`/`core.AuthorizePrincipal` before mutation; PAT restrictions apply *before* role resolution and the admin bypass. | `internal/core/authz.go`; ADR-042 | None identified beyond ordinary authenticated-actor-does-authorized-thing. The former exception, CLI local mode, was removed (ADR-108 Decision A) — see [authorization-rbac.md](authorization-rbac.md) §4 and `../threat-model.md` §4 B1/B2, §5.2. |
| API-3 | Repudiation | An actor denies having performed a security-relevant action. | Every such action is audited with actor identity, `actor_type`, and outcome, including impersonation attribution. | [`audit-chain.md`](audit-chain.md) | None identified for the server-API layer specifically — see `audit-chain.md` for its own residuals. |
| API-4 | Information disclosure | A route serializes a raw internal model to the wire, leaking more (or differently-shaped) data than its contract intends. | Most routes use a dedicated wire type; two specific routes did not propagate an existing redaction decision from their sibling. | `docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md` | **Open, filed.** [#2733](https://github.com/keyorixhq/keyorix/issues/2733) (`threat-model-gap`) — `SearchAuditLogs`/`AccessHistory` leak `IPAddress` (PII) where `GetAuditLogs`/`AuditTrail` already redact it. No tracking issue existed before this threat-model pass. ~24 other routes in the same finding are a lower-severity casing/contract-hygiene defect, not a PII leak. |
| API-5 | Denial of service | An attacker forces excessive server-side work (unbounded request bodies, unbounded graph traversal, request flooding) to degrade availability for other callers. | Rate limiting, request-body size caps (`server/middleware.MaxBodyBytes`), pagination, bulk-op batch caps, and a bounded-BFS fix for `transitiveDependents` (matching its sibling `blastBFS`'s node/depth cap). | [`SECURE-CODING.md`](../SECURE-CODING.md) §9; `security-review-2026-09.md` "Availability and denial-of-service resistance" | None identified beyond ordinary capacity planning. |
| API-6 | Elevation of privilege | A caller reaches a permission or scope beyond their granted role — via role-naming tricks, cross-project leakage, or a gRPC/HTTP parity gap. | Scoped RBAC (system/project/environment), least-privilege defaults, cross-project isolation at every nested-resource route, gRPC authorized identically to HTTP. The admin-bypass marker is a structural field, not a name-matched role. | `SECURITY-VERIFICATION.md` "Access control & authorisation"; [ADR-084](../../adr-084-admin-bypass-structural-marker.md) | None identified after the cross-transport parity fix. |

## 4. Residual risks specific to this component

- The information-disclosure gap above (#2733) is the one open item with
  a filed issue. Everything else in this section is carried forward from
  `../threat-model.md` §6 without re-litigation: the transient
  in-process secret-value exposure (heap copies between decryption and
  the wire) and the ~30s authentication cache window both apply to every
  request through this component and are not re-derived here.
