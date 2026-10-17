# Threat Model: Authentication (sessions, PAT, machine identity, MFA, WebAuthn, OIDC, SAML)

> Part of [`docs/security/threat-models/`](README.md). Derived from
> [`../threat-model.md`](../threat-model.md) (trust boundaries B3/B5) and
> [`../architecture.md`](../architecture.md) §4 — see those for the
> broader system view; this document narrows to the authentication
> mechanisms themselves.

## 1. System context

Nine distinct authentication mechanisms converge on the same
authorization chokepoint ([server-api.md](server-api.md)) once a caller
is authenticated — none of them grant any authority by themselves beyond
establishing *who* is calling.

```mermaid
flowchart TB
    subgraph Credentials
        PW[Password + session]
        PAT[Personal Access Token]
        MID[Machine identity token]
        OIDC[OIDC id_token\n(human or machine)]
        SAML[SAML assertion]
        TOTP[TOTP code]
        WA[WebAuthn assertion]
        REC[Recovery key\n(local only)]
    end

    subgraph Verify["Verification (per mechanism)"]
        SESSV[Session: hash lookup,\nabsolute TTL ceiling]
        PATV[PAT: hash lookup,\nrestriction filter]
        MIDV[Machine identity:\nlifecycle state check]
        OIDCV[OIDC: issuer allowlist →\nasymmetric-alg-only → jwks → aud/exp/nbf]
        SAMLV[SAML: pinned IdP cert →\nsig validation → Audience/Recipient/NotOnOrAfter → anti-replay]
        MFAV[MFA: TOTP window /\nWebAuthn origin+signature]
        RECV[Recovery: SHA-256 verifier\ncompare, local subcommand only]
    end

    IDENTITY[Authenticated principal\n+ actor_type]
    AUTHZ[core.Authorize\n(server-api.md)]

    PW --> SESSV
    PAT --> PATV
    MID --> MIDV
    OIDC --> OIDCV
    SAML --> SAMLV
    TOTP --> MFAV
    WA --> MFAV
    REC --> RECV

    SESSV --> IDENTITY
    PATV --> IDENTITY
    MIDV --> IDENTITY
    OIDCV --> IDENTITY
    SAMLV --> IDENTITY
    RECV -. local admin\nrecovery only .-> IDENTITY
    IDENTITY --> MFAV
    MFAV --> AUTHZ
```

## 2. Trust boundaries

| Boundary | Enforcement chokepoint |
|---|---|
| B3/B4 — session/PAT/machine-token validation | Same HTTP middleware + `core.Authorize` as any client |
| B5 — web UI session delivery | `HttpOnly`/`Secure`/`SameSite=Lax` cookie, never `localStorage` |
| B7 (identity-provider federation) — OIDC/SAML signing-key trust | Issuer/cert pinning checked before key retrieval |
| B8 — emergency admin recovery | Local-only subcommand, never a network endpoint (ADR-108 decision B) |

## 3. Threat table

| ID | STRIDE | Description | Mitigation | Evidence link | Residual risk / GAP |
|---|---|---|---|---|---|
| AUTH-1 | Spoofing / tampering | A forged, guessed, or stolen session cookie lets an attacker act as its owner. | Short-TTL access token plus a hard absolute lifetime ceiling refresh cannot extend; individually listable/revocable; delivered only via an `HttpOnly`/`Secure`/`SameSite=Lax` cookie. | `../architecture.md` §4 | ~30s authentication cache window, narrowed: every cache hit re-checks the credential's revocation state live (session row, account state, PAT, machine token, federated machine identity), so a revocation is honoured on the next request on every replica; when that re-check cannot read the database the request is refused, not served from cache (AUTH-11). What the cache still holds for up to its TTL: an impersonation session's admin-ceiling re-check (run on the slow path only, behind its own 60s cache, `cachedImpersonationCeiling`) and a federated JWT's own `exp` (the cache entry is not clamped to it). |
| AUTH-2 | Elevation of privilege | A PAT reaches more scope/permission than its owner intended at creation. | SHA-256-hashed at rest; optionally restricted at creation to a permission allowlist and/or a single project scope — a filter that only ever narrows below the owner, enforced before role resolution and the admin bypass. Metamorphic-fuzzed to confirm a restriction only ever narrows. | ADR-027, ADR-042; `internal/core/pat_authz_metamorphic_fuzz_test.go` | None identified. |
| AUTH-3 | Spoofing | A machine (service/CI/K8s) identity is impersonated or inherits human-admin privilege it shouldn't have. | Modelled separately from human users with its own lifecycle (`pending → active → suspended ⇄ active`, `revoked` terminal); receives **no** admin-role bypass. | ADR-030 | None identified. |
| AUTH-4 | Spoofing / tampering | A malicious or compromised OIDC-adjacent party forges a token, or performs key-confusion to pass verification. | Asymmetric-only algorithm allowlist (`HS*`/`none` rejected), required `exp`, bounded `nbf` skew, issuer allowlist checked *before* key retrieval, audience intersection, `jwks_uri` must be `https` (loopback exempted for local dev only). | ADR-031; `SECURITY-VERIFICATION.md` "ICT third-party risk / federation trust boundary" | None identified. |
| AUTH-5 | Spoofing / tampering | A forged SAML assertion, or a replayed valid one, authenticates as another identity. | Service Provider built on `crewjam/saml` + `goxmldsig` (never hand-rolled XML-DSig); mandatory signature validation against a **pinned** IdP certificate, `AudienceRestriction`/`Recipient`/`NotBefore`/`NotOnOrAfter` checks, replay protection; IdP-initiated flow off by default. | ADR-063 | Per this repo's standing embargo policy (`../testing.md` header note), a specific finding against `crewjam/saml` itself is embargoed pending upstream disclosure — not detailed here; only the mechanism is described. |
| AUTH-6 | Spoofing | Brute-forcing or stealing a TOTP secret authenticates as the victim. | RFC 6238, two-step login, single-use recovery codes, secret encrypted at rest. | ADR-034 | None identified. |
| AUTH-7 | Spoofing | Credential/session-token theft (phishing) compromises a WebAuthn-protected account. | Origin-bound public-key assertions, no exportable shared secret, FIDO clone detection — phishing-resistant by construction, unlike TOTP. | ADR-036 | None identified. |
| AUTH-8 | Elevation of privilege | A deployment-wide MFA-optional policy leaves one sensitive project without an MFA requirement it actually needs. | `security.require_mfa` (deployment-wide) or a per-project override — a sensitive project can require MFA even when the global policy is off. | ADR-037 | None identified. |
| AUTH-9 | Elevation of privilege | Host access alone (without the separately-held recovery key) grants admin authentication. | `keyorix-server admin recover-admin` requires **both** host access and a separately-held, SHA-256-verified 256-bit recovery key; every use is audited and triggers an admin notification. | ADR-108 decision B.2, `internal/recoverykey` | **Accepted design ceiling, not a gap.** "Host access + the recovery key = can authenticate as admin" is the strongest practical bar for a local break-glass tool — see `../threat-model.md` §5.1 for the full insider-threat analysis. |
| AUTH-10 | Repudiation | An admin acting under impersonation denies having performed an action, or the impersonation itself goes unrecorded. | A separate short-lived session is issued (the admin's own session is untouched); every action under it is tagged `impersonated_by`/`acting_as`, plus discrete `impersonation.start`/`.end` audit events. | — | None identified. |
| AUTH-11 | Elevation of privilege / spoofing | A credential revoked (or an account suspended, a session logged out, a machine identity suspended) on another replica keeps authenticating from this replica's auth cache because the cache-hit re-check that would see the revocation fails during a database outage or blip. | Fail closed (CACHE-FAILCLOSED-1, 2026-10-17): a failed cache-hit re-check refuses the request with 503 `Retry-After` and a fixed message, never authenticates from the cache, does not evict the entry and does not count against the per-IP failed-auth budget; a definitive revocation readable from either half of the session re-check still denies 401 and evicts. gRPC has no auth cache: a storage error on the credential lookup is `Unavailable`. Before this, the cache hit degraded to the cached login for up to ~30s (INV-MW-05's former transient half). | `server/middleware/INVARIANTS.d/INV-MW-cache-hit-recheck-fails-closed.md`; `server/middleware/cache_hit_fail_closed_test.go`; `server/grpc/interceptors/auth_storage_error_fail_closed_test.go` | Availability trade-off, accepted: a brief database outage now rejects cached credentials (503) instead of serving them. Clients should retry on 503 / `Unavailable`. |

## 4. Residual risks specific to this component

Carried forward from `../threat-model.md` §6, not re-derived: the
authentication cache window (~30s, above, narrowed by AUTH-11) is the one
residual risk that belongs specifically to this component rather than the
system generally.
