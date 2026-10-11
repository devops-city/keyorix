# Design: SAML 2.0 SSO (Service Provider)

> **Status: design (not yet built).** OIDC federation is shipped; SAML is the remaining
> SSO gap and a hard requirement for many enterprise/regulated buyers (legacy IdPs, ADFS,
> some government tenants). This is the design pass before implementation. Decision record:
> [ADR-063](adr-063-saml-sso.md).

## 1. Problem & motivation

Keyorix supports human SSO via **OIDC** (`internal/core/sso.go`/`oidc.go`: discovery,
`id_token` verification, JIT provisioning, group→role mapping) and machine federation via
OIDC (ADR-031). But a large share of enterprise and public-sector identity estates still
standardise on **SAML 2.0** (ADFS, Shibboleth, older Okta/Azure AD tenants, government
IdPs). Without a SAML SP, those buyers can't connect Keyorix to their IdP at all — it's a
procurement blocker, not a nice-to-have.

The good news: the **post-authentication half is already built and reusable**. Account
JIT-provisioning (`provisionSSOUser`), group reconciliation (`syncSSOGroups`), group→role
mapping (`syncSSORoles`, `GroupRoleMap`), and session issuance are claim-source-agnostic.
SAML only needs to produce the same `(subject, email, name, groups)` from a signed
assertion instead of an `id_token`.

## 2. Goals / non-goals

**Goals**
- A standards-compliant SAML 2.0 **Service Provider**: SP metadata, SP-initiated login
  (AuthnRequest), and an Assertion Consumer Service (ACS) that validates a signed
  assertion and signs the user in.
- **Reuse** the existing provisioning + group/role-mapping + session path — SAML is a new
  *provider type*, not a parallel auth stack.
- Safe by construction: mandatory signature validation, audience/recipient/time checks,
  and replay protection.

**Non-goals (v1)**
- Acting as a SAML **IdP** (Keyorix is only an SP).
- SAML for **machine** identities (OIDC federation already covers workloads; SAML is for
  humans).
- SCIM provisioning (separate concern; group sync from assertions covers v1).
- IdP-initiated SSO **by default** (supported only behind explicit opt-in — see §5).

## 3. Architecture — SAML as a second SSO provider type

Today `SSOProvider` (`sso.go:46`) is OIDC-shaped (an `oauth2.Config`, a groups *claim*,
JWKS). Generalise the abstraction:

- Add a **`Type`** (`oidc` | `saml`) to the provider, and keep the **shared**
  provisioning fields on a common base: `AutoProvision`, `DefaultRole`, `GroupSync`,
  `GroupRoleMap`. These already exist and are reused verbatim.
- Provider-type-specific config lives in its own block:
  - **OIDC** (unchanged): `OAuth`, `GroupsClaim`, JWKS.
  - **SAML** (new): IdP `entityID`, IdP SSO URL + binding, IdP signing **X.509
    certificate(s)**, SP `entityID`, SP ACS URL, optional SP signing key (for signed
    AuthnRequests / decrypting encrypted assertions), `NameID` format, and an
    **attribute map** (`email`, `name`, `groups` → IdP attribute names).
- The SAML flow produces `(subject, email, name, groups)` and then calls the **same**
  `provisionSSOUser` / `syncSSOGroups` / `syncSSORoles` / session-issuance code the OIDC
  path uses. `GroupRoleMap` works identically — it just maps SAML group *attribute values*
  instead of OIDC group *claim values*.

### Flow (SP-initiated)

```
/auth/saml/{provider}/metadata → SP metadata XML (hand to the IdP admin)
/auth/saml/{provider}/login    → build + sign AuthnRequest, store (RequestID, RelayState),
                                  redirect/POST to the IdP SSO URL
   … user authenticates at the IdP …
/auth/saml/{provider}/acs (POST) → receive SAMLResponse:
   1. validate XML signature against the configured IdP cert (trust chain, not self-sig)
   2. check StatusCode = Success
   3. check Conditions: AudienceRestriction == SP entityID; NotBefore/NotOnOrAfter (± skew)
   4. check SubjectConfirmation: Recipient == ACS URL; NotOnOrAfter; InResponseTo == our
      stored RequestID (SP-initiated)
   5. enforce one-time use: reject a replayed Assertion ID (cache until NotOnOrAfter)
   6. extract NameID (subject) + mapped attributes (email, name, groups)
   7. provisionSSOUser + syncSSOGroups + syncSSORoles → issue session → redirect to RelayState
```

The existing `SSOLoginState` table (`models.go:124`) is reused/extended to carry the SAML
`RequestID` (for `InResponseTo`) and `RelayState`, mirroring the OIDC state/nonce handling.

## 4. Library choice — do NOT hand-roll XML-DSig

SAML signature validation is a notorious source of critical vulnerabilities — XML
signature wrapping (XSW), canonicalization (C14N) mismatches, comment-splitting, and
unsigned-assertion confusion. Unlike the air-gap trust foundation (where hand-rolling
`ed25519` over a fixed byte string is safe and was the right call, ADR-062), SAML XML
processing **must** use a vetted, maintained library:

- `github.com/crewjam/saml` (SP toolkit: metadata, AuthnRequest, ACS, assertion
  validation) on top of `github.com/russellhaering/goxmldsig` (XML-DSig). These are the
  de-facto Go SAML stack.

This is a deliberate dependency: the security cost of a bespoke XML-DSig implementation
far outweighs the dependency cost. Pin the version (SSDLC) and track its advisories.

## 5. Security

- **Signature mandatory.** The Response and/or Assertion must be signed by the configured
  IdP certificate; an unsigned or wrong-key signature is rejected. We trust only the
  **pinned IdP cert** from config/metadata — never a cert embedded in the Response.
- **Audience + recipient + time.** Enforce `AudienceRestriction` = SP entityID,
  `Recipient` = our ACS URL, and the `NotBefore`/`NotOnOrAfter` windows with a small,
  configurable clock skew.
- **Replay protection.** Reject a reused `Assertion ID` (and, for SP-initiated, require
  `InResponseTo` to match a request we issued and have not yet consumed). A short-lived
  assertion-ID cache, keyed to `NotOnOrAfter`, backs this.
- **IdP-initiated SSO is off by default.** Without an `InResponseTo` it loses CSRF/replay
  protection; enable only behind explicit per-provider config for IdPs that require it,
  and still enforce signature/audience/time/replay.
- **Encrypted assertions** (`EncryptedAssertion`) supported when an SP key is configured
  (some IdPs mandate them).
- **No new authorization surface.** A SAML login yields exactly the same session and the
  same JIT/role-mapping outcomes as OIDC — RBAC, audit (`auth.sso_jit_provisioned` and
  login events), and per-project MFA all apply unchanged. Group→role mapping stays
  additive and non-clobbering (manual grants untouched), as today.

## 6. Configuration

A SAML provider in the SSO config block, e.g.:

```yaml
sso:
  providers:
    - name: corp-adfs
      type: saml
      saml:
        idp_metadata_url: https://adfs.corp.example/FederationMetadata.xml  # or static idp_* below
        idp_entity_id: http://adfs.corp.example/adfs/services/trust
        idp_sso_url:   https://adfs.corp.example/adfs/ls/
        idp_certificate: |-
          -----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----
        sp_entity_id:  https://keyorix.internal/saml/corp-adfs
        sp_acs_url:    https://keyorix.internal/auth/saml/corp-adfs/acs
        name_id_format: emailAddress
        insecure_allow_idp_initiated_saml: false   # deprecated alias: allow_idp_initiated
        attribute_map:
          email:  http://schemas.xmlsoap.org/.../emailaddress
          name:   http://schemas.xmlsoap.org/.../displayname
          groups: http://schemas.xmlsoap.org/.../groups
      auto_provision: true
      default_role: system_viewer
      group_sync: true
      group_role_map: { "Keyorix-Admins": "system_admin" }
```

Either `idp_metadata_url`/XML (auto-extract entityID/SSO URL/cert) **or** the static
`idp_*` fields. The SP key (for signed AuthnRequests / decryption) is optional and sourced
like other secrets, never inlined.

## 7. Phased delivery

Each phase its own ADR; nothing changes default behaviour until built (SSO stays
opt-in/config-driven).

1. **Phase 1 — SP core (done):** `SSOProvider` generalised with a type; the SAML provider
   (`internal/saml`, crewjam/saml); the metadata/login/ACS routes; signature/audience/
   time/`InResponseTo` validation (delegated to the vetted stack); and the existing
   provisioning + group/role mapping reused. SP-initiated only. Configure per
   [docs/saml-sso.md](saml-sso.md).
2. **Phase 2 — hardening/parity:** encrypted assertions, IdP-initiated (opt-in), signed
   AuthnRequests, SP-key rotation, and metadata-URL refresh.
3. **Phase 3 — ops:** admin UI/CLI to add/test a provider, a "test connection" assertion
   inspector, and compliance-posture surfacing of SSO enforcement.

## 8. Compliance mapping

Enterprise SSO/federation is an access-control and identity-assurance control under NIS2
(Art. 21 access control), DORA, ISO 27001 (A.5.16 identity management / A.8.5
authentication), and ENS (`op.acc.*`). SAML support removes an onboarding blocker for
regulated tenants whose IdPs predate OIDC.
