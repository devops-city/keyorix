# SAML 2.0 SSO (configuring a provider)

Keyorix is a SAML 2.0 **Service Provider**: users sign in through your IdP (ADFS,
Shibboleth, Okta, Azure AD, …) and Keyorix maps the assertion to an account — the same
session, JIT provisioning, and group→role mapping as [OIDC SSO](#), just driven by a
signed SAML assertion. Design + rationale: [ADR-063](adr-063-saml-sso.md) /
[saml-sso-design.md](saml-sso-design.md).

SAML is a provider **type** under the existing `sso` config block. It is opt-in: with no
SAML provider configured, nothing changes.

## Endpoints

For a provider named `corp`, Keyorix exposes:

| Endpoint | Purpose |
|---|---|
| `GET /auth/saml/corp/metadata` | SP metadata XML — import into your IdP to register Keyorix. |
| `GET /auth/saml/corp/login` | Start login (redirects to the IdP with an AuthnRequest). |
| `POST /auth/saml/corp/acs` | Assertion Consumer Service — your IdP posts the signed response here. |

## Configure

```yaml
sso:
  enabled: true
  providers:
    - name: corp                      # URL slug: /auth/saml/corp/*
      type: saml
      saml:
        # The IdP's SAML metadata (entityID, SSO URL, signing cert) — inline or a file:
        idp_metadata_file: /etc/keyorix/corp-idp-metadata.xml
        # idp_metadata_xml: "<EntityDescriptor …>…</EntityDescriptor>"
        sp_entity_id: https://keyorix.internal/auth/saml/corp/metadata
        acs_url:      https://keyorix.internal/auth/saml/corp/acs
        insecure_allow_idp_initiated_saml: false  # keep off unless your IdP requires it (deprecated alias: allow_idp_initiated)
        # Attribute names to read (defaults suit Azure AD / ADFS):
        email_attribute:  http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
        name_attribute:   http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname
        groups_attribute: http://schemas.xmlsoap.org/claims/Group
      # Shared provisioning controls (same as OIDC):
      auto_provision: true             # JIT-create an account on first login
      default_role: system_viewer
      group_sync: true                 # reconcile native group memberships from the assertion
      group_role_map:                  # map asserted groups → Keyorix system roles
        Keyorix-Admins: system_admin
```

1. Hand your IdP admin the SP metadata (`…/metadata`), or register the SP manually with
   the `sp_entity_id` + `acs_url` above.
2. Put the IdP's metadata at `idp_metadata_file` (or paste it inline).
3. Send users to `/auth/saml/corp/login`. Add `?return_to=<in-app path>` to land them on a
   specific page after sign-in (the path is carried through as RelayState).

## Security

- The assertion's signature is verified against the **pinned IdP certificate** from its
  metadata (never a cert in the response); audience (`sp_entity_id`), recipient
  (`acs_url`), the validity window, and `InResponseTo` are all enforced — by the vetted
  `crewjam/saml` + `goxmldsig` stack (ADR-063), not a bespoke implementation.
- **IdP-initiated SSO is off by default** (it loses `InResponseTo` CSRF/replay
  protection); enable per-provider only when required.
- A SAML login yields the same session, audit (`auth.sso_login`), JIT provisioning, and
  per-project MFA as OIDC. Group→role mapping is additive and non-clobbering — manual role
  grants survive; the IdP only drives the roles named in `group_role_map`.
- Group/role reconciliation runs only when the assertion actually carries groups, so an
  IdP that omits the groups attribute never strips a user's memberships or roles.
