# Per-Component Threat Models

> See [`../SECURITY-MODEL.md`](../SECURITY-MODEL.md) first for the
> one-page public summary (goals, in scope, out of scope, trust
> assumptions) — these documents are the detailed evidence underneath
> it, in the VSO-style format (DFD, trust boundaries, a threat table
> with an ID/STRIDE/Description/Mitigation/Evidence-link/
> Residual-or-GAP column per row) rather than that page's prose.

Each document here narrows [`../threat-model.md`](../threat-model.md) (the
system-wide threat model — trust boundaries, STRIDE, residual risks) to
one component, with a dedicated data-flow diagram and more operational
detail. None of these contradict the system-wide document; where a
narrower document and the system-wide one might seem to disagree, the
system-wide document is the longer-standing, more-reviewed source —
that's a bug in the narrower document, not a real disagreement, and
should be filed as an issue.

| Component | Covers |
|---|---|
| [`server-api.md`](server-api.md) | REST + gRPC request path, the `core.Authorize` chokepoint as seen from the transport layer |
| [`authentication.md`](authentication.md) | Sessions, PAT, machine identity, OIDC, SAML SSO, TOTP MFA, WebAuthn, emergency admin recovery |
| [`authorization-rbac.md`](authorization-rbac.md) | Scoped RBAC, the admin-bypass structural marker, privilege-ceiling derivation |
| [`audit-chain.md`](audit-chain.md) | Hash-chained audit events, signed checkpoints, offline verification |
| [`secret-storage-key-hierarchy.md`](secret-storage-key-hierarchy.md) | Envelope encryption, the KEK/DEK hierarchy, Shamir, HSM/KMS/TPM providers |
| [`backup-restore.md`](backup-restore.md) | `admin backup`/`restore` (SQLite), the operator-driven Postgres path, audit-chain-verified restore |
| [`update-bundles-airgap.md`](update-bundles-airgap.md) | Signed offline update bundles, offline license validation, air-gapped OIDC |
| [`connectors.md`](connectors.md) | AWS/Azure/GCP/Vault/rotation-target connectors, tenant scoping, SSRF guards |
| [`kubernetes-operator.md`](kubernetes-operator.md) | The `KeyorixSecret` CRD controller, namespace-scoped RBAC, confused-deputy guard |
| [`web-ui.md`](web-ui.md) | Session-cookie delivery, CSRF, CSP, client-side state — with the same narrower-scope caveat the system-wide document states |
| [`ha-consistency.md`](ha-consistency.md) | Cross-replica check-then-act races — a threat class no competitor-published security model surveyed names at all |
| [`mcp-server.md`](mcp-server.md) | `keyorix-mcp`: prompt injection and exfiltration modeled as first-class threats, not a one-line disclaimer |
| [`sharing-and-acl.md`](sharing-and-acl.md) | Direct and group shares, `SecretACL` grants, share elevation (a viewer holding a write share), revoke, ownership transfer, and the soft-delete / restore cascade |
| [`break-glass.md`](break-glass.md) | Self-service emergency access: activation gates, expiry, the owed-audit degraded path, alert recipients, independent review, PAT-restricted callers |
| [`scim-and-sso-accounts.md`](scim-and-sso-accounts.md) | The SCIM bearer token, SCIM ownership of accounts, deprovision (sessions and PATs), SSO account binding and group reconcile, an SSO-managed sole administrator |
| [`dynamic-secrets-and-leases.md`](dynamic-secrets-and-leases.md) | Lease issue and revoke, the admin DSN at rest, SSRF guards on the target, ephemeral backends that cannot be revoked early, lease versus project delete |
| [`notifications-webhooks.md`](notifications-webhooks.md) | Channel URL as a bearer credential (encrypted at rest, #2433), SSRF on outbound delivery, redaction in audit diffs and logs, alert loss and replay |
| [`rate-limits-and-lockout.md`](rate-limits-and-lockout.md) | The login budget, per-account lockout, per-IP versus per-principal limits, the in-memory-per-replica residual, lockout clear audit |

## What's not here

The sync agent and External Secrets Operator integration share the
`kubernetes-operator.md` document's underlying API-read path (same
scoping, same "never log values" property) and don't have their own
dedicated file — see that document's own introduction for the pointer
to [`../../k8s-sync.md`](../../k8s-sync.md) and
[`../../k8s-eso.md`](../../k8s-eso.md) if those specific delivery modes
need their own deeper pass later.

## GAPs filed while writing these

Two genuinely open items surfaced while grounding these documents in
the real code rather than being invented for this pass — both labeled
`threat-model-gap`:

- [#2733](https://github.com/keyorixhq/keyorix/issues/2733) — `SearchAuditLogs`/`AccessHistory` leak `IPAddress` (PII) where a sibling route already redacts it (server-api.md)
- [#2734](https://github.com/keyorixhq/keyorix/issues/2734) — no process-level isolation for connector code (connectors.md)
