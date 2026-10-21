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
| [`backup-restore.md`](backup-restore.md) | `admin backup`/`restore` on SQLite and PostgreSQL (live snapshot or `--exclusive`), the manual `pg_dump` alternative, audit-chain-verified restore |
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

### GAPs filed with the sharing, break-glass, SCIM/SSO, dynamic-secrets, notifications and rate-limit documents

Each is a row in the document named, written as a GAP (never as a
mitigation) because the code does not do the thing, or no test on `main`
proves that it does. The `threat-model-gap` label is applied by the
coordinator. "Bug" means reproduced on `main` with a throwaway test;
"decision" means the behaviour is a design choice that needs an explicit
yes or no; "test" means the guard is in the code and no test pins it.

| Issue | Kind | Document / row | Summary |
|---|---|---|---|
| [#3418](https://github.com/keyorixhq/keyorix/issues/3418) | bug | scim-and-sso-accounts.md SCIM-2 | A native account that signs in through SSO gets `external_id = sso:…`, which counts as SCIM-managed: a SCIM token holder can read, edit, deactivate and delete it. Fixed in #3493 (merged 2026-10-20) |
| [#3419](https://github.com/keyorixhq/keyorix/issues/3419) | bug | scim-and-sso-accounts.md SCIM-4 | SCIM `active=false` (PATCH/PUT) does not revoke the user's PATs; an IdP re-enable hands them back (`DELETE` does, #2855). Fixed in #3491 (merged 2026-10-20) |
| [#3420](https://github.com/keyorixhq/keyorix/issues/3420) | bug (fix queued) | break-glass.md BG-6 | The break-glass audit event is best-effort after commit; a failed append leaves a live grant with no chain record. Fix owned by BREAKGLASS-OWED-1 |
| [#3422](https://github.com/keyorixhq/keyorix/issues/3422) | decision | sharing-and-acl.md SHARE-8 | Core `ShareSecret` accepts `IsGroup=true` without the group-in-project check; no caller reaches it, no guard |
| [#3423](https://github.com/keyorixhq/keyorix/issues/3423) | decision | sharing-and-acl.md SHARE-9 | `secrets.manage` for ACL grant/revoke is enforced only in the transports; no guard for a third caller |
| [#3424](https://github.com/keyorixhq/keyorix/issues/3424) | test | dynamic-secrets-and-leases.md DYN-3, DYN-4 | No test for `revalidateAdminDSN`, for refusing a no-native-expiry backend while the sweeper is off, or for issuing against a disabled config |
| [#3425](https://github.com/keyorixhq/keyorix/issues/3425) | decision | notifications-webhooks.md NW-2 | The notification-channel API returns the decrypted webhook URL (a bearer credential) to every `alerts.write` caller |
| [#3426](https://github.com/keyorixhq/keyorix/issues/3426) | bug | notifications-webhooks.md NW-5 | A failed API-managed delivery logs the full URL, including a path-embedded token (`url.Redacted` masks only userinfo) |
| [#3427](https://github.com/keyorixhq/keyorix/issues/3427) | test | notifications-webhooks.md NW-3 | No test for the redirect refusal in alert escalation or for the create-time DNS-resolution refusal |
| [#3428](https://github.com/keyorixhq/keyorix/issues/3428) | decision | rate-limits-and-lockout.md RL-9 | Online `UnlockUser` clears the lockout before a best-effort audit write; the offline command audits first |
| [#3429](https://github.com/keyorixhq/keyorix/issues/3429) | bug (low) | rate-limits-and-lockout.md RL-5 | The gRPC failed-auth IP limiter sweeps its whole map on every call (the HTTP twin was amortised by #G19) |

Already tracked elsewhere, cited in the documents rather than refiled:

| Issue | Document / row | State when written |
|---|---|---|
| [#2798](https://github.com/keyorixhq/keyorix/issues/2798), [#2797](https://github.com/keyorixhq/keyorix/issues/2797), [#2794](https://github.com/keyorixhq/keyorix/issues/2794), [#2795](https://github.com/keyorixhq/keyorix/issues/2795) | sharing-and-acl.md SHARE-13 | Open on `main`; LIFECYCLE-CASCADE-1 ([#3405](https://github.com/keyorixhq/keyorix/pull/3405)) was not merged. Replace each GAP with the test #3405 names when it merges |
| [#2796](https://github.com/keyorixhq/keyorix/issues/2796) | sharing-and-acl.md SHARE-13 | Issue still open, but the lock-first fix is on `main` (`TestConcurrency_DeleteProjectIfEmpty_LockFirstPreventsOrphanedDelete`); the coordinator can close it |
| [#3397](https://github.com/keyorixhq/keyorix/issues/3397) | scim-and-sso-accounts.md SCIM-1 | Design decision: the SCIM token strength check is length-only; recorded, not changed here |
| BACKLOG `JIT-OFFBOARDING-GAP` | scim-and-sso-accounts.md SCIM-7 | Known gap, long-term, not started: an IdP disable or SCIM deactivation does not revoke the PATs and sessions of an SSO/JIT-claimed (`sso:`) account (decided 2026-10-20, option A of #3493) |
| [#3494](https://github.com/keyorixhq/keyorix/issues/3494) | scim-and-sso-accounts.md section 4 | Known issue: SCIM Replace/Patch/Delete map a storage failure to 404, not 500 |
| [#3367](https://github.com/keyorixhq/keyorix/pull/3367) | break-glass.md BG-6 | AUDIT-TX-2, open; changes how grant-shaped mutations write their audit row |

### Keeping the Evidence cells honest

`go test ./internal/threatmodelcheck` fails when an Evidence cell cites a
file, a `Test`/`Fuzz` function or an identifier that does not exist, when a
document is not indexed above, and, for every document written after it was
added, when a row's Evidence cell names no test. It checks that what is cited
**exists**; it does not check that the cited test proves the mitigation.
