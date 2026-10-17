# Keyorix Mapping — BSI IT-Grundschutz APP.bd.6

Maps Keyorix's implemented controls against Germany's BSI IT-Grundschutz
user-defined module **APP.bd.6 "Secrets Management with Hashicorp
Vault"** (last edited 2021-11-19). The module is written specifically for
Vault; this document walks every one of its 18 requirements (A1–A18)
against Keyorix as shipped, not against Vault.

> **Positioning.** Keyorix is **not** assessed or certified against this
> module. This is a self-assessed, evidence-linked mapping. The PDF
> itself is not copied into this repository (per standing instruction);
> source: BSI,
> `bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Hilfsmittel/Benutzerdefinierte_BS/BS_Secrets_Management_mit_Hashicorp_Vault_EN.pdf`,
> read directly on 2026-10-05.
>
> **Status key**: **met** (the requirement's intent is fully satisfied
> by a Keyorix mechanism) · **partly** (satisfied in part, or satisfied
> differently than the requirement's specific wording expects, with the
> difference stated) · **not met** (a real, unaddressed gap) ·
> **not applicable** (the requirement doesn't translate to Keyorix's
> architecture, or is inherently host/operator-owned the same way it
> would be for Vault itself — reason given in each case, never asserted
> without one).

## 3.1 Basic requirements (MUST)

| ID | Requirement | Status | Evidence link | Gap issue |
|---|---|---|---|---|
| A1 | Plan and document the deployment (operating model, functions used, storage-backend choice, application-integration choice, backup/recovery procedure) before deploying. | **Partly met.** Keyorix ships documentation covering every point this requirement lists except the operator's own site-specific deployment plan, which only the operator can write. | [`../SELF_HOSTING.md`](../SELF_HOSTING.md), [`../CONFIGURATION.md`](../CONFIGURATION.md), this `docs/security/` tree | — |
| A2 | The service MUST NOT run with root rights; configuration files MUST restrict access to the service user only. | **Met.** | [`../../SECURITY.md`](../../SECURITY.md) § Security-Relevant Configuration ("Run `keyorix-server` as a non-root service user"); Helm chart `checkov` CI gate enforces non-root, dropped capabilities, no privilege escalation at the container level | — |

## 3.2 Standard requirements (SHOULD)

| ID | Requirement | Status | Evidence link | Gap issue |
|---|---|---|---|---|
| A3 | High availability (cluster); VMs on different hosts; restart-on-failure for containers. | **Met.** | [ADR-039](../adr-039-ha-deployment.md); cross-replica *correctness* under HA is itself threat-modeled, not just assumed — [`threat-models/ha-consistency.md`](threat-models/ha-consistency.md) | — |
| A4 | Encrypt client↔server-cluster communication; load balancers/reverse proxies SHOULD NOT terminate TLS. | **Partly met.** TLS support and cipher-suite hardening exist; Keyorix's default *does* support a TLS-terminating proxy in front as a common deployment shape (with a loud warning if cleartext ends up served) — a deliberate difference from this requirement's specific preference, not an oversight or an omission. | [`architecture.md`](architecture.md) §6 | — (deliberate design choice, not a defect) |
| A5 | Vault SHOULD be the only main process on its host (no multi-tenant host). | **Not applicable.** Host-process isolation is infrastructure policy — no application running as a userspace process (Keyorix included, same as Vault itself) can observe or enforce what else runs on its host. | [`architecture.md`](architecture.md) §9 (deployment-owned controls) | — |
| A6 | Disable SSH/remote-desktop access to the host; access only via the API. | **Not applicable.** Same reasoning as A5 — host access policy is the operator's, not observable or enforceable from the application layer. | [`architecture.md`](architecture.md) §9 | — |
| A7 | Monitor availability, resource utilization, and error states; integrate with central monitoring/log management. | **Met.** A real `/metrics` endpoint (`server/middleware.MetricsHandler`, Prometheus `promhttp`) exposes product metrics; per-mechanism counters exist (e.g. `keyorix_best_effort_failures_total`). Wiring that endpoint into an operator's *own* central monitoring stack is the same integration step any self-hosted product (including Vault) requires. | `server/middleware/metrics.go`; [`SECURE-CODING.md`](SECURE-CODING.md) §7 | — |
| A8 | Disable swap to prevent sensitive data from being paged to disk. | **Met, as a deployment-level control by deliberate design.** Keyorix's own `mlockall` was removed after being measured to cause a real cgroup-OOM-kill availability regression; swap protection is now explicitly a deployment-level control (disable swap on the node/container runtime) — the same recommendation this requirement makes, arrived at independently. | [ADR-100](../adr-100-mlockall-removal-deployment-swap-control.md) | — |
| A9 | Disable core dumps — a forced core dump could expose encryption keys. | **Met.** `RLIMIT_CORE` lowered to `{0,0}` unconditionally at startup; verified by actually triggering a crash (hardened process produces no core file vs. a 46 MB baseline). | [ADR-098](../adr-098-process-memory-hardening.md) | — |
| A10 | Revoke the initialization root token after setup. | **Not applicable — mapped to the Keyorix equivalent, with the architectural difference stated.** Keyorix has no Vault-style bearer "root token" minted at init time. The closest analogous credential is the recovery key (`internal/recoverykey`)/master passphrase, neither of which has a root-token's blast radius, and neither is "revoked after setup" — they remain the ongoing, deliberately-provisioned break-glass mechanism. | [`threat-models/authentication.md`](threat-models/authentication.md) "Emergency admin recovery" | — |
| A11 | Manage configuration via version-controlled files, not manual changes. | **Not applicable.** Whether an operator's config file is under their own version control is their practice, not something Keyorix enforces or can observe. | — | — |
| A12 | Activate audit logging. | **Met, and stricter than this requirement's own phrasing.** This requirement says audit logging "SHOULD be activated," implying it can be left off; Keyorix's audit logging of security-relevant actions is not optional in that sense. Sensitive values are never written to the audit log at all (not merely hashed, as this requirement's own phrasing allows). | [ADR-029](../adr-029-audit-log-tamper-evidence.md); [`threat-models/audit-chain.md`](threat-models/audit-chain.md); [`SECURE-CODING.md`](SECURE-CODING.md) §5 | — |
| A13 | Restrict access to the storage backend to the secrets-management service itself. | **Partly met.** Database-level access restriction (network/firewall/DB grants) is the operator's responsibility, same as for Vault. The compensating control: even full storage-backend read access does not yield plaintext secrets without the separately-held KEK. | [`threat-models/secret-storage-key-hierarchy.md`](threat-models/secret-storage-key-hierarchy.md) | — |
| A14 | Automate configuration rollout to reduce manual error. | **Partly met.** The Helm chart / Kubernetes operator installation path is automatable end-to-end; a bare-binary/Docker-Compose deployment's own rollout automation is the operator's choice of tooling. | [`threat-models/kubernetes-operator.md`](threat-models/kubernetes-operator.md) | — |
| A15 | Use fine-grained, least-privilege ACL policies. | **Met.** Scoped RBAC at system/project/environment granularity; PAT restriction filters that only ever narrow below the owner. | [`threat-models/authorization-rbac.md`](threat-models/authorization-rbac.md) | — |
| A16 | Tokens SHOULD only be valid as long as access is actually needed (ephemeral TTL). | **Met.** Short session TTLs with a hard absolute lifetime ceiling; time-bounded PATs; machine-identity lifecycle states. | [`threat-models/authentication.md`](threat-models/authentication.md) | — |

## 3.3 Requirements for increased protection needs

| ID | Requirement | Status | Evidence link | Gap issue |
|---|---|---|---|---|
| A17 | Rotate the master key / shared keys on staff turnover (entry or departure). | **Met, operator-triggered.** `keyorix-server admin encryption rotate` performs a full DEK re-encryption sweep with verified completeness (a structural guard, not a hand-maintained list). Keyorix does not auto-trigger this on a personnel-roster change — the operator runs it as their own process, same expectation this requirement sets for Vault. | [ADR-010](../adr-010-kek-rotation-reencryption-sweep.md); [`architecture.md`](architecture.md) §2 | — |
| A18 | Use resource quotas (max RPS, lease quotas) to protect against resource exhaustion/DoS. | **Met.** Rate limiting, request-body size caps, pagination, bulk-op batch caps, a bounded-BFS fix for dependency traversal. | [`threat-models/server-api.md`](threat-models/server-api.md); [`SECURE-CODING.md`](SECURE-CODING.md) §9 | — |

## Summary

Of 18 requirements: **10 met** (A2, A3, A7, A8, A9, A12, A15, A16, A17,
A18), **5 partly met** (A1, A4, A13, A14, and A4 differing from the
requirement's specific stated preference by deliberate design), **3 not
applicable** (A5, A6, A11 — host/operator-owned infrastructure policy,
the same for Vault itself), and **1 mapped to a Keyorix-specific
equivalent with the architectural difference stated** (A10). **Zero**
rows are marked "not met" — no real, unaddressed gap was found against
this module's 18 requirements; no gap issue was filed because none was
warranted. This is a self-assessment, not a certification — if a future
reviewer disagrees with any status above, that disagreement is the
useful outcome of publishing this table, not a problem with publishing
it.
