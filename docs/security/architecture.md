# Keyorix Security Architecture

> **Positioning.** This document describes shipped mechanisms, cites the code/ADR
> behind each, and states plainly where a mechanism is still in progress. See
> [`threat-model.md`](./threat-model.md) for the trust-boundary/STRIDE analysis
> this architecture is meant to satisfy, and
> [`../compliance/README.md`](../compliance/README.md) for the regulatory
> control mappings built on top of it.

## 1. Encryption at rest

**Scheme:** envelope encryption. Every secret value is encrypted with
**AES-256-GCM** under a per-install **Data Encryption Key (DEK)**; the DEK
itself is wrapped by a **Key Encryption Key (KEK)**. A 12-byte random nonce is
generated per encryption operation, and Additional Authenticated Data (AAD)
binds each ciphertext to `secretID:projectID:version` — a ciphertext cannot be
transplanted between secrets or projects (`SECURITY-VERIFICATION.md`
"Verified-correct properties").

**KDF / passphrase-derived KEK:** the default KEK source (`key_provider.type:
password`, or an absent `key_provider` block) derives the KEK from
`KEYORIX_MASTER_PASSWORD` (or, since ADR-099, `--passphrase-fd`/
`--passphrase-file`/`--passphrase-stdin`) via **PBKDF2, 600,000 iterations**
(`internal/crypto/password_provider.go`). Only the salt and the wrapped DEK
touch disk — the KEK itself is derived at runtime and never persisted.

**Key-provider options** (`internal/config.KeyProviderConfig`, ADR-038/041),
selected via `key_provider.type`:

| Type | Where the KEK comes from |
|---|---|
| `password` (default) | PBKDF2(`KEYORIX_MASTER_PASSWORD`), 600k iterations |
| `file` | Raw key material at `file_path` — suits a KEK injected by a sealed/SOPS secret or a CSI driver |
| `env` | An env var's value (hex or base64) |
| `exec` | stdout of an operator-supplied command (e.g. `op read`, `sops -d`) |
| `shamir` | K-of-N Shamir reconstruction from `shamir_share_files`/`shamir_share_env`, verified against an HMAC-SHA256 commitment (`shamir_commitment`) to defeat the threshold-1-forges-one-more-share attack a bare magic-byte check couldn't (`internal/crypto`, `#429`) |
| `tpm` | Sealed to a host TPM 2.0 device |
| `aws-kms` / `gcp-kms` / `azure-kms` | Envelope-wrapped by a cloud KMS/HSM key; optional `kms_encryption_context` binds the wrapped blob to this specific install (AWS EncryptionContext / GCP AAD — not supported by Azure's RSA wrap, a hard startup error rather than a silent downgrade if attempted) |

**Fallback-downgrade protection:** a `Fallbacks` chain from a hardware/HSM/
cloud-KMS-backed provider to a weaker software-derivable one requires an
explicit `AllowWeakerFallback: true` — without it, `crypto.DetectFallbackDowngrade`
makes such a chain a hard startup error, so a transient KMS/TPM outage cannot
silently downgrade the deployment's actual security floor with only a log line
marking the moment.

**No plaintext in logs:** audited across every sink — no secret values, key
bytes, passphrases, or raw tokens are ever logged; secret-update audit diffs
carry only a `{"value":{"changed":true}}` marker (`AUDIT-LOG-PROVISIONS.md` §3).

## 2. Key rotation and the DEK re-encryption sweep

`keyorix-server admin encryption rotate` performs a full re-encryption sweep of every
DEK-encrypted table under a newly generated DEK, promotes the new key to disk,
and survives a restart mid-sweep — covered by an end-to-end integration test
(ADR-010). The sweep is **ordered by primary key**, closing a prior gap where
unordered pagination could skip rows and report a rotation complete while some
secrets remained under the old key (`SECURITY-VERIFICATION.md` "Key-rotation
completeness"). Sweep completeness itself — every DEK-encrypted model field has
a corresponding re-encryption sweep — is enforced by a structural AST-parsing
guard (`internal/encryption/sweep_completeness_test.go`), not a hand-maintained
list.

Three KEK-derived siblings besides the DEK are wiped on graceful shutdown and
DEK rotation via a real byte-by-byte overwrite (confirmed at the compiler level
— `runtime.memclrNoHeapPointers`, not eliminated as dead code): the master KEK
itself, the evidence-signing key, and the audit-checkpoint key
(`security-review-2026-09.md` "Memory zeroization").

## 3. Audit chain: hash chaining, checkpoints, and offline verification

A SHA-256 **hash chain** over `audit_events` (ADR-029) makes any modification,
deletion, insertion, or reordering of a row **still present in the table**
detectable by re-walking the chain (`GET /api/v1/audit/verify`). Each entry's
`entry_hash` covers a fixed-order, length-prefixed (TLV) encoding of the row's
semantically meaningful fields plus the previous entry's hash; writes are
serialized (a process mutex, plus a PostgreSQL transaction-scoped advisory lock
for multi-instance deployments) so concurrent appends can't corrupt the chain.

**What a bare re-walk cannot catch:** a *shorter, self-consistent* chain —
tail-truncation or a genesis re-seed — still verifies, because nothing on-box
records how long the chain *should* be. Three independent, composable
mechanisms close this:

1. **Signed in-DB checkpoints** — a scheduler, **enabled by default whenever a
   signing key is available** (encryption configured; `audit_checkpoints.disabled`
   opts out, with a loud warning logged), periodically writes an
   `audit_checkpoints` row (`chained_events`, `head_id`, `head_hash`) with an
   HMAC-SHA256 signature keyed by a value HKDF-derived from the **KEK**
   (deliberately KEK-derived, not DEK-derived, after a real incident — #502 —
   where DEK-derivation caused every routine key rotation to falsely
   invalidate every prior checkpoint). A checkpoint altered in any field
   without the key fails its own signature check; a new checkpoint is refused
   over a chain shorter than an authenticated prior one, so a truncation can
   never be silently re-baselined away.
2. **An off-box anchor** (`--anchor`) — ground truth captured outside this
   host, beforehand, closing the gap even if the local checkpoint/high-water
   rows were themselves deleted.
3. **A third-party RFC 3161 timestamp authority** (`--tsa-roots`) — the one
   check needing no shared secret and no trust in this host at all.

**Independent, offline verification:** `keyorix-server admin verify-audit`
re-derives the chain directly from a SQLite file or a PostgreSQL connection
using a deliberately independent implementation (`internal/auditverify` — not
the same code that wrote the chain), so an auditor is never asked to trust "the
vendor's server says its own log is fine." Full flag reference, exit codes,
the minimum read-only PostgreSQL grant, and the honest "what this does and
does not prove" table: [`../compliance/OFFLINE-AUDIT-VERIFICATION.md`](../compliance/OFFLINE-AUDIT-VERIFICATION.md).

**Stated ceiling, not hidden:** a DB-level actor who can also write
`audit_checkpoints` can neutralize on-box enforcement (delete/overwrite the
latest checkpoint), which forces `verify` to fail closed until the next
scheduler re-baseline — but such an actor can never *forge* a checkpoint that
makes a truncated chain verify as valid, because the HMAC key is never in the
database (ADR-029 "Residual (honest scope)").

## 4. Authentication

| Mechanism | Summary | Governing ADR |
|---|---|---|
| **Sessions** | Short-TTL access token plus a hard **absolute lifetime ceiling** that refresh cannot extend; individually listable/revocable; delivered only via an `HttpOnly`/`Secure`/`SameSite=Lax` cookie, never `localStorage` | — |
| **Personal Access Tokens (PAT)** | SHA-256-hashed at rest; optionally restricted at creation to a permission allowlist and/or a single project scope — a filter that only ever narrows below the owner, enforced at the same chokepoint (`core.Authorize`) as every other authorization decision, before role resolution and before the admin bypass | ADR-027, ADR-042 |
| **Machine identities** | Service/CI/Kubernetes principals modelled separately from human users, with their own lifecycle (`pending → active → suspended ⇄ active`, `revoked` terminal); receive **no** admin-role bypass | ADR-030 |
| **OIDC federation** (human and machine) | Asymmetric-only algorithm allowlist (`HS*`/`none` rejected — defeats key-confusion), required `exp`, bounded `nbf` skew, issuer allowlist checked *before* key retrieval, audience intersection, `jwks_uri` must be `https` | ADR-031 |
| **SAML 2.0 SSO** (human) | Service Provider using `crewjam/saml` + `goxmldsig` (never hand-rolled XML-DSig); mandatory signature validation against a **pinned** IdP certificate, `AudienceRestriction`/`Recipient`/`NotBefore`/`NotOnOrAfter` checks, replay protection; IdP-initiated flow off by default | ADR-063 |
| **TOTP MFA** | Per-user opt-in, RFC 6238, two-step login, single-use recovery codes, secret encrypted at rest | ADR-034 |
| **WebAuthn / passkeys** | Phishing-resistant, origin-bound public-key assertions, no exportable shared secret, FIDO clone detection | ADR-036 |
| **MFA mandate scoping** | `security.require_mfa` (deployment-wide) or a per-project override (a sensitive project can require MFA even when the global policy is off) | ADR-037 |
| **Emergency admin recovery** | `keyorix-server admin recover-admin`, a local-only subcommand (never a network endpoint) requiring both host access and a separately-held, SHA-256-verified 256-bit recovery key; every use is audited and triggers an admin notification | ADR-108 decision B.2, `internal/recoverykey`, `security.recover_admin` config block |
| **Impersonation** | Issues a separate short-lived session (the admin's own session is untouched); every action under it is tagged `impersonated_by`/`acting_as`, plus discrete `impersonation.start`/`.end` audit events | — |

## 5. Authorization

**Model:** scoped RBAC. Roles are granted at **system**, **project**, or
**environment** scope (a `project_id = 0` sentinel marks system scope).
Built-in roles: `system_admin` / `system_auditor` / `system_viewer` and
`project_admin` / `project_developer` / `project_viewer` / `project_auditor`.
Every authorization decision funnels through `core.Authorize`/
`core.AuthorizePrincipal` — the single chokepoint reached identically from HTTP
middleware, in-handler authorizers, and gRPC (`server/grpc/services/*`), which
is what let the PAT-restriction filter (§4) be added at one place and
automatically bind every present and future authorization path.

**Admin bypass is a structural marker, not a name match.**
`models.Role.BypassesPermissionChecks`, resolved by role ID, replaced an
earlier fixed-name lookup (`roleSetContainsAdmin`) at all 8 call sites. It is
written only by role seeding and a one-time migration snapshot;
`CreateRole`/`UpdateRole` never accept it from a request DTO on any transport
(ADR-084) — closing a class of self-escalation-via-role-naming that a
name-matched check would remain exposed to.

**Privilege ceilings are derived from the actor, not just the target.**
Creating or promoting a principal checks the ceiling against the **calling
actor's own effective privileges**, not only the target's current state —
checking only the target would let a zero-standing attacker self-mint into an
empty or attacker-controlled target and pass trivially. This was a real,
fixed gap (`RequireMachinePrivilegeCeiling` checked only the target machine
identity's roles until 2026-08-25).

**Membership lifecycle:** a 5-state project-membership machine
(`invited → identity_verified → provisioned → active`, `revoked` terminal);
access is granted only on `active` and removed on `revoke`.

**Cross-tenant isolation:** every nested-resource route reconciles the child
object's project against the caller's authorized project before acting,
closing a class of cross-project privilege-escalation findings the 2026-09
review found and fixed across five lifecycle routes.

## 6. Transport

- **TLS termination:** either the bundled, opt-in Caddy auto-HTTPS profile
  (`docker compose --profile tls up`, auto-provisioning a publicly-trusted
  certificate for a real domain) or server-terminated TLS
  (`server.http.tls`/`server.grpc.tls`, `internal/config.TLSConfig`) for the
  single-binary deployment.
- **Cipher suite hardening:** `allowed_ciphers` optionally restricts TLS 1.2
  suites to an explicit allowlist (`SecureCipherSuiteNames`); any name outside
  it — including weak/deprecated suites (RC4, 3DES, CBC-mode) — is rejected at
  startup, not silently ignored (`applyTLSHardening`, `#333`).
  `RequireTransportTLS` (`security.require_transport_tls`), when set, refuses
  to start an enabled HTTP/gRPC listener with no TLS configured at all — fail
  closed rather than silently serving cleartext; when left off (the default,
  for the common "TLS-terminating proxy in front" deployment shape), the
  server logs a prominent warning if it does end up serving cleartext, so the
  exposure is never silent either way.
- **HSTS and CSP** ship by default (`script-src 'self'`); the one accepted,
  documented CSP tradeoff (`style-src unsafe-inline`) is recorded in
  `threat-model.md` §4 (B5).
- **Remote-client TLS (CLI remote mode):** certificate verification is on by
  default; an operator must explicitly opt out (`tls_verify: false`) — fixed
  from an earlier default where an *omitted* `tls_verify` key resolved to
  verification off (`SECURITY-VERIFICATION.md` "Remote-client TLS verification
  secure-by-default").
- **Outbound connector/rotation-target requests:** link-local/NAT64 address
  guards (`internal/netutil`) block SSRF against the connector, dynamic-secret,
  and DSN-driven admin surfaces; `rotation_ref` is denylist-validated at
  configuration time against URL/path/SQL metacharacters ahead of each
  backend's own escaping. There is no separate, Keyorix-native network
  egress-policy layer today — outbound reachability is bounded by these
  per-call guards and by the operator's own network/firewall configuration,
  not by an application-level allow/deny-list of destinations.

## 7. Process hardening

Applied once, at server startup, before any key material or decrypted secret
is allocated (`internal/hardening.ApplyMemoryHardening`, `server/main.go`;
ADR-098):

- **Core dump suppression** — `RLIMIT_CORE` lowered to `{0, 0}` (both soft and
  hard limit), unconditionally, no config gate. Verified by actually triggering
  a crash: a baseline process produces a 46 MB core file; a hardened one
  produces none, with the parent shell reporting `Aborted` rather than
  `Aborted (core dumped)`, even with an inherited `ulimit -c unlimited`.
- **`mlockall` — removed 2026-09-04 (ADR-100), superseding ADR-098's original
  design.** It was originally adopted to keep decrypted secret memory off swap
  (mirroring HashiCorp Vault's own default), but measured against the real
  server binary it pinned `VmLck` at roughly 2.6× the shipped Helm chart's
  default memory limit, growing further under load and never shrinking — a
  real cgroup-OOM-kill availability regression, and structurally incapable of
  working correctly in a garbage-collected runtime regardless of tuning (the
  GC moves memory a locked address doesn't follow). **Swap protection is now a
  deployment-level control** (disable swap on the node/container runtime), not
  an in-process one. Applies to the server process only; the CLI is
  out of scope (short-lived, not a long-running daemon holding decrypted
  material resident).
- **What this does not protect against**, stated directly rather than left
  implicit: transient in-process exposure while the process is live (a
  decrypted secret is in heap memory for the window between decryption and
  wipe-after-use — see `threat-model.md` §6), a privileged local attacker
  (root or `ptrace` access reads process memory regardless of any of this),
  and a core dump or memory capture forced by something outside this
  process's own `RLIMIT_CORE` (an external supervisor, a hypervisor snapshot).

## 8. Air-gap operation

Keyorix's default operating mode has no outbound dependency for core secret
management: no Keyorix-operated cloud sits in the secret-resolution path, and
the single static binary serves both the API and the web UI with nothing else
required. Three specific mechanisms extend this to updates and licensing,
where an internet-connected product would normally phone home:

- **Signed, offline-verifiable update bundles** (`internal/bundle`,
  ADR-062) — a single tarball wrapping release artifacts (images, CLI/agent/
  operator/MCP binaries, charts, CRDs, migrations) with a `manifest.json`
  pinning every component by SHA-256 and an `ed25519` signature verified
  against an **embedded, pinned** public key (`keyorix bundle verify`/
  `import`) — asymmetric specifically because an air-gapped customer must
  verify without ever holding the signing secret, unlike the audit chain's
  symmetric HMAC (§3), which assumes the verifier does hold the key.
- **Offline license validation** (`internal/license`, ADR-065) — a compact
  `base64url(payload).base64url(sig)` token evaluated entirely locally against
  a second, independent embedded `ed25519` public key (a separate keypair from
  update signing, so the two blast radii don't overlap); no phone-home, ever,
  by design — a licensing call-home would itself be an exfiltration channel a
  regulated buyer would reject. `airgap_updates` (gating `keyorix bundle
  import`) is the first commercial-tier-gated feature.
- **Air-gapped OIDC federation** (ADR-075) — machine-identity OIDC verification
  without reachability to the issuer's live JWKS endpoint, for Kubernetes and
  CI environments that themselves have no egress.

**Status note:** ADR-062 itself is recorded as "Accepted (design), implementation
phased" — the license (Phase 2a/2b/2c) and bundle-verify mechanisms above are
confirmed present in code (`internal/license`, `internal/bundle`); this
document does not claim every phase named in that ADR's original design is
complete, only what is independently verified to exist.

## 9. What is explicitly not architecture — deployment-owned

Consistent with the self-hosted model, the following remain the operator's
responsibility and are not application-layer controls: network segmentation
and firewalling, host OS hardening (including disabling swap, now that
mlockall no longer provides that protection in-process — see §7), physical
WORM/immutable storage for audit-log durability beyond tamper-*evidence*
(§3), PostgreSQL's own backup/restore mechanics, and — for a file-based KEK —
the fact that host root already has everything the application protects (see
`threat-model.md` §5.1).
