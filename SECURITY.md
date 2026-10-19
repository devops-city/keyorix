# Security Policy

Keyorix is a secrets manager. We hold ourselves to the standard we ask you to trust
us with: every control described here is verifiable in this repository's CI
configuration and release artifacts.

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | ✅ Security fixes |
| Older releases | ❌ Upgrade to latest |

Keyorix is pre-1.0 and has **not yet declared a support period** under the EU Cyber
Resilience Act. Pre-1.0 tags are development releases: they carry no declared support
period and no Declaration of Conformity.

From v1.0, LTS releases receive **five years of security updates**, delivered to
air-gapped deployments as signed offline bundles with an SBOM and a VEX document.
See [SUPPORT.md](SUPPORT.md) for the full policy and
[ADR-067](docs/adr-067-release-lifecycle-support-policy.md) for the rationale.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

- Email: **security@keyorix.com**
- Or use GitHub's private vulnerability reporting on this repository

We acknowledge within **48 hours** and provide an initial assessment within **7 days**.
Please include: a description, reproduction steps, and the affected version
(`keyorix --version` / `keyorix-server --version`).

We follow coordinated disclosure: we'll agree a disclosure timeline with you,
credit you in the advisory unless you prefer otherwise, and publish a fix and
advisory together. As an EU vendor we operate under the EU Cyber Resilience Act
reporting regime for actively exploited vulnerabilities.

## Remediation Timelines

Once a report is acknowledged and assessed (see above), here's what to
expect through to a fix:

| Commitment | Detail |
|---|---|
| Fix, all severities | Within **90 days** of a validated report |
| High / Critical severity | **1 week advance notice** before the security release ships |
| Advisory | A **GitHub Security Advisory with a requested CVE**, published the **same day** as the fix |
| Supported versions | Latest release only (see Supported Versions above) |

The 90-day figure is a ceiling, not a target — most fixes ship well inside
it. We publish one commitment across all severities rather than a
severity-tiered deadline: a severity call made under public time pressure
is exactly the kind of promise a one-person team without redundancy
shouldn't be making a clock out of. We do not publish a release cadence —
releases ship as fixes are ready, not on a calendar.

**This is a current operating commitment, not a CRA-declared support
period.** It says how fast we fix things once a version is receiving fixes
at all; it does not change which versions that is, or for how long — that
is governed separately by the Supported Versions table above and
[SUPPORT.md](SUPPORT.md), and remains undeclared pre-1.0 regardless of
this commitment.

See [ADR-104](docs/adr-104-security-remediation-sla.md) for the reasoning,
the competitor research behind these numbers, and the internal CRITICAL/HIGH
definition used for prioritization. This table is the authoritative,
current source for the published commitment above; ADR-104 also states it
for the record, but if the two ever disagree, this page is current and
ADR-104's copy is stale.

## Threat Model (summary)

Keyorix server runs **entirely within your perimeter**:

- No telemetry, no usage metering, no "phone home" — ever. Air-gapped operation
  is a first-class deployment model, not a degraded mode.
- All secret values encrypted at rest with AES-256-GCM (authenticated encryption,
  AAD-bound to secret identity). Envelope encryption: the data key is wrapped by a
  key derived from an operator passphrase (PBKDF2-SHA256, 600k iterations); no
  plaintext key material is ever written to disk.
- Session tokens, personal access tokens and machine tokens are stored only as
  SHA-256 hashes, never in plaintext, and API client secrets are stored hashed
  too. TOTP shared secrets cannot be hashed and are encrypted at rest.
- Every secret access and every administrative action is written to an append-only
  audit log in your database.
- RBAC is enforced at the API level, not the UI.

What Keyorix never does: open outbound connections to us, embed third-party
analytics, or require internet access for any cryptographic operation.

The full STRIDE threat model — assets, trust boundaries, per-boundary
threats with mitigation citations, and residual risks stated honestly,
including open ones — is public in this repository:
[`docs/security/threat-model.md`](docs/security/threat-model.md), with
per-component breakdowns under
[`docs/security/threat-models/`](docs/security/threat-models/). It is not
gated behind a sales conversation.

## Verifying a Release

Every release ships with `checksums.txt`:

```bash
sha256sum --check --ignore-missing checksums.txt
```

Every release also ships one **CycloneDX SBOM per binary** (e.g.
`keyorix-server_linux_amd64_sbom.cdx.json`, 14 total across the CLI, server
(full + air-gapped, ADR-109), and keyorix-migrate binaries × linux/darwin ×
amd64/arm64, air-gapped server variant linux-only) — a full dependency and
licence inventory, the component list needed to assess CVE exposure under
the EU CRA. The six server/server-airgap binaries embed a built React
dashboard (`server/webui`); each of their SBOMs links to one shared,
production-scope frontend SBOM
(`keyorix-server_frontend_sbom.cdx.json`) via a hashed CycloneDX
`externalReferences` entry, so a scanner pointed at a server binary's own SBOM
can follow the link rather than needing a separate download step (ADR-073).
All 15 SBOMs are covered by `checksums.txt`.

Release binaries are built with `-trimpath` and `CGO_ENABLED=0` from the tagged
commit. `checksums.txt` and every container image are keylessly signed with
[Sigstore/cosign](https://www.sigstore.dev/) via GitHub's OIDC token — no
long-lived signing key exists to leak. Verify with `cosign` installed:

```bash
# checksums.txt (release binaries)
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/keyorixhq/keyorix/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# container images (also carries an SBOM + SLSA build provenance attestation)
cosign verify \
  --certificate-identity-regexp 'https://github.com/keyorixhq/keyorix/\.github/workflows/docker-publish\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/keyorixhq/keyorix-server:<tag>
```

Every release binary and container image (both `keyorix-server` variants and
every other published image) also carries a **SLSA build provenance
attestation** (`actions/attest-build-provenance`, ADR-109 step 6) — an
in-toto statement naming the exact GitHub Actions workflow run, its inputs
(repo, ref, commit SHA), and the builder identity that produced it. This is a
second, independent mechanism from the cosign signature above: cosign proves
"Keyorix's release workflow signed this"; SLSA provenance additionally proves
*which* workflow run, from *which* source commit, with a machine-checkable
build definition GitHub itself attests to (not something Keyorix could forge
even with the signing identity compromised, since GitHub's Attestations API
is the party recording it). Verify with the `gh` CLI (no extra tooling):

```bash
# a downloaded release binary
gh attestation verify keyorix-server_linux_amd64 --owner keyorixhq

# a container image
gh attestation verify oci://ghcr.io/keyorixhq/keyorix-server:<tag> --owner keyorixhq
```

Download releases only from `github.com/keyorixhq/keyorix/releases` over HTTPS.

## Secure Development

- Pre-commit gates: `gofmt`, `go vet`, `go build`, `gosec` (MEDIUM+ severity)
- CI gates on every push and pull request (11+ required checks, see
  [CONTRIBUTING.md](CONTRIBUTING.md) for the full list): `go vet`, race-enabled
  tests, `govulncheck`, `gosec` (pinned version), `golangci-lint`, `gitleaks`
  secret scan (scoped to the PR's own commit history), `CodeQL` (dataflow/taint
  analysis, both Go modules), Helm chart schema validation (`kubeconform`) and
  security-policy scanning (`checkov` — pod security context, RBAC-escalation
  checks), Go dependency license compliance (rejects any dependency outside an
  explicit permissive-license allowlist), and DCO sign-off verification
- Continuous fuzzing: native Go fuzz targets (`go test -fuzz`) at the
  codebase's highest-risk parsing/escaping boundaries (Shamir secret-share
  reconstruction, JWT/OIDC verification, rotation-credential SQL escaping and
  ref interpolation, secret-template parsing) run for hours at a time on
  dedicated infrastructure, well beyond what a CI job's budget allows — see
  [`scripts/fuzzing/README.md`](scripts/fuzzing/README.md)
- Recurring bug classes get a permanent, blocking check, not just a one-off
  fix: every confirmed vulnerability is checked against the fix history for
  the same underlying pattern recurring 3+ times, and each one that does gets
  a custom CodeQL query or Semgrep rule modeled on the real fix and validated
  against it before merge — see
  [`.semgrep/RULE-MINING-PROCESS.md`](.semgrep/RULE-MINING-PROCESS.md) for
  the process and `.github/codeql/go-queries/`/`.semgrep/keyorix-rules.yml`
  for the current rule set. Every `fix(security)` PR is required to carry a
  regression test proving the specific bug is closed, not just that the
  static pattern is gone from the diff.
- [CODEOWNERS](.github/CODEOWNERS) designates the required reviewer for
  cryptography, auth/RBAC, middleware, database migrations, the CI/CD
  pipeline itself, and this policy. **Not currently a GitHub-enforced gate**
  — the live branch-protection ruleset has no required-reviewer rule (see
  `docs/security/SDLC.md`); today this is ownership designation enforced by
  the fact that every commit to date has one human author, not by CI.
- GitHub-native repository security: secret scanning, push protection (blocks
  a commit containing a detected secret before it lands), Dependabot security
  updates, and private vulnerability reporting are all enabled
- Any change to the encryption layer requires a written Architecture Decision
  Record before implementation
- External contributions require DCO sign-off (`git commit -s` — see
  [CONTRIBUTING.md](CONTRIBUTING.md)) and maintainer review. Branch protection
  on `main` is a GitHub ruleset requiring every required CI check to pass
  before a PR can merge, via a merge queue (squash-only); force-pushing or
  deleting `main` is blocked outright. **Correction (2026-10-05):** this
  page previously stated that enforcement has "no bypass, including for
  maintainers." Reading the live ruleset directly showed a standing
  `OrganizationAdmin` bypass actor on the required checks — real, not a
  hypothetical. **Resolved the same day**: kept as a deliberate break-glass
  path for a CI outage, narrowed from `bypass_mode: always` to
  `bypass_mode: pull_request` — it only applies inside a pull request's own
  checks, every use is visible on the PR, and it is scoped to the
  `OrganizationAdmin` actor type, not named individuals. See
  [`docs/security/SDLC.md`](docs/security/SDLC.md) § Branch protection for
  the full ruleset detail.

## Safe Harbor

Keyorix will not pursue or support legal action against anyone who makes a
good-faith effort to find and report a vulnerability under this policy,
provided that you:

- Only test against your own Keyorix instance (self-hosted, or a disposable
  environment you control) — never a deployment you don't own or operate.
- Avoid privacy violations, data destruction, and service disruption to
  anyone other than yourself.
- Give us the chance to resolve the issue before any public disclosure,
  consistent with the coordinated-disclosure timeline above.
- Don't exploit a finding beyond what's needed to demonstrate and report it.

Testing conducted consistent with this policy is authorized under the
Computer Fraud and Abuse Act and equivalent anti-hacking laws, and we will
not initiate legal action for research that stays within these bounds. If
a third party (not Keyorix) initiates legal action related to research that
followed this policy, we will make clear — to the extent we're able — that
your actions were authorized.

## Hall of Fame

Keyorix credits reporters by name in the published advisory, unless they
prefer otherwise (see Reporting above). No third-party vulnerability
reports have been validated and published as advisories yet — this
section will list credited researchers as advisories publish.

## Security-Relevant Configuration

- `KEYORIX_MASTER_PASSWORD` is the root credential — inject it via systemd
  credentials/`EnvironmentFile` (0600) or a Kubernetes Secret, never a config file.
- Run `keyorix-server` as a non-root service user.
- TLS is required in production; the CLI `--insecure` flag is for local
  development only.
