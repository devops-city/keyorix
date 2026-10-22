# Support Policy

This document states which Keyorix versions receive security updates, for how long,
and how those updates reach deployments that cannot reach the internet.

For reporting a vulnerability, see [SECURITY.md](SECURITY.md).

## Current status: pre-1.0

**Keyorix has not yet declared a support period.** Releases before v1.0 are
development releases. They do not carry a declared support period, a Declaration of
Conformity, or a CE marking, and they are not offered as products placed on the EU
market.

Pre-1.0, the security fix rules are in the table in
[SECURITY.md](SECURITY.md#supported-versions-pre-10). In short: fixes of every
severity land on the current minor release line, and only Critical and High fixes
are backported to the previous minor. For Medium and Low severity, upgrade to the
current minor. A new policy is published with 1.0.0 and replaces this rule.

The policy below takes effect at v1.0.

## Release classes

Keyorix ships continuously from trunk. Not every tag is a supported product.

| Class | What it is | Support |
|---|---|---|
| **Development tag** | Cut from trunk between releases | None. No declared support period, no conformity documentation, no update bundle. |
| **Designated release** | A version placed on the market | Security updates until the next designated release. |
| **LTS release** | A designated release marked long-term support | **Five years** of security updates from general availability. |

Every designated release states its **end-of-support month and year** on the release
page, in the release artifacts, and in the Declaration of Conformity.

## LTS releases

An LTS release is designated every **18 to 24 months**. The first is **v1.0**.

Each LTS receives security updates for **five years** from its general availability
date. At most **three** LTS lines are maintained at any time. If designating a new
LTS would exceed three, the designation is delayed — we do not maintain more lines
than we can patch properly, and we will not shorten a period already promised.

### What "security updates" covers

An LTS line receives:

- Fixes for security vulnerabilities in Keyorix
- Fixes for vulnerabilities in bundled dependencies that are reachable in Keyorix
- Fixes for defects that can cause data loss or service outage

An LTS line does **not** receive new features, performance improvements, or cosmetic
fixes. Those land on trunk and reach you at your next LTS upgrade. This scoping is
deliberate: it is what allows the five-year commitment to be real.

### Upgrade path

Direct upgrade from any LTS to the next LTS is supported and tested. You never need
to step through intermediate releases. If you upgrade from an LTS to a non-LTS
designated release, you leave the extended support window — the shorter period for
that release applies instead.

## Air-gapped and offline deployments

Deployments without internet access receive updates as signed offline bundles: a
single verifiable file carried across the gap, cryptographically verified against a
public key embedded in your binary at build time. See
[ADR-062](docs/adr-062-air-gap-updates.md) and
[ADR-064](docs/adr-064-air-gap-update-bundles.md).

Every bundle for a designated release contains:

- The release artifacts, each pinned by SHA-256 digest in a signed manifest
- A **CycloneDX 1.6 SBOM**
- A **VEX document** stating which known CVEs in bundled dependencies are and are not
  exploitable in Keyorix

The VEX document matters if you run your own vulnerability scanners. Scanners
frequently flag CVEs in vendored dependencies whose affected code paths Keyorix never
executes. The VEX statement tells your scanner, in machine-readable form, which
findings are genuinely exploitable in Keyorix and which are not — so your security
team can triage on evidence rather than on our word.

## Regulatory context

Keyorix is developed in the EU by Keyorix SL (Valencia, Spain).

This policy is written to meet the support-period obligations of the EU Cyber
Resilience Act (Regulation (EU) 2024/2847), Article 13(8): a declared support period
of at least five years, with each security update remaining available for ten years
after issue or the remainder of the support period, whichever is longer.

Security updates are provided **free of charge** for the declared support period, on
both the AGPL-3.0 and the commercial licence. Security is never behind a paywall.

Commercial licence holders may additionally receive response-time commitments and
extended support arrangements. Those are contractual terms in the MSA and Order Form,
separate from the support period declared here, which applies to everyone.

## Getting help

| Need | Where |
|---|---|
| Report a vulnerability | [SECURITY.md](SECURITY.md) — **do not** open a public issue |
| Bug report or feature request | GitHub Issues |
| Questions and discussion | GitHub Discussions |
| Commercial support and licensing | sales@keyorix.com |

## Changes to this policy

A support period, once declared for a release, is never shortened. This policy may
change for future releases; changes are announced in the CHANGELOG and take effect
only for releases designated after the change.
