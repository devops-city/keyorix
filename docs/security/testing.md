# How Keyorix Is Tested

> **Positioning.** This describes the testing and verification program behind
> the claims in [`architecture.md`](./architecture.md) and
> [`threat-model.md`](./threat-model.md) — what runs, on what cadence, and what
> it does and doesn't prove. Per standing policy, this document does not name
> specific third-party-library vulnerability findings (e.g. in `crewjam/saml`)
> that are embargoed pending upstream disclosure — the *mechanisms* that would
> catch or have caught such issues are described without naming the finding
> itself. The `digitorus/pkcs7` finding is public
> ([GHSA-3xqc-rpq8-wgp9](https://github.com/advisories/GHSA-3xqc-rpq8-wgp9),
> published 2026-09-14) and is fixed in the pinned version; its regression
> guard is `FuzzDigitorusPKCS7BoundedWork`.

## 1. Standing CI gates (every PR, every merge to `main`)

A GitHub ruleset on `main` requires 18 status-check contexts and routes every
merge through a squash-only merge queue (`gh api
repos/keyorixhq/keyorix/rulesets` → "Require core CI checks on main"). The
table below groups them by what they check conceptually; the ruleset's own
context names (`build-and-test`, `static-analysis`, `lint`, `licenses`,
`fuzz-targets`, `fuzz-reach`, `adr-numbers`, `exclusion-freshness`,
`assert-leg-completeness`, `base-branch-check`, `gitleaks`, `helm-chart`,
`helm-chart-security`, `operator`, `pnpm-workspace-root-guard`,
`workflow-lint`, `dco-check`, `security-fix-regression-check`) are CI job
names, not a 1:1 mapping to this table. The ruleset also blocks force-pushing
and deleting `main` outright (`non_fast_forward`, `deletion`). **Correction
(2026-10-05):** this section previously said "no bypass, including for
maintainers." The ruleset's `bypass_actors` list carried a standing
`OrganizationAdmin` entry with `bypass_mode: always` — real, not
hypothetical. Resolved the same day: kept as a deliberate break-glass path,
narrowed to `bypass_mode: pull_request` (visible on the PR, scoped to the
actor type, not individuals) rather than removed; see
[`SDLC.md`](SDLC.md#branch-protection) for the full detail.

| Gate | What it catches |
|---|---|
| `govulncheck` | Known vulnerabilities in any dependency reachable from the code |
| `gosec` (medium+) | Insecure patterns: weak crypto, hardcoded credentials, unsafe SQL |
| `golangci-lint` | Broader static analysis |
| `go test -race` | The full test suite, including every security regression test, under the race detector |
| `go vet` | Standard Go correctness checks |
| `gitleaks` | Secret-shaped strings in the PR's own commit history (scoped to the PR, not every branch present in the CI clone) |
| `CodeQL` | Cross-function-boundary taint-flow analysis, both Go modules (root + Kubernetes operator) |
| `checkov` | Helm chart *security-policy* scanning (non-root, dropped capabilities, no privilege escalation, seccomp) — distinct from `kubeconform`'s schema-only validation |
| `go-licenses` | Dependency license compliance; the allowlist (MIT/Apache-2.0/BSD-2/3-Clause/ISC/MPL-2.0) was derived from the actual dependency tree and verified to fail on an injected AGPL test dependency |
| Fuzz-target staleness | A `func FuzzXxx` that exists but isn't declared in `scripts/fuzzing/targets.d/` (or vice versa) — checked in both directions, because a target that silently drops out of the declared list gets no coverage signal at all |
| DCO sign-off | Every commit carries a `Signed-off-by` trailer matching its author |

Full detail and the hardening log behind each gate (what each one has actually
caught, not just what it's designed to catch):
[`../compliance/SECURITY-VERIFICATION.md`](../compliance/SECURITY-VERIFICATION.md).

## 2. The fuzzing program

Two distinct tiers, deliberately not conflated:

- **Per-PR / weekly bounded fuzzing** (`.github/workflows/fuzz*.yml`) — fast,
  seeded from the committed corpus, regression-oriented. Runs in CI's normal
  time budget.
- **Continuous discovery on dedicated infrastructure** — a self-hosted rig
  running the shared `keyorixhq/fuzz-harness` runner (the same runner used
  across multiple Keyorix-adjacent projects), re-pulling `main` before each
  target given this repo's commit velocity. Rotates through the targets judged
  highest-risk for deep, continuous discovery — parsing/escaping boundaries
  where an attacker-influenced input crosses a trust boundary (cryptographic
  share reconstruction, JWT/OIDC verification, rotation-credential
  interpolation into a URL or hand-rolled SQL escaping, secret-template
  parsing) — not blanket coverage of every declared target.

**Scale, stated precisely rather than as one headline number:**
`scripts/fuzzing/targets.d/` declares **93** `FuzzXxx` targets across the
tree as of this writing — the CI drift-guard's complete, bidirectionally-checked
list (a target existing in code but missing from this directory fails CI, and
vice versa). This is the full declared population subject to per-PR/weekly bounded
fuzzing; it is a materially larger number than, and should not be confused
with, the smaller rotation the continuous discovery rig runs at any one time
on dedicated hardware.

**Crash handling is deliberately private by default.** The rig's report sink
defaults to a private corpus repository, not a public issue or PR — an
unfixed vulnerability in Keyorix's own code is never disclosed before a fix
ships. (An earlier in-repo rig that posted failing-run logs to a public
tracking issue was recognized as a disclosure anti-pattern for a security
product and removed.)

### Harness quality gates — a never-panic harness proves nothing on its own

Two checks keep a fuzz harness honest, not just present:

1. **Reach and coverage-delta.** For a harness that seeds from a valid
   fixture and mutates past a signature/parsing "wall" (an *in-wall* harness),
   coverage of the specific post-wall functions is measured against a floor —
   and, where a byte-level sibling harness exists, must exceed it. A harness
   that never clears the floor is effectively dry: every mutation is dying at
   the wall without ever exercising the code the harness exists to test.
2. **Rediscovery / regression.** A harness encoding a genuine security
   invariant keeps a labeled reproducer of the bug class it exists to catch,
   plus a deterministic regression test proving the current code handles it —
   turning a one-time catch into a standing check that fires again if the fix
   ever regresses.

## 3. Differential and property-based testing

- **Dual-backend differential testing** — `internal/storage/store/backend_differential_fuzz_test.go`
  drives the same operation sequence against both SQLite and PostgreSQL
  backends and asserts identical observable behavior, catching a backend-specific
  divergence (a query that behaves differently under SQLite's looser
  type/locking semantics than under Postgres's stricter ones) before it reaches
  production.
- **Operation-sequence fuzzing** — `internal/core/core_sequence_fuzz_test.go`
  generates sequences of core operations and checks system-wide invariants hold
  after each, rather than testing one function in isolation; this is what
  catches an interaction bug that neither operation's own unit test would.
- **Concurrent linearizability** — `server/http/concurrent_linearizable_fuzz_test.go`
  checks that concurrent HTTP requests produce a result consistent with *some*
  valid serial ordering — the class of bug a single-threaded test suite cannot
  see at all, and the same class of bug the 2026-09 security review's
  multi-replica-safety findings belong to (see `security-review-2026-09.md`).
- **PAT lifecycle metamorphic testing** — `internal/core/pat_validate_lifecycle_fuzz_test.go`,
  `internal/core/pat_authz_metamorphic_fuzz_test.go` — checks that a PAT
  restriction (ADR-042) only ever narrows access relative to its owner across
  fuzzed permission/scope combinations, not just the hand-picked examples a
  unit test would cover.

## 4. Coverage and closure ledgers (machine-checked, not asserted)

Three CI-enforced ledgers make "was this reviewed / is this fix real / does
this ADR-claimed property still hold" checkable rather than a matter of
recollection:

| Ledger | Enforced by | What it proves |
|---|---|---|
| `docs/review-coverage.tsv` | `scripts/check-review-coverage.sh` | Every Go package (derived live from `go list ./...`) has a recorded adversarial-review depth (`full-adversarial` / `targeted` / `structural-only` / `none`-with-a-reason) — fails if any package has no row, or any row names a package that no longer exists. |
| `docs/security-closures.d/` | `scripts/check-closures.sh` | Every claimed security-fix closure names a real, currently-passing test — fails the build if the test doesn't exist or doesn't produce a `--- PASS` in the environment its `verification` column claims (`default-ci`, `pg-gated`, or `manual` with a cited artifact). |
| `docs/adr-conformance-enforced.tsv` | `scripts/check-adr-conformance.sh` | An ongoing architectural property an ADR asserts (e.g. "PBKDF2 uses 600k iterations") has a currently-passing test proving it, re-verified rather than transcribed from a point-in-time audit. |

These exist specifically because a hand-written claim of "this was reviewed" or
"this is fixed" decays silently otherwise — see this repository's own engineering
practices around preferring the machine-checked over the asserted.

## 5. Independent, offline verification

Distinct from CI: `keyorix-server admin verify-audit` re-derives the audit
tamper-evidence chain using a deliberately independent implementation
(`internal/auditverify`, not the code that wrote the chain), so a customer's
own auditor can check the integrity claim without trusting the running server
process. Full design: [`../compliance/OFFLINE-AUDIT-VERIFICATION.md`](../compliance/OFFLINE-AUDIT-VERIFICATION.md).

## 6. What this program does not claim

- **No independent third-party certification.** These are Keyorix's own CI
  gates, fuzzing program, and internal review ledgers — not an external audit
  or a SOC 2 report (see [`../compliance/SOC2-CONTROLS.md`](../compliance/SOC2-CONTROLS.md)
  for what a self-hosted product can and cannot supply toward one).
- **A green gate proves what it's named for, and states what it doesn't.**
  Per this repository's own engineering discipline, a mechanism's name should
  state what it verifies and what it silently skips — a fuzz target that
  never clears its coverage floor (§2) or a review-coverage row of `none` are
  both recorded honestly rather than counted as coverage.
- **Fuzzing findings against embargoed third-party libraries are not detailed
  here** (see the note at the top of this document; at this writing that is
  `crewjam/saml` only) — their existence as a *mechanism* (the harness, the
  triage gate) is documented; the specific findings are not, until upstream
  disclosure.
