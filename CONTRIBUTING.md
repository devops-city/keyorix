# Contributing to Keyorix

Thanks for considering a contribution.

## Before you start

- **Security issues**: do not open a public issue or PR. See
  [SECURITY.md](SECURITY.md) for the private disclosure process.
- **Bigger changes**: open an issue first to discuss the approach, especially
  for anything touching encryption/key management (see
  [SECURITY.md](SECURITY.md) — those changes need a written ADR before
  implementation) or authentication/authorization.
- **License**: everything in this repository is AGPL-3.0 (see
  [LICENSE](LICENSE) / [LICENSING.md](LICENSING.md)). Your contribution will
  be under the same license.

## Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying you wrote it (or otherwise have
the right to submit it) under the
[Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s -m "your commit message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer to the
commit, matching your git author identity — nothing more. A CI check
(`.github/workflows/dco.yml`) verifies every commit in a PR has one; PRs
without it won't pass CI. If you forgot:

```
git commit --amend -s --no-edit                              # last commit only
git rebase --exec 'git commit --amend --no-edit -s' <base>    # every commit since <base>
```

### Optional git hooks

This repo ships two opt-in hooks in `.githooks/` (not installed by default —
`.git/hooks/` and `.githooks/` are different directories, and git only uses
the latter once you point it there):

```
git config core.hooksPath .githooks
```

- **`prepare-commit-msg`** — auto-appends `Signed-off-by:` to every commit
  message from your git author identity, so the DCO check above never fails
  on a forgotten `-s`. Skips merge/squash/revert/fixup commits and commits
  that already have a trailer.
- **`pre-push`** — runs `golangci-lint` locally before a push leaves your
  machine, scoped to just the package(s) your push actually changed (diffed
  against `origin/main`); runs the full module instead if `go.mod`, `go.sum`,
  or `.golangci.yml` changed, since those can change any package's lint
  result. Mirrors CI's own gate, just earlier. Skips silently (never blocks
  a push) if `golangci-lint` isn't installed. Bypass with
  `git push --no-verify` if you need to push anyway — CI still gates the
  merge regardless.
  Same hook also **warns** (never blocks) if the branch you're pushing has an
  already-open PR based on something other than `main` — the shape that let
  #1961 merge into `fix/sweepfn-error-swallow` after THAT branch had already
  landed on `main` under a different PR, so #1961's own commit never reached
  `main` even though GitHub still showed it as "Merged." It's a warning, not
  a hard failure:
  a legitimate, still-in-progress stacked PR looks identical to a stale one
  from git alone, and this repo opens correctly-stacked PRs routinely (CI's
  own `base-branch-check` job is the actual hard gate, with a `stacked-pr`
  label escape hatch — see `CLAUDE.md`'s "A merge badge is not a merge"
  section). Silence it for
  a deliberate, still-in-progress stack by naming the branch
  `stacked-on-...`, or adding a `Stacked-On: <branch>` line to the latest
  commit's body. Skips silently if `gh`/`jq` aren't available or `gh` isn't
  authenticated.

Neither hook is required — CI enforces both independently — but they turn a
CI round-trip into an immediate local one.

## Making a change

1. Fork (or branch, if you have write access) and make your change.
2. Run the checks locally before opening a PR — CI enforces all of these:
   ```
   make ci          # go vet + go test -race + gosec + govulncheck + build
   golangci-lint run ./...
   ```
   For a change touching `operator/` (its own Go module):
   ```
   cd operator && GOWORK=off go vet ./... && GOWORK=off go test ./...
   ```
3. Add a test that fails without your change and passes with it — this is a
   hard requirement for anything security-relevant (see
   [docs/compliance/SECURITY-VERIFICATION.md](docs/compliance/SECURITY-VERIFICATION.md)
   for what that verification standard looks like in practice).
4. If the change is user-visible, add a changelog fragment
   `changelog.d/<PR-number>-<slug>.md` ([format](changelog.d/README.md)). Do
   not edit `CHANGELOG.md` directly; fragments are assembled at release time.
5. Open a PR against `main`. CI must pass in full before it can merge via a
   squash-only merge queue (branch protection enforces this through a
   GitHub ruleset). **Correction (2026-10-05):** this used to say "no
   bypass, including for maintainers" — the live ruleset
   (`gh api repos/keyorixhq/keyorix/rulesets`) carries a standing
   `OrganizationAdmin`/`bypass_mode: always` bypass actor, so that wasn't
   accurate. See [docs/security/SDLC.md](docs/security/SDLC.md#branch-protection)
   for the ruleset evidence.

## What CI checks

11 required checks gate every merge to `main` via branch protection. (The
underlying GitHub ruleset names 18 status-check contexts — CI job names, not
a 1:1 match to this tool-level list; see
[docs/security/SDLC.md](docs/security/SDLC.md#branch-protection) for the
literal context list.)

- `go vet`, `go build`, `go test -race` (full suite)
- `gosec` (medium+ severity) and `golangci-lint`
- `govulncheck` against known vulnerabilities in dependencies
- `gitleaks` (the PR's own commit history, not the whole repo's other branches)
- `CodeQL` (dataflow/taint analysis, both Go modules)
- Helm chart lint + schema validation (`kubeconform`) for all three charts
- `checkov` — Helm chart security-policy scanning (pod security context,
  RBAC-escalation checks), distinct from `kubeconform`'s schema-only validation
- Go dependency license compliance (`go-licenses`) — rejects any dependency
  outside an explicit permissive-license allowlist, both Go modules
- Fuzz-target staleness — `scripts/fuzzing/targets.d/` (one file per target,
  the self-hosted continuous-fuzzing rig's config) must exactly match every
  real `func FuzzXxx` in the tree; adding a fuzz target without declaring it
  there fails CI
- DCO sign-off (`git commit -s` on every commit — see above)

## Code style

`gofmt` and `golangci-lint` are the source of truth — there's no separate
style guide to read. If the linter's happy, the style's right.
