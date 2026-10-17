# scripts/ci

Helpers used by CI workflows, or run locally next to them.

| Script | Run by | What it does |
|---|---|---|
| `failure-issue.sh` | scheduled workflows | Opens one GitHub issue per failing scheduled job, comments on repeat failures, and closes the issue when the job goes green. |
| `check-bug-origin-block.sh` | CI (`ci.yml`) | Checks that a `fix(...)` PR has filled in its "Bug origin" block (Introduced-by, Detected-by, Class, Severity). |
| `precheck-open-prs.sh` | the merge coordinator, **locally** | Rebases each listed open PR onto current `main` in a throwaway worktree and runs the checks that tend to fail only inside the merge queue. |
| `select-affected.py` | CI (`ci.yml`: `select`, on merge_group) | Merge-queue selection: from the entry's diff against `merge_group.base_sha`, the affected root-module packages (changed + importers), the test-suite legs that run, and the path gates of the heavy jobs. Full suite on go.mod/go.sum, `internal/testutil/**`, `ci.yml`, `scripts/ci/**`, the leg definitions or a generated-code input, and on any error. Pinned by `select_affected_test.go`. |
| `run-guards.sh` | CI (`ci.yml`: repo-guards, on a selected merge_group run) | Every repo-wide guard, whatever the entry touches: the named guards (`*Guard`/`*Sweep`/`*Completeness`/`TestEvery*`/`TestNoRaw*`) and every source-scanning test in the root module, plus `global-guards.txt`. |
| `global-guards.txt` | `run-guards.sh` | Mirror of the coordinator preflight's global guard package list; keep both identical. |
| `install-gosec.sh` | CI (`ci.yml`: static-analysis, operator, cli, migrate) | Installs gosec in a throwaway module that also requires a newer `golang.org/x/tools`, so MVS picks that instead of gosec's own (older) requirement -- see the script header for why. |

## precheck-open-prs.sh

Two PRs passed their own CI and then failed in the merge queue. The queue
tests against today's `main`, and the PR's own CI did not:

- **#2641**: after an audit API change landed on `main`, a benchmark the
  PR added ignored the new `error` return, so errcheck failed.
- **#2559**: a Postgres-only test asserted log text that the PR's own
  refactor had changed. Only the PG leg runs that test.

```sh
# one PR number per line; blank lines and '#' comments are ignored
printf '2641\n2559\n' | scripts/ci/precheck-open-prs.sh
scripts/ci/precheck-open-prs.sh --quick < prs.txt   # test-compile changed pkgs only

# lint must be the exact version CI pins (read from ci.yml); otherwise SKIP
GOTOOLCHAIN=go1.27.0 GOBIN=$HOME/bin go install \
  github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
GOLANGCI_LINT=$HOME/bin/golangci-lint scripts/ci/precheck-open-prs.sh < prs.txt

# the #2559 class: also run the changed packages' tests against Postgres
KEYORIX_TEST_PG_DSN='host=localhost port=5432 dbname=keyorix user=keyorix sslmode=disable password=…' \
  scripts/ci/precheck-open-prs.sh < prs.txt

scripts/ci/precheck-open-prs.sh --self-test         # red/green proof, no network
```

Example output:

```
PR     rebase    build  vet    lint                test-compile  pg       overall
2641   ok        ok     ok     FAIL                ok            not-run  FAIL
2559   ok        ok     ok     ok                  ok            FAIL     FAIL
2682   ok        n/a    n/a    n/a                 n/a           not-run  OK
```

A check that did not run never shows as `ok`. A missing or wrong-version
golangci-lint shows as `SKIP(lint-missing)` or `SKIP(lint-version)` and
makes that PR's overall verdict `INCOMPLETE`. Exit codes: `0` when every PR
is OK, `1` when any PR fails or conflicts, `2` when nothing failed but
something was skipped. Without a DSN the pg column shows `not-run`, which
is expected for this opt-in check and does not make the run incomplete.

The script never moves your checkout or any branch. Each PR is checked on a
detached HEAD in a `mktemp -d` worktree, and that worktree is removed on
exit or Ctrl-C. The script header covers the full method: how changed
packages map to the repo's several Go modules, why a replay conflict falls
back to a 3-way merge, how the test-compile timing was measured, and how it
relates to `scripts/git-write-guard.sh`.
