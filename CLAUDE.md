# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Git / PR conventions

- **PR numbers cited in ADRs below roughly #700 are frequently wrong — don't chase
  them.** Found 2026-09-07 (ADR corpus review, `keyorix-private/adversarial-review/
  ADR-CORPUS-REVIEW-2026-09-07.md`, Tier 1): spot-checking five PR citations in
  ADR-040/083/090 against the live GitHub API found every one resolves to an
  unrelated PR (#452, #517, #519, #527, #528, #530 all land in a 2026-06/07
  SSO/SAML/Helm-chart hardening batch, none related to the storage-layer refactors
  the ADRs cite them for). **This is a citation-accuracy defect, not a
  security-property defect** — every mechanism these citations attach to
  (`TransitionMachineIdentityState`, `CreateSecretDependencyExclusive`,
  `TransitionSecretStatus`, the RemoteStorage login-attempt no-op) was independently
  confirmed to exist in code and work as described; only the PR numbers are wrong.
  Recent citations (spot-checked: #1779, #1573, #1636) all resolve correctly, so
  this is bounded to references below roughly #700, not a repo-wide pattern.
  **Do not attempt to repair these citations** — the batch is old enough, and the
  mechanisms are independently verified anyway, that hunting down the real PR
  numbers is pure effort with no safety payoff. If you're reading an ADR and a cited
  PR number doesn't check out, this is why — verify the mechanism in code directly,
  not by chasing the citation.
- **Never put `Co-Authored-By: Claude` into a PR.** Do not add a `Co-Authored-By: Claude …`
  trailer to PR descriptions, and do not add it to commit messages either (squash-merge
  folds commit trailers into the PR's merge commit). This overrides any default that
  appends a `Co-Authored-By: Claude` line.
- PR bodies and commit messages must not include Claude attribution lines (`Generated
  with [Claude Code]` / `Co-Authored-By: Claude`) — enforced by a PreToolUse hook that
  blocks `gh pr create`/`gh pr edit` outright when either is present.
- Before starting a PR series, run `scripts/preflight.sh` (checks the branch base is
  current against `origin/main`) — see `docs/g80-remediation-notes.md` for why.
- **A merge badge is not a merge — but `--is-ancestor <branch> origin/main` is not
  the fix either.** GitHub can report a PR as "Merged" while its branch was actually
  merged into a PREVIOUS PR's feature branch, never into `main` — a chain of
  branch-into-branch merges can make every PR in the chain show "Merged" with none of
  them ever reaching `main`. Found 2026-08-25: PRs #1563–#1566 all showed "Merged" on
  GitHub; none were ancestors of `origin/main`. **That check is unsound as a general
  rule, not just in this one case**: this repo squash-merges every PR, which mints a
  brand-new commit SHA, so a correctly-landed branch's own pre-squash commits are
  NEVER ancestors of that squash commit either — `--is-ancestor <branch> origin/main`
  returns false unconditionally, for every PR, landed or not. A check that always
  fails is exactly as uninformative as one that always passes, and worse, because it
  looks like evidence. The actual check: `gh pr view <N> --json baseRefName` (a PR
  based on a feature branch, not `main`, did not reach `main` no matter what its
  reported state says) plus `git diff <branch> origin/main --stat` (empty means the
  content is already there). Guard closures on artifacts present in the tree (a
  marker: a test that must exist, a symbol that must exist or must be absent), or on
  the baseRefName+diff check above — never on `--is-ancestor` across a squash
  boundary. Checking `--is-ancestor <sha> HEAD` for one already-resolved commit SHA
  against your own branch's own live history is a different, sound question (is this
  specific object included) — the unsound case is specifically a whole branch tip
  checked against a squash-merge target. **This is a post-hoc verification
  practice, not a gate** — it only catches the mistake after the fact, by
  re-reading a specific PR someone already suspects is wrong. It recurred
  (#1594, docs/adr-089-mfa-purge-relay-deletion.md: merged into an
  already-squashed base branch, never reached `main`) because a written
  practice that has failed twice is a note, not a safeguard. The preventive
  gate is `.github/workflows/ci.yml`'s `base-branch-check` job: it fails a
  PR outright if its base is not `main`, unless explicitly labeled
  `stacked-pr`. Prefer fixing this class of mistake at merge time, not by
  writing down one more sentence to remember to check.
- **An agent's last act before finishing is to commit and push its branch** —
  alongside "start in a worktree" and "run tests in the foreground." Found
  2026-09-07: a worktree with real, uncommitted single-use-grant follow-up
  work sat unpushed and un-flagged until a `git worktree remove` attempt
  happened to fail on it; a separate worktree's own commit landed on an
  `worktree-agent-*` branch, not the shared branch it was meant to reconcile
  onto, and was only confirmed safe by tracing it to an already-merged PR
  after the fact. Removal is only safe to make routine (see
  `scripts/worktree-branch-health.sh`, run at session start for uncommitted/
  unpushed work and on demand for the full stranded/duplicate-branch sweep)
  once every agent's own last step already got its work to a remote ref —
  don't rely on detection to catch what creation should have prevented.
- **One session with write access per repository at a time. Others read, or
  work in a separate `git clone` — not a worktree off the shared tree.**
  Found 2026-09-07: two sessions in this exact repo raced each other's
  branch checkouts in the shared main checkout (`git branch --show-current`
  returned a different branch across two consecutive commands, seconds
  apart), one session's own accidental test commit landed on whatever branch
  a *different* session happened to have checked out at that instant, and a
  background daemon session committed directly over another session's
  in-progress ADR draft, self-assigning "Accepted" status that was never
  actually ratified. Worktrees do **not** isolate against this — they share
  one `.git`, and this incident was specifically about HEAD moving inside
  that shared state, not about worktree-vs-worktree collisions. Enforced by
  `scripts/git-write-guard.sh`: a lock file at `$(git rev-parse
  --git-common-dir)/write-lock.json` (shared by a main checkout and all its
  worktrees; distinct for a separate clone by construction), claimed/
  refreshed by `SessionStart` and by every HEAD-moving git subcommand
  (`commit`/`checkout`/`switch`/`rebase`/`merge`/`reset`/`cherry-pick`/
  `revert`/`pull`/`worktree add`/`worktree remove`), timestamp-stale after
  3 hours (widened from an initial 20 minutes after confirming the lock only
  refreshes on a gated command, not on a timer or ordinary work, and agents
  here routinely run 40-80 minutes between them) rather than requiring PID
  liveness (no persistent PID exists to check from inside a short-lived
  hook). Read-only git commands (`status`/`log`/`diff`/`show`/etc.) are
  never gated; `git reset --`/`git checkout --` pathspec forms are exempt
  even though the bare subcommand is guarded, since they never move HEAD.
  Respects `-C <path>` in the command being gated.

- **Changelog: add a `changelog.d/` fragment, never edit `CHANGELOG.md`.** One file
  per PR, `changelog.d/<PR-number>-<slug>.md` (or `<branch-slug>.md` before the PR
  number exists), containing `### <Section>` heading(s) and the bullets exactly as they
  would have appeared under "Unreleased". Format and sections: `changelog.d/README.md`;
  `scripts/changelog-assemble.sh --check` validates. The maintainer assembles fragments
  into `CHANGELOG.md` at release (`RELEASING.md`). Editing `CHANGELOG.md` directly
  reintroduces the merge-main conflict churn this removed.

## Engineering practices

Reasoning and incidents behind these: `docs/g80-remediation-notes.md`.

### Read the package's INVARIANTS.md before changing its code

Every core package (`internal/core`, `internal/storage`(`/store`), `internal/encryption`,
`internal/auditverify`, `server/middleware`, `server/http`, `server/grpc`(`/services`), `cli`,
`web/src`, …) has an `INVARIANTS.md` next to its code: the rules a change there must keep,
each linked to the test/fuzzer/static guard that enforces it, or marked `UNGUARDED` with a
follow-up issue. See `docs/INVARIANTS.md` for the index. **Read the relevant file(s) before
editing code in one of these packages.** If your change would have to break a listed
invariant, stop and ask rather than silently removing it; if you discover or add one while
working, add it to that package's file in the same PR.

**New invariants go in `<pkg>/INVARIANTS.d/INV-<PKG>-<kebab-slug>.md`** (one per file,
same bullet format, a slug ID named for what it protects — never "the next number", which
is how `INV-CORE-41` came to be defined twice), not appended to `INVARIANTS.md`.
`internal/statemap/invariants_fragments_guard_test.go` fails on any duplicate ID involving a
fragment, on malformed or misnamed fragments and on orphan `INVARIANTS.d/` directories, and
logs legacy-only duplicates, which become fatal when a package is migrated by
`scripts/ledgers/migrate-invariants-to-fragments.sh` (coordinator only, quiet window). See
`docs/invariants-fragments.md`.

### Core principle: prefer the machine-checked over the asserted

**Every claim this codebase makes should have a mechanism that fails when the claim stops
being true. A claim with no such mechanism is a comment, however carefully written.**

This is a constraint, not an aesthetic. Keyorix is built and maintained by one person. A
hand-written artefact that duplicates a truth stated somewhere else does not stay correct —
it decays silently, and the decay is invisible until a customer or an auditor finds it. We
have the receipts: two gRPC control gaps found by accident years apart (ADR-105), 145 of 167
OpenAPI operations with no response schema (ADR-074), and a CI exclusion that claimed
"auto-generated, no tests to write" in a comment nobody had checked
(`server/proto/pb/generated_code_test.go` exists because of it).

Preference order, strongest first:

1. **Generate it.** One source of truth, other artefacts derived by a build step. The build
   cannot be wrong about what it generated. First large application: ADR-106 (the proto
   generates the HTTP surface and the OpenAPI document).
2. **Derive and check it.** Where generation is not available, compute the fact from the
   code and assert it: `contracttest.AssertOpenAPIResponse`, `CheckPartition` over
   `pendingRegistry`, `adrOpenDecisionRegistry`'s premise functions, the schema-epoch
   tripwires. Most of this codebase's guarantees live here, and that is fine.
3. **Assert it in prose.** Acceptable only when 1 and 2 genuinely do not apply. Say so
   explicitly — an ADR that declines to enforce something should say it is declining, so
   the omission reads as considered rather than overlooked.

**Corollary, and the part most easily skipped: a mechanism must be validated against a
failure that actually happened, not against the one its author imagined.** Red/green plus
mutation-kill proves a check fires on planted violations — it says nothing about whether
those shapes occur. The RemoteStorage proxy campaign is the standing evidence: four checks,
each red/green-validated and mutation-kill-confirmed, caught **zero of nine** real historical
defects, and one of them actively *certified* a real bug as correct. A green check that does
not cover what its name implies is worse than no check, because it converts an unknown into a
false assurance. Name mechanisms for what they verify, and state in the doc comment what they
do not.

**Guard against over-applying this.** Building a generator or a framework where a hand-written
thing would do is meta-work that feels like progress. The test: does this fact exist in more
than one place, or will someone rely on the claim? If neither, write it by hand and move on.

Related: "Ask of any mechanism: what does it silently skip, and does it say so?" below is the
same idea applied to a mechanism already in front of you.

- Check reachability and liveness before designing a fix, not just call sites. **A Go
  call graph is not a deployment path.** Before concluding a route is reachable OR
  unreachable, verify the wiring can be constructed at runtime — not just that a call
  site exists (or doesn't). Four instances from this campaign, cutting both directions:
  - Over-claimed reachable, wiring existed but couldn't be constructed: tracing
    `server/http/handlers → core → storage` for 19 deleted `/system` proxies found a
    real call graph and nearly reverted a correct deletion — `RemoteStorage` can never
    be wired into `server/http/handlers` in any deployment (`validateRemoteStorageNotServer`,
    `internal/config/config.go:2057`, unconditional since #1549).
  - Over-claimed reachable, wiring existed but nothing used it: the WebAuthn trio +
    `CreateMFAStepUpGrantProxy`'s full `RemoteStorage` client implementation was
    complete and correct (ADR-085); Group B assumed that implied a hub-side caller
    worth preserving — the liveness sweep found zero callers anywhere.
  - Under-claimed reachable, a shallow flag check missed the real wiring: the original
    `validateRemoteStorageNotServer` checked only `server.http.enabled`/`.grpc.enabled`;
    a scheduler-only process looked safe by that check, but `server/main.go`'s
    `startSchedulers` runs unconditionally regardless of either flag (`e98141b7`).
  - Correctly withheld "unreachable" until the wiring was actually verified closed: the
    5 handlers orphaned by that same scheduler fix stayed classified "uncertain," not
    "safe," until the fix's actual effect on the scheduler path was confirmed — only
    then reclassified to no-caller/delete.
  - A demonstration proves reachability only at the layer actually demonstrated, not
    the whole path to it: #1642's recon called `storage.NewStorageFactory().CreateStorage(cfg)`
    directly and genuinely demonstrated an NFC/NFD project-name collision at the storage
    layer — real demonstration, done correctly. It wasn't reachable through any live
    caller: `internal/core`'s `validateProjectName` rejects non-ASCII before any real
    request reaches storage. The demonstration wasn't wrong; treating it as proof the
    *application* was reachable was the gap. Pair every storage/DB-layer demonstration
    with a trace of whether a live caller can drive that exact code path with that exact
    input — don't infer application-level reachability from a lower-layer repro alone.
- Ask of any mechanism: what does it silently skip, and does it say so?
- **A ceiling that inspects only the target is not a ceiling.** A privilege-ceiling
  check must derive the ceiling from the ACTOR's own effective privileges as well as
  the target's — checking only the target (e.g. "does the machine identity being
  minted a credential currently hold a higher role than the one requested") lets an
  attacker with zero standing self-mint into an empty/attacker-controlled target and
  pass trivially. Derive a ceiling, don't pick one: creating a principal inherits the
  ceiling of the privilege that principal can come to hold, checked against the
  ACTOR requesting the creation, and applied at creation time, not only at
  credential-mint time. Found 2026-08-25: `RequireMachinePrivilegeCeiling` checked
  only the target machine identity's current roles, never the calling actor's.
- Verify a repaired test by breaking its subject and confirming it goes red.
- A test whose premise turns out to be untested is a coverage gap, not a stale test —
  fix the fixture or quarantine it; never adjust the assertion to match behaviour.
- A guard nobody has watched fail is not a guard.
- A check that always fails is as useless as one that always passes — and worse,
  because it teaches people to ignore it (or, if CI-enforced, blocks everything
  indiscriminately until someone routes around it). Before adding a guard, confirm
  it is green on a known-good case as well as red on a known-bad one — both
  directions, not just the failure you set out to catch.
- When a verdict depends on a condition, guard the condition, not the conclusion.
  A guard aimed at the conclusion is often vacuous — the population it checks is
  empty precisely *because* the condition holds, so it passes unconditionally
  forever regardless of whether the conclusion is still true. #1494's closure
  ("role renaming is blocked") was proposed as a guard on `IsBuiltinRole`
  covering every rename path — but there are zero rename paths (neither
  transport's `UpdateRoleRequest` carries a `Name` field), so that guard would
  never have anything to check. The guard that actually landed
  (`TestUpdateRoleRequest_CarriesNoNameField`) asserts the precondition itself:
  no such field exists. Same move, stated in advance rather than caught after
  the fact: ADR-088's own "Precondition this rule depends on" section names the
  CLI/hub execution split its no-full-delegation rule requires, and says the
  rule is void the moment that split changes; ADR-087's Authorize-chain tracing
  makes reachability turn on whether a call site's actor identity flows through
  `Authorize`, not on the call site existing. All three are the same
  discipline: identify the condition a claim rests on, then write the checkable
  thing to be that condition, not a proxy for it.
- A skip with a wrong reason is worse than no skip.
- Timeouts detect hangs; they don't enforce speed. Set them generously, watch durations.
- When determining whether something needs fixing costs more than fixing it, fix it.
- On Postgres, catching a constraint violation after the failing statement is not
  recovery — the transaction is already aborted at the protocol level, and a
  subsequent COMMIT is silently downgraded to a ROLLBACK. Prevent the conflict
  (`INSERT ... ON CONFLICT DO NOTHING`, then read back), don't catch it. A caught
  violation that returns a non-nil error (triggering ROLLBACK) is fine — ROLLBACK
  succeeds on an already-aborted transaction; only a caught violation that returns
  `nil` (intending COMMIT) is dead code on Postgres. `TryAcquireSchedulerLock`
  (`local_scheduler_lock_lease.go`) was the confirmed instance; a full-repo sweep of
  every other `isUniqueViolation`/constraint-catch site found no other dead ones —
  every other site either isn't inside a multi-statement transaction at all, or
  returns a non-nil error.
- A test named for a condition it does not create proves nothing. The original
  `TestConcurrency_BootstrapSystem_CrossReplicaExactlyOneAdmin` handed every
  simulated "replica" the SAME shared `storage.Storage` instance — one
  `LocalStorage`, one process-local mutex — so it would have passed identically
  even with the Postgres advisory lock deleted outright. The name asserted
  cross-replica safety; the fixture could not structurally exercise it (multiple
  independent `*gorm.DB` connections are required, not multiple wrapper objects
  sharing one).
- "Green when the lock is disabled" is ambiguous, and the ambiguity is unfalsifiable
  from that observation alone: it is equally consistent with *the lock is redundant*
  and with *this harness never exercised the lock*. Don't conclude redundancy from a
  disabling-mutation result by itself — first confirm the harness reproduces the
  production concurrency shape (same transaction boundaries as the real caller, same
  call sequence), and that the assertion states an invariant that holds under EVERY
  legal interleaving, not just the one the test author had in mind. The
  machine-identity row-lock test failed both checks at once, and each one masked the
  other: (1) it called `LockMachineIdentityForUpdate` and `TransitionMachineIdentityState`
  standalone rather than inside the same `WithTransaction` the real caller
  (`transitionMachineInTx`) uses — `SELECT ... FOR UPDATE` outside an explicit
  transaction is a no-op on Postgres (the lock releases the instant that single
  autocommit statement completes), so the "lock" was never actually held across the
  read+write; (2) its assertion ("exactly one of two racing transitions may win")
  was false as an invariant regardless of locking, because `active`→`revoked` is
  itself a legal transition — if `active` wins the race to go first, `revoked`
  legitimately gets a second, later, ALSO-successful write, and the assertion never
  checked the one thing that actually mattered: that `revoked` must always win the
  row's FINAL value. Fixing the transaction-wrapping bug alone made the flawed
  assertion flaky (2/10); only fixing both together — real transaction boundaries AND
  a correctly-derived invariant — made the lock's true load-bearing status visible
  (red 13/15 runs without it). A `securefiles.safeRelComponents` vs `resolveInside`
  case from earlier in this campaign IS genuine redundancy (confirmed by disabling
  both layers, with a harness that correctly reproduced the real call path
  throughout) — the lesson isn't "assume redundancy is always wrong," it's that the
  observation alone never tells you which one you're looking at. A same-worktree
  follow-up audit then traced every real production caller of all six FOR UPDATE
  sites in `internal/storage/store` (not test callers) and confirmed every one
  correctly shares one transaction with its guarded write — the standalone-lock bug
  the test harness had was a test-only defect, not a production one.
- **An enumeration is only as complete as the idioms it knows about.** Before
  trusting an exclusion-by-pattern (a grep/regex that says "these are safe/dead
  because they only match caller shape X"), derive the full set of shapes the
  target behavior can take from the code itself, don't assume the first one found
  is the only one — and state how the list was established to be complete, not
  just what it found. State which call forms the enumeration recognises
  explicitly, in the code or the doc that defines it — that list is itself
  something a reviewer can check, not an implicit assumption. This is the
  third instance of this exact failure in this campaign (unexported helpers;
  a stub-completeness regex that matched only one stub-call shape and missed
  13 raw ones — see `docs/g80-wave0-remote-storage-partition.md`), with two
  more since: the raw-storage-bypass guard's own `/system`-only route
  scoping (fourth), and `raw_storage_bypass_guard_test.go`'s
  `exportedCoreStorageWrappers`, which recognizes `c.storage.X()` and
  one-hop unexported-sibling calls but not a call through a `tx` handle
  inside `WithTransaction` — invisible to it for 9 real wrappers,
  `ActivateMFA`/`DisableMFA`/`RegenerateMFARecoveryCodes`/
  `PurgeExpiredSoftDeletes` among them (fifth, see
  `docs/adr-088-system-proxy-layer-design.md`). The third instance, in
  detail: the G80 Wave 0 partition excluded
  a CLI command from `RemoteStorage`'s live-caller set by grepping for
  `common.NewRemoteClient()` as *the* raw-HTTP-passthrough guard idiom — but
  `internal/cli/run/run.go` calls `common.ResolveRemote()` directly instead, a
  second idiom the grep never knew existed, so `run` was wrongly classified as an
  unconditional, `RemoteStorage`-reaching command. That single miss produced a
  "flagship command is broken in its primary deployment shape" finding
  (`GetLatestSecretVersion` marked LIVE) that turned out, on direct live testing,
  to be wrong — the command works fine, because the second idiom guards it exactly
  like the first guards everything else. The fix wasn't "check more carefully"; it
  was deriving the complete idiom set first (grep every exported function in
  `internal/cli/common` that builds a raw remote client or resolves remote
  credentials, confirm no command rolls its own `net/http` client outside that
  package, confirm no command branches on `Storage.Type`/`IsClientMode()` directly)
  and re-running the exclusion against that set — which is what should have
  happened before the first partition, not after a false finding forced a redo.
- **To test a fails-open path, assert the effect, not the return value.** A
  silent failure returns success at every layer by construction — the
  triggering call succeeds, the wrapper that swallowed the error returns
  nothing to indicate it, and every caller up the stack sees the same
  green result a genuinely-working path would produce. No return value
  anywhere in the chain distinguishes "it happened" from "it silently
  didn't." Only the absence of the effect does. This is the counterpart to
  "a mock that models a shape the real system cannot produce is not a
  test" — here the failure mode is that a return-value assertion models a
  signal the real system does not produce. Worked example:
  `TestRemoteStorageCreateNotification_ClosesTheFailsOpenLoop`
  (`server/http/remote_storage_notifications_test.go`, #1589): asserting
  `RequestProjectAccess` returned no error would have passed both before
  and after the fix — `notifyWithSeverity` swallows the
  `CreateNotification` error by design, so the triggering call always
  reports success regardless of whether the notification actually got
  created. The test instead reads the approver's notifications directly
  off the upstream server's own storage and asserts one exists — the only
  assertion that could have told `CreateNotification` was a permanently-
  failing stub from `CreateNotification` genuinely working.

## Closing a security fix

- Add a file to `docs/security-closures.d/<claim_id>.tsv` (one row: claim id,
  package, proving test, **verification**, commit, **issue** — see
  `docs/security-closures.d/README.md`)
  and commit just that file. `docs/security-closures.tsv` is a generated,
  gitignored build artifact (never commit it): `scripts/check-closures.sh`
  builds it from the fragments on every run, and CI runs
  `scripts/gen-security-closures-tsv.sh --check` to validate the fragments.
  Added 2026-09-28 (C1) so two closure PRs open at once no longer conflict on one
  shared file. `scripts/check-closures.sh` fails the build if the named test
  does not exist, or does not produce a `--- PASS` line in the environment its
  `verification` column claims. Verify by test, never by commit — this repo
  squash-merges.
- `verification` is `default-ci` (runs and passes with no special environment
  — a skip is always a failure), `pg-gated` (needs `KEYORIX_TEST_PG_DSN`, e.g.
  a cross-replica race only real Postgres can demonstrate — a skip is
  expected and NOT a failure when the checker itself has no DSN, but IS one
  the moment it does; `.github/workflows/ci.yml`'s `test-suite` job, `core`
  leg, is the one job that actually proves these), or `manual` (no automated
  test can exist — `note` must cite a specific artefact; this is an escape
  hatch, not a shortcut, and CI cannot verify it). Added 2026-09-08 after
  #1646 and #1780 — both real, both Postgres-race closures — sat with no row
  for the same reason each time: their proving test could only skip in a
  DSN-less run, and the checker treated a skip as a failure unconditionally,
  so a row could not be added without either breaking CI or weakening the
  check for every other claim. See `scripts/check-closures.sh`'s own header
  for the full reasoning, and its `--self-test` for the calibration cases
  (red AND green) that prove this doesn't silently accept an unproven claim.
- `issue` is the GitHub issue number this closes, or `-` when there isn't a
  single corresponding one. `scripts/report-unlisted-security-issues.sh`
  cross-references closed issues carrying the `security` label against this
  column, as an informational CI step — it never fails the build and never
  should: the label is empirically unreliable (confirmed 2026-09-08: #1646,
  #1780, #1551, and #1572 all carry zero labels), so its silence is not
  completeness. Read that script's own header before trusting either its
  output or a bare `-` in this column as proof nothing is owed — no known
  reliable way exists in this repo today to derive that automatically.
- If the root cause has sibling call sites, the fix is an invariant test, not a
  site patch. Extend an existing registry test
  (`TestEveryDirectRoleGrantChecksAuthority`, `remote_reachability_registry_test.go`)
  rather than adding a one-off.
- Reasoning and the failures behind these:
  `keyorix-private/adversarial-review/LESSONS-LEARNED.md` and `SECURITY-INVARIANTS.md`.

## Closing/confirming an ADR-claimed security property (not an incident)

Same discipline as above, separate ledger: `docs/adr-conformance-enforced.tsv`
(`scripts/check-adr-conformance.sh`, a thin wrapper reusing
`check-closures.sh`'s exact verification logic). Use this one for an ongoing
architectural property an ADR asserts (e.g. "PBKDF2 uses 600k iterations",
"a machine identity can never hold a role at global scope") — properties that
were never an incident, just a design claim that needs to stay true. Add a row
whenever you land or touch a test that enforces one. Started 2026-09-07 from
the full-corpus ADR conformance pass
(`keyorix-private/adversarial-review/ADR-CONFORMANCE-MATRIX-2026-09-07.md`,
260 ENFORCED properties found, ~10 seeded here so far — see that file's own
tranche detail for the rest, and QUEUE.md for the incremental-population
follow-up). Don't transcribe a row from that matrix without re-running its
test first — a property verified during that pass is not the same claim as
"this test exists and passes right now."

## Shared ledgers: new rows go in `<name>.d/`

`docs/adr-conformance-enforced.tsv`, `docs/review-coverage.tsv` and
`docs/check-then-act-lock-exempt.tsv` are dual-read: their readers
(`scripts/check-adr-conformance.sh`, `scripts/check-review-coverage.sh`,
`TestCheckThenActLockGuard_UnlockedSecurityCheck`) read the flat file PLUS
every one-row `*.tsv` fragment in the sibling `<name>.d/` directory, and fail
on a duplicate key involving a fragment. **Add a new row as a new fragment
file (`docs/<name>.d/<key>.tsv`, naming in that directory's `README.md`), never
by appending to the flat file** — appends to one shared file were the main
reason approved PRs fell out of the merge queue on 2026-10-03/04. Existing
rows stay in the flat files until the coordinator runs
`scripts/ledgers/migrate-to-fragments.sh` in a quiet window; don't run it on a
feature branch. `docs/security-closures.tsv` is different: it is no longer
committed at all, only built from `docs/security-closures.d/` on demand (see
"Closing a security fix" above).

## Code-scanning alerts

A confirmed false positive is **dismissed**, never silenced by editing the
file. Alerts are anchored to a file and line: editing near one marks the
original "fixed", respawns it under a new number at the new line, and leaves
an audit trail that looks like the problem keeps recurring — this happened
for real (#816/#817 → #819/#820, both `dynamic-urllib-use-detected` in
`scripts/memory-measurement/*.py`; the nosemgrep comment added to fix them
shifted the flagged lines by two, closing the originals and opening new
alerts at the new lines instead of actually closing the finding).

Before dismissing, run `scripts/triage-code-scanning-alert.sh <alert-number>`
— it reruns the single file with the advisory scan's own config
(`--config=auto --config=.semgrep/keyorix-rules.yml`) and checks that the
flagged line carries a `nosemgrep` matching the alert's rule id exactly (not
a prefix, not a bare `nosemgrep`). It dismisses only when both hold; "it
looks like a false positive" is a claim, the rerun is the evidence. The
script's own red/green paths were verified against real, live alerts before
being trusted: pointed at a still-firing finding and at a bare-`nosemgrep`
line (Semgrep's own engine silenced, but not naming the alert's exact rule),
it refused both and dismissed nothing; pointed at a genuine false positive,
it dismissed it via the real API, independently confirmed with a follow-up
`GET`.

`dismissed_reason` is the literal string `false positive` — a space, not an
underscore; `false_positive` is rejected by the API. `dismissed_comment` is
capped at 280 characters (a 422 above that); the script constructs the
comment within the cap, pointer-to-workflow-note first so it survives
truncation, and never fails on it.

A real finding is fixed in code. This procedure is only for a finding the
verification proves absent.
