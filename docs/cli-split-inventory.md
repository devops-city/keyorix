# CLI/server split — Phase 2 inventory

Inventory-only deliverable for the program ADR-108 (`docs/adr-108-cli-server-split.md`, Accepted,
Andrei, 2026-09-23 — not yet merged to `main`, lives on branch `docs/adr-108-109-cli-split-decoupling`
at the time of writing) describes. Builds on ADR-107 (CLI over the human-facing API, Proposed),
ADR-083 (`storage.type: remote` is CLI/client-mode only, Accepted), ADR-102 (`system.write` blast
radius, Proposed/open), ADR-106 (proto-first API definition — direction Accepted, migration
**not yet implemented**: the HTTP surface is still 151 hand-written handler files today, so "the
CLI's client is generated from the canonical API definition" per ADR-108 §Decision 1 is aspirational,
not current state).

This report walks every `keyorix` CLI command (`internal/cli/main.go`'s cobra tree, 35 top-level
groups, ~240 leaf subcommands) as it exists on `origin/main` (`db6dacfa`) as of 2026-09-23, and for
each one records: what it calls today, the REST route that does the same thing, a classification
(API / ADMIN-B1..B4 / CLIENT-ONLY / DROP), behavior differences between the local and remote code
paths, and candidate security findings. No code was changed to produce this report.

**Methodology note**: this pass was done as parallel per-command-group research (one pass per
package cluster below), each independently cross-referencing `server/http/router.go` +
`server/http/handlers/*.go` + `internal/core/*.go` against the CLI source. Citations are file:line
against the worktree used for this inventory; "not independently verified" is stated explicitly
wherever a claim rests on a router/handler comment rather than a direct read of the handler body.

## Contents

1. [Summary](#1-summary)
2. [Per-command-group inventory](#2-per-command-group-inventory)
3. [`/system` route caller census](#3-system-route-caller-census)
4. [CLI-side state today](#4-cli-side-state-today)
5. [Version skew: what exists today](#5-version-skew-what-exists-today)
6. [Top 5 GAPs by user impact](#6-top-5-gaps-by-user-impact)
7. [Phase 3 PR breakdown](#7-phase-3-pr-breakdown)
8. [Candidate security findings — consolidated](#8-candidate-security-findings--consolidated)
9. [Command census (FINISH-SPLIT step 3)](#9-command-census-finish-split-step-3)

---

## 1. Summary

| Metric | Count |
|---|---|
| Top-level command groups | 35 |
| Leaf cobra subcommands inventoried | ~240 |
| Classified **API** (moves to thin CLI, already or trivially REST-backed) | ~190 |
| Classified **ADMIN-B1** (server won't start: diagnose/repair/migrate) | 3 (`system init` local mode, `system audit`, `system validate`) |
| Classified **ADMIN-B2** (recover-admin) | 0 — this mechanism does not exist anywhere in the codebase yet; it is wholly prospective (ADR-108 §Decision B.2) |
| Classified **ADMIN-B3** (exclusive-DB ops incl. KEK/DEK re-encryption) | 15 (all of `encryption/`) |
| Classified **ADMIN-B4** (offline audit-chain verification) | 0 — does not exist in any form today; `audit verify` is REST-only and asks the *live server* to grade its own audit chain, which is the opposite of B4's premise |
| Classified **CLIENT-ONLY** (config/credential files, output formatting, offline tooling) | ~25 |
| Classified **DROP** (dead, duplicate, or removed-by-design under ADR-108 Decision A) | ~10 |
| Hard GAPs (CLI operation with no REST route and one is needed) | 7 (see §6) |
| Candidate security findings (report only, not fixed) | 14 distinct findings across the whole surface (see §8) |
| `/system` routes (current count) | 151 registered routes (`rg`-verified; ADR-102's own snapshot was 148 — see §3) |
| `/system` routes with a non-CLI caller | **0** — confirmed by repo-wide grep (web UI, k8s-sync, mcp, operator, SDKs all checked); every `/system` route is either CLI-only-reachable or zero-caller |

**Headline findings, most important first:**

1. **A live, un-guarded privilege-escalation-adjacent gap on the human-facing `PUT /api/v1/users/{id}`
   route itself** — not a local-mode artifact. This route (ADR-107's own recommended sole path for
   `user update`) lacks the `RequireEqualOrGreaterAdminAuthority` admin-rank ceiling its `/system`
   proxy sibling (`UpdateUserIfActiveStateMatchesProxy`) already had to acquire to close the F5
   finding from the 2026-09-21 authority-ceiling campaign. See §8, Finding S1.
2. **Two live, independent-of-the-split correctness/security bugs on `main` today**: `secret rotate`
   and `secret render` build a broken, silently-ignored `?environment=<name>` query filter and then
   name-match unscoped across every secret the caller can read — `rotate` can silently overwrite the
   WRONG secret's value. See §8, Finding S2. Recommend filing and fixing independently of this
   program, not gated on it.
3. **`keyorix run`'s embedded/local-mode secret-value fetch has zero authorization check and zero
   audit event**, while the functionally identical remote path (in the same file) correctly hits the
   permission-checked, audited REST route. See §8, Finding S18 (the sharpest finding in this batch).
4. **B4 (offline, don't-trust-the-running-server audit-chain verification) does not exist.** `audit
   verify` is 100% REST and asks the live server to grade its own chain — the opposite of what
   ADR-108 §B.4 wants. This needs to be built new as `keyorix-server admin`, not reclassified from
   an existing command.
5. Every `/system` route is reachable from at most one place: the CLI's narrow
   `NewRemoteClient()`-fails fallback. No web UI, SDK, k8s-sync, MCP server, or operator code calls
   any `/system` route. This confirms ADR-107/ADR-108(C)'s premise directly, not by inference.

---

## 2. Per-command-group inventory

Legend: **F** = tries `common.NewRemoteClient()` first, falls back to `common.InitializeCoreService()`
(or `InitializeStorage()+core.NewKeyorixCore`) for local/embedded mode — the ADR-107 pattern. **R** =
remote-only, no fallback (refuses loudly if not connected). **L** = local-only, no remote path at all
(rare — mostly `encryption/`). Unless noted, "no behavior difference" means the local-mode path is a
plain, unauthenticated re-implementation of the same operation (the general ADR-108 "local mode
bypasses the API's authorization, audit and rate limits" pattern) with nothing command-specific to
add — that systemic pattern is stated once here rather than repeated on every row.

### 2.1 `secret` (internal/cli/secret/) — 62 leaf subcommands, the largest and highest-stakes group

Every `secret` subcommand already has a working REST route; **0 hard GAPs** in this group (2
CLI-feature-only notes: `create` has no `--tags`/`--metadata`/`--classification` flags though the
REST DTO accepts them; `template apply`'s REST route has no CLI subcommand).

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `secret create` | create.go:57-115 | F | `POST /secrets` (in-handler auth) | `secrets.write` + per-project MFA policy | API |
| `secret get` (`--id`/`--name`/`--ref`) | get.go:69-219 | F | `GET /secrets/{id}[?include_value]`, `/secrets/value?ref=`, `/secrets?...` (name, client-filtered) | `secrets.read` scoped | API |
| `secret update` | update.go:64-192 | F | `PUT /secrets/{id}` | `secrets.write` scoped | API |
| `secret delete` | delete.go:45-229 | F (via `InitializeStorage()`, not `InitializeCoreService()`) | `DELETE /secrets/{id}` | `secrets.delete` scoped | API |
| `secret list` | list.go:55-180 | F | `GET /secrets` (in-handler auth, union-of-scopes) | in-handler | API — local mode documented as "lists everything, admin tool" in its own `--help` |
| `secret info` | info.go:42-92 | R | `GET /secrets/{id}` + `GET /secrets/{id}/tags` | `secrets.read` scoped | CLIENT-ONLY |
| `secret versions` | versions.go:38-206 | F (`InitializeStorage()`) | `GET /secrets/{id}/versions` | `secrets.read` scoped | API |
| `secret version comment {add,list,delete}` | version_comments.go | R | `POST/GET/DELETE /secrets/{id}/versions/{v}/comments[/{c}]` | write/read/manage scoped | CLIENT-ONLY |
| `secret rollback` | rollback.go:33-37 | R | `POST /secrets/{id}/rollback` | `secrets.write` scoped | CLIENT-ONLY — the one mutation core method (`RollbackSecret`) that audits itself directly, unlike create/update/delete |
| `secret diff <name> <from> <to>` | diff.go:57-111 | F (`InitializeStorage()`) | `GET /secrets/by-name`, `GET /secrets/{id}/versions/{from}/diff/{to}` | `secrets.read` scoped | API — remote resolves by name+project/env filter; embedded requires `--id` (capability asymmetry, own doc string) |
| `secret tags` | tags.go:34-37 | R | `GET/PUT /secrets/{id}/tags` | read/write scoped | CLIENT-ONLY |
| `secret description` | description.go:33-36 | R | `GET /secrets/{id}`, `PATCH /secrets/{id}/description` | write scoped | CLIENT-ONLY |
| `secret acl {list,grant,revoke}` | acl.go:128-134 | R | `GET/POST/DELETE /secrets/{id}/acl[/{aclId}]` | `secrets.manage` scoped | CLIENT-ONLY — correctly so: `RemoteStorage`'s ACL storage methods are hard stubs, so an embedded fallback couldn't work under `storage.type: remote` anyway |
| `secret folder {create,list,delete}` | folder.go:48-250 | F | `POST/GET/DELETE /folders[/{id}]` | in-handler create / `secrets.read` scoped list / `secrets.delete` scoped delete | API — **`folder delete`'s embedded path has a real footgun, see §8 Finding S4** |
| `secret move` | move.go:35-38 | R | `POST /secrets/{id}/move` | write scoped | CLIENT-ONLY |
| `secret copy` | copy.go:30-33 | R | `POST /secrets/{id}/copy` | read (source, route) + write (target, in-handler) | CLIENT-ONLY |
| `secret copy-environment` | copy_environment.go:33-36 | R | `POST /projects/{id}/environments/{envId}/copy-secrets` | write (project) + read (source env) dual-gate | CLIENT-ONLY — dual-gate exists specifically to stop write-only exfiltration; having only one caller (no embedded path) removes the risk of under-replicating that logic |
| `secret templates {list,get,create,delete}` | templates.go | R | `GET/POST/DELETE /secret-templates[/{id}]` | read/write | CLIENT-ONLY |
| `secret deps {list,add,rm,impact}` | dependencies.go:222-228 | R | `GET/POST/DELETE /secrets/{id}/dependencies[/{depId}]`, `GET .../impact` | read/write scoped | CLIENT-ONLY |
| `secret access` / `access-log` | access.go:43-76 | R | `GET /secrets/{id}/access`, `GET /secrets/{id}/access-log` | read scoped | CLIENT-ONLY |
| `secret {set,get,clear}-schedule` | schedule.go:158-164 | R | `PUT/GET/DELETE /secrets/{id}/schedule` | `secrets.manage` scoped | CLIENT-ONLY |
| `secret suspend` / `resume` | suspend.go:29-49 | R | `POST /secrets/{id}/suspend`, `.../resume` | write scoped | CLIENT-ONLY — distinct from the `/system` CAS route `TransitionSecretStatusProxy`; unaffected by that route's fate |
| `secret trash` / `restore` | recycle.go:38-72 | R | `GET /projects/{id}/secrets/deleted`, `POST /secrets/{id}/restore` | read (project) / write (deleted-secret scope) | CLIENT-ONLY |
| `secret classify` | classify.go:33-36 | R | `PATCH /secrets/{id}/classification` | write scoped | CLIENT-ONLY |
| `secret export` | export.go:88-202 | R | `GET /projects`, `GET .../environments`, `GET /secrets?...`, `GET /secrets/{id}?include_value` ×N | read scoped | API — N+1 per-secret fetch is *more* audit fidelity than a hypothetical bulk endpoint, not less |
| `secret import` (file mode) | import.go:119-270 | R | `GET /projects`, `GET .../environments`, `POST /secrets` ×N | in-handler | API |
| `secret import --source {vault,aws,azure,gcp}` | import.go | R (never touches Keyorix for the fetch half) | n/a | n/a | **CLIENT-ONLY** — reads live cloud/Vault credentials locally, never sends them to Keyorix; in tension with ADR-108's "SBOM lists no cloud SDKs" goal unless deliberately dropped or shipped as a plugin — flagged as an open scope question |
| `secret render` | render.go:41-137 | R | *should* use `POST /projects/{id}/secrets/render` (exists, unused) | `secrets.read` (project) | API, **wrong route today — see §8 Finding S2** |
| `secret explain` | explain.go:143 | L (no calls at all) | n/a | n/a | CLIENT-ONLY — static lookup table |
| `secret expiring` | expiring.go:27-63 | R | `GET /projects/{id}/secrets/expiring` | read (project) | API |
| `secret orphaned` | orphaned.go:23-55 | R | `GET /projects/{id}/secrets/orphaned` | read (project) | API |
| `secret name-conformance` | name_conformance.go:36-101 | R | `GET /projects/{id}/secrets/name-conformance`, `GET /secrets/name-conformance` (org-wide) | read (project) / **`audit.read`** (org-wide) | API — org-wide help text wrongly says `system.read` (doc-only mismatch, §8 Finding S7) |
| `secret quota-report` | quota.go:21-50 | R | `GET /secrets/quota-report` | `audit.read` | API — help text wrongly says `secrets.read` (doc-only, §8 Finding S7) |
| `secret ownership-history` | ownership_history.go:24-57 | R | `GET /secrets/{id}/ownership-history` | read scoped | API |
| `secret reassign-owner` | reassign_owner.go:18-44 | R | `POST /projects/{id}/secrets/reassign-owner` | **`roles.assign`** (project) | API — help text wrongly claims `secrets.write` + per-secret auth; actual is one project-level `roles.assign` check gating the whole bulk op (§8 Finding S7) |
| `secret rotate` | rotate.go:43-89 | R | lookup step broken (same bug as `render`), `POST /secrets/{id}/rotate` correct | write scoped | API, **broken lookup — §8 Finding S2, the write-path (worse) half** |
| `secret rotation-simulate` | rotation_dryrun.go:38-72 | R | `POST /secrets/{id}/rotation/simulate` | read scoped | API |
| `secret auto-rotate` | autorotate.go:21-56 | R | `PATCH /secrets/{id}/auto-rotate` | write scoped | API |
| `secret bulk-rotate` | bulk_rotate.go:34-145 | R | `POST /projects/{id}/secrets/bulk-rotate` | write (project) | API |
| `secret bulk-rename` | bulk_rename.go:42-119 | R | `POST /projects/{id}/secrets/bulk-rename` | write (project) | API |
| `secret bulk-delete` | bulk_delete.go:38-201 | **F** | `POST /projects/{id}/secrets/bulk-delete` | delete (project) | API (remote) / **DROP** (embedded — see §8 Finding S5) |
| `secret scan` | scan.go:19-159 | L | n/a | n/a | CLIENT-ONLY — local filesystem/git regex scan for hardcoded secrets |
| `secret score` | score.go:29-180 | **F** | `GET /secrets/{id}/risk` | read scoped | API (remote) / **DROP** (embedded — no authz, possibly no audit either, §8 Finding S6) |
| `secret blast-radius` | blast_radius.go:34-68 | R | `GET /secrets/{id}/blast-radius` | read scoped | API |
| `secret fix` | fix.go:47-212 | L | n/a | n/a | CLIENT-ONLY — local source-tree rewriter |
| `secret cert` | certificate.go:31-47 | R | `GET /secrets/{id}/certificate` | read scoped | API |
| `secret audit` | audit.go:27-60 | R | `GET /secrets/{id}/audit` | read scoped | API |

**Systemic findings for this group** (detailed in §8): embedded-mode `create`/`update`/`delete`
perform no authorization check and emit no `secret.created`/`secret.updated`/`secret.deleted` audit
event at all (`internal/core/secrets.go`'s `CreateSecret`/`UpdateSecret`/`DeleteSecret` call no
`LogSecret*` helper — that only happens in the HTTP handler layer). Embedded-mode `get --show-value`/
`get --ref` never audit a value read either, though max-reads enforcement is unaffected (it lives in
`GetSecretValue` itself, called from both paths). `secret folder delete`'s embedded path has no
type-guard the REST route has and can silently delete a SECRET instead of a folder. `bulk-delete` and
`score` are the only two `secret` commands with a genuine embedded/local-DB fallback (not a
`/system`-proxy one) — see Findings S5/S6.

### 2.2 `project`, `group`, `invite`, `share`, `user` — 51 leaf subcommands

All five packages follow the ADR-107 `NewRemoteClient()`-first pattern almost without exception.
ADR-107 itself directly traced 5 commands (`user update`, `group create/update/delete`, `invite
revoke`) and found their embedded/`RemoteStorage` fallback is real but narrow, and — for the 3 group
commands — **already authority-equivalent** to the REST path (the `/system` proxy's
`requireGroupsProxyUsersWrite` re-derives the identical `users.write` check, closed independently of
ADR-107 during the F5/F6 campaign). This inventory re-verified all 5 and extended the same trace to
every other command in these packages.

**`project` (14 leaf + 1 container):** moved to `cli/cmd/project.go` (PR 6, #2049).

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `project create` | create.go:19-83 | F | `POST /projects` | `secrets.write` (global) | API |
| `project list` | list.go:12-60 | F | `GET /projects` | `secrets.read` (global) | API |
| `project use <name>` | use.go:14-76 | F (validate only) | `GET /projects` (validate) | — | CLIENT-ONLY — mutation is writing `active_project` to `~/.keyorix/cli.yaml` |
| `project current` | current.go:13-32 | L | n/a | n/a | CLIENT-ONLY |
| `project describe [name]` | describe.go:16-136 | F | `GET /projects`, `GET .../environments` | read scoped | API — **GAP**: remote branch never prints a secret count the embedded branch does; no missing route, `describe` just never calls `/projects/{id}/stats` |
| `project stats <name>` | stats.go:22-208 | F | `GET /projects/{id}/stats` | read scoped | API |
| `project hygiene <id>` | hygiene.go:21-59 | **R** (no fallback at all, unlike siblings) | `GET /projects/{id}/hygiene[?unused_days=&expiring_days=&stale_days=]` | read scoped | API — CLI never sends the optional query overrides the route supports (CLI-completeness gap, not a REST gap); also the one `project` command with no local-mode path even though `core.ProjectHygieneSummary` exists and could back one |
| `project health <name>` | health.go:32-177 | F | `GET /projects/{id}/health[?limit=]` | read scoped | API |
| `project environments <id>` (legacy alias) | environments.go:13-50 | F | same as `env list` | read scoped | **DROP candidate** — confirmed backward-compat alias (`project.go:34-35`'s own comment), functionally identical to `env list`; flag for a product decision on whether to keep, not a unilateral drop |
| `project env list` | env.go:29-64 | F | `GET /projects/{id}/environments` | read scoped | API |
| `project env create` | env.go:71-113 | F | `POST /projects/{id}/environments` | write scoped | API |
| `project env delete <id>` | env.go:120-213 | F | `DELETE /environments/{id}` | delete, scoped from the env's own project | API — CLI's optional `--project` cross-check is a client-only safety net with no server equivalent; REST's own scope resolution is correct either way, but the CLI safety net must be ported forward deliberately, not assumed |
| `project env clone <src> <dst>` | env_clone.go:17-122 | F | `POST /projects/{id}/environments/{envId}/clone` | write (project) + read (source env), dual-gate | API (remote) / functionally broken (embedded) — **§8 Finding S8**: hardcoded `"cli"`/`0` actor, fails closed on the resulting zero-ID permission check, but misreports the 100%-failure as "already exist in destination" |

**`group` (8 leaf):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `group create` | create.go:18-68 | F | `POST /groups` | `users.write` | API — ADR-107-confirmed, authority-equivalent via `/system` proxy's `requireGroupsProxyUsersWrite` |
| `group get` | get.go:15-51 | F | `GET /groups/{id}` | `users.read` | API |
| `group update` | update.go:20-67 | F | `PUT /groups/{id}` | `users.write` | API — ADR-107-confirmed |
| `group delete` | delete.go:21-95 | F | `DELETE /groups/{id}` | `users.write` | API — ADR-107-confirmed |
| `group list` | list.go:11-52 | F | `GET /groups` | `users.read` | API |
| `group members` | members.go:15-74 | F | `GET /groups/{id}/members` | `users.read` | API |
| `group add-member` | add-member.go:19-58 | F | `POST /groups/{id}/members` | `roles.assign` | API |
| `group remove-member` | remove-member.go:19-60 | F | `DELETE /groups/{id}/members/{userId}` | `roles.assign` | API |

**`invite` (4 leaf):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `invite send` | send.go:38-95 | F | `POST /projects/{id}/invitations` | `roles.assign` (project) | API — embedded's `requireInviteAuthority` matches exactly |
| `invite list` | list.go:34-86 | F | `GET /projects/{id}/invitations` | `users.read` (project) | API — **embedded's `requireInviteAuthority` checks `roles.assign`, STRICTER than the route's actual `users.read`** — fails closed, not open, but a real parity gap (§8 Finding S9) |
| `invite revoke` | revoke.go:34-71 | F | `DELETE /projects/{id}/invitations/{invitationId}` | `roles.assign` (project) | API — the exact command ADR-107 traced; re-confirmed accurate |
| `invite resend` | resend.go:25-70 | F | `POST /projects/{id}/invitations/{invitationId}/resend` | `roles.assign` (project) | API |

**`share` (7 leaf):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `share create` | create.go:40-114 | F | `POST /secrets/{id}/share` | write scoped + in-core live-owner check | API |
| `share list` | list.go:29-88 | F | `GET /secrets/{id}/shares` | read scoped + in-handler owner-only re-check | API — **embedded path uses the non-authorization-checked core variant** (documented in-repo as accepted, `list.go:41-55` "cli-connect-007") — §8 Finding S10 |
| `share update` | update.go:37-92 | F | `PUT /shares/{id}` | write scoped (share) + in-core live-owner check | API — minor CLI output-parity gap only (remote branch prints 3 of ~8 available fields) |
| `share revoke` | revoke.go:27-51 | F | `DELETE /shares/{id}` | write scoped (share) + in-core live-owner check | API |
| `share self-remove` | self_remove.go:15-35 | **R**, no fallback | `DELETE /secrets/{id}/self-share` | self-service (RecipientID == caller) | API — the one command in the package already at ADR-107's target shape; structurally distinct from `revoke` (own-share removal vs. owner-driven revocation of anyone's share) |
| `share shared-secrets [--user-id]` | shared_secrets.go:29-91 | F | `GET /shared-secrets` (self, `--user-id` omitted) or `GET /users/{id}/shared-secrets` (arbitrary target, admin-scoped) | `secrets.read` (global) + S1 admin-rank ceiling for a target other than the caller | API — **GAP CLOSED**: `GET /api/v1/users/{id}/shared-secrets` added (`ListSharedSecretsForUser`, `server/http/handlers/shares_query.go`); `--user-id` is now optional (defaults to the caller) and routes through the new admin-scoped endpoint in remote mode instead of being silently ignored. Embedded mode's own `--user-id` still has no actor check (§8 Finding S10's embedded-mode half stands, unchanged) |
| `share group-shares` | group_shares.go:32-77 | F | `GET /groups/{id}/shares` | `secrets.read` (global) + in-core `#G10` actor-authorization check | API — the strongest-parity command in the package; `#G10` already closed the enumeration gap here specifically |

**`user` (11 leaf):** moved to `cli/cmd/user.go` (PR 6, #2049).

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `user create` | create.go:56-229 | F | `POST /users` (all 3 credential modes) | `users.write` | API — plain-password local branch has NO `--by`/authority check at all (weaker even than its own sibling modes) |
| `user get` | get.go:59-112 | F | `GET /users/{id}`, `GET /users/by-email` | `users.read` (group-level) | API |
| `user update` | update.go:54-103 | F | `PUT /users/{id}` | `users.write` (group-level only — **no admin-rank ceiling**, §8 Finding S1) | API — **local mode has NO `--by`/authority check at all, unlike every other lifecycle command in this package (§8 Finding S1b)**; ADR-107's "2 round trips" claim undercounts (3, for the deactivating case) and its "different response struct" claim is confirmed with a sharper edge: the local response is never confirmed by the server at all |
| `user delete` | delete.go:35-107 | F | `DELETE /users/{id}` | `users.delete` | API — local `--by` actually attributes the audit actor; remote `--by` is silently ignored (real UX divergence, not a security gap — remote's real-session attribution is the more correct one) |
| `user list` | list.go:30-85 | F | `GET /users` | `users.read` (group-level) | API |
| `user suspend` | lifecycle.go:34-53 | F | `POST /users/{id}/suspend` | `users.write` | API |
| `user reactivate` | lifecycle.go:55-74 | F | `POST /users/{id}/reactivate` | `users.write` | API |
| `user force-password-reset` | lifecycle.go:76-96 | F | `POST /users/{id}/require-password-reset` | `users.write` | API |
| `user revoke-sessions` | lifecycle.go:103-138 | F | `POST /users/{id}/revoke-sessions` | `users.write` | API |
| `user resend-setup-link` | setup_link.go:24-52 | F | `POST /users/{id}/resend-setup-link` | `users.write` | API — checked explicitly against ADR-108 B2 and found unrelated: normal `users.write`-gated onboarding redelivery, not a "everyone locked out" recovery mechanism |
| `user suspend-inactive` | inactivity_suspend.go:38-97 | F | `POST /admin/jobs/suspend-inactive-users` | **`system.write`** (deployment-wide sweep, not a resource-scoped `users.*` permission) | API — the most symmetric command in the package: both paths call the identical `core.SuspendInactiveUsers`, actor `0` on both |

### 2.3 `machine`, `pat`, `rbac`, `auth` — 35 leaf subcommands

**`machine` (14 leaf, ADR-023/030/031):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `machine create` | create.go:34-74 | F | `POST /projects/{id}/machine-identities` | `roles.assign` (project) | API |
| `machine list` | list.go:24-36 | F | `GET /projects/{id}/machine-identities` | `users.read` (project) | API |
| `machine describe <ref>` | describe.go:24-50 | F | (fetches list, filters client-side; no dedicated by-ref GET route used) | `users.read` (project) | API |
| `machine suspend/reactivate/revoke <ref>` | lifecycle.go:17-93 | F | `PUT /projects/{id}/machine-identities/{machineId}` (action body) | `roles.assign` (project) | API |
| `machine binding add/list/rm` | binding.go:33-205 | F | `POST/GET/DELETE .../oidc-bindings[/{id}]` | `roles.assign`/`users.read` scoped | API |
| `machine token issue/list/revoke` | token.go:44-268 | F | `POST/GET/DELETE .../tokens[/{id}]` | `roles.assign`/`users.read` scoped, `BlockWhenImpersonating` on issue | API |
| `machine token-hygiene` | token_hygiene.go:25-56 | R | `GET /machine-token-hygiene` | `audit.read` | API |
| `machine audit` | audit.go:22-52 | R | `GET /machine-identities/audit` (+`.csv`) | `audit.read` | API |

Every `machine` command with a fallback correctly threads `common.ResolveActorID()` through to the
core call — this package is the positive counter-example to rbac's D1 finding below.

**`pat` (6 leaf, self-service — no local mode anywhere in the package):**

| Command | File:line | REST route | Permission | Class |
|---|---|---|---|---|
| `pat create` | pat.go:72-115 | `POST /auth/tokens` | self-service, `BlockWhenImpersonating` | API |
| `pat list` | pat.go:118-145 | `GET /auth/tokens` | self-service | API |
| `pat revoke <id>` | pat.go:159-178 | `DELETE /auth/tokens/{id}` | self-service | API |
| `pat list-expired` | expired.go:21-48 | `GET /auth/tokens/expired` | self-service | API |
| `pat cleanup-expired` | expired.go:50-64 | `DELETE /auth/tokens/expired` | self-service | API |
| `pat hygiene` | hygiene.go:33-57 | `GET /pat-hygiene` | `audit.read` | API |

**`rbac` (11 leaf — dual-mode via `InitializeStorage()+core.NewKeyorixCore`, not `InitializeCoreService()`):**

| Command | File:line | REST route | Permission | Class |
|---|---|---|---|---|
| `rbac assign-role` | assign_role.go:51-88 | `POST /user-roles` | `roles.assign` scoped to body target | API — **§8 Finding S11 (D1)**: embedded path's core method takes no actor param at all |
| `rbac remove-role` | remove_role.go:40-67 | `DELETE /user-roles` (body-carrying) | same | API — same Finding S11 |
| `rbac list-roles` | list_roles.go:18-47 | `GET /roles` | `roles.read` | API |
| `rbac list-user-roles --user` | list_user_roles.go:26-57 | `GET /users/{id}/roles` | `roles.read` | API |
| `rbac list-permissions --user` | list_permissions.go:26-57 | no single by-email route; assembled client-side from `GET /roles/{id}/permissions` per role | `roles.read` per call | API — not a GAP, matches the documented "no single endpoint, composed client-side" shape |
| `rbac check-permission --user --permission` | check_permission.go:33-66 | same composition | same | API |
| `rbac assign-role-to-group` / `remove-role-from-group` | group_role.go:41-139 | `POST/DELETE /groups/{id}/roles[/{roleId}]` | `roles.assign` | API — embedded path correctly threads `common.ResolveActorID()`, contrast with Finding S11 |
| `rbac list-group-roles` | group_role.go:187+ | `GET /groups/{id}/roles` | `roles.read` | API |
| `rbac audit-logs` | audit_logs.go:29-97 | `GET /audit/rbac-logs` | `audit.read` (group) | API — embedded path calls a `RemoteStorage`-backed core method whose live/stub status wasn't found in the reachability census's explicit lists (unresolved, flag for Phase 0) |
| `rbac export-matrix` | export_matrix.go:34+ | `GET /rbac/permission-matrix` | `roles.read` | API — explicitly relocated OUT of `/system` (#G79) specifically to fix this CLI command's 404 |

**`auth` (4 leaf):**

| Command | File:line | Calls today | REST route | Class |
|---|---|---|---|---|
| `auth login [--server]` | auth.go:74-169 | Writes `storage.type: remote`+credentials to **`./keyorix.yaml`** (CWD-relative, `#G73`/`#G74`-flagged untrusted); verifies via `GET /auth/profile` first | `GET /auth/profile` (self-service) | CLIENT-ONLY |
| `auth logout` | auth.go:194-217 | Local config edit only, does NOT revoke the server-side PAT | none | CLIENT-ONLY — §8 Finding S12 (informational) |
| `auth status` | auth.go:219-254 | Local config read only, no live verification | none | CLIENT-ONLY |
| `auth mfa stepup --code` | mfa_stepup.go:40-68 | R | `POST /auth/mfa/stepup` | API |

### 2.4 `encryption`, `breakglass`, `migrate`, `dynamic-secret`, `rotation` — 35 leaf subcommands

**`encryption` (15 leaf) — the flagship ADMIN-B3 cluster.** Every command operates on local key
files and/or a directly-opened DB (`storage.OpenGormDB`); none has ever had a `NewRemoteClient()`
branch, and every write-path command explicitly refuses `cfg.Storage.Type == "remote"`. The only
related REST route in the whole router is the read-only `GET /system/encryption-config`
(config dump, not an operation) — **GAP is total for this package by design**, not an oversight;
this is exactly ADR-108 §B.3's "full KEK re-encryption sweep" family.

| Command | File:line | Local mechanism | Server-stop required? | Class |
|---|---|---|---|---|
| `encryption init` | encryption.go:174-201 | shared key lock | No | ADMIN-B3 |
| `encryption status` | encryption.go:203-238 | shared key lock, read-only | No | ADMIN-B3 |
| `encryption rotate` | encryption.go:279-358 | exclusive key lock + raw `*gorm.DB`, full re-encryption sweep (ADR-010) | **Yes**, enforced twice (CLI gate + inside `RotateDEKWithSweep`) | ADMIN-B3 — the literal textbook case |
| `encryption upgrade-aad` | encryption.go:413-460 | shared lock (brief per-table write lock only) | No | ADMIN-B3 |
| `encryption validate` | encryption.go:471-510 | shared lock, read-only | No | ADMIN-B3 (borderline B1/diagnose) |
| `encryption fix-perms` | encryption.go:512-545 | shared lock | No | ADMIN-B3 (borderline B1/repair) |
| `encryption shamir-split` | shamir_split.go:29-134 | pure crypto + local file write, **no config/DB import at all** | N/A | **not ADMIN — genuinely CLIENT-ONLY**, the one command in this package that structurally satisfies ADR-108's thin-CLI constraint today, unmodified |
| `encryption rotate-kek` | rotate_kek.go:64-149 | exclusive lock, no DB access at all | **Yes**, doc comment states it plainly, double-enforced | ADMIN-B3 |
| `encryption migrate-provider` | migrate_provider.go:348-428 | exclusive lock enforced INSIDE `RewrapDEKWithProvider`, not at the CLI's own call site | **Yes** | ADMIN-B3 — flag for whoever builds the admin subcommand: a thin wrapper calling a different re-wrap path would silently lose this |
| `encryption migrate-provider cleanup` | migrate_provider.go:153-183 | no lock at all — operates only on backup files | Not obviously, **not fully determined** (a narrow TOCTOU against a concurrent migrate-provider run is theoretically possible, not confirmed reachable) | ADMIN-B3 |
| `encryption auth-encryption status/enable/migrate/validate` | auth_encryption.go, auth_encryption_migrate.go, auth_encryption_validate.go | shared lock, direct `*gorm.DB` | No | ADMIN-B3 |
| `encryption auth-encryption rotate` | auth_encryption.go:173-198 | **no lock call at all**, unlike its 4 siblings in the same file | Unverified — §8 Finding S13 | ADMIN-B3 |

**`breakglass` (3 leaf) — already fully conforms, zero migration work. Moved to `cli/cmd/breakglass.go`
in PR 1 (split/pr1-cli-dynamic-rotation-breakglass, §7).**

| Command | File:line | REST route | Permission | Class |
|---|---|---|---|---|
| `break-glass activate` | breakglass.go:52-78 | `POST /projects/{id}/break-glass` | un-gated by design (justification + audit + auto-expiry instead), `BlockWhenImpersonating` | API |
| `break-glass list` | breakglass.go:80-110 | `GET /projects/{id}/break-glass` | `roles.read` (project) for all; a project member for their own (BREAKGLASS-OWN-1) | API |
| `break-glass revoke` | breakglass.go:112-132 | `POST /projects/{id}/break-glass/{activationId}/revoke` | `roles.assign` (project) | API |

Not ADR-108 §B.2 ("recover-admin") — break-glass is project-scoped, self-service, and requires an
already-authenticated session; B2 is specifically for when no admin session exists at all.

**`migrate` (1 leaf):**

| Command | File:line | REST route | Class |
|---|---|---|---|
| `migrate user-to-machine <username>` | user_to_machine.go:48-100 | `POST /projects/{id}/machine-identities/migrate-from-user` (route exists, matching both permissions the local path hand-derives: `roles.assign`@project + `users.write`@global) | Currently local-DB-only by deliberate design (refuses if remote is configured) — **should collapse to API**, not a genuine ADMIN item; nothing is lost by dropping the local path and adding a remote-calling branch instead |

**`dynamic-secret` (9 leaf) — fully conforms, zero migration work. Moved to `cli/cmd/dynamicsecret.go`
in PR 1 (split/pr1-cli-dynamic-rotation-breakglass, §7).** All 9 commands (`get-config`,
`classify`, `list`, `issue`, `leases`, `renew`, `revoke`, `revoke-all`, `create`) are pure REST, no
fallback: `POST/GET/PATCH` under `/dynamic-secrets/{configs,leases}*`, `secrets.read`/`secrets.write`
scoped to the config/lease's project+environment. These routes were real and already called by the
old CLI's remote mode, but entirely undocumented in `openapi.yaml` until PR 1 — see §7's PR 1
closure note.

**`rotation` (7 leaf) — fully conforms, zero migration work. Moved to `cli/cmd/rotation.go` in PR 1
(split/pr1-cli-dynamic-rotation-breakglass, §7).** `list`/`create`/`show`/`delete` under
`/rotation-policies*`, `plan [project-id | --all-projects]` under `/projects/{id}/rotation-plan` or
global `/rotation-plan`, `order <project-id>` under `/projects/{id}/rotation-order` — all
`secrets.read`/`secrets.write` scoped as expected; `--all-projects` deliberately steps up to a
GLOBAL `secrets.read` grant (documented, not a gap). **Correction (verified against the old CLI's
actual source, not asserted): `status` does NOT call `/rotation-policies/status` as this line
previously said — it calls `GET /rotation-policies/evaluate`** (`internal/cli/rotation/rotation.go`'s
real `statusCmd`), listing only overdue/approaching secrets, never "ok" ones. See §7's PR 1 closure
note for the full writeup; `cli/cmd/rotation.go`'s new port preserves this exact (if misleadingly
named) behavior.

### 2.5 `audit`, `anomalies`, `notification`, `accessreview`, `request` — 37 leaf subcommands

**Moved to `cli/cmd/{audit,anomalies,notification,accessreview,request}.go` (PR 7, #2056).**

**`audit` (6 leaf) — REST-only, `audit.read`-gated (except checkpoint/migrate which need
`system.write`):**

| Command | File:line | REST route | Permission | Class |
|---|---|---|---|---|
| `audit verify` | audit.go:135-195 | `GET /audit/verify` | `audit.read` | API today — **but does NOT satisfy ADR-108 §B4** (see §6 GAP-1: it asks the live server to verify its own chain, the opposite of B4's "without trusting the running server" premise) |
| `audit export` | audit.go:227-274 | `GET /audit/export` (paginated) | `audit.read` | API |
| `audit checkpoint` | audit.go:332-351 | `POST /audit/checkpoint` | `system.write` | API |
| `audit migrate-chain-encoding` | audit.go:382-413 | `POST /audit/migrate-chain-encoding` | `system.write` | API |
| `audit logs` | audit.go:455-475 | `GET /audit/logs` | `audit.read` | API |
| `audit search` | audit.go:579-599 | `GET /audit/search` | `audit.read` | API |

**`anomalies` (8 leaf across anomalies.go/config.go/escalation.go), all REST-only:**

`anomalies list`/`acknowledge` → `GET/POST /audit/anomalies[/{id}/acknowledge]` (`system.read`/
`system.write`). `anomaly config get/set` → `GET/PUT /admin/anomaly-config` (`system.read`/
`system.write` — registered outside the `/system` proxy group; naming coincidence only).
`anomaly escalation list/create/delete/run` → `GET/POST/DELETE /alert-escalation-policies[/{id}]`,
`POST /admin/jobs/run-alert-escalation` — all `system.write`, including the two GETs (a router
design choice, not a CLI/REST mismatch). All API, 0 GAPs.

**`notification channel` (5 leaf), REST-only:**

`list`/`add`/`get`(list+filter)/`update`(resolve+PUT)/`delete`(resolve+DELETE) →
`GET/POST/PUT/DELETE /notification-channels[/{id}]`, `system.write`. All API. Aside: REST also
exposes `PUT/GET /notification-channels/{id}/retry-policy` with no CLI subcommand — feature gap,
not a REST gap.

**`accessreview` (3 + 5 campaign leaf), REST-only:**

`access-review [--project-id]`/`revoke`/`attest` → `GET/POST /projects/{id}/access-review[/revoke|/attest]`,
`roles.read`/`roles.assign` (project). `access-review campaign open/list/show/decide/close` →
`/projects/{id}/access-review/campaigns*`, same permission split. All API, 0 GAPs. The `/system`
proxy's separate `access-review-campaigns*` family is confirmed dead-to-CLI (zero matches anywhere
in `internal/cli/`).

**`request` (8 top-level + 3 template leaf) — the one genuinely dual-mode package in this cluster:**

| Command | File:line | REST route | Class |
|---|---|---|---|
| `request access` | access.go | `POST /projects/{id}/access-requests` (self-service, no permission middleware) | API — local `--user` can file "as" an arbitrary user; remote is hard-wired to the caller's own session (§8 Finding S14) |
| `request list` | list.go | `GET /projects/{id}/access-requests` | API — local `requireListAuthority` matches the route's `roles.assign` exactly, no skip |
| `request withdraw` | withdraw.go | `POST /projects/{id}/access-requests/{id}/withdraw` (self-service) | API — same `--user` shape as `access` |
| `request review` (role-scoped) | review.go | `PUT /projects/{id}/access-requests/{id}` | API |
| `request review` (secret-scoped approve/reject) | review.go | `PUT /secret-access-requests/{requestId}` | API — **GAP-1 closed** |
| `request secret-access` | secret_access.go | `POST /secret-access-requests` | API — **GAP-1 closed** |
| `request bulk-approve` | bulk.go:47-52 | `POST /access-requests/bulk-approve` (exists) | API, **but the CLI never calls it** — §8 Finding S15 (GAP-F-BULK) |
| `request bulk-reject` | bulk.go:105-110 | `POST /access-requests/bulk-reject` (exists) | API, same bug — Finding S15 |
| `request rejection-templates list/add` | bulk.go:189-248 | `GET/POST /rejection-reason-templates` | API — correctly checks `NewRemoteClient()` |
| `request rejection-templates delete` | bulk.go:294-299 | `DELETE /rejection-reason-templates/{id}` (exists) | API, same bug as bulk-approve/reject — Finding S15 |

Every core method reached by `request`'s local-mode paths that has a REST sibling was checked for a
skipped authority/audit check — none found; local mode re-implements the identical `Authorize(...)`
call the router middleware would do, with in-code comments explaining why. The one systemic pattern
here (§8, noted once) is that 4 local-mode commands (`access`, `withdraw`, `list --by`,
`review --by`) resolve identity from a caller-supplied email flag with no session to verify it against
— already documented in-repo as accepted for embedded mode, and structurally eliminated once ADR-108
removes local mode.

### 2.6 `risk`, `sod`, `legalhold`, `compliance`, `hygiene`, `trust` — 24 leaf subcommands

**Moved to `cli/cmd/{risk,sod,legalhold,hygiene,trust,compliance}.go` (PR 8, #2060).** The
`compliance export`/`verify` round-trip bug (§6 GAP-4, GAP-2 below) was explicitly deferred, not
fixed, in that PR: ported as-is (conservative default) since it is a transport-only porting PR and
the existing behavior is degraded-but-safe (an unsigned pack is labeled `signed: false`, never
silently claimed authentic). Fixing the signing-path bug itself is a separate, non-transport change.

**None of these 23 non-`trust` commands has a local-mode or `/system`-proxy fallback at all** — every
one is `common.NewRemoteClient()`-only, confirmed by grep (zero matches for
`InitializeCoreService|core.KeyorixCore|RemoteStorage` anywhere in these 5 packages). This means
Finding-5's "does local mode skip an authz/audit check" question is structurally inapplicable here —
there is only one code path per command. All routes below already exist; 0 hard GAPs except the
compliance evidence round-trip bug (§8, Finding S16 / §6 GAP-2).

**`risk` (4 leaf):** `list[--all]`/`add`/`approve`/`revoke` → `/risk-exceptions*`, `audit.read`
(list) / `system.write` (mutations). Doc-comment inaccuracy only: CLI help says list needs
`system.read`, actual gate is `audit.read`.

**`sod` (4 leaf):** `policy list/create/delete`, `violations` → `/sod/policies*`, `/sod/violations`;
`system.read`/`system.write`/`audit.read` respectively. Same doc-comment class of inaccuracy on
`violations` (says `system.read`, actual `audit.read`).

**`legalhold` (3 leaf):** `status`/`place`/`lift` → `/legal-hold*`, `audit.read` (status) /
`system.write` (mutations). CLI's `--yes` confirm on `lift` is the one genuinely CLIENT-ONLY piece;
server-side authorization is independent of it. Same doc-inaccuracy class on `status`.

**`hygiene` (1 leaf):** `hygiene [--unused-days --expiring-days --stale-days]` →
`GET /hygiene[?...]`, `audit.read`. CLI's own printed `--help` text (not just a source comment) is
wrong here — says `system.read`.

**`compliance` (10 leaf):** `report`/`export`/`controls[.csv]`/`verify`/`digest[/send]`/
`permission-changes`/`permission-baseline[.csv]`/`inventory`/`credential-trends`/
`rotation-by-backend` — all `audit.read`-gated REST routes matching 1:1, this package's own doc
comments are the one correct-permission-doc set found across the whole G cluster. **The one real
functional GAP in this whole cluster**: `compliance export` followed by `compliance verify` can
**never produce VALID for a genuinely untampered pack** — `export` calls `GenerateComplianceEvidence`
(never signs, never assigns a canonical filename, never writes `.sig`), while the ONLY function that
ever produces a valid `(signature, filename)` pair, `ExportComplianceEvidence`, has exactly one
caller in the whole repo: the scheduled job in `server/main.go`. `verify`'s own POST body has no
`filename` field at all, though `VerifyComplianceEvidence`'s request struct declares one specifically
for AUD-009 filename-bound signatures. See §6 GAP-2 and §8 Finding S16.

**`trust` (1 leaf):** `trust keygen` — pure local ed25519 keypair generation via `internal/trust`,
no server call of any kind (confirmed: no `internal/cli/common`, no `net/http` import in the file).
CLIENT-ONLY, by design (ADR-062 — the private key must never touch the server).

### 2.7 `bundle`, `license`, `usage`, `billing`, `system`, `status`, `connect`, `config`, `run` — 23 leaf subcommands

**Correction to this batch's own framing**: `internal/cli/connect/` is CLI connection-mode state
(embedded↔client switch, `~/.keyorix/cli.yaml`), **not** cloud-connector (AWS/Azure/GCP backend)
registration — that lives under `internal/connect`, a different, non-CLI package out of scope here.

**`bundle`/`license`** (ADR-062/065, air-gap update tooling) — purely offline, no server call
anywhere in either package.

| Command | What it does | Class |
|---|---|---|
| `bundle build` | Signs a release tarball with an offline key | N/A/out of scope — Keyorix-internal release tooling |
| `bundle verify` | Verifies against the embedded pinned trust registry | CLIENT-ONLY, deliberately offline |
| `bundle import` | Same verify + license-gated (`airgap_updates`) local staging | CLIENT-ONLY |
| `license issue` | Mints a signed license token (Keyorix-internal signing key) | N/A/out of scope |
| `license install` | Writes a token file the server reads at its own startup | CLIENT-ONLY / undecided-admin — closer to B3 in spirit but not enumerated in ADR-108; flag as an open question |
| `license status` | Evaluates a local token file offline | CLIENT-ONLY as implemented; **GAP** if operators need the *running server's* actual license state remotely — no such route exists (`system info`'s `Features` map is feature-flags, not licensee/plan/expiry detail) |

**`usage`/`billing`** — one subcommand each, genuinely dual-mode:

| Command | REST route | Permission | Class |
|---|---|---|---|
| `usage show` | `GET /admin/usage[?days=&project_id=]` | `audit.read` | API — **embedded mode calls `core.GetUsageReport` directly with literally no `userID` parameter on the method signature — nothing for a permission check to even thread through** (§8 Finding S17) |
| `billing report` | `GET /admin/billing/report[?from=&to=&project_id=]` | `audit.read` | API — same shape, same missing-signature-parameter root cause (§8 Finding S17); the license-feature gate itself IS shared (lives inside `core.GenerateBillingReport`), only the `audit.read` authorization is skipped |

**`system info`/`role-expiry-check`/`token-expiry-check` moved to `cli/cmd/system.go` (PR 10,
#2062).** `system init`/`audit`/`validate` remain ADMIN-B1, not ported to the thin CLI (see below).
`status` (remote branch) was ported in an earlier PR, already on `origin/main`. `bundle`/`license`
were deliberately left out of PR 10 — porting `verify`/`import`/`install`/`status` hits a real
architecture question (`internal/bundle`/`internal/license` contain security-critical
verification/evaluation logic that `cli/internal/depguard` currently forbids importing; duplicating
it locally would violate this repo's own "prefer the machine-checked over the asserted" principle).
Flagged to the coordinator in #2062's PR body with three options; not yet decided.

**`system` (6 leaf)** — a genuine mix, half ADMIN-B1, half already-correct API:

| Command | What it does | Class |
|---|---|---|
| `system init` (no `--server`) | Writes `keyorix.yaml`, creates DEK/salt dirs, creates an empty DB file (`O_EXCL`), touches a log file — pure host-filesystem setup, no server interaction | **ADMIN-B1** — literally provisions the files a server needs to start at all |
| `system init --server <url>` | `POST /system/init` (unauthenticated, bootstrap-token-gated, public-path listed) | API — already correct, needs only a module move |
| `system audit` | Local file-permission/ownership diagnostics on config + every key-material path | **ADMIN-B1** |
| `system validate` | `startup.ValidateStartup` — explicitly "the same validation that runs on system startup" | **ADMIN-B1** — the clearest literal match to B1's language of any command in this report |
| `system info` | `GET /system/info` | API, `system.read` |
| `system role-expiry-check` / `token-expiry-check` | `POST /admin/jobs/{role,token}-expiry-check` | API, `system.write` — a stale comment in `admin_jobs.go` claims these are nested under `/system`; verified by brace-matching they are NOT (the `/admin/jobs` group opens at router.go:2205, well after `/system` closes at :2078) — the CLI code is correct, only the handler's own comment is wrong |

**`status`** — branches on FOUR config states, not simple remote-vs-embedded. Remote branch
(`GET /health`, unauthenticated) is **API**, already correct. The `storage.type: remote`-in-config
and local/sqlite branches both go through `InitializeCoreService()`+`HealthCheck` — **DROP** under
ADR-108 Decision A (no local DB mode; "is my local SQLite file reachable" is meaningless to a
thin, DB-less CLI). **Version-skew relevance**: `status` reads literally nothing from `/health`'s
response body today (`rc.GetRaw` result is discarded entirely) — see §5.

**`connect`/`disconnect`/`connect status`** — CLIENT-ONLY, all three; writes/reads
`~/.keyorix/cli.yaml`, calls only already-existing `/auth/login` and `/health`. Already hardened
(anti-SSRF redirect refusal, cleartext-endpoint refusal, credentials never on argv). Dead code found
while reading this package's config backing: `CLIConfig.Connections[]` and its 4 methods
(`AddConnection`/`RemoveConnection`/`GetConnection`/`GetDefaultConnection`) have zero callers
anywhere outside their own definitions and tests — **DROP**, a whole unused "saved connections"
schema.

A second, separate piece of dead code sits one level up from any command package:
`internal/cli/modes.go`'s `NewCLI()`/`CLI`/`CLIMode` (the `EmbeddedMode`/`ClientMode`
auto-detecting dispatcher, `initEmbeddedMode`/`initClientMode`) has **zero production callers** —
`rg -n "NewCLI\(\)"` across `internal/cli` matches only `main_test.go`/`modes_s23_test.go`/
`modes_s24_test.go`. Every real command instead uses the per-file `common.NewRemoteClient()`/
`common.InitializeCoreService()` pattern documented throughout §2. **DROP** — this whole
mode-dispatch abstraction was superseded by the per-command pattern and never wired into
`rootCmd`/`Execute()` (`internal/cli/main.go`) at all; removing it is a pure deletion, not a
migration.

**`config`** (`keyorix.yaml`, distinct from `connect`'s `~/.keyorix/cli.yaml`) — `status`/
`set-remote`/`use-local`/`test-connection`: **DROP the whole group.** `set-remote`/`use-local`
configure exactly the `storage.type` mechanism ADR-108 Decision A/C removes outright; `status`/
`test-connection` exist only to inspect/exercise that state and become vestigial once it's gone.

**`run`** — traced ADR-107's flagged "second idiom" (`common.ResolveRemote()` called directly
instead of `common.NewRemoteClient()`) fully: `NewRemoteClient()` is *implemented as*
`ResolveRemote()` + `newHardenedRemoteClient()`; `run` calls `ResolveRemote()` directly only to
override the token half for `--token`, then builds its client via
`NewRemoteClientWithCredentials`, which shares the identical hardened `http.Client`. **Not a
distinct bypass** — confirmed, not assumed. Remote path (4 existing routes: `/projects`,
`/projects/{id}/environments`, `/secrets`, `/secrets/{id}?include_value=true`) is **API**, already
correct. Embedded/local path is **DROP** — and dropping it is a security fix, not just cleanup: see
§8 Finding S18, the sharpest finding in this batch.

---

## 3. `/system` route caller census

`server/http/router.go:1126` registers the `/system` route group (`r.Route("/system", ...)`),
gated by `RequirePermission(permSystemWrite)` at `router.go:1127`, closing at `router.go:2078`
(verified by brace-depth matching, not assumed). **Current count: 151 route registrations**
(`rg -c '\.(Get|Post|Put|Patch|Delete)\('` restricted to lines 1126–2078, re-run during final
review — corrects an earlier draft of this section, which undercounted at 133; the resource-family
table below sums to the earlier 133 figure and has not been re-derived line-by-line against the
corrected count, so treat its per-family numbers as illustrative of the route mix, not as an
exhaustive partition of all 151). ADR-102's own snapshot ("148") remains a reasonable prior count;
the small drift from 148 to 151 is expected route churn since ADR-102 was written, not a
discrepancy worth chasing further. It is the server-to-server proxy tier originally built for the
ADR-049 downstream-node-relay topology and implements `storage.Storage` for `RemoteStorage`, the
CLI's client-mode Go type.

### Architectural finding: no non-CLI caller can reach `/system` today, and none ever could

Two independent facts, both verified directly (not assumed):

1. **No server process can construct a `RemoteStorage` client.** `internal/config/config.go`'s
   `validateRemoteStorageNotServer` unconditionally rejects `storage.type: remote` for any server
   process (ADR-083, Accepted) — no hub/spoke/replica/relay topology can exist that would give a
   *different Keyorix server* a reason to call `/system`.
2. **No other component calls `/system` over raw HTTP either.** `web/src/services/system.ts` calls
   `/api/v1/system/info`, `/system/metrics`, `/system/auth-config`, `/system/encryption-config` —
   all four are explicitly registered *outside* the `/system` proxy group (router.go:421-430,
   comment: "Deliberately NOT inside the `/system` route group below... these are human-facing
   reads"). Grep for `/system` across `web/src` found no other match. `cmd/keyorix-k8s-sync` and
   `operator/`: zero matches for `/api/v1/system` or `/system/`. `cmd/keyorix-mcp`: one match, an
   unrelated code comment, not a caller. No `sdk/`-named directory exists in the repo.

**Conclusion: every one of the 151 `/system` routes has exactly one possible caller category — the
CLI, in client mode, on the narrow fallback path where its `NewRemoteClient()`-first /
`InitializeCoreService()`-under-`RemoteStorage`-fallback pattern (ADR-107) actually falls through to
the fallback.** There is no "other caller: web UI / SDK / k8s-sync / mcp / operator" bucket for this
route group — confirmed empty by grep, not merely unclaimed.

### Within the CLI-only-reachable set: live vs. dead, per the existing reachability registry

`internal/storage/store/remote_reachability_registry_test.go` (the G80 158-method classification
pass, ADR-087) already carries an exhaustive per-method reachability verdict for every
*structurally-stub* `RemoteStorage` method — this report reuses that registry as the authoritative
caller-census evidence rather than re-deriving it by hand:

- **190 entries `reachabilityDead`** — the reaching core method is called only from `server/http`,
  `server/grpc`, or `server/main.go` (server-only, foreclosed by ADR-083), or has zero caller
  anywhere. Strongest Phase 6 deletion candidates.
- **16 entries `reachabilityLive`** — a real CLI command reaches this stub today, unguarded by the
  `NewRemoteClient`/`ResolveRemote`/`IsClientMode` idiom family: `AddPasswordHistory`,
  `CountSecretReadsBySecretIDs`, `CreateSecretAccessLog`, `GetBillingReport`,
  `GetProjectUsageStats`, `GetUserGroupRoleIDsAt`, `GetUserRoleIDsAt`, `ListAccessRequestsByIDs`,
  `ListAllUserRoleGrants`, `ListInactiveUsers`, `ListLiveSecretNamesByProject`, `ListSecretACLs`,
  `ListSecretAccessLogs`, `ListSessionTokenHashesForUser`, `RoleSetHasPermission`, `WithTransaction`.
  These are real, currently-broken (hard stub) features under `storage.type: remote` — exactly the
  set that must get a working human-facing REST equivalent before their CLI fallback can be
  deleted, per ADR-107's own Phase 2 framing. `GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`/
  `RoleSetHasPermission` are additionally covered by ADR-086's separate carve-out (the
  `core.Authorize` direct-entry-point path) — intentionally kept, not an oversight.
- **5 entries `reachabilityUnresolved`** — `AssignPermissionToRole`, `GetMachineRoleScopes`,
  `GetUserGroupPermissions`, `GetUserRoleIDsExact`, `GetUserRoleScopes`. Not independently
  re-verified to the same depth; Phase 0 of ADR-107's migration should resolve these first.
- **Working (non-stub) proxy files are outside this registry by design** — `remote_sod.go`,
  `remote_invitations.go`, `remote_memberships.go`, `remote_rotation_policies.go` etc. implement
  real HTTP proxying, so never entered `actualRemoteUnsupportedStubs`. Reachable only on the same
  narrow fallback edge case ADR-107 already characterized for `user update`/`group
  create/update/delete`/`invite revoke` — real, but rare, not a second caller category.

### Full route enumeration

The 133 routes group into these resource families (handler prefix, route count, resource area):

| Resource family | Route count | Representative handler(s) |
|---|---|---|
| Access requests / access-review campaigns | 12 | `CreateAccessRequestProxy`, `ListAccessReviewCampaignsProxy`, `GetLatestClosedAccessReviewCampaignProxy` |
| Machine identities / credentials / OIDC bindings | 24 | `CreateMachineIdentityProxy`, `TransitionMachineIdentityStateProxy`, `CreateMachineIdentityCredentialProxy`, `CreateOIDCBindingProxy` |
| RBAC (role/permission grants, group role assignments) | 9 | `AssignRoleWithExpiryProxy`, `RemoveGlobalAdminRoleGuardedProxy`, `ListProjectRoleAssignmentsProxy` |
| Setup tokens / login attempts / SSO state / WebAuthn / MFA | 20 | `CreateSetupTokenProxy`, `RecordLoginAttemptProxy`, `CreateSSOLoginStateProxy`, `ListWebAuthnCredentialsProxy`, `GetMFASecretProxy` |
| Groups / project memberships | 11 | `AddGroupMemberProxy`, `RestoreGroupProxy`, `CreateMembershipProxy`, `TransitionMembershipProxy` |
| Dynamic secrets (configs + leases) | 7 | `ListDynamicSecretConfigsProxy`, `ListDynamicSecretLeasesProxy` |
| Break-glass / legal hold / risk exceptions / SoD policies | 15 | `GetBreakGlassActivationProxy`, `UpdateLegalHoldProxy`, `ApproveRiskExceptionProxy`, `CreateSoDPolicyProxy` |
| Secrets (dependency graph, status transitions, including-deleted) | 5 | `CreateSecretDependencyExclusiveProxy`, `TransitionSecretStatusProxy`, `GetSecretIncludingDeletedProxy` |
| Users (active-state transitions, PAT/session bulk revoke, group lookup) | 6 | `UpdateUserIfActiveStateMatchesProxy`, `RevokeAllPersonalAccessTokensForUserProxy`, `DeleteSessionsForUserExceptProxy` |
| Retention sweeps / shares / notifications / audit ingest / access-activity | 24 | `DeleteExpiredRoleGrantsProxy`, `ListSharesByOwnerProxy`, `CreateNotificationProxy`, `IngestAuditEventProxy`, `LastUserSecretReadActivityProxy` |

(Full 133-row path+handler table available in the inventory working notes; grouped above by
resource family for readability — every route in every family above is CLI-only-reachable per the
architectural finding, none has a confirmed non-CLI caller.)

### What this means for Phase 6

Every route this report's per-command-group sections classify as **API** (has a working
human-facing REST equivalent already) is a Phase-6 deletion candidate the moment ADR-107 Phase 1
removes its CLI command's `InitializeCoreService()` fallback — no new REST work needed. Every route
this report flags as a **GAP** (the `reachabilityLive` list above, or a command whose only path is
the raw-proxy one with no REST sibling) is ADR-107 Phase 2 scope: a new/extended REST capability
must land *before* that command's fallback can be deleted.

---

## 4. CLI-side state today

**Three independent, overlapping remote-target/config mechanisms exist today, not one, with a fixed
but undocumented precedence order** (`common.ResolveRemote()`, `internal/cli/common/remote_client.go:57-108`):

1. **Env vars** `KEYORIX_SERVER`/`KEYORIX_TOKEN` — highest priority, no file involved.
2. **`~/.keyorix/cli.yaml`** (`$XDG_CONFIG_HOME/keyorix/cli.yaml`, falling back through
   `./keyorix-cli.yaml`) — written by `keyorix connect`, read by
   `internal/cli/config/cli_config.go`'s `CLIConfig` (`Mode: "embedded"|"client"`,
   `Client.Endpoint`, `Client.Auth.APIKey`, `ActiveProject`, plus a `Connections[]` list that has
   **zero callers anywhere in the CLI outside its own definition and tests** — confirmed dead code,
   see §2.7). Written via `securefiles.SecureWriteFile(..., 0600)`, `O_NOFOLLOW`-hardened.
3. **`./keyorix.yaml`** (CWD-relative, written by `keyorix config set-remote` or `keyorix auth
   login --server`) — the exact same config format the *server itself* reads. Explicitly flagged
   in-code (`#G73`/`#G74`, `remote_client.go:37-47`, `config.go:240-248`) as untrusted/
   attacker-plantable, since it resolves from the current working directory regardless of
   `KEYORIX_CONFIG_PATH` — both `auth login` and `ResolveRemote()` print an explicit warning when
   a security-relevant value is sourced from it.

**Token storage**: neither mechanism uses an OS keychain (Keychain/Credential Manager/Secret
Service) anywhere in the codebase. Both files store the API key/token in **plaintext YAML**, at file
mode **0600** with `O_NOFOLLOW` anti-symlink protection — real OS-level permission hardening, but
not keychain integration. This is a genuine open gap: today's plaintext-file model is a defensible
bar for a server-side root-owned config file, but a materially weaker one for a small,
widely-distributed client binary meant to run on individual operators' laptops.

**Auth per mode**:
- **Embedded/local mode**: no authentication layer at all. `common.InitializeCoreService()` opens
  storage directly; every mutation is audit-stamped with a *self-asserted*, unverified actor ID
  from `KEYORIX_CLI_ACTOR` (`common.ResolveActorID()`, defaults to `0` if unset) — the literal
  mechanism ADR-108 names as bypassing "the API's authorization, audit and rate limits."
- **Client mode (REST)**: a long-lived, non-expiring API key/PAT sent as `Authorization: Bearer
  <token>` on every request. `auth login` verifies the key against `GET /auth/profile`
  (self-service, unpermissioned) before persisting it — a bad/mistyped key/URL is caught at login
  time. **No refresh flow exists anywhere** — the PAT is the credential itself, not a short-lived
  session token with a refresh grant; revocation is `keyorix auth logout` (clears local config
  only — does **not** revoke the server-side PAT, see §8 Finding S12) or server-side
  `DELETE /auth/tokens/{id}`.
- **Client mode (raw proxy / `RemoteStorage`)**: same bearer-token transport, through the `/system`
  route group — the narrow fallback path §3 documents.

**Hardening already present** on the REST transport (`remote_client.go`): anti-SSRF redirect
refusal, split connect/idle timeouts, `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` support, a 10MB
response-size cap, and an HTTPS/loopback-only warning for cleartext bearer-token transmission. This
is already close to what a thin, REST-only CLI module needs — it does not need to be rebuilt, only
relocated.

**What the thin CLI needs instead**: collapse to **one** credential-storage mechanism (the
`~/.keyorix/cli.yaml`-style, XDG-aware, 0600, symlink-hardened one should absorb what `auth
login`/`./keyorix.yaml` does today) — the CWD-planted-file attack surface disappears entirely once
the thin CLI has no reason to ever read the server's own `keyorix.yaml`. No embedded/local mode at
all (ADR-108 Decision A), so the `KEYORIX_CLI_ACTOR` self-assertion and its audit-attribution gap
disappear structurally. OS keychain integration and a token-refresh story are both explicitly
**not** decided by ADR-108 today — flag as product decisions needed before or during Phase 2, not
silently inherited.

---

## 5. Version skew: what exists today

**Nothing exists today.** Grepped `server/http/router.go`, `server/http/handlers/system.go`,
`internal/cli/common`, `internal/cli/status`, `internal/cli/system` for `api.?version`,
`x-api-version`, `minimum.?cli`, `min.?cli.?version`, `x-keyorix-version`, `ServerVersion`
(case-insensitive) — **zero matches, anywhere.**

The closest existing artefact: `GET /api/v1/system/info` (`system.read`-gated) returns a `Version`
field sourced from `internal/version`'s build-time value — but this is the server's **binary
release version** (e.g. `v0.92.1`), not a separate **API version** number, and carries no
minimum-CLI-version field. It also requires a prior successful login (`system.read`), which is
circular for the exact "is my CLI compatible with this server before I try to authenticate" check
ADR-108's tiered version-skew model needs.

The unauthenticated `GET /health` endpoint — the one route a thin CLI can always reach before any
credential exchange — **deliberately omits version/commit by explicit design**
(`server/http/handlers/health.go:18-20`: "disclosing the exact build aids CVE targeting... the
precise version is available on the `system.read`-gated `/api/v1/system/info` instead"). `keyorix
status`'s remote branch calls `GET /health` today and **discards the response body entirely** —
`rc.GetRaw(ctx, "/health")`'s result is checked only for a transport error, never parsed
(`internal/cli/status/status.go:189`).

**GAP**: ADR-108's tiered version-skew rule (same major = allowed with a warning if older, clear
"server too old" if the CLI is newer than a route the server has; different major or below the
server's stated minimum = refused) has no server-side field to read today, authenticated or not,
and no CLI code path that would read one even if it existed. Closing this needs: (a) a new,
deliberately narrow field on `/health` (or a new unauthenticated `/api/v1/version`-style endpoint)
carrying `api_version` + `minimum_cli_version` — a bare semantic version is much lower-signal than
the full build/commit `health.go` already declines to expose, so this is a distinct disclosure
decision, not a reversal of that one; and (b) new CLI code to compare it against the CLI's own
compiled-in version and warn/refuse per the tiered rule. Neither exists today. This is
infrastructure every future thin-CLI request should be able to check, so it belongs early in the
PR sequence (§7, PR 0) — before the bulk of command migration, not woven into any single command's
own PR.

---

## 6. Top 5 GAPs by user impact

1. **CLOSED.** ~~Secret-scoped access-request approval has no REST route at all.~~ Andrei decided:
   keep the feature, build the routes. `POST/GET /api/v1/secret-access-requests`,
   `GET/PUT /api/v1/secret-access-requests/{requestId}`, and
   `POST /api/v1/secret-access-requests/{requestId}/withdraw` now back
   `RequestSecretAccess`/`ApproveSecretAccessRequest`/`RejectSecretAccessRequest`/
   `WithdrawAccessRequest`/`GetSecretAccessRequest` (`internal/core/classification_gate.go`,
   `server/http/handlers/secret_access_requests.go`). `request secret-access` and the secret-scoped
   branch of `request review --action approve`/`reject` now use these routes when a remote client is
   configured (`internal/cli/request/secret_access.go`, `review.go`); local mode is unchanged pending
   Phase 5. No remaining blocker for the Phase 3 `request`/`accessreview` PR on this point.
2. **B4 (offline, independent-of-the-running-server audit-chain verification) doesn't exist in any
   form.** `audit verify` is 100% REST and asks the live server to verify its own chain — the
   opposite of what regulated customers need this for. This is new `keyorix-server admin` work,
   not a reclassification.
3. **No version-skew infrastructure exists anywhere** (§5) — blocks every future CLI/server
   release from advertising compatibility safely. This blocks ADR-108's own stated tiered-skew
   decision from being enforceable on day one of the split, not just a nice-to-have.
4. **`compliance export`/`compliance verify` cannot round-trip successfully today for a genuinely
   untampered evidence pack** — `export` never signs or assigns the canonical filename `verify`
   needs, and `verify`'s own request never carries a `filename` field despite the server's
   AUD-009 filename-binding requiring one. A compliance operator running exactly the documented
   `export` → `verify` workflow gets a false "invalid" result today, with no code path to ever get
   `VALID`. Independent of the split, but the split's migration work is a natural forcing function
   to fix it (or decide the CLI needs a different route entirely) rather than porting the broken
   pair forward unchanged.
5. **GAP-F-BULK: `request bulk-approve`, `bulk-reject`, and `rejection-templates delete` silently
   hit the local embedded core instead of the connected remote server**, even though a matching
   REST route exists for all three and their sibling commands in the same file correctly check
   `NewRemoteClient()` first. Today, on `main`, an operator with `keyorix connect`-configured
   remote access who runs any of these three commands gets local/embedded behavior instead —
   inconsistent with every other command in the package, and it blocks a straight lift-to-thin-CLI
   since the thin CLI has no local-mode fallback to (accidentally) fall into. This is the highest
   user-impact GAP that is purely a bug fix, not new capability — recommend fixing before or as
   part of the `request` package's migration PR, independent of any ADR decision.

(One more real gap, lower individual user impact but structural: OS-keychain-vs-plaintext
credential storage — §4. `share shared-secrets --user-id`'s missing arbitrary-target REST route —
§2.2 — is now closed: `GET /api/v1/users/{id}/shared-secrets`, admin-rank-ceiling-gated.)

---

## 7. Phase 3 PR breakdown

Proposed order, smallest-safe-first, per ADR-108's own "Order of work" §2 ("Move commands group by
group: secrets, projects, users, then the rest" — adapted here to sequence by risk and by
dependency on gap-closing work, not strictly alphabetically).

**PR 0 — thin CLI module skeleton + version-skew infrastructure (prerequisite for everything else).**
New Go module, own `go.mod`, dependency-guard CI job that fails the build if the module imports
`internal/core`/`internal/storage`/`internal/config` server code or any cloud SDK. Add the
`api_version`/`minimum_cli_version` field(s) (§5) to `/health` or a new endpoint, plus CLI-side
comparison/warn/refuse logic. Depends on: a product decision on the OS-keychain-vs-plaintext
question (§4) landing in this PR's config-storage design, even if the decision is "keep plaintext
for now, revisit later." No command migration yet. Size: medium (new module scaffolding + CI +
one small new server endpoint). Tests: dependency-guard CI test (a forbidden import fails the
build); a version-skew unit test matrix (same-major-older/newer, different-major, below-minimum).

**Closed by PR split/pr0-cli-module (2026-09-23).** `cli/` (module
`github.com/keyorixhq/keyorix/cli`), excluded from the root `go.work` and gated by its own
`cli` CI job, matching `operator/`'s existing precedent. `cli/internal/depguard`'s test walks
the module's real dependency graph (`go list -deps`, not a source grep) and fails on any
`internal/core`/`internal/storage`/`internal/config`/`server/` or cloud-SDK import;
red/green-proven on this PR (a forbidden `internal/core` import pulled in the full AWS/Azure/
GCP SDK surface transitively — see the PR description for the exact failure output). The
server side adds `GET /api/v1/version` (`server/http/handlers/version.go`), unauthenticated
like `/health`, returning only `api_version` (`internal/version.APIVersion`, starts at 1) and
`minimum_cli_version` (new `Config.MinimumCLIVersion`, empty by default) — deliberately never
the build version/commit, matching `/health`'s own disclosure rationale; a handler test
asserts exactly those two fields and nothing else. `cli/internal/skew.Check` implements the
tiered rule (§ above this PR's own reasoning, in the package doc comment): `minimum_cli_version`
(when set) is a hard floor checked by both major-line and numeric comparison; independently,
the CLI's compiled `TargetAPIVersion` vs. the server's `api_version` produces a soft
same-major-older/newer warning, with the true "server too old for this command" case surfacing
per-request when a specific route actually 404s. Credential storage: single mechanism (§4's
"one mechanism only" decision), a 0600 plaintext file at `os.UserConfigDir()/keyorix/
credentials.yaml` (`cli/internal/credstore`) behind a `Store` interface that refuses to `Load`
on any permission wider than 0600 or through a symlink — an OS-keychain implementation is a
later option behind the same interface, not decided here. The HTTP client
(`cli/internal/apiclient`) is generated (`oapi-codegen`, `cli/Makefile`'s `client` target) from
a filtered copy of `server/http/handlers/openapi.yaml` (`cli/internal/apiclient/gen/
filterspec.go`'s `keptPaths`, extended by each future Phase 3 PR) rather than the full spec —
narrows the generated surface to what's actually wired (`/health`, `/api/v1/version`,
`/auth/login`, `/api/v1/auth/profile`) while still being real generation from the canonical
spec, not a hand-maintained subset. Commands: `keyorix-next version`, `login`, `status` — all
three exercised against a real running server (SQLite, no mocks) as part of this PR's manual
verification, not just unit tests. Follow-up needed outside this PR: add `cli` to the
repository's required-status-checks branch-protection list (a repo setting, not a file this PR
can change).

**PR 1 — `dynamic-secret`, `rotation`, `breakglass` (9+7+3 = 19 commands).** Zero GAPs, zero
security findings, already 100% REST with no fallback anywhere — the lowest-risk group, proves the
new module's plumbing end-to-end before anything harder. Size: small. Tests: golden-output
comparison against the current CLI's remote-mode output for every subcommand (should be byte-for-byte
identical, since the new module calls the same routes the same way).

**Closed by PR split/pr1-cli-dynamic-rotation-breakglass (2026-09-24, stacked on split/pr0-cli-module
and split/pr2-cli-pat-auth-machine).** All 19 commands ported into `cli/cmd/` (`dynamicsecret.go`,
`rotation.go`, `breakglass.go`) against the generated `apiclient`, REST-only, no new local mode.

**OpenAPI spec gap found and closed:** the `dynamic-secrets/*` routes (8 operations backing all 9
`dynamic-secret` commands) were entirely undocumented in `openapi.yaml` — not just schema-less, the
paths didn't exist in the spec at all — despite being real, working, `Zero-GAPs` routes already
called by the old CLI's remote mode. `getProjectRotationOrder`/`getProjectRotationPlan`/
`getDeploymentRotationPlan` (backing `rotation order`/`plan`) were the same. Authored full
operations (request + response schemas, new `components/schemas` entries: `DynamicSecretConfig`,
`DynamicSecretLease`, `RotationPolicy`, `RotationPolicyEvaluation`, `RotationOrder`, `RotationPlan`,
`DeploymentRotationPlan`) rather than terse description-only stubs, per CLAUDE.md's "generate it"
preference. This mechanically converted 18 operations from "pending" to "enforced" in
`contracttest`'s ADR-074 registry (`registry.go`'s `pendingRegistry` → `exercisingTests`,
`checks_test.go`'s `TestEnforcedSetMatchesADR074` pinned baseline) — closed with new, self-contained
happy-path tests in `server/http/handlers/openapi_contract_pr1_test.go`.

**This table's own route mapping for `rotation status` was wrong, and the code is the source of
truth, not this doc:** the entry above (and §2.4 below, before this update) said `status` maps to
`GET /rotation-policies/status` (`getRotationStatus`). It doesn't — `internal/cli/rotation/
rotation.go`'s real `statusCmd` calls `GET /rotation-policies/evaluate` (`evaluateRotationPolicies`)
and only lists overdue/approaching secrets, never "ok" ones. Confirmed directly against the old
CLI's source before porting, per this ADR's own "verify it yourself" instruction; `getRotationStatus`
stays in `pendingRegistry`, unused by any of the 19 commands. `cli/cmd/rotation.go`'s `runRotStatus`
doc comment and `cli/cmd/rotation_test.go`'s `TestRunRotStatus_CallsEvaluateNotStatus` pin this down
as a regression guard.

**Two real, pre-existing server bugs found by this port, not by unit tests — by running both CLIs
against the same real, live `keyorix-server` process** (`scripts/cli-parity-check.sh`, extended for
this PR's 19 commands; a unit test using `httptest.ResponseRecorder` cannot catch either one, because
the recorder doesn't enforce net/http's real header-ordering semantics):
1. `RotationPolicyHandler.Create` and `CatalogHandler.ActivateBreakGlass` both called
   `w.WriteHeader(http.StatusCreated)` *before* `sendSuccess`'s `Header().Set("Content-Type", ...)` —
   net/http silently drops any header set after the first `WriteHeader`/`Write` call, so both 201
   responses left the server with **no Content-Type header at all**. The generated CLI client
   gates JSON decoding on Content-Type, so `CreateRotationPolicyWithResponse`/
   `ActivateBreakGlassWithResponse` got a nil typed response despite a genuinely successful,
   JSON-bodied 201 — invisible to any consumer that doesn't check Content-Type, which is most of
   them, but a real defect regardless. Fixed by routing both through the already-existing,
   correctly-ordered `sendCreated` helper (`helpers.go`) instead of the manual
   `WriteHeader`+`sendSuccess` sequence. **Not fixed as part of this PR** (out of scope — found by
   `grep -rn "w.WriteHeader(http.StatusCreated)"` across `server/http/handlers/`, ~25 other call
   sites match the same shape): every other 201 path in the handler package should be audited for
   the identical bug in a dedicated follow-up, since the pattern is clearly not unique to these two.
2. `models.RotationPolicy` (the GORM model, `internal/storage/models/models.go`) carried no `json:`
   tags on most fields, so its real wire format was PascalCase (`ID`, `ProjectID`, `IntervalDays`, ...)
   — Go's `encoding/json` case-insensitive decode fallback matches `"ID"`~`"id"` but does **not**
   match `"ProjectID"`~`"project_id"` (an extra underscore isn't a case difference). The OLD CLI's
   `policyView` struct uses snake_case tags against this exact model and had therefore always
   decoded every multi-word field (interval, alert threshold, active flag, created-by, the
   project/environment number in `target`) as its zero value — `rotation show`/`list`/`create`
   had been silently displaying `0`/`false`/empty for these fields in production. Confirmed live via
   `scripts/cli-parity-check.sh` against a real server (a synthetic `httptest` fixture with
   hand-chosen field casing would never have exposed this).

   **Follow-up (same PR, separate commit): fixed at the source instead of documented as a
   PascalCase exception.** `models.RotationPolicy` now carries the correct, explicit snake_case
   `json:` tags directly (GORM's own column-naming strategy is derived from the Go field name, not
   from `json:` tags, so this changes only the wire format, not the schema); `openapi.yaml`'s
   `RotationPolicy` schema reverted to this spec's normal snake_case convention; the generated CLI
   client regenerated to match. This fixes the bug for every consumer of the model's JSON form, not
   only the new CLI — including the OLD CLI, whose `policyView` struct now decodes correctly too,
   confirmed by `internal/cli/rotation/rotation_policy_wire_regression_test.go`'s
   `TestOldCLIPolicyView_DecodesRealCreateResponse`/`DecodesRealGetResponse` (a real handler response
   decoded by the OLD CLI's own struct, red/green-verified: reverting the model's tags makes both
   tests fail on exactly the previously-zeroed fields). `scripts/cli-parity-check.sh`'s `rotation
   create`/`list`/`show` checks, previously carved out as "not literal parity" because the two CLIs
   necessarily disagreed, are now genuine byte-for-byte comparisons again like every other resource
   in that script — the divergence is gone, not just documented. `cli/cmd/rotation.go`'s `runRotList`
   was also switched from `cliout`'s tabwriter to the old CLI's exact fixed-width `Printf` format
   (a separate, pre-existing formatting divergence the byte-comparison surfaced, unrelated to
   casing), for full parity on that command too. The web frontend
   (`web/src/features/secrets/useRotationPolicies.ts`) already normalized both casings defensively
   before this fix and needed no change; `keyorix-sdks` (all four language SDKs) has no
   rotation-policy bindings at all yet, so nothing there was affected either.

Tests: unit tests per command (flag/argument validation + golden-output-shape assertions against a
fake `httptest.Server`, `cli/cmd/{dynamicsecret,rotation,breakglass}_test.go`); OpenAPI contract
tests (`server/http/handlers/openapi_contract_pr1_test.go`); and a full live-server run of
`scripts/cli-parity-check.sh` (old CLI vs. new CLI vs. a real `keyorix-server` process, SQLite-backed,
real HTTP) — 42/42 passing, run twice to confirm no flakiness, after fixing the two bugs above and
several script-only environment gaps (the SSRF guard needing `dynamic_secrets.allow_private_network_targets:
true` for the loopback DSN this script deliberately uses; `break_glass.enabled`/`emergency_role` needing
explicit config since it's opt-in and off by default; the admin bootstrap user needing an explicit
project-scoped role grant since `ActivateBreakGlass` requires real project membership, not just a
global role; and the admin's session token going stale immediately after that role grant, worked
around with a re-login immediately before each call that needs it — plausibly a "permissions
changed, invalidate this principal's other sessions" security measure, not root-caused further).

**PR 2 — `pat`, `auth` (mfa/login/logout/status), `machine` identities (6+4+14 = 24 commands).**
Zero GAPs. `auth login/logout/status`/`connect`/`config` need the credential-storage consolidation
decided in PR 0 — land that here for real (collapse to one config mechanism, drop `config
set-remote`/`use-local`/`test-connection` per §2.7, drop `connect disconnect`'s embedded-mode
meaning). Size: medium. Tests: same golden-output comparison; a dedicated regression test for the
credential-file consolidation (old `~/.keyorix/cli.yaml` + `./keyorix.yaml` precedence collapses
correctly to the new single mechanism, no credential silently dropped).

**Closed by PR split/pr2-cli-pat-auth-machine (2026-09-24, stacked on split/pr0-cli-module —
#2019 had not yet merged when this PR opened).** All 24 commands ported into `cli/cmd/` against
the generated `apiclient`, REST-only, no new local mode. `login`/`status` were already PR 0's;
this PR added `logout`, `mfa stepup`, `pat` (6 leaf), and `machine` (14 leaf: create/list/
describe/suspend/reactivate/revoke, `binding` add/list/rm, `token` issue/list/revoke,
token-hygiene, audit) as flat top-level commands, matching PR 0's convention of not nesting under
an `auth` group. `machine`/`pat` have no "active project" concept yet (that lands with the
`project` command group in a later PR per this table) — every command takes `--project` or
`KEYORIX_PROJECT` directly, no fallback.

**OpenAPI spec gap found and closed, not just filtered:** 13 of the 24 commands' REST operations
either had no 2xx response schema in `server/http/handlers/openapi.yaml` (`createPAT`,
`listPATs`, `createMachineIdentity`, `listMachineIdentities`, `issueMachineToken`,
`listMachineTokens`, `listProjects`) or did not exist in the spec at all (`listExpiredPATs`,
`bulkRevokeExpiredPATs`, `patHygiene`, `machineTokenHygiene`, `getMachineAuditReport`,
`mfaStepUp`, and the three OIDC-binding operations) despite being real, working, `Zero-GAPs`
routes reachable in `router.go` — filterspec.go's `run()` would have failed outright the moment
any of these was added to `keptPaths` without a matching spec entry. Authored full operations
(request + response schemas, 8 new `components/schemas` entries: `PATToken`,
`PATHygieneRow`, `MachineIdentity`, `MachineToken`, `MachineTokenHygieneRow`, `OIDCBinding`,
`MachineAuditRow`, `MachineAuditReport`) rather than terse description-only stubs, per
CLAUDE.md's "generate it" preference — a schema-less operation cannot produce a typed generated
accessor, which would have forced the CLI code back onto raw `json.Unmarshal`, the exact pattern
ADR-106/108 are moving away from. This mechanically converted 13 operations from "pending" to
"enforced" in `contracttest`'s ADR-074 registry (`registry.go`'s `pendingRegistry` →
`exercisingTests`, `checks_test.go`'s `TestEnforcedSetMatchesADR074` pinned baseline) — closed
with new, self-contained happy-path tests in `server/http/handlers/openapi_contract_pr2_test.go`,
not by grafting onto an existing test whose fixture/path might not actually reach a 2xx.
`bulkRevokeExpiredPATs` was reclassified to its real status code (204, `outOfScopeRegistry`) after
tracing the handler; the two other net-new schema-less operations (`deleteOIDCBinding`,
`mfaStepUp`) were added to `pendingRegistry`, matching the existing `removeMachineRole`/
`revokeMachineToken` precedent of a 200-with-message response with no schema yet.

Two real bugs the schema-authoring step itself caught (server/http/handlers/openapi.yaml, not
CLI-side): an unquoted comma inside a YAML flow-mapping description silently produced a spurious
"extra sibling field" that `contracttest`'s spec-load validation rejected outright (caught before
merge, not after); and `PATToken.scopes`/`allowed_cidrs` needed `nullable: true` -- the real
handler serializes a nil `[]string` as JSON `null`, which a non-nullable array schema rejects
(`kx_pat_...`/scope round-trip, caught by `TestContractPR2_CreatePAT` failing against the real
handler, not by hand-inspection).

Credential/config: no consolidation work was actually needed beyond what PR 0 already decided —
`login`/`status`/`logout`/`mfa` all use PR 0's single `credstore` file
(`os.UserConfigDir()/keyorix/credentials.yaml`); the new CLI never had `config set-remote`/
`use-local`/`test-connection`/`connect` to begin with, so there is nothing to drop. `logout` was
the one real gap: the old CLI's `auth logout` never told the server (§8 Finding S12); this one
calls `POST /auth/logout` first (`TestRunLogout_RevokesServerSideThenDeletesLocalCredentials`
asserts the server actually received the call, not just that the local file is gone — asserting
the return value alone would have passed even with the revocation call deleted, see CLAUDE.md's
"assert the effect, not the return value"), then deletes the local credential file regardless of
whether the server call succeeded (`TestRunLogout_StillDeletesLocalCredentialsWhenServerUnreachable`).
Migration helper (`cli/internal/migrate`): `login` detects a server URL from either pre-ADR-108
config file (`./keyorix.yaml`, `~/.keyorix/cli.yaml`/XDG) and offers it as a confirmable default
-- never auto-imports, and structurally cannot read a credential (`Candidate` has no field for
one); `./keyorix.yaml` takes precedence over `cli.yaml` per `internal/migrate`'s own doc comment
(most-recent-explicit-login wins), confirmed by `TestDetectOldServerURL_CWDConfigTakesPrecedence`
independently re-discovering the lower-precedence candidate once the higher one is removed (not
lost, not merged).

New shared package `cli/internal/cliout` (named to avoid the repo root `.gitignore`'s generic
`output/` build-artifact rule): `Table` (tabwriter wrapper) and `SanitizeForTerminal`
(control-character stripping for attacker-controlled free text -- mirrors the old CLI's
`internal/cli/common.SanitizeForTerminal`), for reuse by later Phase 3 PRs.

Verified: `go build`/`go vet`/`go test ./...` clean for both `cli` (depguard green -- no
forbidden import pulled in by any of this PR's additions) and the main module's
`server/http/handlers` + `.../contracttest` packages; `gosec -severity medium` and
`golangci-lint` both clean on `cli/`.

**PR 3 — `rbac`, `group`, `invite` (11+8+4 = 23 commands).** Zero hard GAPs. Requires an explicit
decision on Finding S11 (D1: `rbac assign-role`/`remove-role`'s embedded-mode actor-0 attribution —
moot once local mode is gone, but decide explicitly rather than silently drop) and Finding S9
(`invite list`'s stricter-than-REST local check — also moot, same reasoning). Size: medium.

**Closed by PR split/pr3-cli-rbac-group-invite (2026-09-24).** All 23 commands ported into
`cli/cmd/` against the generated `apiclient`, REST-only. Findings S11(D1) and S9 decided
explicitly, per this entry's own instruction, rather than silently dropped: both existed only on
the embedded (direct-DB) code path, and this module has no embedded mode at all (ADR-108 Decision
A) — there is no local authority check left to diverge from the real HTTP session's.

**OpenAPI spec gap found and closed, not just filtered**, mirroring PR 2's own precedent: 20
operations this PR wires either had no 2xx response schema in `server/http/handlers/openapi.yaml`
(`listGroups`, `createGroup`, `getGroup`, `updateGroup`, `getGroupMembers`, `addGroupMember`,
`getGroupRoles`, `assignRoleToGroup`, `listProjectInvitations`, `createProjectInvitation`,
`resendProjectInvitation`, `revokeProjectInvitation`, `listProjectEnvironments`, `listUsers`,
`getUserRolesForUser`, `listRoles`, `getRolePermissions`, `assignUserRole`, `listRBACAuditLogs`)
or did not exist in the spec at ALL (`getPermissionMatrix` — `GET /api/v1/rbac/permission-matrix`
was a real, routed, `roles.read`-gated endpoint with zero OpenAPI documentation, despite having
been deliberately relocated out of `/system` specifically to be reachable, #G79). Authored full
request/response schemas (12 new `components/schemas` entries: `Group`, `UserSummary`,
`GroupRoleGrant`, `RoleRef`, `Permission`, `RoleWithPermissions`, `Environment`,
`ProjectInvitation`, `ProvisionSetupResult`, `RBACAuditLogEntry`, `PermissionMatrixRow`) rather
than terse description-only stubs. Two of these (`Environment`, `ProjectInvitation`) document a
genuinely surprising real wire format: `internal/storage/models.Environment` and
`.ProjectInvitation` carry no `json:` tags at all, unlike every other model in that file, so the
server actually serializes them with bare capitalized Go field names (`ID`, `ProjectID`,
`CreatedAt`, ...) — not the snake_case this spec uses everywhere else. Verified by regenerating the
CLI client from the authored schema and confirming the emitted struct tags match what
`encoding/json` on the server side actually produces (not by hand-inspection). This mechanically
converted these 20 operations from "pending" to "enforced" in `contracttest`'s ADR-074 registry
(`registry.go`'s `pendingRegistry` → `exercisingTests`, `checks_test.go`'s
`TestEnforcedSetMatchesADR074` pinned baseline) — closed with new, self-contained happy-path tests
in `server/http/handlers/openapi_contract_pr3_test.go`, one per operation, not by grafting onto an
existing test whose fixture/path might not actually reach the intended status code.

One real, pre-existing spec bug the schema-authoring step caught (`server/http/handlers/
openapi.yaml`, not CLI-side, independent of the split): `DELETE /api/v1/groups/{id}/members/
{userId}` has always read an optional `project_id` query parameter in its real handler
(`groups_members.go`'s `RemoveGroupMember`) — the old CLI's `group remove-member --project` has
sent it since that command existed — but this spec never documented the parameter, so no client
generated from it could ever construct a request carrying it. Added the missing parameter, ported
`group remove-member`'s `--project` support unchanged, and added
`TestRunGroupRemoveMember_SendsProjectIDQueryParam` asserting the actual query string that reaches
the server (not just that the command returns success), so a future regression that silently drops
the parameter again fails loud.

Credential/config, shared output: no new work needed — this PR is a pure command-group port using
PR 0's `credstore` and `cliout` exactly as PR 2 already established; no new "active project"
concept (still deferred to the `project` command group, per this table).

Verified: `go build`/`go vet`/`go test ./...` clean for both `cli` (`depguard` green) and the main
module's `server/http/handlers` + `.../contracttest` packages; `gosec -severity medium` and
`golangci-lint` both clean on `cli/`.

**PR 4 — `secret` core CRUD + metadata (create/get/update/delete/list/versions/diff/folder +
the ~30 already-CLIENT-ONLY commands, ~40 commands).** **Hard prerequisite**: fix Finding S1 (the
`PUT /api/v1/users/{id}` admin-rank ceiling gap) is a `user` package concern but should land
*before or alongside* this PR since it's the single highest-severity finding in the whole report —
sequencing note, not a blocker specific to `secret`. This PR itself has no REST gaps. Size: large
(highest command count, highest scrutiny given it's the product's core surface). Tests: full
behavioral-parity suite (today's dual-mode CLI vs. new thin-CLI's remote-only output) for every
command, explicit regression tests for the 4 documented audit-skip findings (S-secret-1 through
S-secret-4 in §8) being *closed by deletion* (once local mode is gone, there's no path left to
regress) rather than fixed in place.

**Closed by PR split/pr4-cli-secret-core (2026-09-24, from fresh `origin/main` — independent of
split/pr3-cli-rbac-group-invite, does not stack on it).** ~40 commands ported into `cli/cmd/`:
core CRUD (create/get/update/delete/list), versions (list/rollback/diff, version comments
add/list/delete), metadata (tags get/set, description, classify), organize (move/copy/copy-
environment), ACL (list/grant/revoke), dependencies (list/add/remove/impact), access
(list/access-log), schedule (get/set/delete), lifecycle (suspend/resume/restore/list-deleted),
folder (list/create/delete), and secret templates (list/get/create/update/delete/apply) — all
REST-only against the generated `apiclient`, no local mode.

**OpenAPI spec gaps found and closed, not just filtered:** `createSecret`'s request schema never
documented `description`/`expiration`, even though the handler has accepted both since #1808 —
added both fields. ~25 routes existed in `router.go` (folder CRUD, secret templates, version
comments/diff, dependencies, access/access-log, schedule, organize, lifecycle,
`GET /secrets/by-name`, `GET /secrets/value`, `GET /projects/{id}/secrets/deleted`) with no
OpenAPI path entry at all; authored full request+response schemas for all of them (16 new
`components/schemas` entries: `Secret`, `SecretGetResult`, `SecretListEntry`, `SecretVersion`,
`SecretVersionDiffChange`, `SecretVersionDiffResult`, `SecretVersionComment`,
`SecretDependencyEdge`, `SecretDependencies`, `SecretImpactedSecret`, `SecretImpact`,
`SecretAccessor`, `SecretAccessLogEntry`, `SecretAccessSchedule`, `SecretTemplate`,
`DeletedSecretEntry`), per CLAUDE.md's "generate it" preference — matching PR 2's precedent of
full operations over description-only stubs. `SecretListEntry` hit the same oapi-codegen
field-collision PR 3 hit (`SecretWithSharingInfo` embeds `*SecretNode`, so `IsShared` is
promoted onto the same object as the model's own `is_shared` field, producing two Go fields
with the identical generated name `IsShared`); resolved the same way, dropping the unused
`is_shared` property and documenting the collision in the schema comment. This mechanically
moved 35 operations from `pendingRegistry`/unregistered to `exercisingTests` in `contracttest`'s
ADR-074 registry (`registry.go`, `checks_test.go`'s `TestEnforcedSetMatchesADR074` pinned
baseline) — 8 (`createSecret`, `getSecret`, `updateSecret`, `getSecretVersions`,
`grantSecretACL`, `revokeSecretACL`, `classifySecret`, `listSecrets`) backfilled schemas for
previously-schema-less existing routes, the other 27 are the brand-new routes above. Each is
closed with a new, self-contained happy-path test in
`server/http/handlers/openapi_contract_pr4_test.go`, not grafted onto an existing test. 5
operations (`deleteSecretVersionComment`, `removeSecretDependency`, `deleteSecretSchedule`,
`deleteFolder`, `deleteSecretTemplate`) are 204 No Content and landed in `outOfScopeRegistry`
instead. Two real schema gaps the contract tests themselves caught (not hand-inspection):
`DiffSecretVersions`' `acl_user_ids` and `changes` fields are both nil, not empty-array, when
there is nothing to report (no ACL grants; no tracked-field differences between the two
versions) — a non-nullable array schema rejected the real handler's actual JSON `null` output,
exactly the same class of gap PR 2's `PATToken.scopes` fix closed.

One real, deliberate behavior fix, not a faithful port: the old CLI's `secret diff`
`--project`/`--environment` flags sent them as non-numeric name filters to
`GET /secrets/by-name`, which actually requires numeric `project_id`/`environment_id` — a
pre-existing bug (the old CLI's by-name lookup would 400 whenever a diff needed the by-name
path). The new CLI's `secret diff` takes required numeric `--project`/`--environment` IDs
instead, matching the real route's actual requirements and every sibling command's convention;
documented in code rather than silently ported.

Security-critical test (per this PR's own explicit instruction): `cli/cmd/secret_test.go`'s
`TestNoSecretCommandLeaksTheCanaryValue` runs `create --value`/`update --value` with a
distinctive canary value and asserts it never appears on stdout or stderr — verified red→green
by planting a debug leak into `runSecretCreate`, confirming the test caught it, then reverting.
`TestSecretGet_ShowValueOnlyReachesStdout` and `TestSecretGet_DefaultHidesValue` cover the
`get`/`--show-value` value-hiding parity the old CLI has (value hidden by default,
`include_value` never sent unless `--show-value`, decrypted value only ever reaches stdout).
`TestWarnInsecureFlag_NeverPrintsTheValue` covers the shared `--value`-is-insecure warning path
that every mutating secret command with a `--value` flag reuses — it names the flag, never
prints the flag's value.

Verified: `go build`/`go vet`/`go test ./...` clean for both `cli` (depguard green) and the main
module's `server/http/handlers` + `.../contracttest` packages; `gosec -severity medium` and
`golangci-lint` both clean on `cli/`; `gosec` clean on `server/http/handlers`; `spectral lint`
zero errors on `openapi.yaml`; `scripts/check-closures.sh --self-test` green.

**PR 5 — `secret` bulk/rotation/export/import/scan/hygiene (~22 commands).** **Hard prerequisite,
must land first and independently, NOT gated on this program**: fix Finding S2 (the broken
`?environment=<name>` filter in `rotate`/`render` — a live correctness/security bug on `main`
today). File and fix this as its own PR before this group's migration PR opens, so the migration
doesn't carry the bug into the new module under a "matches old behavior" banner. `bulk-delete` and
`score`'s embedded paths are DROP (Findings S5/S6). Size: large.

**Prerequisite status: already closed.** Finding S2 landed on `main` in #2013
("fix(cli): scope secret render/rotate/score to project+environment (inventory #2012, S2)")
before this PR opened — `render.go` calls the purpose-built
`POST /projects/{id}/secrets/render`, and `rotate.go`'s `findExactSecretID` resolves the
environment name to a numeric ID first and scopes its lookup by both `project_id` and
`environment_id`, refusing to guess on an ambiguous match. Verified directly against this PR's
own fresh `origin/main` checkout before starting the migration, not assumed from the citation.

**Decision: `secret import --source {vault,aws,azure,gcp}` is moved out, not dropped.** This PR
ports `secret import` in file mode only (REST-only, no cloud SDKs) — matching ADR-108's "SBOM
lists no cloud SDKs" goal for the new thin CLI. The cloud/Vault-credential import modes stay on
the OLD CLI until a separate migration tool (working name `keyorix-migrate`: its own module and
binary, cloud SDKs allowed there since it never ships as part of the client surface, writes via
REST like everything else) replaces them. The Phase 5 deletion of the old CLI is gated on that
tool existing — Vault/cloud import is a real customer migration path, not a command to silently
lose. Decided 2026-09-24, not unilaterally — this is a scope call with SBOM/dependency-graph
consequences beyond this one PR.

**Closed by PR split/pr5-cli-secret-bulk (2026-09-24, from fresh `origin/main` — independent
of split/pr3-cli-rbac-group-invite and split/pr4-cli-secret-core, does not stack on either).**
21 commands ported into `cli/cmd/`: rotation (`rotate`, `rotation-simulate`, `auto-rotate`),
bulk (`bulk-rotate`, `bulk-rename`, `bulk-delete`), hygiene reports (`expiring`, `orphaned`,
`name-conformance`, `quota-report`, `ownership-history`, `reassign-owner`), risk/inspection
(`score`, `blast-radius`, `cert`, `audit`), `render`, `export`, `import` (file mode), and the
local-only tools `scan`, `explain`, `fix` — all REST-only against the generated `apiclient`
except the three local-only tools, which have no server call at all. `bulk-delete`'s and
`score`'s embedded-mode paths (Findings S5/S6) are moot by construction — this module has no
local/embedded mode.

Every command that took a project/environment **by name** in the old CLI (`export`, `render`,
`import`, `score` — via `common.ResolveProject`/`ResolveProjectIDRemote`/
`ResolveEnvironmentIDRemote`, an "active project" fallback concept) now takes required numeric
`--project`/`--environment` IDs instead, matching PR 4's `secret diff` precedent and the
convention every other command in this module already uses — that name-resolution
infrastructure doesn't exist yet in the new CLI (it's PR 6's job), and porting it here would
have been scope creep. `bulk-rotate`/`bulk-rename`/`bulk-delete` already used numeric IDs in
the old CLI, so those three needed no change.

**Prerequisite status: already closed.** Finding S2 (the broken `?environment=<name>` filter
in `rotate`/`render`) landed on `main` in #2013 before this PR opened — verified directly
against this PR's own fresh `origin/main` checkout, not assumed from the citation (see the note
above PR 5's plan bullet).

**New shared package `cli/internal/securefiles`** — a trimmed port of the main module's
`internal/securefiles` (`SecureOpenBeneath`'s per-path-component `O_NOFOLLOW` walk,
`SecureCreateFileHandle`'s `O_EXCL` + that same walk), since the `cli` module cannot import
the main module's package at all (ADR-108 Decision A: `cli/go.mod` carries no dependency on
the main module). Used by `export --output`, `render --output`, `scan --report`, and `fix`'s
source-tree rewrites — the exact same symlink-TOCTOU protection the old CLI's equivalents had,
not a downgrade.

**OpenAPI spec gaps found and closed:** 16 routes existed in `router.go` with no OpenAPI path
entry at all (bulk-rotate/rename/delete, expiring, orphaned, name-conformance ×2, reassign-owner,
render, rotation/simulate, auto-rotate, audit, ownership-history, certificate, blast-radius,
quota-report); 2 more (`rotateSecret`, `getSecretRisk`) existed with no response schema.
Authored full request+response schemas for all 18 (18 new `components/schemas` entries), moving
each from `pendingRegistry`/unregistered into `contracttest`'s `exercisingTests` registry, each
closed by a new, self-contained happy-path test in
`server/http/handlers/openapi_contract_pr5_test.go`.

**Decision (this PR): `secret export`/`import`/list-name-resolution decode local DTOs off the
raw generated client methods (`ListSecretsWithResponse`'s `.Body []byte`), not typed
`JSON200` accessors** — `listSecrets`/`createSecret`/`getSecret` have no response schema in
*this* PR's branch point (authoring `Secret`/`SecretGetResult`/`SecretListEntry` is PR 4's job,
a sibling independent PR on its own branch); waiting on that schema to land here would have
made this PR depend on PR 4's merge order. `filterspec.go`'s `keptPaths` comment documents this
explicitly so the reason doesn't get lost. When PR 4 merges, this decode path becomes just as
correct with a typed accessor available — a follow-up simplification, not a functional gap.

Verified: `go build`/`go vet`/`go test ./...` clean for both `cli` (depguard green) and the main
module's `server/http/handlers` + `.../contracttest` packages; `gosec -severity medium` and
`golangci-lint` both clean on `cli/`; `gosec` clean on `server/http/handlers`; `spectral lint`
zero errors on `openapi.yaml`; `scripts/check-closures.sh --self-test` green. Security-critical
regression tests (per this track's standing mandate): `TestSecretRotate_NeverLeaksTheCanaryValue`
and `TestSecretImport_NeverLeaksTheCanaryValue`/`..._DryRunNeverLeaksTheCanaryValue` run a
canary value through `rotate --value` and `import`, asserting it never reaches stdout or
stderr — verified red→green by planting a debug leak into `runSecretRotate`, confirming the
test caught it, then reverting. New `cli/internal/securefiles` package carries its own
symlink-refusal tests (leaf symlink, intermediate-component symlink, pre-existing-path refusal).

**PR 6 — `project`, `user` (14+11 = 25 commands).** **Hard prerequisite**: Finding S1 (admin-rank
ceiling gap on `PUT /api/v1/users/{id}`) must be fixed on the server route itself before this PR
deletes `user update`'s local fallback — today's fallback is, ironically, the better-guarded of the
two paths; deleting it first would narrow the CLI's own protection against the F5-class attack.
Also decide Finding S8 (`project env clone`'s misleading local-mode failure report — DROP recommended,
not a fix). Size: medium.

**Status: open (#2049).** S1 confirmed already merged (#2017). Finding S8 doesn't apply to the
thin CLI's port (there is no local-mode fallback to have a misleading failure report at all);
`project environments` (legacy alias) kept for flag compatibility, flagged as a conservative
default rather than a unilateral drop. Also closed 7 live-but-undocumented OpenAPI routes this
port needed, and a real HTTP-layer gap found while porting `user update`: the last-install-
administrator refusal wasn't surfaced readably (fixed, see the PR).

**PR 7 — `audit`, `anomalies`, `notification`, `accessreview`, `request` (37 commands).** **Hard
prerequisite**: fix GAP-F-BULK (Finding S15 / §6 GAP-5) — 3 of 6 `request bulk.go` commands need
rewiring to check `NewRemoteClient()` like their siblings, otherwise they silently break the moment
local mode is removed. GAP-1 (`request secret-access`/secret-scoped `review approve`/`reject`) is
now closed — both commands are REST-backed in remote mode, so this PR's scope no longer depends on
that decision. Size: medium.

**Status: open (#2056).** GAP-F-BULK confirmed already fixed independently (PR #2014, before this
track started) — this entry was stale, not a live gap; `internal/cli/request/bulk.go` checks
`NewRemoteClient()` correctly in all three previously-flagged commands. Also closed 18 live-but-
undocumented OpenAPI routes this port needed, and corrected one live behavior gap while porting:
`anomalies escalation run` now calls the real human `/api/v1/admin/jobs/run-alert-escalation`
route instead of the old CLI's doomed `/system` proxy equivalent.

**PR 8 — `risk`, `sod`, `legalhold`, `compliance`, `hygiene`, `trust` (24 commands).** **Needs a
product/engineering decision**: the `compliance export`/`verify` round-trip bug (§6 GAP-4) — fix
independently first (recommended, since it's a live compliance-workflow bug, not split-specific),
or explicitly defer with a documented known-broken state. Every other command in this group is a
trivial move (already REST-only, no fallback anywhere). Size: small once GAP-4 is resolved
elsewhere.
**PR 8 — `risk`, `sod`, `legalhold`, `compliance`, `hygiene`, `trust` (24 commands). DONE (#2060).**
The product/engineering decision this entry originally flagged — the `compliance export`/`verify`
round-trip bug (§6 GAP-4) — was resolved by deferring: PR 8 ported `export`/`verify` as-is
(conservative default, documented known-broken behavior) rather than fixing the signing-path bug
in a transport-only porting PR. Every other command in this group was a trivial move (already
REST-only, no fallback anywhere). 11 previously-undocumented-but-live OpenAPI routes were added,
plus a real pre-existing doc defect fixed: `DELETE /api/v1/legal-hold` genuinely requires a
`{"reason"}` JSON body that the spec never declared.

**PR 9 — `share` (7 commands).** `shared-secrets --user-id`'s missing arbitrary-target REST route
(§6, secondary gap) is now closed — `GET /api/v1/users/{id}/shared-secrets`, admin-rank-ceiling-
gated; no remaining product decision here. Size: small.

**Closed by PR split/pr9-cli-share.** Ported all 7 commands (`create`, `list`, `update`, `revoke`,
`self-remove`, `shared-secrets`, `group-shares`) to `cli/cmd/share.go` against a freshly generated
client. Two REST routes this PR needed already had live server handlers with no route wired
(`RemoveSelfFromShare`, `ListGroupShares` in `shares_query.go`) — only the OpenAPI path/schema and
CLI client were missing, not the underlying logic; both `#G66` findings the old CLI's own comments
already named as the reason those handlers existed unreached. Spec gaps closed in this PR: added the
`Share` and a PR9-local `Secret` component schema (both PascalCase, `models.ShareRecord`/`SecretNode`
have no json tags — sibling-PR duplication of `Secret` is expected, see PR4/PR5's identical note);
added `expires_at` to `shareSecret`'s request body and a full response schema; added
`expires_at`/`clear_expiry` to `updateSharePermission`'s request body and a full response schema;
added response schemas to `listSecretShares`, `listSharedSecrets`, `listSharedSecretsForUser`; added
the brand-new `DELETE /api/v1/secrets/{id}/self-share` and `GET /api/v1/groups/{id}/shares` paths
outright (previously absent from the spec, not just schema-less). `revokeShare` was already
204-typed and out-of-scope; `removeSelfFromShare` (also 204) was added to `outOfScopeRegistry`
alongside it, matching the existing 204 convention. The other 6 newly-schema'd operations moved from
`pendingRegistry` to enforced, each exercised by a dedicated `openapi_contract_pr9_test.go` test —
`TestEnforcedSetMatchesADR074`'s pinned baseline and `exercisingTests` updated accordingly. Deliberate
output-parity fix (not a faithful port): `share update`'s old CLI remote-mode output printed only 3
of the ~8 fields the embedded branch and `share create` print (§2.x inventory table, "API — minor
CLI output-parity gap only"). This port prints all 8 (adding Secret ID, Owner ID, Recipient ID, Is
Group, replacing the label with "Updated At"), matching create/list/revoke's shape instead of
carrying the narrower one forward.

**PR 10 — `bundle`, `license`, `system info`/`role-expiry-check`/`token-expiry-check`, `status`
(remote branch only), `run` (remote branch only) — CLIENT-ONLY/API cleanup (~15 commands).**
**`system info`/`role-expiry-check`/`token-expiry-check` DONE (#2062)**; `status`'s remote branch
was already done in an earlier PR. `bundle`/`license` deliberately deferred — real architecture
question (depguard vs. duplicating security-critical verification code), flagged in #2062's body,
not yet decided. `run`'s local/embedded-branch drop (Finding S18, security fix not just cleanup)
is still open. Drop `status`'s and `run`'s local/embedded branches (Findings S18, §2.7) — dropping
`run`'s is a security fix, not just cleanup. Size: small.

**PR 11 (parallel track, `keyorix-server admin`) — B1 subcommands.** `system init` (local mode),
`system audit`, `system validate` port near-verbatim (`internal/startup.ValidateStartup`,
`securefiles.FixFilePerms`, `generateConfigFile`/`initializeEncryption`/`initializeDatabase` are
already core/storage-independent). Size: small — mostly relocation, not new logic. Tests: existing
CLI-level tests for these 3 commands should port unchanged onto the new `admin` subcommand
entrypoint.

**PR 12 (parallel track, `keyorix-server admin`) — B3 subcommands (`encryption` family, 15
commands).** All 15 port with the "testable core" pattern already in place (`rotateWithConfig`,
`migrateProviderWithConfig` etc. take no cobra/flag dependency). Fix Finding S13
(`auth-encryption rotate`'s missing lock call) as part of this port, not before — it's isolated to
this one command and the port is the natural place to normalize it against its 4 siblings in the
same file. Size: medium.

**PR 13 (parallel track, `keyorix-server admin`) — B4, new work.** Build offline audit-chain
verification from scratch: open the DB file directly (no running server, no HTTP), re-derive the
hash chain independent of `k.storage`. This is the least-defined PR in the whole program — no
existing code to port, ADR-108 §B.4 states the requirement but not a design. Size: large,
should not be scheduled until the design is scoped separately.

**PR 14 (final, ADR-108 §Decision C) — delete `/system` and `RemoteStorage`.** Gated on every prior
PR that removes an `InitializeCoreService()`/`NewRemoteClient()`-fallback pattern having landed
(PRs 1-10) and on the `reachabilityLive`/`reachabilityUnresolved` 21 methods (§3) either getting a
real REST route or being confirmed genuinely dead by that point. Delete the 151 route
registrations, their handlers, `internal/storage/store/remote_*.go`, the `~18`
`remote_storage_*_test.go` parity-fuzzer files, `validateRemoteStorageNotServer`'s enforcement
(carefully — per its own doc comment, this must go LAST, after the topology it forbids is already
gone, not alongside it). Size: large but mechanical (deletion, not new logic). Tests: the existing
`remoteUnsupportedAllowlist`/reachability-registry tests should go to zero real entries; a final
CI check that nothing in the repo imports `internal/storage/store/remote_*` outside test files.

---

## 8. Candidate security findings — consolidated

Ranked by severity/impact. All are report-only per this task's scope — none were fixed. "Local mode"
below means `common.InitializeCoreService()`/`InitializeStorage()`+`core.NewKeyorixCore` (direct-DB,
no HTTP layer) unless stated otherwise.

**S1 — HIGH. `PUT /api/v1/users/{id}` (the human-facing route ADR-107 wants as the CLI's SOLE path
for `user update`) is missing an authorization ceiling its own `/system` proxy sibling already had
to acquire.** `server/http/handlers/users_active_transition_proxy.go:169`
(`UpdateUserIfActiveStateMatchesProxy`) calls `RequireEqualOrGreaterAdminAuthority` (defined
`internal/core/users.go:829`) — an admin-rank ceiling that refuses a caller from rewriting a target
user's identity fields (email especially — the F5 finding this exists to close) when the target
holds, at any scope, a permission the caller does not also hold.
`server/http/handlers/users_crud.go:727-783` (`UserHandler.UpdateUser`, backing
`PUT /api/v1/users/{id}`) does **not** call this or any equivalent — only session presence plus the
blanket group-level `RequirePermission(permUsersWrite)`. Repo-wide grep confirms only 2 call sites
for `RequireEqualOrGreaterAdminAuthority` exist at all (`webauthn_proxy.go:289` and this one
`/system` proxy). **Practical effect**: a principal holding only `users.write` (not global admin)
can, via the route both the web UI and the CLI's primary path already use, rewrite a
HIGHER-privileged target's email/username with no admin-rank check, then pivot via
password-reset/setup-token completion exactly as the `/system` proxy's own fix comment describes for
the now-fixed path — via the sibling route that fix was never applied to. Not hypothetical scope
creep — this is the literal attack the existing fix names, unaddressed on the primary route.
Location: `internal/cli/user/update.go` cross-referenced against `server/http/router.go:878`,
`server/http/handlers/users_crud.go:727-783`, `internal/core/users.go:793-795,829`.

**S1b — MEDIUM, compounding S1. `user update`'s own local-mode path is inconsistent with its
package's own established mitigation pattern.** Every other account-lifecycle command in
`internal/cli/user/` (`suspend`, `reactivate`, `force-password-reset`, `revoke-sessions`, `delete`,
`resend-setup-link`, `create --setup-link/--one-time-password`) requires `--by` and calls
`resolveAdminID`+`requireUserAuthority` — the package's own hand-rolled simulation of the HTTP
layer's check. `update.go`'s local branch has no `--by` flag, no `resolveAdminID` call, no
`requireUserAuthority` call at all — combined with S1 (core itself checks nothing), local-mode
`user update --active=true` performs **zero** authorization of any kind, not even the weak,
spoofable `--by`-email check its siblings at least attempt. Migrating this command by simply
deleting the local fallback (ADR-107 Phase 1's usual move) would, ironically, remove the
*better-guarded* of the two existing paths for this specific operation unless S1 is fixed first.
Location: `internal/cli/user/update.go:58-73` vs. `internal/cli/user/lifecycle.go:179-185`,
`delete.go:53-59`, `setup_link.go:45-51`.

**S2 — HIGH, live bug on `main` today, independent of the CLI/server split. `secret rotate` and
`secret render` build a broken, silently-ignored `?environment=<name>` filter and name-match
unscoped across every secret the caller can read.** `GET /api/v1/secrets` only ever reads
`environment_id` (numeric) — `environment=<name>` matches zero code path anywhere in
`secrets_list.go` (grepped across all of `server/http/handlers/*.go`). `render.go`'s resolver
(page_size=1000) and `rotate.go`'s (default page_size=20, no explicit override) both silently get
an unscoped, cross-project/cross-environment page of the caller's readable secrets and take the
first case-(in)sensitive name match. A purpose-built, project-scoped server-side renderer
(`POST /projects/{id}/secrets/render`) already exists and is simply never called. **Concrete
failure modes**: `render` can silently substitute a same-named secret from a different
project/environment into rendered output headed for a live config file — no error, no warning.
`rotate` — the worse half, since it's a write — can silently `POST /secrets/{wrong-id}/rotate`,
overwriting an unrelated secret's value, with zero output indicating anything went wrong. Recommend
filing and fixing this **independently of, and before, the split program** — it is a real,
currently-exploitable-by-mistake defect on `main`, not a migration artifact. Location:
`internal/cli/secret/render.go:108-137`, `rotate.go:72-89`, cross-referenced against
`server/http/handlers/secrets_list.go:120`, `internal/core/secret_render.go:40`,
`server/http/router.go:552`.

**S3 — HIGH. `keyorix run`'s embedded/local-mode secret-value fetch has zero authorization check
and zero audit event, where the functionally identical remote path in the same file correctly hits
both controls.** `fetchSecretsEmbedded` (`internal/cli/run/run.go:227`) calls the bare
`svc.GetSecretValue(ctx, s.ID)` — always treated as `userID 0`, runs `enforceSecretReadGuards`
(expiry/suspension/classification-approval/schedule) but never `ValidateSecretAccess` (that only
happens inside `GetSecretValueWithPermissionCheck`, which this isn't). `internal/core/versions.go`
has zero audit-emitting calls anywhere in the file. The REST route `run`'s own remote path
correctly uses (`GET /secrets/{id}?include_value=true`) calls
`GetSecretValueWithPermissionCheck(ctx, id, userCtx.UserID)` AND explicitly emits
`LogSecretReadWithProject` for every read. **Net effect**: running `keyorix run` today in
embedded/local mode against a project with restricted-classification or otherwise access-controlled
secrets silently reads and injects EVERY secret in the project+environment into a child process's
environment with no RBAC check against the invoking OS user and no audit trail recording the read
happened at all. The sharpest concrete instance in this whole report of ADR-108's abstract "second
server that bypasses the API's authorization, audit and rate limits" framing. Location:
`internal/cli/run/run.go:170-239` vs. `internal/core/versions.go:148-238`,
`server/http/handlers/secrets_crud.go:274,296`.

**S4 — MEDIUM. `secret folder delete`'s embedded path has no type-guard the REST route has, and
can silently delete a SECRET instead of a folder.** `FolderHandler.DeleteFolder` explicitly
re-fetches the target node and 400s if `node.IsSecret` is true (with a dedicated test,
`TestDeleteFolder_IsSecret_Returns400`). The embedded CLI path calls
`service.DeleteSecret(ctx, folderDeleteID)` directly — the generic secret-delete method, which has
no such check. An embedded-mode operator who mistypes a secret's ID into `secret folder delete --id
<secretID>` silently deletes that secret (after a confirmation prompt that only asks about "folder
N", not what kind of node N actually is). Location: `internal/cli/secret/folder.go:245` vs.
`server/http/handlers/folders_handler.go:202-211`.

**S5 — MEDIUM. `secret bulk-delete`'s embedded path attributes every deletion to actor `0`/username
`"cli"` with empty ip/ua — a documented, not silent, attribution gap, still worth flagging as
concrete evidence for ADR-108's own B2 rationale.** `bulk_delete.go`'s own doc comment explicitly
names `actorID==0` as the embedded-CLI signal and states per-secret re-authorization is
deliberately skipped ("physical access to the local DB file is the authorization boundary"). The
audit event IS still written (not an audit-skip, unlike S3/S-secret-1..4) — just attributed to a
non-identity. Recommend DROP under ADR-108 Decision A, not a fix. Location:
`internal/cli/secret/bulk_delete.go:152-201` vs. `internal/core/bulk_delete.go:89-104`.

**S6 — MEDIUM, one point unresolved. `secret score`'s embedded path has NO authorization check
reachable at all (not even the actor-0 convention S5 has), and possibly no audit either.**
`ComputeSecretRiskScore(ctx, secretID)` takes no actor/permission argument whatsoever — genuinely
unlike `bulk-delete`'s documented pattern. Whether the REST route's handler (`GetSecretRisk`) itself
emits an audit event that the embedded path then simply lacks was **not fully determined** in this
pass (handler body not read) — flagged as the sharpest unresolved item in the whole `secret`
inventory; recommend a follow-up trace before assuming parity either way. Location:
`internal/cli/secret/score.go:142-180`.

**S7 — LOW, doc-only, not an authorization defect (the router is the real gate in all three cases).**
Three CLI help-text/doc-comment mismatches, all in the direction of UNDER-claiming the required
permission (so an operator is surprised by an unexpected 403, never granted more than intended):
`secret reassign-owner`'s help text says `secrets.write` + per-secret authorization; actual
enforcement is a single project-level `roles.assign` check gating the whole bulk operation.
`secret quota-report` and `secret name-conformance` (org-wide form) both say `secrets.read`/
`system.read` respectively; both routes actually require `audit.read`. Same class of mismatch
recurs across `risk list`, `sod violations`, `legalhold status`, and `hygiene`'s own printed
`--help` text (all say `system.read`, all actually gate on `audit.read`) — a calibration change
that landed in the router without a corresponding CLI doc-string update, repeated across 7
commands. Worth a single pass fixing all 7 help strings together when these commands migrate, not
7 separate fixes.

**S8 — MEDIUM, functional bug, not a security bypass (fails closed). `project env clone`'s
embedded path hardcodes actor `"cli"`/`0` instead of using the `ResolveActorID`/`ResolveActorLabel`
self-assertion helpers used elsewhere in the same package, and — because
`GetSecretValueWithPermissionCheck` proven-fails-closed on `actorID==0`
(`TestGetSecretValueWithPermissionCheck_ZeroUserID`) — this makes the command silently copy ZERO
secrets on every embedded-mode run while reporting a hardcoded, incorrect "already exist in
destination" reason and exiting 0 (success). The permission check is doing its job; the CLI is
lying about why nothing happened. Recommend DROP under ADR-108 Decision A rather than fixing the
actor-threading — this embedded path has, in effect, never worked, so removing it loses nothing a
user could have relied on. Location: `internal/cli/project/env_clone.go:88-130` vs.
`internal/core/env_clone.go:33,83-92`, `internal/core/secret_copy.go:53`.

**S9 — LOW, correctness/parity gap, fails closed (stricter, not weaker). `invite list`'s
embedded-mode authority check requires `roles.assign`, a materially HIGHER permission than the
route's actual `users.read` gate.** An embedded-mode `--by` actor holding only `users.read` (what
the REST route actually requires) would be refused locally for an operation the equivalent REST
call would allow them. Not exploitable — fails safe — but real local/remote parity divergence
worth correcting rather than silently carrying forward. Location: `internal/cli/invite/list.go:58-70`
vs. `server/http/router.go:494`.

**S10 — LOW/MEDIUM, already documented and accepted in-repo, reported per this task's instruction
to surface it, not a fresh discovery. `share list` and `share shared-secrets --user-id`'s
embedded paths can enumerate a secret's share graph / an arbitrary user's shared-secrets list with
no ownership/actor check at all**, where the REST routes enforce an owner-only or self-only
restriction respectively. Both are explicitly flagged in the CLI's own code comments
("cli-connect-007 (info, deliberate — not a bug)") as an accepted consequence of embedded mode
having no authenticated-user concept — the residual-risk condition (embedded mode pointed at a
genuinely multi-tenant backend) is exactly what ADR-108's removal of local mode closes structurally.
`share shared-secrets --user-id`'s REST-equivalent gap (§6, secondary gap) is now closed —
`GET /api/v1/users/{id}/shared-secrets` (admin-rank-ceiling-gated) — so this finding now stands
only for `share list`'s embedded path and `share shared-secrets`'s own embedded path (still no
actor check locally, per cli-connect-007). Location: `internal/cli/share/list.go:41-55`,
`internal/cli/share/shared_secrets.go:46-58`.

**S11 (= "D1" in the source inventory) — MEDIUM. `rbac assign-role`/`remove-role`'s embedded-mode
core methods are structurally incapable of carrying an actor, where the identical group-scoped
operation in the SAME package IS correctly actor-threaded — proving the fix is a core-layer
signature change, not a CLI oversight.** `internal/core/rbac.go:19,41`
(`AssignUserRoleScoped`/`RemoveUserRoleScoped`) take no actor parameter at all — line 28 hardcodes
`c.AssignUserRole(ctx, 0, ...)` inside `core`, not passed in by the caller; the method's own doc
comment states this outright ("actorID 0 = local CLI/system"). Contrast:
`internal/core/rbac_management.go:200,246` (`AssignRoleToGroup`/`RemoveRoleFromGroup`) — the
group-scoped equivalent, same package — DO take an explicit `actorID`, and
`internal/cli/rbac/group_role.go:109,175` correctly passes `common.ResolveActorID()`. Every
embedded-mode direct user-role grant/revocation (arguably the more common, more security-relevant
of the two operations) is audit-attributed to actor `0` regardless of `KEYORIX_CLI_ACTOR`, with no
way for the CLI to fix this without a core-layer signature change. Scope note: embedded-mode-only;
moot once ADR-108 Decision A removes local mode, but worth deciding explicitly (fix the signature,
or accept and document) rather than silently dropping, since the same core methods likely have
other embedded-mode callers repo-wide not traced in this pass.

**S12 — LOW, informational/UX gap, not a code defect. `auth logout` clears local config only — it
does not call `DELETE /api/v1/auth/tokens/{id}` to revoke the server-side PAT.** A copy of
`~/.keyorix/cli.yaml`/`keyorix.yaml` taken before `logout` still holds a live, usable credential
after the operator believes they've "logged out." Documented CLI behavior ("remove stored API key"),
not a bug, but worth a UX/docs fix (or an explicit revoke-on-logout default) when this migrates.
Location: `internal/cli/auth/auth.go:194-217`.

**S13 — LOW, unresolved (not confirmed either way). `encryption auth-encryption rotate` acquires no
key-directory lock at all, unlike all 4 of its siblings in the same file** (`status`/`enable`/
`migrate`/`validate` all explicitly call `AcquireSharedKeyLock`). Whether
`AuthEncryption.RotateAuthEncryption` takes a lock internally the way `Service.RewrapDEKWithProvider`
does for `migrate-provider` was not verified in this pass (the implementation file wasn't read) —
flagged as the single highest-priority follow-up read from the `encryption` cluster, and a natural
fix-point when this command ports to `keyorix-server admin` (PR 12, §7). Location:
`internal/cli/encryption/auth_encryption.go:173-198`.

**S14 — LOW, documented-by-design, positive framing for the split. Four local-mode `request`
commands (`access`, `withdraw`, `list --by`, `review --by`) resolve identity from a caller-supplied
email flag with no session to verify it against** — `access`/`withdraw` can file/withdraw "as" an
arbitrary resolvable user; `list`/`review`'s `--by` at least passes through a real `Authorize(...)`
check against the resolved actor, so only identity (not privilege) is unverified there. Every
instance carries an in-code comment acknowledging the tradeoff as inherent to embedded mode having
no session concept. This entire class of risk disappears by construction once ADR-108 Decision A
removes local mode — cited here as positive evidence for the split's security value, not a fix
request.

**S15 (= "GAP-F-BULK") — MEDIUM, confirmed implementation bug (not a design gap), independent of
the split. 3 of `request/bulk.go`'s 6 subcommands (`bulk-approve`, `bulk-reject`,
`rejection-templates delete`) never check `common.NewRemoteClient()` at all and go straight to the
local embedded core — even though a matching REST route exists for all three, and their siblings in
the same file (`rejection-templates list`/`add`) check correctly.** Today, on `main`, an operator
with a `keyorix connect`-configured remote server who runs any of these three commands silently
operates on the local embedded core instead of the connected server. See §6 GAP-5 for the
migration-blocking framing; listed here for its security angle: `BulkApproveAccessRequests`/
`BulkRejectAccessRequests` DO perform genuine per-item project-scoped authorization inside `core`
(`bulk_access_requests.go:89,150`) — so this bug is a "silently wrong target," not a privilege
escalation — but it means an operator's bulk decision may land in a local SQLite file nobody is
reading while believing it reached the hub, a trust/correctness defect ADR-108's thin-CLI (no local
DB mode at all, compiler-enforced) eliminates structurally once fixed and migrated. Location:
`internal/cli/request/bulk.go:47-52,105-110,294-299`.

**S16 — MEDIUM, functional gap not an authz/audit skip. `compliance export`/`compliance verify`
cannot round-trip to VALID for a genuinely untampered pack, see §6 GAP-4 for full detail.** Not an
authorization or audit-emission bug — `GenerateComplianceEvidence` (what `export` calls) and
`ExportComplianceEvidence` (the only function that ever produces a valid signed pack, called only
by the scheduled job in `server/main.go`) are two different functions for two different purposes,
never wired together the way the CLI's `export`→`verify` UX implies. No test would have caught this
(`TestVerify_ValidAndInvalid` stubs the HTTP response directly rather than exercising the real
signing/verification logic).

**S17 — MEDIUM. `usage show` and `billing report`'s embedded-mode paths call disclosure-sensitive,
deployment-wide report generators with literally no `userID`/caller-identity parameter on the core
method signature — there is nothing for a permission check to even be threaded through.** REST
gates both at `audit.read`; local mode has zero. Both reports are explicitly documented in their
own handler header comments as "disclosure-sensitive" (`admin_usage.go`, `admin_billing.go`), and
`admin_billing.go` additionally notes "no per-project ownership check anywhere in the call chain" —
meaning `audit.read` is the ONLY control on this data, and local mode has none of it. Location:
`internal/cli/usage/usage.go:53-65` vs. `internal/core/usage_report.go:13`;
`internal/cli/billing/billing.go:81-97` vs. `internal/core/billing.go:16`.

**S18 — HIGH (= S3 restated for emphasis as the report's own "sharpest finding" callout). See S3
above — `keyorix run`'s local-mode secret-value fetch is the single clearest concrete instance in
this entire inventory of ADR-108's abstract "local mode is a second server that bypasses
authorization, audit, and rate limits" framing, with disclosure-sensitive, file:line evidence on
both sides of the split.**

**Systemic pattern underlying most of the above (stated once, not re-derived per finding)**: per
ADR-108's own Context section, local/embedded mode "opens the SQLite DB itself, which makes it a
second server that bypasses the API's authorization, audit and rate limits." This report confirms
that pattern with concrete call-chain evidence across `secret`, `project`, `group`, `machine`,
`rbac`, `usage`, `billing`, and `run` — `internal/core.KeyorixCore` methods generally assume the
HTTP router already authorized the caller and do not re-check themselves; local-mode CLI commands
never construct a router, so they skip that check entirely. Three distinct sub-shapes were found
(not one uniform gap): (1) no check at all, ever; (2) a check exists but is explicitly bypassed for
actor `0` specifically (documented, deliberate, e.g. `requireGranterHoldsRolePermissions`); (3) a
check exists and fails closed for actor `0` (the safer minority shape, e.g.
`requireMachinePrivilegeCeiling`). Every instance of this pattern not individually numbered above
(the majority of "no behavior difference beyond the general pattern" rows in §2) becomes moot,
structurally, the moment ADR-108 Decision A removes local mode from the CLI — that removal is this
report's single strongest piece of evidence *for* the program, not against it.

---

## 9. Command census (FINISH-SPLIT step 3)

Machine-checked, not asserted: `internal/cli/command_census_test.go`'s `TestCLICommandCensus` walks
the old CLI's live cobra tree (`internal/cli`'s `rootCmd`, reusing the existing
`walkLeafCommands`/`leafCommand` helper from `cli_remote_mode_behavior_test.go` rather than
duplicating it) and checks every leaf command against a hand-maintained classification map in the
same file. A leaf command with no entry fails CI immediately — this is the mechanism (not this
document) that stays correct as the old CLI keeps changing underneath it. Run it directly with
`scripts/cli-command-census.sh`, or regenerate the table below with
`scripts/cli-command-census.sh --regen`.

**259 leaf commands** as of 2026-09-24 (256 counted by a naive "no-children" walk, plus 3 the real
walker's `cmd.Runnable()` check correctly caught that a naive walk misses: `access-review`,
`connect`, and `encryption migrate-provider` are all runnable in their own right *and* have
subcommands — a real gap the machine check found on its first run, not a hypothetical).

Full table: [`docs/cli-split-inventory-census.md`](cli-split-inventory-census.md) (generated;
do not hand-edit — edit `commandCensus` in `internal/cli/command_census_test.go` instead).

**8 open gaps** at this writing — commands with no assigned home yet. These block PR 14 (delete
`/system` + `RemoteStorage`) and Phase 5 (delete the old CLI); `TestNoGapsRemain`
(`KEYORIX_CENSUS_CHECK_GAPS=1`) is the gate that gets re-run before either starts:

- `billing report`, `usage show` — dual-mode REST routes exist (`GET /admin/billing/report`,
  `GET /admin/usage`) and are genuinely `audit.read`-gated on the server side, but neither was in
  any split PR's scope (§8 Finding S17: the embedded-mode path has no `userID` parameter to
  authorize against at all). Needs a small PR, unassigned.
- `migrate user-to-machine` — should collapse to a REST-backed thin-CLI command (the route already
  exists: `POST /projects/{id}/machine-identities/migrate-from-user`); not related to the separate
  `keyorix-migrate` tool (Vault/cloud import) despite the name collision. Needs a small PR,
  unassigned.
- `system init`'s `--server` half — the local-host half (create config/keys/DB) moved to
  `keyorix-server admin init` (B1, #2016); the network-bootstrap half (`POST /system/init`,
  unauthenticated, bootstrap-token-gated) has no thin-CLI home yet. Tracked as a note on the
  `system init` row (same cobra leaf, can't be split in the census map), not a separate gap key.
- `bundle import`, `bundle verify`, `license install`, `license status`, `run` — in progress this
  same track (FINISH-SPLIT step 2, opened alongside or immediately after this PR); flip to
  `censusMoved` once that PR lands.

`bundle build`, `license issue`, and everything under the old `config`/`connect` groups are
`censusDropped` (maintainer-only tooling and ADR-108 Decision A's config-mechanism consolidation,
respectively) — not gaps, a closed decision each with its own reason in the table.

## 10. PR 14 readiness (analysis only — no deletions in this pass)

PR 14 deletes the `/system` route tier and `internal/storage/store`'s `RemoteStorage` type
entirely (the server-to-server proxy tier `RemoteStorage` is the CLI's client-mode Go
implementation of, per §3 above). This section resolves the last open question blocking that
deletion — whether every currently-live-or-unresolved `RemoteStorage` method is safe to remove —
and sizes the actual deletion.

### 10.1 The 21 `reachabilityLive`/`reachabilityUnresolved` methods, resolved

`internal/storage/store/remote_reachability_registry_test.go` classifies every structurally-stub
`RemoteStorage` method's reachability. As of this pass, 21 of ~183 are `reachabilityLive` or
`reachabilityUnresolved` (not `reachabilityDead`) — every one of them, without exception, traces
to a call made by the **old CLI's (`internal/cli`) embedded-mode fallback** (`storage.type:
remote` configured for a CLI process, not a server), never to the new thin CLI (`cli/`): the
thin CLI performs no local authorization or local storage access at all — every command is a
REST call, with the real server doing its own authorization over the wire. That structural fact
is why the resolution below is the same shape for all 21: either the underlying feature already
has a REST-routed thin-CLI equivalent (so the old-CLI path becomes dead, not replaced, the moment
Phase 5 deletes `internal/cli`), or fresh verification found no real caller at all, old CLI
included.

| Method | Resolution |
|---|---|
| `AddPasswordHistory` | ROUTED — old path: `internal/cli/user/create.go` embedded fallback → `core.CreateUser`. Thin-CLI equivalent: `keyorix-next user create` (`cli/cmd/user.go`, PR 6/3, REST `createUser`). Note: the storage error was already discarded at every call site (`internal/core/users.go`, `account.go`), so this was a registry-accuracy issue, not a functional one, even before Phase 5. |
| `AssignPermissionToRole` | **CONFIRMED DEAD** — fresh repo-wide grep for `.AssignPermissionToRole(` outside `_test.go` finds only `server/http/handlers/rbac.go` and boot-time-only `auth_bootstrap.go`/`rbac_reconcile.go`/`rbac_roles.go` callers of the *core* method; zero matches anywhere under `internal/cli` (old or new). The original Wave 0 "no CLI caller found" holds up under a full re-check — this is the one entry not gated on Phase 5 at all. |
| `CountSecretReadsBySecretIDs` | ROUTED — old path: `internal/cli/project/health.go` embedded fallback → `core.GetProjectHealthSummary`. Thin-CLI equivalent: `keyorix-next project health` (`cli/cmd/project.go:575`, PR 6). |
| `CreateSecretAccessLog` | ROUTED — old path: `internal/cli/secret/bulk_delete.go` embedded fallback → `core.BulkDeleteSecrets`. Thin-CLI equivalent: `keyorix-next secret bulk-delete` (`cli/cmd/secret_bulk.go`, PR 5). |
| `GetBillingReport` | ROUTED — old path: `internal/cli/billing/billing.go` embedded fallback → `core.GenerateBillingReport`. Thin-CLI equivalent: `keyorix-next billing report` (`cli/cmd/billing.go`, this track's FINISH-SPLIT census-gaps PR, `GET /admin/billing/report`). |
| `GetMachineRoleScopes` | ROUTED (ADR-086 family, see `GetUserRoleIDsAt` below) — the one path independently traced to a real caller (`core.ReadFederatedSecret`/`ConnectReadableConnectorNames`, the ADR-082 Connect *feature* — unrelated to the CLI's own `connect`/`disconnect` commands despite the name collision) is itself **confirmed dead**: called only from `server/grpc/services/connect_service.go` and `server/http/handlers/connect.go`, both server-only per ADR-083. The remaining path is via `core.GetReadableScopes`, part of the same local-authorization-resolution family as `GetUserRoleIDsAt`. |
| `GetProjectUsageStats` | ROUTED — old path: `internal/cli/usage/usage.go` embedded fallback → `core.GetUsageReport`. Thin-CLI equivalent: `keyorix-next usage show` (`cli/cmd/usage.go`, this track's FINISH-SPLIT census-gaps PR, `GET /admin/usage`). |
| `GetUserGroupPermissions` | ROUTED — old path: `internal/cli/rbac/assign_role.go` embedded fallback → `core.AssignUserRole` → `requireNoSoDViolation` → `userHeldPermissionSet`. Thin-CLI equivalent: `keyorix-next rbac assign-role` (`cli/cmd/rbac.go`, PR 3, #2044, REST `assignUserRole`). The `GetUserPermissionsByID`/dashboard path (`server/http/handlers/users_roles.go`) is separately server-only, zero CLI caller either way. |
| `GetUserGroupRoleIDsAt` | ROUTED (ADR-086 family, see `GetUserRoleIDsAt` below). |
| `GetUserRoleIDsAt` | ROUTED — called directly by `core.Authorize`, reached by 11 old-CLI commands doing their own local authorization check under `storage.type: remote` (#1575) — e.g. `internal/cli/migrate/user_to_machine.go`'s `requireMigrationAuthority`, which calls `svc.Authorize(...)` directly. Deliberately kept an unconditional stub per ADR-086 (implementing scoped-authorization over the wire would be a fat-client anti-pattern) — not something PR 14 changes, but every one of those 11 old-CLI local-authorization checks has a thin-CLI equivalent that defers authorization to the server instead of checking it locally (e.g. `migrate user-to-machine`'s own thin-CLI port, this same track, drops the local authority check entirely — the bearer token IS the authorization). |
| `GetUserRoleIDsExact` | ROUTED — old path: `internal/core/rbac_management.go`'s `AssignUserRole`/`RemoveUserRole` (called from `internal/cli/rbac/assign_role.go`'s embedded fallback, same as `GetUserGroupPermissions` above). Thin-CLI equivalent: `keyorix-next rbac assign-role`/`remove-role` (PR 3, #2044). The separate `project_members.go` (add/remove project member) and `break_glass.go` call sites have **zero CLI caller at all**, old or new — server-only. |
| `GetUserRoleScopes` | ROUTED (ADR-086 family) — three real paths, all old-CLI-only: (1) `core.HasPermissionByEmail`, doc-commented as "the CLI diagnostic" (#376), called by `internal/cli/rbac/check_permission.go` → thin-CLI equivalent `keyorix-next rbac check-permission` (PR 3, #2044); (2) `core.requireEqualOrGreaterAdminAuthority`, the admin-ceiling check on user mutations → thin-CLI equivalent `keyorix-next user update`/etc. (PR 6) defers this to the server; (3) `core.GetReadableScopes`, used by old-CLI embedded-mode scoped listing. The fourth path (`connectOwnershipSatisfied`/`ReadFederatedSecret`) is separately confirmed dead — server-only, see `GetMachineRoleScopes` above. |
| `ListAccessRequestsByIDs` | ROUTED — old path: none at all (Finding S15/GAP-F-BULK: the OLD CLI's `request bulk-approve`/`bulk-reject` never actually called the REST route despite the route existing). Thin-CLI equivalent now genuinely calls it: `keyorix-next request bulk-approve`/`bulk-reject` (`cli/cmd/request.go`, `BulkApproveAccessRequestsWithResponse`). |
| `ListAllUserRoleGrants` | ROUTED — old path: `internal/cli/rbac/export_matrix.go` embedded fallback → `core.GetPermissionMatrix`. Thin-CLI equivalent: `keyorix-next rbac export-matrix` (`cli/cmd/rbac_audit.go`, PR 3, #2044). |
| `ListInactiveUsers` | ROUTED — old path: `internal/cli/user/inactivity_suspend.go` embedded fallback → `core.SuspendInactiveUsers`. Thin-CLI equivalent: `keyorix-next user suspend-inactive` (`cli/cmd/user.go`, PR 6, `POST /admin/jobs/suspend-inactive-users`). |
| `ListLiveSecretNamesByProject` | ROUTED — old path: `internal/cli/project/stats.go` embedded fallback → `core.GetProjectStats`. Thin-CLI equivalent: `keyorix-next project stats` (`cli/cmd/project.go:395`, PR 6). |
| `ListSecretACLs` | ROUTED — old path: `internal/cli/secret/diff.go` embedded fallback → `core.DiffSecretVersions`. Thin-CLI equivalent: `keyorix-next secret diff` (`cli/cmd/secret_versions.go`, PR 4, `DiffSecretVersionsWithResponse`). |
| `ListSecretAccessLogs` | ROUTED — old path: `internal/cli/secret/score.go` embedded fallback → `core.ComputeSecretRiskScore`. Thin-CLI equivalent: `keyorix-next secret score` (`cli/cmd/secret_risk.go`, PR 5, `GetSecretRiskWithResponse`). |
| `ListSessionTokenHashesForUser` | ROUTED — old path: `user update --active=false` embedded fallback. Thin-CLI equivalent: `keyorix-next user update --active=false` (`cli/cmd/user.go:313`, PR 6, REST). |
| `RoleSetHasPermission` | ROUTED (ADR-086 family, see `GetUserRoleIDsAt` above — final step of the same `core.Authorize` chain). |
| `WithTransaction` | ROUTED — same `user update --active=false` path as `ListSessionTokenHashesForUser` above; no real cross-call atomicity under `RemoteStorage` (each sub-call its own HTTP round trip) but the thin-CLI's REST call is a single request handled transactionally server-side, so the limitation this entry described doesn't carry forward at all. |

**Net result: 20 of 21 resolve to ROUTED (blocked only on Phase 5 deleting `internal/cli`, not on
any unported functionality), 1 resolves to CONFIRMED DEAD (no blocker at all).** No entry is
newly promoted to a hard blocker — the one true blocker (Phase 5) was already known, not
discovered by this pass.

### 10.2 What PR 14 deletes, sized

| Group | Files | Lines (impl / test) |
|---|---|---|
| `/system` route registrations (`server/http/router.go:1126`–`:2078`) | 1 (partial) | 953 (registrations only) |
| `/system` proxy handlers (`server/http/handlers/*_proxy.go` and siblings) | 29 | 9,239 / 6,008 |
| `internal/storage/store/remote_*.go` (the `RemoteStorage` type itself + its own package tests) | 50 impl + 92 test | 9,743 / 19,339 |
| `server/http/remote_storage_*_test.go` (the differential/parity conformance harness, PR #1812) | 59 (all test) | 0 / 22,631 |
| `validateRemoteStorageNotServer` (`internal/config/config.go:2396`) + the `storage.type: "remote"` factory case (`internal/storage/factory.go`) | 2 (partial) | ~15 |
| **Total** | **~141 files touched** | **~67,928 lines** |

Far over the ~3,000-line single-PR guideline — proposed 3-PR split, in dependency order (each
PR's deletions must compile clean on their own; test files that assert against code a later PR
deletes have to go first):

1. **PR 14a — delete the parity/conformance test harness.** All 59
   `server/http/remote_storage_*_test.go` files (~22,631 lines, entirely test code, zero
   production risk). These tests exercise both the `/system` handlers and `RemoteStorage`
   together; they must be deleted before either side, or PR 14b/14c break the build.
2. **PR 14b — delete `RemoteStorage` itself.** `internal/storage/store/remote_*.go` (impl +
   package tests, ~29,082 lines) plus the small `factory.go` wiring update
   (`createRemoteStorage`'s call site and the `"remote"` switch case — a few lines, not counted
   above). Also deletes `scripts/analysis/remote_storage_stub_rewrite.go` (a one-off dev tool
   whose only purpose was maintaining these files, per §10.3's guard). Does NOT yet touch
   `/system` — `RemoteStorage`'s wire calls are HTTP at runtime, not a Go import dependency on
   the handler package, so this compiles standalone.
3. **PR 14c — delete the `/system` route tier, last.** The `server/http/router.go` route block
   (953 lines) and the 29 proxy handler files (9,239 impl + 6,008 test lines). As the FINAL
   commit in this PR, not a separate one: remove `validateRemoteStorageNotServer` and the
   `storage.type: "remote"` config value's validation entirely — sequenced last on purpose, so
   at every intermediate commit up to this point, a misconfigured `storage.type: remote` still
   fails loudly (via this validator) rather than silently succeeding with nothing behind it.

### 10.3 CI guard added now (this PR)

`internal/storage/store/remote_storage_importer_allowlist_test.go`
(`TestNoNewRemoteStorageImportersOutsideAllowlist`) fails the build if any NEW non-test file
outside `internal/storage/store` references `store.RemoteStorage`/`store.NewRemoteStorage` — the
allowlist is today's exactly two real external references (`internal/storage/factory.go`,
`scripts/analysis/remote_storage_stub_rewrite.go`) and must only shrink toward PR 14, never grow.
A sibling test (`TestRemoteStorageAllowlistEntriesStillExistAndStillReference`) guards the
allowlist itself against staleness in both directions. Verified RED (a planted
`store.RemoteStorage{}` reference in `internal/core` was caught and reported by name) and GREEN
(the real, unmodified tree) before landing.

### 10.4 Still blocking

**One thing, and it was already known, not newly discovered: `internal/cli` (the old CLI) still
exists and still imports `internal/storage/store` — every one of §10.1's 20 ROUTED findings
stays live until Phase 5 deletes it.** PR 14 as scoped above (the `/system` route tier +
`RemoteStorage` + the conformance harness) does not require deleting the old CLI first — the old
CLI's embedded-mode commands would simply start failing at runtime against a `storage.type:
remote` config the moment `RemoteStorage` is gone (a config value that stops working, not a
compile break, since `internal/cli` depends on `internal/core`/`internal/storage`, not on
`RemoteStorage` directly) — but that IS a real, if narrow, regression for anyone still running
the old CLI in client mode against a real server, until Phase 5 formally retires it. Whoever
schedules PR 14a–c should confirm Phase 5's timeline is either already ahead of it, or accept
that narrow window explicitly, rather than deleting silently and discovering the gap from a
support ticket.
## 11. Phase 6 deletion progress (ADR-108 Decision C)

Tracks the 3 PRs in §7's "PR 14 (final)" plan, now split into one PR per deletion tier (14a/14b/14c)
to keep each under review size. Started only after the Phase 5 switch PR (§1) merged.

- **14a — RemoteStorage differential/parity conformance harness.** Deleted all 59
  `server/http/remote_storage_*_test.go` files (364 `Test`/`Fuzz` functions; net -22,639 lines).
  No standalone parity fuzzer existed only for this harness (checked every `func Fuzz` in
  `server/http/*.go`: the 5 that exist — `FuzzKeyorixHTTPAPISequence`, `FuzzConcurrentOpsLinearizable`,
  `FuzzMultiTenantIsolation`, `FuzzGRPCRESTSecretReadAuthzParity`, `FuzzCanarySecretLeakage` — are all
  independent, no `RemoteStorage`/`RealServer`/`conformance` references), so `scripts/fuzzing/targets.conf`
  needed no change. Same check for `docs/review-coverage.tsv`'s `internal/testutil/fuzzworld` row (its
  "server/http fuzz test files" clause still holds — those 5 fuzzers are the ones importing it, not any
  file in the deleted set) — no change needed there either.
  - `docs/security-closures.d/`: retired FIX-3-1551 (verification→`manual`, pkg/test→`-`, note prefixed
    `SURFACE REMOVED` — the RemoteStorage machine-identity-credential-revoke proxy this proved is being
    deleted in the same Phase, so the property is moot). `secret-delete-machine-actor-001` was NOT
    moot — its fixed code (`secrets_crud.go`'s `DeleteSecret` handler, an ordinary REST route Phase 6
    doesn't touch) is still live and had zero other coverage, so it was re-pointed at a new direct
    handler test (`TestDeleteSecret_MachineActorUsesScopedPermissionNotOwnerCheck`,
    `server/http/handlers/secrets_crud_s13_test.go`) instead of retired — red/green-verified against
    the real `isMachine` branch.
  - Two `server/http` guard tests broke on the deletion and needed re-pointing, not retiring, since
    the routes/properties they cover are still live (Phase 6 hasn't reached them yet):
    `system_write_ceiling_walk_test.go`'s `systemCeilingAllowlist` had 2 entries citing deleted
    `TestConformance_*` functions for `/system/project-memberships` routes — re-pointed at the
    already-existing, already-equivalent `TestG3Probe_CreateMembershipProxy_...`/
    `TestG3Probe_TransitionMembershipProxy_...` gap probes (no new test needed, these already proved
    the same ceiling). `node_credential_route_classification_test.go`'s `perActorCeilingCoverage` had
    2 dead wire-level entries (for the groups and risk-exception per-actor ceilings); removed them,
    leaving the still-live `internal/core`-level entries each route already had as its other,
    still-real, coverage.
  - `go build ./...`, `go vet ./...`, and the full `go test ./...` all green; `scripts/check-closures.sh`
    and `scripts/check-adr-conformance.sh` both green.
- **14b-1 — the old, thick CLI (`internal/cli`).** Deleted the whole tree (611 files, 110,460
  lines), its entrypoint (`main.go`, the `keyorix-legacy` build), and the tools that existed only to
  test/generate docs from it (`scripts/cli-parity-check.sh`, `scripts/cli-command-census.sh`,
  `scripts/smoke-legacy.sh`). 615 files, 111,209 lines total across both commits. `Makefile`/CI's
  `smoke-legacy` job/`docs/security-closures.d/` (6 embedded-mode-bug rows, all surface-removed)/
  `docs/review-coverage.tsv` (38 rows + the now-fileless root `.` package) all updated in a
  separate, smaller commit for review. `docs/cli-migration.md` and `docs/cli-split-inventory-census.md`
  (both generated FROM `internal/cli`) marked FROZEN rather than deleted — still the real
  old-command -> new-command reference, just no longer regeneratable.
- **14b-2 — RemoteStorage itself** (`internal/storage/store/remote_*.go`, `internal/storage/remote/`,
  the factory's `"remote"` case, `scripts/analysis/remote_storage_stub_rewrite.go`). The real
  footprint reached beyond those paths, confirmed by a repo-wide sweep for
  `store.RemoteStorage`/`store.NewRemoteStorage`/`internal/storage/remote` imports before finalizing
  scope (three more stray non-`remote_`-prefixed files inside `internal/storage/store` turned up
  this way: `store_s17_remote_test.go`, `store_s21_remote_test.go`, and a mixed file,
  `store_s28_test.go`, trimmed to keep its 17 `TestLocalStorage_S28_*` tests and drop 100+
  RemoteStorage-only ones). Landed as 3 commits:
  - **Storage (this track's own paths):** the bulk deletion, `internal/storage/factory.go`'s
    `"remote"` case removed (falls into the existing `default:` "invalid storage.type" error, updated
    to stop listing "remote" as valid), `internal/storage/store/entry.go`'s package doc + `RemoteStorage`
    struct/constructor/`putConditionalTransition` removed (kept `LocalStorage` and everything else).
    `gormdb.go`'s own independent `"remote"` rejection (a *different* function, still used by
    `server/admin`/`internal/encryptionops` — untouched, no RemoteStorage dependency) needed no change.
    One local test file (`local_failopen_stub_test.go`) used an AST-printing helper (`exprString`)
    that had lived in a deleted remote_*.go file — restored as a small helper in its only remaining
    caller. `docs/security-closures.d/` (1 more surface-removed row), `docs/review-coverage.tsv`
    (the now-gone `internal/storage/remote` package row), `docs/adr-conformance-enforced.tsv`
    (1 surface-removed row for the RemoteStorage half of the rate-limit ADR) updated.
  - **cross-track: CORE** (`internal/core/**`, not this track's paths — mechanically tied 1:1 to the
    storage deletion, not a design change; checked no overlapping open CORE PR first). Removed the
    dead `*remote.HTTPError` branch from `IsUserNotFound`/`IsSessionNotFound`/`IsSecretNotFound`/
    `IsSecretVersionNotFound` (`internal/core/storage/errors.go`) — local-sentinel behavior
    unchanged, verified red/green by breaking `IsUserNotFound` and confirming the new
    `TestIsXNotFound_SentinelAndWrapped` table test catches it. Of 4 RemoteStorage-referencing test
    files, none were pure delete-and-forget: `rate_limit_test.go` kept ~13 tests, dropped only the 1
    RemoteStorage-only test + its helpers; `password_remote_test.go` kept its 1 LocalStorage test
    (moved to `password_local_test.go`, file renamed since nothing "remote" was left);
    `user_notfound_backend_test.go` same pattern (kept the local test, renamed to
    `user_notfound_test.go`); `invitation_accept_remote_membership_test.go` was genuinely
    100% RemoteStorage and deleted outright. `login_lockout_remote_test.go` (not in the original
    4-file list — found via the `apiOKUser` helper it defined becoming unused once
    `password_remote_test.go` was gone) renamed to `login_lockout_unsupported_backend_test.go` with
    the dead helper removed; its own remaining test was already RemoteStorage-independent.
  - **cross-track: API** (`server/http/*.go`, top-level package, not `handlers/**`). Two RemoteStorage
    parity tests deleted outright (`user_notfound_backend_parity_test.go`, its 1 local subtest ported
    to a new `user_notfound_local_test.go`). Two more turned up only via a build-time chain reaction
    (`delete_environment_proxy_scope_test.go` used a helper defined in
    `delete_project_proxy_scope_test.go`): both are `/system`-proxy authorization-ceiling tests
    (`DeleteProjectProxy`/`DeleteEnvironmentProxy`) that merely used a real `store.RemoteStorage` as
    a convenient authenticated HTTP test client, not testing RemoteStorage itself — deleted rather
    than ported to a raw HTTP client, since their subject routes are the entire `/system` proxy tier
    14c deletes next anyway. **DECISION (review):** this leaves those two specific ceiling properties
    untested on `main` for the window between 14b-2 and 14c landing (both queued in the same session);
    accepted rather than porting throwaway test infra for a route about to be deleted regardless.
  - `go build ./...`, `go vet ./...`, `gofmt`, and the full `go test ./...` all green across every
    commit; `scripts/check-closures.sh`, `scripts/check-review-coverage.sh`, and
    `scripts/check-adr-conformance.sh` all green after the ledger updates above.

- **14b-1 — the old, thick CLI (`internal/cli`).** Deleted `internal/cli` (611 files,
  110,460 lines) + root `main.go` (its entry point) + 3 legacy-only scripts
  (`cli-command-census.sh`, `cli-parity-check.sh`, `smoke-legacy.sh`), plus the Makefile/CI/
  docs fallout: the `keyorix-legacy` build target and `smoke-legacy` CI job (its own comment
  pre-anticipated this removal), 38 stale `docs/review-coverage.tsv` rows (81 packages remain,
  down from 120), 6 `docs/security-closures.d/` rows retired as `SURFACE REMOVED`.
  `docs/cli-migration.md` and `docs/cli-split-inventory-census.md` frozen as historical record
  rather than deleted. CHANGELOG's switch entry updated from "removed entirely in Phase 6"
  (forward-looking) to "now removed entirely" (done) now that it's actually landed.
  - Rebasing this (originally built on top of 14a before 14a merged) onto the post-merge
    `origin/main` hit real conflicts, not just mechanical ones: 10 files under
    `internal/cli/{bundle,license,trust}` plus `command_census_test.go` had been modified by an
    unrelated, later-merged PR (`internal/trust` → `pkg/trust` import-path rename) — resolved
    as deletions (`git rm`) since this commit deletes the whole directory regardless of that
    rename. The Makefile conflicted for real: `VERSION_LDFLAGS` needed the OLD CLI's
    `internal/cli.version` symbol dropped (this commit's job) while KEEPING the already-renamed
    `pkg/trust.updateKeysB64`/`licenseKeysB64` paths (unrelated, already-landed rename); the
    `.PHONY` list and the `smoke`/`airgap-e2e` target block needed `keyorix-legacy`/
    `smoke-legacy` dropped while keeping `check-release-assets`/`airgap-e2e` (added by later,
    unrelated PRs after this branch's original divergence point).
  - `go build ./...` clean for all 3 modules (root, `cli/`, `migrate/`); `golangci-lint run
    ./...` clean for root and `cli/` (a real `unused` finding on 14a's own PR earlier in this
    same session — `createNodeToken` left dead by the harness deletion — is the reason this
    step ran golangci-lint explicitly rather than trusting `go vet`/`go test` alone); full
    `go test ./...` green for root, `cli/`, and `migrate/`; `check-closures.sh`,
    `check-review-coverage.sh`, `check-adr-conformance.sh` all green.

- **14b-2 — RemoteStorage itself, rebased onto the merged 14b-1.** Cherry-picked 14b-2's 3
  original commits onto the post-14b-1-merge `origin/main`. Two more modify/delete conflicts,
  same shape as 14b-1's: `internal/storage/store/remote_{rbac,secrets,sharing}.go` +
  `remote_wire_route_coverage_test.go` had been touched by 3 unrelated, later-merged snake_case
  wire-format PRs (#2098/#2149/#2156) — resolved as deletions, since this commit removes the
  whole `remote_*.go` tree regardless; `internal/core/password_remote_test.go` similarly touched
  by an unrelated bcrypt-cost test-speed PR — same resolution.
  - `TestRemoteStorageAllowlistEntriesStillExistAndStillReference` (the guard's own
    staleness-in-both-directions check) failed for real after the rebase: both allowlist entries
    (`internal/storage/factory.go`, `scripts/analysis/remote_storage_stub_rewrite.go`) were
    already gone by the time this rebased onto 14b-1 -- `remoteStorageImporterAllowlist` set to
    `map[string]string{}` (empty), matching the backlog's own instruction ("assert zero").
    `TestNoNewRemoteStorageImportersOutsideAllowlist` confirmed clean against the empty
    allowlist (zero remaining package-qualified `store.RemoteStorage`/`store.NewRemoteStorage`
    references anywhere in the repo).
  - `golangci-lint run ./...` (explicit, not skipped, per the lesson from 14a/14b-1) found 2
    more real `unused` findings the rebase's own build/vet/test pass missed: `apiAuditLogsPath`
    (a route constant only the now-deleted `remote_audit.go` ever referenced) and
    `queryBuilder.addPage` (a method no live caller reached). Investigating `addPage` found the
    whole `queryBuilder` type (`query.go`) had no remaining NON-test caller at all -- its doc
    comment named exactly the 3 files this PR deletes (`remote_secrets.go`, `remote_users.go`,
    `remote_audit.go`) as its only real consumers; every other method (`add`/`addUint`/
    `addString`/`addBool`/`addTime`/`addTags`/`String`) was only "used" by its own dedicated
    unit tests, not flagged individually by `unused` only because a test reference is enough to
    suppress that linter. Deleted `query.go` and `query_escape_test.go` wholesale, and extracted
    the `TestQueryBuilder_*` blocks out of `store_s4_test.go`/`store_max_test.go` (mixed in with
    unrelated coverage-sweep tests in both files) rather than deleting either file.
  - No `scripts/ci-test-legs.sh` change needed: checked (per the coordinator's own heads-up
    about `internal/storage/remote*` after 14b-1's stale-pin CI failure) and confirmed the only
    pin at this path is the whole-package `internal/storage/store` (still exists, unaffected --
    deleting files inside a package that itself survives doesn't orphan a package-level pin).
  - `go build ./...` and `golangci-lint run ./...` clean for root; `GOWORK=off golangci-lint run
    ./...` clean for `cli/`; full `go test ./...` green for root (3483 tests, 65 packages) and
    `cli/` (462 tests, 11 packages); `check-closures.sh` (54 verified, 1 known intermittent
    flake on a pre-existing, already-filed CORE-owned `system_viewer` role-lookup-ordering bug
    -- reran clean, not a regression from this PR), `check-review-coverage.sh` (80/80 packages,
    down from 81 -- `internal/storage/store` package itself survives, just fewer distinct rows
    since some remote_* files had their own ledger entries), `check-adr-conformance.sh` (10
    verified) all green.


- **14c-1/14c-2 — the `/system` route tier itself, last** (rebased onto merged 14b-1/14b-2;
  cherry-picked cleanly, zero conflicts). Deletes `server/http/router.go`'s 953-line `/system`
  route block (151 routes, per §10.2's own inventory) and all 28 handler implementation files
  (`server/http/handlers/*_proxy.go`, 9,239 lines) in 14c-1; retires ~80 files of now-dead
  test/registry surface in 14c-2 (guard tests, G3 gap-probe files, security-ceiling walk tests
  whose entire target population no longer exists).
  - **Zero-callers proof, repo-wide** (per direct instruction, beyond what §10's original
    inventory covered): `operator/` and `internal/k8ssync` — zero `/system/` references, either
    literal or constant-built. `migrate/` and `cmd/` — zero. `keyorix-sdks` (go/java/node/python)
    — zero. `web/src/services/system.ts` — exactly the 5 routes already confirmed live and
    already registered OUTSIDE the deleted block (`/system/info`, `/system/metrics` — built via
    `"/system"+pathMetrics`, missed by a first literal-string grep, confirmed by reading the
    route registration directly — `/system/auth-config`, `/system/encryption-config`,
    `/system/init`). `server/http/handlers/openapi.yaml` — exactly those same 5 paths
    documented, zero stale proxy paths to remove.
  - **The G3 `/system` authority campaign's 2 open gaps (`AddGroupMemberProxy`,
    `RemoveGroupMemberProxy`) are moot**: both routes, and the `system_proxy_g3_gap_probes_test.go`
    file tracking them as open findings, are deleted in 14c-2 — there is no longer a route for
    either gap to apply to.
  - Full verification surfaced 4 more real cross-track findings the mechanical deletion alone
    didn't catch (all fixed in this same PR, clearly labeled):
    - **`internal/core`** (2 allowlist guard tests failed for real): `g80_1530_machine_actor_attribution_guard_test.go`'s
      `auditAttributionAllowlist` still listed `audit_ingest_proxy.go:IngestAuditEventProxy`
      (deleted) — entry removed, doc comment corrected (1 direct `LogAuditEvent` caller outside
      `emitAudit` remains, not 2). `mfa_stepup_purpose_guard_test.go`'s `mfaStepUpPurposeAllowlist`
      still listed `mfa_stepup_proxy.go:63` (deleted) — entry removed.
    - **`server/faultops`** (2 tests failed for real, only visible once the FULL test suite ran,
      not just build/vet): the fault-injection `opCatalog` (`opcatalog_test.go`) had 6 REST
      operation entries hitting now-404 `/system/*` routes (`machine-identities` create+transition,
      `groups` create+delete, `projects` delete, `break-glass revoke`, `secret-dependencies
      exclusive`) — each a full `Key`/`Setup`/`Execute` struct entry, removed along with the 2
      helpers (`createMachineIdentityForFuzz`, `machineIdentityWireForFuzz`) that existed only to
      serve them. Mirrored the same 6 keys' removal in `inventory_overrides_test.go` (the
      hand-maintained classification file) and a stale fuzz-seed reference in
      `fuzz_storage_fault_operations_test.go`, then regenerated
      `inventory_registry_generated_test.go` via `REGEN_INVENTORY=1` (245 keys, down from 251) --
      `TestOperationTableRatchet` and `TestOpCatalog_SucceedsWithNoFaultArmed` both green after.
  - `go build ./...` and `golangci-lint run ./...` clean for root (explicit `cd <path> &&` prefix
    used for every lint invocation this PR, after twice catching a silently-wrong-cwd false
    "clean" result mid-session — see the report for the full incident); `GOWORK=off golangci-lint
    run ./...` clean for `cli/`; full `go test ./...` green for root, `cli/`, and `migrate/`;
    `check-closures.sh` (55 verified), `check-review-coverage.sh` (80/80), `check-adr-conformance.sh`
    (10 verified), `assert_leg_completeness` (no `scripts/ci-test-legs.sh` change needed — no pin
    named any of the deleted files/packages individually) all green.
