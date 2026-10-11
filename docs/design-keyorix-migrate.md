# Design: `keyorix-migrate`

**Status:** Draft (2026-09-25, updated 2026-09-25 with Andrei's decisions on all-versions
scope and PAT UX, and PR #2077's review items — private CA, credential file/stdin, pinned CI
images + OpenBao leg). Implements the decision recorded in
`docs/cli-split-inventory.md` §PR5 ("`secret import --source {vault,aws,azure,gcp}`
is moved out, not dropped") and ADR-108. The old thin-CLI's `secret import` now
supports file mode only (`cli/cmd/secret_import.go`); the live-credential import
modes move here. The old monolithic CLI's Phase 5 deletion is gated on this tool
existing for at least the Vault source (customers' most common migration path —
an existing, often orphaned Vault install).

## Why a separate module and binary

ADR-108's thin CLI (`cli/`) carries no cloud SDKs in its SBOM — that is the whole
point of the split. A Vault/AWS/Azure/GCP importer needs exactly those SDKs (or,
for Vault, a hand-rolled HTTP client against its KV API — see "Vault client"
below). Bolting that onto `cli/` would reintroduce the dependency the split
removed. `keyorix-migrate` is therefore its own Go module (`migrate/go.mod`), its
own binary, built and SBOM'd separately — the same shape `cli/` and `operator/`
already use in this repo, one more sibling, not a new pattern.

(Step 3, below, delivers the AWS/Azure/GCP sources; each is additionally behind
its own build tag so an operator who only needs a subset isn't forced to carry
every SDK's SBOM weight — see "Step 3" for the size numbers.)

## Module boundaries (compiler-enforced, per `cli/`'s precedent)

- `migrate/go.mod` has **no `replace` directive to `../`** and does not depend on
  the root module at all — unlike `cli/`, which the split explicitly kept
  standalone from the main module too (ADR-108 Decision A). `migrate` is
  stricter than even that: it doesn't need `internal/apiclient`'s generator
  tooling to *run* from the main module, only to *generate* its own copy (see
  below).
- `migrate` must not import `internal/core`, `internal/storage`, or anything
  under `internal/` — a `depguard`-style test (`migrate/internal/depguard_test.go`,
  mirroring `cli/`'s own boundary guard) fails the build if it ever does. This
  is the same "ceiling checked against the actor, not asserted in a comment"
  discipline the rest of this repo uses for security boundaries — here the
  boundary is architectural, not authz, but the mechanism (a test that inspects
  the actual import graph, not a doc comment) is the same idea.
- It talks to Keyorix **only** through the public REST API, authenticated with a
  Personal Access Token (`--token` / `$KEYORIX_TOKEN`), exactly like `cli/`'s
  `Authorization: Bearer` pattern (`cli/cmd/client.go:newAPIClient`). It never
  opens the database directly — there is no local/embedded mode, matching
  ADR-108's Decision A for the thin CLI (this tool is even further from the
  server than `cli/` is: it has no server-side counterpart at all).
- Reads from the source (Vault, later AWS/Azure/GCP) use that source's own SDK
  or HTTP API. Nothing about the source read path touches Keyorix's storage
  layer.

## Generated API client

Reuses `cli/`'s exact approach (`cli/Makefile`'s `client` target,
`cli/internal/apiclient/gen/filterspec.go`): `oapi-codegen` against a filtered
copy of `server/http/handlers/openapi.yaml`, containing only the paths this tool
needs. `migrate` generates its **own** copy
(`migrate/internal/apiclient/{types,client}.gen.go`) via its own filterspec
program and its own `Makefile` target — it does not import `cli/internal/apiclient`
(that would violate "no dependency on `cli/` or the main module" just as much as
importing `internal/core` would; `cli/` is not a dependency-safe leaf either,
since it itself is a full sibling module with its own release cadence).

Initial `keptPaths` for `migrate`:

```
/api/v1/version                              # skew check, same method as cli/
/api/v1/projects
/api/v1/projects/{id}/environments
/api/v1/secrets
/api/v1/secrets/{id}
/api/v1/secrets/by-name
/api/v1/auth/tokens                          # pre-flight (see "PAT provisioning UX")
```

`CreateSecretJSONBody` already carries a `Metadata map[string]string` field
(`secrets_crud.go:88`, accepted since #1808) that is stored on `SecretNode.Metadata`
and round-trips back out through `GetSecret` (which serializes the full
`*models.SecretNode`, unlike the narrower `Secret`/`SecretGetResult` response
schemas `cli/`'s filtered spec documents — a real gap in the documented response
shape, not a missing feature; see "Idempotency" below for how this tool reads it
back without waiting on that schema fix). `migrate` decodes it via a local raw-JSON
DTO, matching the `decodeData[T]` fallback convention `cli/cmd/client.go` already
established for exactly this class of gap — not a new pattern.

## Source-to-Keyorix mapping (dry-run plan)

Every run builds a **mapping plan** before touching anything:

| Source | Keyorix |
|---|---|
| Vault path (e.g. `secret/data/team-a/db-password`) | `--project`/`--environment` (required flags, numeric IDs — matching `cli/`'s PR5 convention of taking scope by ID, not by name) + a deterministic secret name derived from the path's last segment(s), sanitized the same way the old CLI's `sanitizeSecretName` did |
| Vault KV field(s) | one secret per field when the leaf has more than one field (`<path>-<field>`), one secret named after the path when it has a single `value` field — same shape `cli/cmd/secret/source_vault.go`'s `readLeaf` already uses, ported rather than redesigned |
| Vault custom-metadata / KV v2 metadata | Keyorix `metadata` map, prefixed `vault.` to avoid colliding with this tool's own bookkeeping key (see Idempotency) |

The plan is a report, not an action: for every candidate it states `create`,
`update` (idempotent match, value differs), `skip` (idempotent match, value
identical), or `conflict` (a secret already exists at the target name whose
stored source-id metadata does not match this run's source, or is absent —
i.e., a name collision with something migrate didn't create). Nothing is
written to Keyorix until `--apply` is passed. `--apply` re-derives and re-checks
the plan immediately before executing each item (not trusting a plan computed
and shown seconds or minutes earlier) — the source or the target could have
changed in between.

**Oversized values (#2544).** No API exposes the target's configured
`secrets.limits.max_secret_size`, so the plan checks each value against the two
bounds it can know (`target.DefaultMaxSecretSize` / `target.MaxSecretSizeHardCeiling`,
mirrors of the server constants pinned by `TestSizeLimitsMatchServer`). A value
above the 1 MiB hard ceiling is planned as `error` naming the path, its size and
the limit, and is never sent: no server configuration can accept it. A value
above the 64 KiB default stays `create`/`update` but carries a warning reason,
because the target's limit may have been raised. A server-side 413 at apply time
is classified as `target.ValueTooLargeError`. Either way the JSON report line
carries `error_kind: "value_too_large"`, the human line shows `toolarge`
instead of `error`, and the run summary counts that class separately. The run
continues with every other item.

## Idempotency

Every secret `keyorix-migrate` creates gets a stable **source-id** written to
its `metadata` map at creation time:

```
metadata["migrate.source"]    = "vault"
metadata["migrate.source-id"] = sha256("<vault addr>|<mount>|<kv-version>|<full path>|<field, if exploded>")
```

A re-run looks up the deterministic target name via `GET /secrets/by-name`
(scoped to `--project`/`--environment`, same call `cli/`'s `secret get --name`
uses), and if found, reads `migrate.source-id` back via `GET /secrets/{id}`
(the full `SecretNode` JSON — see "Generated API client" above). Three
outcomes:

1. **No existing secret** → plan says `create`.
2. **Existing secret, source-id matches** → this tool made it on a prior run.
   Compare values (an extra unauthenticated-to-report bit is not implied — this
   tool has to read the source and target values anyway to import/compare
   them, and neither can be logged, see "Never log secret values" below): `skip`
   if identical, `update` if the source changed.
3. **Existing secret, source-id missing or different** → a name collision with
   something this tool did not create (hand-created secret, a different
   source's migration, a stale/renamed source path reusing an old name).
   Plan says `conflict` and the item is never written without `--force`
   (a separate, explicit flag from `--apply`, required in addition to it) —
   the default is to stop and let the operator resolve the collision by
   renaming one side, matching this repo's "fail closed and loud, never
   silently merge" convention for exactly this class of collision (see
   `docs/normalization-boundary-design-1642.md`'s "backfill fails on collision,
   never merges" precedent, memory `[[normalization-boundary-design-1642]]`).

The name-based lookup is the primary key (cheap: one `by-name` call per item,
no full-project listing); the source-id in metadata is the correctness check
that turns an accidental name collision into a loud `conflict` instead of a
silent overwrite or a silent duplicate.

## Never log, print, or report a secret value

The per-item result report (JSON + human-readable, one line per source item) —
consistent with this repo's "assert the effect, not the return value" testing
discipline (`CLAUDE.md`'s "To test a fails-open path" entry) — carries: source
path, target project/environment/name, outcome (`created`/`updated`/`skipped`/
`conflict`/`error`), and on error, the error message. It never carries a
`value` field, a diff of values, or an error message interpolated from a value
(a Vault or Keyorix API error message could echo back part of a payload in
some failure modes — errors from both clients are sanitized to strip anything
that looks like it echoes request/response body content before it reaches the
report). The canary-value test (Step 2) plants a known marker value and greps
every byte this tool writes to stdout, stderr, and the JSON report for it.

## Audit-trail origin (#2545)

Every `Create`/`UpdateValue` sends `X-Keyorix-Client-Origin:
keyorix-migrate/<version> source=<source locator>` (e.g.
`source=vault:secret/team-a/db#password`); the locator is the same
human-readable path the report already prints, and never a value. The server's
`CreateSecret`/`UpdateSecret` handlers append it to that write's
`secret.created`/`secret.updated` audit description as
`[client-asserted origin: …]` (sanitized, capped at 256 runes;
`core.ClientOriginHeader`). It is deliberately a labelled note, not
attribution: any caller can send the header, so `actor_type` and every other
attribution field still come only from the authenticated principal. A
structured audit column was declined (it would need a schema change for a value
no server-side check can verify). Only the HTTP surface records it — this tool
never uses gRPC.

## Resume

`--apply` writes each item's outcome to the JSON report incrementally (flushed
per item, not buffered to the end) so a killed-mid-run process leaves a
truncated-but-valid-prefix report. A re-run with the same source/target flags
recomputes the plan fresh (per-item `by-name` + source-id check, as above) —
already-created items resolve to `skip` (or `update`, if the source changed
since), so a resume is just an ordinary re-run, not a special mode. There is no
separate "resume from report" flag; the idempotency check already makes every
run resumable by construction. This is deliberate: a special-cased resume path
would be a second, less-exercised code path to keep correct, when the ordinary
path already has to be correct for every subsequent run anyway (this repo's
"a mechanism must be validated against a failure that actually happened"
principle applied narrowly — the realistic failure here is "process killed
mid-run," which the ordinary idempotency path already has to survive).

## Auth: token and AppRole (Vault), namespaces

- **Token auth**: `--vault-token` / `$VAULT_TOKEN`, same as the old CLI's
  `source_vault.go`.
- **AppRole auth**: `--vault-role-id`/`--vault-secret-id` (or their `$VAULT_ROLE_ID`/
  `$VAULT_SECRET_ID` env equivalents) exchanged for a token via
  `POST {addr}/v1/auth/approle/login` at startup; the resulting client token is
  used for all subsequent KV calls exactly like a directly-supplied token. Not
  ported from anywhere in this repo (the existing `source_vault.go` and
  `connect/vault.go` are both token-only) — new code, small surface (one POST,
  one field extracted from the response).
- **Namespace** (Vault Enterprise / OpenBao): `--vault-namespace` /
  `$VAULT_NAMESPACE`, sent as the `X-Vault-Namespace` header on every request
  (KV and AppRole login alike) — Vault's own documented mechanism, nothing
  bespoke.

## Vault client: ported, not reused directly

`migrate` cannot import `cli/cmd`'s `source_vault.go` (unexported, and `cli/`
is not a dependency-safe leaf per the module-boundary rule above) or
`internal/connect/vault.go` (inside the forbidden `internal/` tree). Both are
read *once per call* and single-path; `migrate` needs recursive-tree KV walk
plus AppRole/namespace, which neither existing implementation has. The design
carries forward the parts worth keeping without copy-pasting blindly:

- `internal/connect/vault.go`'s `resolveKVMountVersion` (query
  `sys/internal/ui/mounts/<path>` rather than sniff response shape) is the
  correct way to distinguish KV v1/v2 — ported over `source_vault.go`'s
  `--vault-kv-version` flag-driven approach, since `keyorix-migrate` walks
  whatever mounts a customer's real Vault has and should not require the
  operator to already know each mount's KV version up front.
- `source_vault.go`'s recursive `walk`/`list`/`readLeaf` shape (LIST to find
  children, recurse into `/`-suffixed keys, read leaves) is the right
  traversal and is ported directly — this is exactly the "recursive paths"
  requirement.
- Both existing clients' redirect-refusal (`CheckRedirect: http.ErrUseLastResponse`
  — an X-Vault-Token-carrying redirect must never be followed to an
  attacker-controlled host) and response-size caps are carried forward
  unchanged; there is no reason to weaken either for this tool.
- **"All versions" (deferred — Andrei, 2026-09-25).** Keyorix secrets are
  versioned already (`SecretVersion`), so importing "all versions" most
  naturally maps to creating the Keyorix secret at its oldest Vault version
  and then adding a new Keyorix version per subsequent Vault version, in
  order — but the `by-name`/create/update API surface `migrate` is scoped to
  (see `keptPaths` above) does not include a "create version" route yet.
  **Decision: defer.** `--all-versions` is accepted as a flag but returns a
  clear, explicit "not yet supported" error (`vaultsource.Client.Walk`, tested
  in both `vault_test.go` — no live Vault needed, the check is `Walk`'s first
  line — and `vault_integration_test.go` against a real server) rather than
  silently behaving like latest-only. "Latest only" (the default) covers the
  primary migration case (get off Vault); versioned import can be scoped
  properly once there's a real customer ask for it, at which point it needs
  its own design pass for the `POST /secrets/{id}/versions` route above.
  **What ships now instead:** every imported secret records which source
  version it came from, even though only the latest is ever imported —
  `metadata["migrate.source-version"]` (Vault KV v2's `version` number) and
  `metadata["migrate.source-created-at"]` (KV v2's `created_time`), written
  by `plan.Apply`'s `Create` branch alongside `migrate.source-id`/
  `migrate.source`. Both are empty for a source with no version concept (Vault
  KV v1) — the metadata keys are omitted entirely rather than written empty.
  This means a future all-versions implementation can tell, for every secret
  already imported under "latest only," exactly which version it captured,
  without re-deriving it from Vault (which may have moved on by then).
- **Skipped items are reported, not silently dropped (Andrei, 2026-09-25).** A
  KV v2 leaf whose latest version is soft-deleted or destroyed is real data
  `keyorix-migrate` chose not to import, not an absence — it must show up in
  the plan/report as `skip` with a reason (`"version N was soft-deleted at
  <time>"` / `"version N was destroyed"`), never silently vanish the way the
  original implementation did. `vaultsource.Client.Walk` returns a second
  slice, `[]Skipped{Path, Reason}`, alongside the imported entries; `cmd/vault.go`
  turns each into a `plan.Item{Outcome: Skip}` that flows through the same
  report as every other item. The same rule covers a field with an empty (or
  JSON `null`) value, a field with an empty name, and a leaf with no fields at
  all (#2543): each is a `skip` with a reason (multi-field leaves report as
  `path#field`), never absent from the report — and a `null` is never
  stringified into a literal `"<nil>"` secret (`TestWalk_EmptyValuesAreReportedAsSkips`).
  **A correction found while building this, not merely designed:** the
  original implementation (and this repo's existing `internal/connect/vault.go`
  `GetSecret` doc comment and `cli/cmd/secret/source_vault.go`, neither of
  which this module depends on) assumed a soft-deleted/destroyed KV v2 read is
  "a 200 OK, not a 404." Verified directly against a real Vault 1.15 server
  (`TestIntegration_KVv2_RecursiveWalk`), **that assumption is wrong**: it is
  a 404, carrying the same `{"data": null, "metadata": {...}}` envelope a 200
  read would. The fix (`vaultsource.read`, via a new `doRawRead` that returns
  the body on both 200 and 404) reads the body regardless of status and lets
  the decoded metadata — not the HTTP status — decide whether the path is
  soft-deleted/destroyed (metadata present, e.g. `version` ≥ 1) or genuinely
  never existed (`{"errors":[]}`, no `data` key, metadata all zero-valued).
  This module's own doc comments have been corrected; the two pre-existing
  files above were not touched (out of scope — see CLAUDE.md's reachability
  discipline: this finding is specific to the data-read-on-delete path, not a
  claim about either file's own call paths, which this migration didn't
  trace).

## Step 3: cloud sources (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)

Three new packages (`migrate/internal/awssource`, `azuresource`, `gcpsource`) implement the
exact same contract as `vaultsource`: a `List`/`Walk`-shaped method returning entries plus
skipped items with reasons, no direct Keyorix write, and the identical dry-run/`--apply`/
idempotency/resume/never-log-a-value guarantees documented above (`cmd/aws.go`, `cmd/azure.go`,
`cmd/gcp.go` are the same shape as `cmd/vault.go`, sharing the mapping and intra-batch
collision-detection logic via `cmd/cloud_common.go` rather than each re-deriving it).

- **Auth**: each provider's own standard default credential chain only (AWS: env/profile/
  IMDS/IRSA via `aws-sdk-go-v2/config.LoadDefaultConfig`; Azure: `azidentity.DefaultAzureCredential`;
  GCP: Application Default Credentials) — never a Keyorix config field or a CLI flag, matching
  `internal/connect`'s own three connectors' precedent. The only source-side flags are the ones
  that pick WHAT to read (`--region`, `--vault-url`, `--gcp-project`, `--name-prefix`), never a
  secret-bearing one.
- **Read logic is ported, not shared**: `migrate` cannot import `internal/connect`
  (`internal/` is forbidden by the module boundary above), so each package re-implements the
  same hardening `internal/connect/awssm.go`/`azurekv.go`/`gcpsm.go` already apply to their
  single-ref `GetSecret` — the empty-string-value bug class (`SecretString`/`Value` being a
  non-nil pointer to `""` must not read as "has a value"), redirect refusal and a response-size
  cap for the two HTTP-based providers (`migrate/internal/httpsafe`, a migrate-owned copy of
  `hardened_client.go`'s two safeguards), and GCP's `grpc.MaxCallRecvMsgSize` cap. What's new
  (LISTING every secret, not just resolving one ref) has no precedent to port from — connect's
  connectors only ever read a single caller-supplied reference.
- **`--split-json`**: a JSON-object secret value explodes into one Keyorix secret per top-level
  key (`migrate/internal/splitjson`, shared by all three providers — the decode/sort/coerce
  rules are identical regardless of source) instead of importing the whole string as one secret
  (the default). A binary secret value (AWS `SecretBinary`) is skipped with a reason, never
  base64-imported the way `internal/connect/awssm.go`'s single-ref `GetSecret` does — there is
  no live Keyorix consumer expecting a base64 string here the way a dynamic connector's caller
  might.
- **Deleted/disabled/destroyed secrets are skipped, reported, never silently dropped** — the
  same discipline as Vault's soft-deleted KV v2 leaf: AWS excludes pending-deletion secrets from
  `ListSecrets` by default, checked again defensively from `DeletedDate` on the listed entry;
  Azure's `SecretProperties.Attributes.Enabled` is checked before ever calling `GetSecret` (Key
  Vault's data-plane read does not itself refuse a disabled secret); GCP's `SecretVersion.State`
  (`DISABLED`/`DESTROYED`) is checked via `GetSecretVersion` before `AccessSecretVersion`, and a
  secret with no versions at all (`GetSecretVersion` returning `NotFound`) is its own skip
  reason rather than a hard error aborting the whole run.
- **Intra-batch name collisions** (`cmd/cloud_common.go`'s `splitIntraBatchNameCollisions`): a
  risk `--split-json` introduces (two cloud source items in the SAME run landing on the same
  sanitized Keyorix name) that turned out NOT to be Vault-specific once checked directly:
  `sanitizeSecretName` collapses both `/` and a literal `-` to the same separator, so two
  genuinely distinct Vault paths (e.g. `a/b/c` and `a/b-c`) can sanitize to the identical name —
  "KV paths are unique by construction" is true and says nothing about their SANITIZED names also
  being unique. `plan.BuildPlan`'s per-item, independent `LookupByName` calls cannot see either
  case (both read not-found and each plan as `Create`); `cmd/vault.go`'s `runVault` now runs the
  same guard `cmd/aws.go`/`cmd/azure.go`/`cmd/gcp.go` use, before calling `BuildPlan`, reporting
  every occurrence after the deterministic winner (see below) as `conflict`, never a silent
  double-create. The winner is chosen by sorting candidates on `SourceID` first, not by
  whichever happened to appear first in the source's own list/walk order — that order is not
  guaranteed stable run to run (a source's map iteration, an API's pagination, or Vault's own
  KV tree walk order), so a winner that depended on it would make which of two colliding items
  gets created and which gets flagged nondeterministic for identical input, merely reordered.
- **Binary size is opt-out, not opt-in**: each provider's SDK is large enough to matter (GCP's
  gRPC + Google API dependency tree most of all — measured +14.4MB over the Vault-only 10.0MB
  baseline binary, vs. +4.0MB for AWS and +3.2MB for Azure). All three compile in by default
  (`nomigrate_aws`/`nomigrate_azure`/`nomigrate_gcp` build tags default OFF, i.e. the provider is
  included), so the tool works against any source out of the box; an operator who only needs a
  subset can drop the rest with `-tags nomigrate_gcp`, etc. See `docs/migrate-from-cloud.md`'s
  size table.
- **Testing**: unit tests per provider against an SDK-level fake (no live cloud account, no
  network) covering list pagination, the empty-value bug class, the deleted/disabled/destroyed
  case, `--split-json`, and a canary-value test (a distinctive marker used as a real secret
  value, asserted to appear only in `Entry.Value`/`Entry.Field`, never in a `Locator` or
  `Skipped.Reason`) — the same property Vault's canary test proves, at the unit level rather
  than through a live integration harness, since none of the three cloud SDKs has a
  self-hostable fake server the way Vault/OpenBao do. The resume mechanism itself needs no new
  per-provider test: `plan.BuildPlan`/`Apply` are already source-agnostic
  (`internal/plan/plan_test.go`), so `cmd/cloud_common_test.go` proves resume once, directly
  against `cloudentry.Entry`-shaped input, rather than standing up a third redundant
  Vault-shaped e2e harness per provider.

## PAT provisioning UX (confirmed — Andrei, 2026-09-25)

`cli/` already has `pat.go` (`keyorix pat create`) for minting a token;
`keyorix-migrate` assumes the operator already has one in hand
(`--token`/`--token-file`/`$KEYORIX_TOKEN`), matching `cli/`'s own precedent of
not auto-provisioning credentials. Confirmed, with three additions:

1. **Pre-flight check.** Before printing the dry-run plan, and again
   immediately before `--apply` executes (the plan may have been shown
   minutes earlier), `target.Client.Preflight` calls `GET /api/v1/auth/tokens`
   (added to `keptPaths`) and identifies the caller's own token among the
   list by matching `TokenPrefix` — `raw[:len("kx_pat_")+6]`, mirroring
   `internal/core/pat.go`'s own construction of that field (duplicated as a
   constant rather than imported; `migrate` cannot depend on `internal/core` —
   see "Module boundaries"). When identified, it fails fast on: revoked;
   expires within the next hour (or already expired); `project_scope`/
   `environment_scope` set and not matching the target; or `scopes` non-empty
   and containing none of `"*"`, `"secrets.*"`, `"secrets.write"` (ADR-042's
   scope allowlist — empty scopes means "inherits the owner's full
   permissions," per `openapi.yaml`'s `createPAT` doc, so that case passes).
   A token this tool **cannot identify** (a machine token, or a future prefix
   scheme) skips the scope/expiry checks without failing — `ListPATs`
   succeeding already proves the token authenticates at all, so an
   identification miss is not evidence of invalidity, only of "can't say
   anything more specific." This is a real (if best-effort) write-authorization
   check, not merely a read check: it inspects the PAT's own server-enforced
   scope declaration rather than attempting a mutating call to find out.
2. **Credential file/stdin.** `--token`, `--vault-token`, and
   `--vault-secret-id` each have a sibling `--*-file` flag (a path, or `"-"`
   for stdin) — `resolveCredential` (`cmd/credentials.go`) applies the
   precedence plain-flag (warns) → file/stdin → env var. Passing a credential
   directly on the command line warns to stderr, naming the flag and never
   the value (`warnInsecureFlag`, ported from `cli/cmd/secret.go`'s function
   of the same name) — visible via `ps`/`/proc` and saved to shell history.
   **Env vars remain the documented default** (`$KEYORIX_TOKEN`,
   `$VAULT_TOKEN`, `$VAULT_SECRET_ID`, …) — no warning for that path.
3. **Least-privilege recipe.** `docs/migrate-from-vault.md` (step 4)
   documents minting a project/environment-scoped PAT
   (`keyorix pat create --project-id --environment-id --scope secrets.write
   --expires <~24h>`) for a migration run, and revoking it afterward.

## Private CA (`--vault-cacert`/`--vault-capath`) — PR #2077 review item 1

Most on-prem and air-gapped Vaults — this tool's target customers — use an
internal CA. `vaultsource.Config.CACertPath`/`CACertDir` (flags
`--vault-cacert`/`--vault-capath`, env `$VAULT_CACERT`/`$VAULT_CAPATH`,
matching Vault's own CLI convention) build the HTTP client's `tls.Config.RootCAs`
**exclusively** from the given cert(s) — replacing, not appending to, the
system trust store, since pinning to a specific CA is the point. **There is no
skip-TLS-verify option anywhere in this package** — `vault_test.go`'s
`TestNoSkipVerifyEscapeHatch` greps the package source for an
`InsecureSkipVerify:` field assignment and fails the build if one appears, so
this stays true by construction, not by review discipline alone.
`TestClient_PrivateCA` proves both directions against an `httptest.NewTLSServer`:
reachable with the matching CA cert configured, unreachable (TLS verification
genuinely failing, not merely "an option exists") without it.

## Testing (Step 2, Vault)

- **CI integration test**: a service container running Vault (pinned by
  digest: `hashicorp/vault@sha256:0450896c…`) alongside an `httptest` fake
  Keyorix implementing exactly the four endpoints `internal/target.Client`
  calls, under the same `{"data": ...}` envelope every real handler uses
  (`internal/e2e`) — the "an httptest Keyorix" option this design originally
  named as an alternative to a full `keyorix-server` binary, since it
  exercises the real generated `apiclient`'s HTTP wire encoding without the
  overhead of bootstrapping a real server. `vaultsource`'s own integration
  suite (`vault_integration_test.go`) separately covers KV v1/v2 read/walk,
  AppRole, namespaces, custom-metadata, and version/created-time extraction
  directly against Vault. Both suites are `VAULT_ADDR`-gated
  (`default-ci` per `docs/security-closures.d/`'s verification tiers — a skip
  is only expected when `VAULT_ADDR` is unset, which CI's service container
  ensures it never is). **PR #2077 review item 4:** the whole suite also runs
  once per CI invocation against OpenBao (`openbao/openbao@sha256:05d777d6…`,
  a matrix leg, not a one-off manual check) — verified to need zero client
  code changes (OpenBao's KV/AppRole HTTP API is wire-compatible; only its
  dev-mode bootstrap env vars differ, `BAO_DEV_*` vs `VAULT_DEV_*`, handled by
  setting both unconditionally in the CI service block).
- **Canary-value test** (`internal/e2e/TestEndToEnd_CanaryValueNeverLogged`):
  plant one Vault secret with a distinctive, greppable value; assert it
  appears nowhere in this tool's JSON or human-readable report (only in the
  actual Keyorix secret value, fetched back via the fake server to confirm
  the import worked) — see "Never log, print, or report a secret value"
  above.
- **Resume test** (`internal/e2e/TestEndToEnd_ResumeAfterPartialApply`): apply
  only the first item of a multi-item plan (simulating a kill mid-run),
  rebuild the plan fresh from scratch — the actual resume mechanism, see
  "Resume" above — and apply the rest; assert the already-applied item
  resolves to `skip` on the second pass and the final Keyorix secret count
  matches the source item count exactly (no duplicates).
- **Soft-deleted/destroyed skip test**
  (`vault_integration_test.go/TestIntegration_KVv2_RecursiveWalk`): seed a KV
  v2 leaf, soft-delete it, and assert `Walk` reports it in the `skipped`
  slice with a reason mentioning "soft-deleted" — not in `entries`, and not
  silently absent from both (the bug this test caught while being written;
  see "Skipped items are reported, not silently dropped" above).
