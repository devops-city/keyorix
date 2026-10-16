# Keyorix CLI reference

<!-- GENERATED from the command tree by `keyorix docs markdown`; do not edit.
     Regenerate: make -C cli docs   (TestCLIReferenceIsFresh fails when this file is stale). -->

keyorix is the Keyorix CLI. It talks to a Keyorix server exclusively over the REST API; it has no local database mode. Host-side operations (config/keys/database setup, encryption key rotation) are "keyorix-server admin", a separate command.

## Global flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ca-file` | `string` | — | PEM CA/certificate file to trust for the server's TLS certificate, instead of the system roots (or set KEYORIX_CA_FILE, or: keyorix config set ca_file \<path\>) |

## Commands

- [`keyorix access-review`](#keyorix-access-review) — Review who has role-based access to a project's secrets (ISO 27001 A.5.18)
- [`keyorix anomalies`](#keyorix-anomalies) — Manage anomaly detection alerts
- [`keyorix audit`](#keyorix-audit) — Verify and export the tamper-evident audit trail
- [`keyorix billing`](#keyorix-billing) — FinOps billing and usage reports (requires billing license feature)
- [`keyorix break-glass`](#keyorix-break-glass) — Self-service emergency access (incident response)
- [`keyorix bundle`](#keyorix-bundle) — Air-gap update bundles: verify and import offline
- [`keyorix change-password`](#keyorix-change-password) — Change your own password (drops your other sessions)
- [`keyorix completion`](#keyorix-completion) — Generate the autocompletion script for the specified shell
- [`keyorix compliance`](#keyorix-compliance) — Deployment controls-posture report (ISO 27001 / SOC 2 / NIS2 / DORA)
- [`keyorix config`](#keyorix-config) — Show or change CLI settings stored with your credentials
- [`keyorix docs`](#keyorix-docs) — Print the CLI reference (Markdown) or its man page
- [`keyorix dynamic-secret`](#keyorix-dynamic-secret) — Issue and manage on-demand database credentials (dynamic secrets)
- [`keyorix group`](#keyorix-group) — Manage groups
- [`keyorix hygiene`](#keyorix-hygiene) — Deployment-wide secret-hygiene rollup across all projects (admin)
- [`keyorix invite`](#keyorix-invite) — Manage project invitations
- [`keyorix legal-hold`](#keyorix-legal-hold) — Deployment-wide legal hold — block purges to preserve records (A.5.34)
- [`keyorix license`](#keyorix-license) — Offline license: install and check status
- [`keyorix login`](#keyorix-login) — Authenticate to a Keyorix server and store the resulting token
- [`keyorix logout`](#keyorix-logout) — Revoke the stored session and forget it locally
- [`keyorix machine`](#keyorix-machine) — Manage machine identities
- [`keyorix mfa`](#keyorix-mfa) — Manage MFA (multi-factor authentication)
- [`keyorix notification`](#keyorix-notification) — Manage notifications and notification channels
- [`keyorix pat`](#keyorix-pat) — Create and manage personal access tokens
- [`keyorix project`](#keyorix-project) — Manage projects
- [`keyorix rbac`](#keyorix-rbac) — Role-Based Access Control management commands
- [`keyorix request`](#keyorix-request) — Manage project access requests
- [`keyorix risk`](#keyorix-risk) — Risk register — governed, time-bound exceptions to control gaps (A.5.8)
- [`keyorix rotation`](#keyorix-rotation) — Manage secret-rotation policies and see rotation posture
- [`keyorix run`](#keyorix-run) — Inject secrets as env vars and run a command
- [`keyorix secret`](#keyorix-secret) — Manage secrets
- [`keyorix share`](#keyorix-share) — Share secrets with users and groups
- [`keyorix sod`](#keyorix-sod) — Separation-of-duties policies and violations (ISO 27001 A.5.3)
- [`keyorix status`](#keyorix-status) — Show the configured server, login state, and version-skew check
- [`keyorix system`](#keyorix-system) — Server info and on-demand admin job triggers
- [`keyorix trust`](#keyorix-trust) — Air-gap signing-key tooling (ed25519 keypairs for update bundles / licenses)
- [`keyorix usage`](#keyorix-usage) — View usage and activity reports
- [`keyorix user`](#keyorix-user) — Manage users
- [`keyorix version`](#keyorix-version) — Print the CLI version and the API version it targets

## `keyorix access-review`

Review who has role-based access to a project's secrets (ISO 27001 A.5.18)

List every principal (user or group) that can reach a project's secrets via an
assigned role, with the highest secrets action that role grants — the role-based
standing-access surface for periodic access recertification. Requires roles.read
at the project scope.

**Usage:** `keyorix access-review [command] [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project-id` | `int` | — | Project to review (required) |

**Subcommands:**

- [`keyorix access-review attest`](#keyorix-access-review-attest) — Attest an access-review grant (certify it was reviewed and kept)
- [`keyorix access-review campaign`](#keyorix-access-review-campaign) — Manage access-review campaigns (periodic recertification cycles, A.5.18)
- [`keyorix access-review revoke`](#keyorix-access-review-revoke) — Revoke an access-review grant (remove the role assignment or share)

## `keyorix access-review attest`

Attest an access-review grant (certify it was reviewed and kept)

Record that the grant identified by the flags was reviewed and intentionally
kept — the audit evidence of recertification (access_review.attested). Changes no
access. Requires roles.read at the project scope.

**Usage:** `keyorix access-review attest [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment-id` | `uint` | — | Environment scope of a role grant (0 = whole project) |
| `--principal-id` | `uint` | — | User or group ID the grant is for (required) |
| `--principal-type` | `string` | `user` | Principal type: user\|group (for role grants) |
| `--project-id` | `int` | — | Project the grant belongs to (required) |
| `--role-id` | `uint` | — | Role ID (required when --source=role) |
| `--secret-id` | `uint` | — | Secret ID (required when --source=direct_share\|group_share) |
| `--source` | `string` | — | Grant source: role\|direct_share\|group_share (required) |

## `keyorix access-review campaign`

Manage access-review campaigns (periodic recertification cycles, A.5.18)

Run periodic access recertification as a tracked campaign: open snapshots the
project's current access into reviewable items, decide attests or revokes each, and
close freezes the cycle as audit evidence.

**Usage:** `keyorix access-review campaign [command]`

**Subcommands:**

- [`keyorix access-review campaign close`](#keyorix-access-review-campaign-close) — Close a campaign (freeze as evidence); refuses pending items unless --force
- [`keyorix access-review campaign decide`](#keyorix-access-review-campaign-decide) — Decide on one campaign item: attest (keep) or revoke
- [`keyorix access-review campaign list`](#keyorix-access-review-campaign-list) — List a project's access-review campaigns
- [`keyorix access-review campaign open`](#keyorix-access-review-campaign-open) — Open a new access-review campaign (snapshots current access)
- [`keyorix access-review campaign show`](#keyorix-access-review-campaign-show) — Show a campaign and its items (snapshot + decisions)

## `keyorix access-review campaign close`

Close a campaign (freeze as evidence); refuses pending items unless --force

**Usage:** `keyorix access-review campaign close [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--campaign-id` | `int` | — | Campaign to close (required) |
| `--force` | — | — | Close even if items remain pending |
| `--project-id` | `int` | — | Project (required) |

## `keyorix access-review campaign decide`

Decide on one campaign item: attest (keep) or revoke

**Usage:** `keyorix access-review campaign decide [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--action` | `string` | — | attest \| revoke (required) |
| `--campaign-id` | `int` | — | Campaign (required) |
| `--item-id` | `int` | — | Item to decide (required) |
| `--project-id` | `int` | — | Project (required) |
| `--reason` | `string` | — | Optional reviewer note |

## `keyorix access-review campaign list`

List a project's access-review campaigns

**Usage:** `keyorix access-review campaign list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project-id` | `int` | — | Project (required) |

## `keyorix access-review campaign open`

Open a new access-review campaign (snapshots current access)

**Usage:** `keyorix access-review campaign open [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--name` | `string` | — | Campaign name (e.g. "Q4 2026 access recertification") |
| `--project-id` | `int` | — | Project to review (required) |

## `keyorix access-review campaign show`

Show a campaign and its items (snapshot + decisions)

**Usage:** `keyorix access-review campaign show [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--campaign-id` | `int` | — | Campaign to show (required) |
| `--project-id` | `int` | — | Project (required) |

## `keyorix access-review revoke`

Revoke an access-review grant (remove the role assignment or share)

Remove the grant identified by the flags — a project-scoped role assignment
(--source role --role-id N) or a secret share (--source direct_share|group_share
--secret-id N). The removal is audited (access_review.revoked). Requires
roles.assign at the project scope.

**Usage:** `keyorix access-review revoke [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment-id` | `uint` | — | Environment scope of a role grant (0 = whole project) |
| `--principal-id` | `uint` | — | User or group ID the grant is for (required) |
| `--principal-type` | `string` | `user` | Principal type: user\|group (for role grants) |
| `--project-id` | `int` | — | Project the grant belongs to (required) |
| `--role-id` | `uint` | — | Role ID (required when --source=role) |
| `--secret-id` | `uint` | — | Secret ID (required when --source=direct_share\|group_share) |
| `--source` | `string` | — | Grant source: role\|direct_share\|group_share (required) |

## `keyorix anomalies`

Manage anomaly detection alerts

**Usage:** `keyorix anomalies [command]`

**Subcommands:**

- [`keyorix anomalies acknowledge`](#keyorix-anomalies-acknowledge) — Acknowledge an anomaly alert
- [`keyorix anomalies config`](#keyorix-anomalies-config) — Manage anomaly detection runtime configuration
- [`keyorix anomalies escalation`](#keyorix-anomalies-escalation) — Manage alert escalation policies
- [`keyorix anomalies list`](#keyorix-anomalies-list) — List anomaly alerts

## `keyorix anomalies acknowledge`

Acknowledge an anomaly alert

**Usage:** `keyorix anomalies acknowledge <id>`

## `keyorix anomalies config`

Manage anomaly detection runtime configuration

**Usage:** `keyorix anomalies config [command]`

**Subcommands:**

- [`keyorix anomalies config get`](#keyorix-anomalies-config-get) — Show the current anomaly detection configuration
- [`keyorix anomalies config set`](#keyorix-anomalies-config-set) — Update one or more anomaly detection configuration fields

## `keyorix anomalies config get`

Show the current anomaly detection configuration

**Usage:** `keyorix anomalies config get`

## `keyorix anomalies config set`

Update one or more anomaly detection configuration fields

Update the anomaly detection runtime configuration.

Only flags that are explicitly provided are changed; all others keep their
current stored values. Changes take effect on the next detection scan
without restarting the server.

**Usage:** `keyorix anomalies config set [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--lookback-days` | `int` | — | Lookback window for baseline (days) |
| `--ml-enabled` | — | — | Enable ML (Isolation Forest) anomaly detection |
| `--ml-num-trees` | `int` | — | ML Isolation Forest tree count |
| `--ml-sample-size` | `int` | — | ML Isolation Forest per-tree subsample size |
| `--ml-threshold` | `float64` | — | ML anomaly-score threshold (0.5–1.0) |
| `--off-hours-enabled` | — | — | Enable off-hours rule |
| `--off-hours-end` | `int` | — | Off-hours band end hour (0–23) |
| `--off-hours-start` | `int` | — | Off-hours band start hour (0–23) |
| `--off-hours-timezone` | `string` | — | IANA timezone for off-hours band (e.g. America/New_York) |
| `--quarantine-hours` | `int` | — | Quarantine period before a new actor is trusted (hours) |

## `keyorix anomalies escalation`

Manage alert escalation policies

**Usage:** `keyorix anomalies escalation [command]`

**Subcommands:**

- [`keyorix anomalies escalation create`](#keyorix-anomalies-escalation-create) — Create an alert escalation policy
- [`keyorix anomalies escalation delete`](#keyorix-anomalies-escalation-delete) — Delete an alert escalation policy
- [`keyorix anomalies escalation list`](#keyorix-anomalies-escalation-list) — List alert escalation policies
- [`keyorix anomalies escalation run`](#keyorix-anomalies-escalation-run) — Trigger the alert escalation job immediately

## `keyorix anomalies escalation create`

Create an alert escalation policy

**Usage:** `keyorix anomalies escalation create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--after-minutes` | `int` | `30` | Escalate if unacknowledged for this many minutes |
| `--channels` | `string` | — | Comma-separated NotificationChannel IDs |
| `--min-severity` | `string` | `medium` | Minimum severity to escalate: low\|medium\|high\|critical |
| `--name` | `string` | — | Policy name (required) |

## `keyorix anomalies escalation delete`

Delete an alert escalation policy

**Usage:** `keyorix anomalies escalation delete <id>`

## `keyorix anomalies escalation list`

List alert escalation policies

**Usage:** `keyorix anomalies escalation list`

## `keyorix anomalies escalation run`

Trigger the alert escalation job immediately

**Usage:** `keyorix anomalies escalation run`

## `keyorix anomalies list`

List anomaly alerts

**Usage:** `keyorix anomalies list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--unacknowledged` | — | — | Show only unacknowledged alerts |

## `keyorix audit`

Verify and export the tamper-evident audit trail

**Usage:** `keyorix audit [command]`

**Subcommands:**

- [`keyorix audit checkpoint`](#keyorix-audit-checkpoint) — Write a signed checkpoint of the current audit-chain head (ADR-029)
- [`keyorix audit export`](#keyorix-audit-export) — Stream the audit feed as NDJSON (one event per line) for SIEM pull
- [`keyorix audit logs`](#keyorix-audit-logs) — Query the audit trail with filters (human-readable table)
- [`keyorix audit migrate-chain-encoding`](#keyorix-audit-migrate-chain-encoding) — One-time re-derivation of the audit hash chain under the current encoding
- [`keyorix audit search`](#keyorix-audit-search) — Search the audit trail with structured filters
- [`keyorix audit verify`](#keyorix-audit-verify) — Report the audit hash chain's integrity (non-zero exit if broken or not proven)

## `keyorix audit checkpoint`

Write a signed checkpoint of the current audit-chain head (ADR-029)

**Usage:** `keyorix audit checkpoint`

## `keyorix audit export`

Stream the audit feed as NDJSON (one event per line) for SIEM pull

**Usage:** `keyorix audit export [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--after-id` | `uint` | — | Resume after this event id (exclusive cursor) |
| `--all` | — | — | Follow the cursor to the end, emitting every event |
| `--csv` | — | — | Emit CSV (header + one row per event) instead of NDJSON |
| `--limit` | `int` | `100` | Events per page (1–1000) |
| `--since` | `string` | — | Only export events at/after this time (RFC3339) |

## `keyorix audit logs`

Query the audit trail with filters (human-readable table)

**Usage:** `keyorix audit logs [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--actor-type` | `string` | — | Filter by actor kind: user \| machine_identity \| system |
| `--cursor` | `string` | — | Continue after a previous page (the cursor printed under it) |
| `--event-type` | `string` | — | Filter by event type (e.g. secret.read, secret.deleted) |
| `--include-total` | — | — | Count every matching event (exact total; slower on a large audit trail) |
| `--limit` | `int` | `50` | Max events to show (1–100) |
| `--project-id` | `uint` | — | Filter by project id |
| `--since` | `string` | — | Only events at/after this time (RFC3339) |
| `--until` | `string` | — | Only events at/before this time (RFC3339) |
| `--user-id` | `uint` | — | Filter by actor user id |

## `keyorix audit migrate-chain-encoding`

One-time re-derivation of the audit hash chain under the current encoding

**Usage:** `keyorix audit migrate-chain-encoding [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--confirm` | — | — | Apply the migration for real. Without this flag, the command only previews what would change — nothing is written. |

## `keyorix audit search`

Search the audit trail with structured filters

**Usage:** `keyorix audit search [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--action` | `string` | — | Filter by exact event type (e.g. secret.read) |
| `--actor` | `string` | — | Partial match on actor username |
| `--cursor` | `string` | — | Continue after a previous page (the cursor printed under it) |
| `--include-total` | — | — | Count every matching event (exact total; slower on a large audit trail) |
| `--ip` | `string` | — | Filter by originating IP address |
| `--limit` | `int` | `100` | Max results (1–1000) |
| `--offset` | `int` | — | Pagination offset (offset+limit up to 10000; use --cursor beyond) |
| `--project-id` | `uint` | — | Filter by project ID |
| `--resource-id` | `uint` | — | Filter by exact resource ID (secret_node_id) |
| `--resource-type` | `string` | — | Filter by resource kind (e.g. secret, user, role) |
| `--since` | `string` | — | Only events at/after this RFC3339 time |
| `--success` | `string` | — | Filter by outcome: true or false |
| `--until` | `string` | — | Only events at/before this RFC3339 time |
| `--user-id` | `uint` | — | Filter by exact actor user ID |

## `keyorix audit verify`

Report the audit hash chain's integrity (non-zero exit if broken or not proven)

Report the audit hash chain's integrity.

By default this reads the server's incremental verification: the rolling full
re-walk (every row re-hashed at least once per cycle) plus a check of the rows
after the latest signed checkpoint. Status is VALID, BROKEN, or NOT PROVEN
(no recent full verification covers the older rows yet). --full runs a full
walk on the server now, as a background job, and waits for it.

**Usage:** `keyorix audit verify [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--full` | — | — | Run a full walk of the chain on the server now (a background job) and wait for its result |
| `--json` | — | — | Emit the raw verification result as JSON (for recording the external anchor) |
| `--timeout` | `duration` | `30m0s` | With --full: how long to wait for the job |

## `keyorix billing`

FinOps billing and usage reports (requires billing license feature)

**Usage:** `keyorix billing [command]`

**Subcommands:**

- [`keyorix billing report`](#keyorix-billing-report) — Generate a per-project billing report for a date range

## `keyorix billing report`

Generate a per-project billing report for a date range

Generate a per-project billing report showing secret counts, reads, writes,
rotations, unique human users, and machine reads for the specified date window
(GET /admin/billing/report). Requires audit.read and the "billing" license feature.

**Usage:** `keyorix billing report [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | `string` | `table` | Output format: table or json |
| `--from` | `string` | — | Start of billing window, RFC3339 (e.g. 2026-01-01T00:00:00Z) — required |
| `--project-id` | `string` | — | Comma-separated project IDs to include (omit for all) |
| `--to` | `string` | — | End of billing window, RFC3339 (e.g. 2026-02-01T00:00:00Z) — required |

## `keyorix break-glass`

Self-service emergency access (incident response)

Activate emergency access to a project: immediately self-grant the configured
emergency role, time-bound and auto-expiring, with a written justification. Every
activation is loudly audited and alerts the project's admins. Use list/revoke to
review and end activations.

**Usage:** `keyorix break-glass [command]`

**Subcommands:**

- [`keyorix break-glass activate`](#keyorix-break-glass-activate) — Activate emergency access (self-grant the emergency role, time-bound)
- [`keyorix break-glass list`](#keyorix-break-glass-list) — List a project's break-glass activations (all with roles.read, else your own as a member)
- [`keyorix break-glass revoke`](#keyorix-break-glass-revoke) — Revoke an active emergency grant early

## `keyorix break-glass activate`

Activate emergency access (self-grant the emergency role, time-bound)

**Usage:** `keyorix break-glass activate [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--justification` | `string` | — | Written reason for emergency access (required) |
| `--project-id` | `uint32` | — | Project to activate emergency access for (required) |
| `--ttl` | `string` | — | Grant lifetime override, e.g. 2h (default + capped by server config) |

## `keyorix break-glass list`

List a project's break-glass activations (all with roles.read, else your own as a member)

**Usage:** `keyorix break-glass list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project-id` | `uint32` | — | Project (required) |

## `keyorix break-glass revoke`

Revoke an active emergency grant early

**Usage:** `keyorix break-glass revoke [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--activation-id` | `uint32` | — | Activation to revoke (required) |
| `--project-id` | `uint32` | — | Project (required) |

## `keyorix bundle`

Air-gap update bundles: verify and import offline

Verify and stage Keyorix air-gap update bundles (ADR-062 Phase 1).

A bundle is a single signed tarball carrying a release's artifacts, pinned by sha256 in a
manifest that is signed with an offline ed25519 key. An air-gapped operator carries the
file across the gap and verifies it offline against the public key embedded in this binary
at build time -- trust follows a pinned chain, never a key shipped inside the bundle.
"bundle build" (signing a new release) is maintainer-only tooling and lives in the old CLI.

**Usage:** `keyorix bundle [command]`

**Subcommands:**

- [`keyorix bundle import`](#keyorix-bundle-import) — Verify a bundle offline and stage its artifacts into a directory
- [`keyorix bundle verify`](#keyorix-bundle-verify) — Verify a bundle offline against the embedded pinned key and component digests

## `keyorix bundle import`

Verify a bundle offline and stage its artifacts into a directory

**Usage:** `keyorix bundle import <bundle> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--deployment-id` | `string` | — | this deployment's configured license.deployment_id, if the license is deployment-bound |
| `--dest` | `string` | — | directory to stage verified artifacts into (required) |
| `--force` | — | — | proceed without --installed-version on a first import into --dest (dangerous -- skips the no-downgrade / anti-skip check) |
| `--installed-version` | `string` | — | currently-installed version, to enforce no-downgrade / min-upgrade-from (required on a first import into --dest, unless --force) |
| `--license` | `string` | — | path to the installed license token (bundle import is a commercial feature) |
| `--reset-install-state` | — | — | acknowledge that --dest's install state was intentionally reset (e.g. --dest was deliberately cleared or recreated): required when the external install-state record disagrees with --dest itself, otherwise refused as a possible downgrade-reset attempt |

## `keyorix bundle verify`

Verify a bundle offline against the embedded pinned key and component digests

**Usage:** `keyorix bundle verify <bundle> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | — | — | proceed without --installed-version (dangerous -- skips the no-downgrade / anti-skip check, verifies signature and digests only) |
| `--installed-version` | `string` | — | currently-installed version, to enforce no-downgrade / min-upgrade-from (required unless --force) |

## `keyorix change-password`

Change your own password (drops your other sessions)

change-password calls POST /auth/change-password to set a new password for the
currently logged-in account. Every other active session belonging to this account is
revoked as a result -- the current one is not.

This is the command to run right after logging in with a one-time password
(e.g. the one keyorix-server admin recover-admin prints) -- the account stays
confined to this command (and a handful of others) until a real password is set.
With security.require_mfa on and no second factor yet, that login is a short
setup session that must also enrol MFA ("keyorix mfa enroll" + "keyorix mfa
activate", before or after this command); once both are done the session ends
and the next "keyorix login" asks for a code.

**Usage:** `keyorix change-password [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--current-password` | `string` | — | Current password (omit to be prompted) |
| `--new-password` | `string` | — | New password (omit to be prompted) |

## `keyorix completion`

Generate the autocompletion script for the specified shell

Generate the autocompletion script for keyorix for the specified shell.
See each sub-command's help for details on how to use the generated script.

**Usage:** `keyorix completion [command]`

**Subcommands:**

- [`keyorix completion bash`](#keyorix-completion-bash) — Generate the autocompletion script for bash
- [`keyorix completion fish`](#keyorix-completion-fish) — Generate the autocompletion script for fish
- [`keyorix completion powershell`](#keyorix-completion-powershell) — Generate the autocompletion script for powershell
- [`keyorix completion zsh`](#keyorix-completion-zsh) — Generate the autocompletion script for zsh

## `keyorix completion bash`

Generate the autocompletion script for bash

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

```text
	source <(keyorix completion bash)

```
To load completions for every new session, execute once:

#### Linux:

```text
	keyorix completion bash > /etc/bash_completion.d/keyorix

```
#### macOS:

```text
	keyorix completion bash > $(brew --prefix)/etc/bash_completion.d/keyorix

```
You will need to start a new shell for this setup to take effect.

**Usage:** `keyorix completion bash [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-descriptions` | — | — | disable completion descriptions |

## `keyorix completion fish`

Generate the autocompletion script for fish

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

```text
	keyorix completion fish | source

```
To load completions for every new session, execute once:

```text
	keyorix completion fish > ~/.config/fish/completions/keyorix.fish

```
You will need to start a new shell for this setup to take effect.

**Usage:** `keyorix completion fish [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-descriptions` | — | — | disable completion descriptions |

## `keyorix completion powershell`

Generate the autocompletion script for powershell

Generate the autocompletion script for powershell.

To load completions in your current shell session:

```text
	keyorix completion powershell | Out-String | Invoke-Expression

```
To load completions for every new session, add the output of the above command
to your powershell profile.

**Usage:** `keyorix completion powershell [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-descriptions` | — | — | disable completion descriptions |

## `keyorix completion zsh`

Generate the autocompletion script for zsh

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

```text
	echo "autoload -U compinit; compinit" >> ~/.zshrc

```
To load completions in your current shell session:

```text
	source <(keyorix completion zsh)

```
To load completions for every new session, execute once:

#### Linux:

```text
	keyorix completion zsh > "${fpath[1]}/_keyorix"

```
#### macOS:

```text
	keyorix completion zsh > $(brew --prefix)/share/zsh/site-functions/_keyorix

```
You will need to start a new shell for this setup to take effect.

**Usage:** `keyorix completion zsh [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-descriptions` | — | — | disable completion descriptions |

## `keyorix compliance`

Deployment controls-posture report (ISO 27001 / SOC 2 / NIS2 / DORA)

**Usage:** `keyorix compliance [command]`

**Subcommands:**

- [`keyorix compliance controls`](#keyorix-compliance-controls) — Control matrix — controls mapped to ISO 27001 / SOC 2 / NIS2 / DORA with status
- [`keyorix compliance credential-trends`](#keyorix-compliance-credential-trends) — Show 30/60/90-day credential hygiene trends (stale/expired PATs, stale machine creds)
- [`keyorix compliance digest`](#keyorix-compliance-digest) — Print the compliance digest, or broadcast it to notification channels (--send)
- [`keyorix compliance export`](#keyorix-compliance-export) — Export the auditor evidence pack (posture + supporting records) as JSON
- [`keyorix compliance inventory`](#keyorix-compliance-inventory) — Export the secret asset inventory as CSV (deployment-wide, or one project)
- [`keyorix compliance permission-baseline`](#keyorix-compliance-permission-baseline) — Export the permission baseline (every user's effective permissions) as CSV or JSON
- [`keyorix compliance permission-changes`](#keyorix-compliance-permission-changes) — Show role grant/revoke events from the audit trail (permission change audit)
- [`keyorix compliance report`](#keyorix-compliance-report) — Print the deployment's controls-posture report
- [`keyorix compliance rotation-by-backend`](#keyorix-compliance-rotation-by-backend) — Rotation-overdue secrets grouped by backend
- [`keyorix compliance verify`](#keyorix-compliance-verify) — Verify an exported evidence pack against its detached signature

## `keyorix compliance controls`

Control matrix — controls mapped to ISO 27001 / SOC 2 / NIS2 / DORA with status

**Usage:** `keyorix compliance controls [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--csv` | — | — | Download the control matrix as CSV instead of the text report |
| `--force` | — | — | With --csv, overwrite an existing --output file (default: refuse) |
| `--output` | `string` | — | With --csv, write to a file instead of stdout |

## `keyorix compliance credential-trends`

Show 30/60/90-day credential hygiene trends (stale/expired PATs, stale machine creds)

**Usage:** `keyorix compliance credential-trends [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--days` | `int` | `30` | Trend window in days (30, 60, or 90) |

## `keyorix compliance digest`

Print the compliance digest, or broadcast it to notification channels (--send)

Print the on-demand compliance digest (the same title + body that is normally
broadcast on a schedule to Slack/Teams/webhook/email channels), or trigger an
immediate broadcast to the configured notification channels with --send.

**Usage:** `keyorix compliance digest [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--send` | — | — | Broadcast the digest to configured notification channels instead of printing it |

## `keyorix compliance export`

Export the auditor evidence pack (posture + supporting records) as JSON

Export a timestamped evidence pack — the posture plus the records that
substantiate it (the audit-chain anchor, access-review campaigns, the break-glass
register, and overdue rotations) — as JSON, for an auditor to archive. Writes to
stdout by default, or to --output FILE. Refuses to overwrite an existing --output file
unless --force is passed (a scheduled/CI evidence run reusing a fixed path needs it).

**Usage:** `keyorix compliance export [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | — | — | Overwrite an existing --output file (default: refuse) |
| `--output` | `string` | — | Write the evidence pack to a file instead of stdout |

## `keyorix compliance inventory`

Export the secret asset inventory as CSV (deployment-wide, or one project)

Download the secret asset-inventory as CSV for an auditor hand-off — secrets
listed by name, project, environment, type, classification, owner, and lifecycle
status, with no secret values. Deployment-wide by default (needs system.read);
--project \<id\> scopes it to a single project (needs secrets.read on that project).
Writes to stdout, or to --output FILE. Refuses to overwrite an existing --output file
unless --force is passed (a scheduled/CI evidence run reusing a fixed path needs it).

**Usage:** `keyorix compliance inventory [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | — | — | Overwrite an existing --output file (default: refuse) |
| `--output` | `string` | — | Write the CSV to a file instead of stdout |
| `--project` | `uint32` | — | Scope to one project by ID (default: deployment-wide) |

## `keyorix compliance permission-baseline`

Export the permission baseline (every user's effective permissions) as CSV or JSON

Download the full permission baseline — every user's effective permissions,
expanded through direct role grants and group membership — for auditor hand-off.
Outputs CSV by default; use --format json for the JSON form.
Writes to stdout by default, or to --output FILE. Refuses to overwrite an existing
--output file unless --force is passed (a scheduled/CI evidence run reusing a fixed
path needs it).
Requires audit.read.

**Usage:** `keyorix compliance permission-baseline [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | — | — | Overwrite an existing --output file (default: refuse) |
| `--format` | `string` | `csv` | Output format: csv or json |
| `--output` | `string` | — | Write the output to a file instead of stdout |

## `keyorix compliance permission-changes`

Show role grant/revoke events from the audit trail (permission change audit)

Download a structured list of permission change events (role grants and
revokes) from the audit trail. Prints a table of: Time | Actor | Action | Target | Role | Scope.
Requires audit.read.

**Usage:** `keyorix compliance permission-changes [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--limit` | `int` | — | Maximum number of events to return (default 100, max 1000) |
| `--since` | `string` | — | Start of the time window (RFC3339, e.g. 2026-01-01T00:00:00Z); defaults to 30 days ago |
| `--until` | `string` | — | End of the time window (RFC3339); defaults to now |

## `keyorix compliance report`

Print the deployment's controls-posture report

**Usage:** `keyorix compliance report`

## `keyorix compliance rotation-by-backend`

Rotation-overdue secrets grouped by backend

Print a table of rotation-overdue secrets grouped by RotationBackend across
the whole deployment. Requires audit.read permission.

**Usage:** `keyorix compliance rotation-by-backend`

## `keyorix compliance verify`

Verify an exported evidence pack against its detached signature

Verify the authenticity of an archived evidence pack. Reads the pack file and
its signature (default \<file\>.sig) and asks the server to recompute the HMAC with its
DEK-derived signing key — proving the pack was produced by this deployment and has
not been modified. Requires server-side encryption (the signing key is DEK-derived).

**Usage:** `keyorix compliance verify [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--file` | `string` | — | Path to the evidence pack JSON to verify (required) |
| `--sig` | `string` | — | Path to the signature file (default \<file\>.sig) |

## `keyorix config`

Show or change CLI settings stored with your credentials

config reads and writes CLI settings kept in the credentials file (see "keyorix status --help").

Keys:
```text
  ca_file   PEM CA/certificate file trusted for the server's TLS certificate, instead of
            the system roots. "keyorix-server admin init" prints the path of the certificate
            it generates. --ca-file and KEYORIX_CA_FILE override it for one command.
```

**Usage:** `keyorix config [command]`

**Subcommands:**

- [`keyorix config get`](#keyorix-config-get) — Show the effective value of a CLI setting and where it comes from (key: ca_file)
- [`keyorix config set`](#keyorix-config-set) — Set a CLI setting (key: ca_file)
- [`keyorix config unset`](#keyorix-config-unset) — Remove a stored CLI setting (key: ca_file)

## `keyorix config get`

Show the effective value of a CLI setting and where it comes from (key: ca_file)

**Usage:** `keyorix config get <key>`

## `keyorix config set`

Set a CLI setting (key: ca_file)

**Usage:** `keyorix config set <key> <value>`

## `keyorix config unset`

Remove a stored CLI setting (key: ca_file)

**Usage:** `keyorix config unset <key>`

## `keyorix docs`

Print the CLI reference (Markdown) or its man page

docs prints documentation generated from this binary's own command tree, so it always
matches the commands, flags and examples of the version you run. docs/cli-reference.md and
docs/man/keyorix.1 in the repository are produced the same way and checked for freshness
by the test suite.

**Usage:** `keyorix docs [command]`

**Subcommands:**

- [`keyorix docs man`](#keyorix-docs-man) — Print the man page (roff)
- [`keyorix docs markdown`](#keyorix-docs-markdown) — Print the full command reference as Markdown

## `keyorix docs man`

Print the man page (roff)

**Usage:** `keyorix docs man`

**Examples:**

```sh
# Read it without installing anything
keyorix docs man | man -l -
# Install it for the current user
mkdir -p ~/.local/share/man/man1 && keyorix docs man > ~/.local/share/man/man1/keyorix.1
```

## `keyorix docs markdown`

Print the full command reference as Markdown

**Usage:** `keyorix docs markdown`

**Examples:**

```sh
keyorix docs markdown > cli-reference.md
```

## `keyorix dynamic-secret`

Issue and manage on-demand database credentials (dynamic secrets)

**Usage:** `keyorix dynamic-secret [command]`

**Subcommands:**

- [`keyorix dynamic-secret classify`](#keyorix-dynamic-secret-classify) — Set a dynamic-secret config's classification level
- [`keyorix dynamic-secret create`](#keyorix-dynamic-secret-create) — Register a new dynamic-secret target config
- [`keyorix dynamic-secret get-config`](#keyorix-dynamic-secret-get-config) — Show a dynamic-secret config's details
- [`keyorix dynamic-secret issue`](#keyorix-dynamic-secret-issue) — Issue a short-lived credential from a config (shown once)
- [`keyorix dynamic-secret leases`](#keyorix-dynamic-secret-leases) — List leases issued from a config
- [`keyorix dynamic-secret list`](#keyorix-dynamic-secret-list) — List dynamic-secret target configs
- [`keyorix dynamic-secret renew`](#keyorix-dynamic-secret-renew) — Extend an active lease (up to the config's max TTL)
- [`keyorix dynamic-secret revoke`](#keyorix-dynamic-secret-revoke) — Revoke an active lease now
- [`keyorix dynamic-secret revoke-all`](#keyorix-dynamic-secret-revoke-all) — Revoke ALL active leases from a config (incident kill switch)

## `keyorix dynamic-secret classify`

Set a dynamic-secret config's classification level

**Usage:** `keyorix dynamic-secret classify <config-id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--level` | `string` | — | Classification level (required) |

## `keyorix dynamic-secret create`

Register a new dynamic-secret target config

Register a target database/store Keyorix can mint on-demand credentials for.

The admin DSN -- a privileged connection string used only to create and drop the
short-lived users -- is read from the KEYORIX_DYNAMIC_ADMIN_DSN environment variable, or
prompted for with hidden input. It is never accepted as a flag (so it cannot land
in shell history); the server encrypts it at rest and never returns it.

For the cloud-IAM backends (aws-sts, gcp, azure, kubernetes) the "admin DSN" is
instead a small JSON config and the issued credential is a short-lived cloud token,
not a username/password:
```text
  aws-sts:    {"role_arn":"...","region":"...","duration_seconds":3600} (optional
              creation template = an inline STS session policy)
  gcp:        {"service_account":"sa@project.iam.gserviceaccount.com","scopes":[...]}
  azure:      {"scopes":["https://management.azure.com/.default"]}
  kubernetes: {"namespace":"app","service_account":"my-app","audiences":["https://svc"]}
              (mints a ServiceAccount token via TokenRequest; add
              "api_server"/"ca_cert"/"token" to target an out-of-cluster API server;
              add "revocable":true to let Revoke genuinely invalidate the token
              early instead of waiting for its natural expiry -- this binds each
              token to a dedicated per-lease Secret and requires the calling
              identity to also hold create+delete on secrets in the namespace,
              on top of create on serviceaccounts/token)
```
Cloud credentials for the mint call come from the ambient identity (AWS chain /
GCP ADC / Azure DefaultAzureCredential / in-cluster ServiceAccount), never from
Keyorix config. AWS STS, Azure, and GCP tokens have no safe early-revoke
mechanism and always self-expire -- see internal/dynamic's per-backend file
header comments for why.

Examples:
```text
  keyorix dynamic-secret create --name app-db --project-id 1 --backend postgres \
    --creation-template 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};'
  keyorix dynamic-secret create --name cache --project-id 1 --backend redis \
    --creation-template '~app:* +@read'
  # cloud: paste the JSON config at the hidden prompt
  keyorix dynamic-secret create --name aws-readonly --project-id 1 --backend aws-sts
  keyorix dynamic-secret create --name gcp-token   --project-id 1 --backend gcp
  keyorix dynamic-secret create --name k8s-token   --project-id 1 --backend kubernetes
```

**Usage:** `keyorix dynamic-secret create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--backend` | `string` | — | Backend: postgres \| mysql \| mongodb \| redis \| aws-sts \| gcp \| azure \| kubernetes (required) |
| `--creation-template` | `string` | — | Backend-specific grant/role/ACL template ({{name}} for SQL) |
| `--default-ttl` | `int` | — | Default lease TTL in seconds (0 = server default) |
| `--environment-id` | `int` | — | Environment ID (0 = project-wide) |
| `--max-active-leases` | `int` | — | Max concurrent active leases from this config (0 = no ceiling) |
| `--max-ttl` | `int` | — | Max lease TTL ceiling in seconds (0 = no ceiling) |
| `--name` | `string` | — | Config name (required) |
| `--project-id` | `int` | — | Project ID (required) |

## `keyorix dynamic-secret get-config`

Show a dynamic-secret config's details

**Usage:** `keyorix dynamic-secret get-config <config-id>`

## `keyorix dynamic-secret issue`

Issue a short-lived credential from a config (shown once)

**Usage:** `keyorix dynamic-secret issue <config-id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ttl` | `int` | — | Lease TTL in seconds (0 = the config default) |

## `keyorix dynamic-secret leases`

List leases issued from a config

**Usage:** `keyorix dynamic-secret leases <config-id>`

## `keyorix dynamic-secret list`

List dynamic-secret target configs

**Usage:** `keyorix dynamic-secret list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment-id` | `int` | — | Filter by environment ID |
| `--project-id` | `int` | — | Filter by project ID |

## `keyorix dynamic-secret renew`

Extend an active lease (up to the config's max TTL)

**Usage:** `keyorix dynamic-secret renew <lease-id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ttl` | `int` | — | Renewal TTL in seconds (0 = the config default) |

## `keyorix dynamic-secret revoke`

Revoke an active lease now

**Usage:** `keyorix dynamic-secret revoke <lease-id>`

## `keyorix dynamic-secret revoke-all`

Revoke ALL active leases from a config (incident kill switch)

**Usage:** `keyorix dynamic-secret revoke-all <config-id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--yes` | — | — | Skip the confirmation prompt |

## `keyorix group`

Manage groups

Create, read, update, delete, list groups and manage membership.

**Usage:** `keyorix group [command]`

**Subcommands:**

- [`keyorix group add-member`](#keyorix-group-add-member) — Add a user to a group
- [`keyorix group create`](#keyorix-group-create) — Create a group
- [`keyorix group delete`](#keyorix-group-delete) — Delete a group
- [`keyorix group get`](#keyorix-group-get) — Get a group by name or id
- [`keyorix group list`](#keyorix-group-list) — List groups
- [`keyorix group members`](#keyorix-group-members) — List members of a group
- [`keyorix group remove-member`](#keyorix-group-remove-member) — Remove a user from a group
- [`keyorix group update`](#keyorix-group-update) — Update a group

## `keyorix group add-member`

Add a user to a group

**Usage:** `keyorix group add-member [group] [flags]`

**Examples:**

```sh
keyorix group add-member platform-team --user alice
keyorix group add-member --group-id 1 --user-id 2
```

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--group` | `string` | — | Group name or numeric ID (required) |
| `--group-id` | `int` | — | Group ID (alternative to the positional \<group\>, which also takes a name) |
| `--project` | `int` | — | Scope membership to a project (0 = global) |
| `--user` | `string` | — | User username, email or numeric ID (alternative to --user-id) |
| `--user-id` | `int` | — | User ID (or use --user) |

## `keyorix group create`

Create a group

**Usage:** `keyorix group create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--description` | `string` | — | Description |
| `--name` | `string` | — | Group name (required) |

## `keyorix group delete`

Delete a group

**Usage:** `keyorix group delete [group] [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | — | — | Skip the confirmation prompt |
| `--id` | `int` | — | Group ID (alternative to the positional \<group\>, which also takes a name) |

## `keyorix group get`

Get a group by name or id

**Usage:** `keyorix group get [group] [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Group ID (alternative to the positional \<group\>, which also takes a name) |

## `keyorix group list`

List groups

**Usage:** `keyorix group list`

## `keyorix group members`

List members of a group

**Usage:** `keyorix group members [group] [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Group ID (alternative to the positional \<group\>, which also takes a name) |

## `keyorix group remove-member`

Remove a user from a group

**Usage:** `keyorix group remove-member [group] [flags]`

**Examples:**

```sh
keyorix group remove-member platform-team --user alice
keyorix group remove-member --group-id 1 --user-id 2
```

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--group` | `string` | — | Group name or numeric ID (required) |
| `--group-id` | `int` | — | Group ID (alternative to the positional \<group\>, which also takes a name) |
| `--project` | `int` | — | Scope membership to a project (0 = global) |
| `--user` | `string` | — | User username, email or numeric ID (alternative to --user-id) |
| `--user-id` | `int` | — | User ID (or use --user) |

## `keyorix group update`

Update a group

**Usage:** `keyorix group update [group] [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--description` | `string` | — | New description |
| `--id` | `int` | — | Group ID (alternative to the positional \<group\>, which also takes a name) |
| `--name` | `string` | — | New name |

## `keyorix hygiene`

Deployment-wide secret-hygiene rollup across all projects (admin)

Summarize every project's outstanding cleanup signals in one call: secrets whose
owner departed, secrets unused for a long window, secrets expiring/expired, stale
machine identities, and secrets overdue for rotation. Shows install-wide totals plus a
per-project breakdown of the projects that carry debt. Requires global system.read.
Counts only — never secret names or values.

**Usage:** `keyorix hygiene [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--expiring-days` | `int` | — | Expiring-secret window in days (default server-side: 30) |
| `--stale-days` | `int` | — | Stale-machine-identity window in days (default server-side: 90) |
| `--unused-days` | `int` | — | Unused-secret window in days (default server-side: 90) |

## `keyorix invite`

Manage project invitations

Send, list, resend, and revoke project invitations (ADR-024).

**Usage:** `keyorix invite [command]`

**Subcommands:**

- [`keyorix invite list`](#keyorix-invite-list) — List project invitations
- [`keyorix invite resend`](#keyorix-invite-resend) — Reissue and redeliver an invitation's setup link (ADR-028)
- [`keyorix invite revoke`](#keyorix-invite-revoke) — Revoke a pending invitation
- [`keyorix invite send`](#keyorix-invite-send) — Send a project invitation

## `keyorix invite list`

List project invitations

List a project's invitations. With --stale-days, show only pending invites older than N days.

**Usage:** `keyorix invite list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name (or set KEYORIX_PROJECT) |
| `--stale-days` | `int` | — | Show only pending invitations older than this many days |

## `keyorix invite resend`

Reissue and redeliver an invitation's setup link (ADR-028)

Reissue a pending invitation's accept link, invalidating any prior link, and
deliver it again. In out-of-band mode the link is printed for you to relay.
Throttled per the ADR-028 resend limits.

**Usage:** `keyorix invite resend [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Invitation ID (required) |
| `--project` | `string` | — | Project name (or set KEYORIX_PROJECT) |

## `keyorix invite revoke`

Revoke a pending invitation

Cancel a pending project invitation by ID (ADR-024).

**Usage:** `keyorix invite revoke [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Invitation ID (required) |
| `--project` | `string` | — | Project name (or set KEYORIX_PROJECT) |

## `keyorix invite send`

Send a project invitation

Invite an email address to a project with an intended role (admin-driven, ADR-024).

**Usage:** `keyorix invite send [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--email` | `string` | — | Invitee email address (required) |
| `--project` | `string` | — | Project name (or set KEYORIX_PROJECT) |
| `--role` | `string` | — | Intended project role (required) |

## `keyorix legal-hold`

Deployment-wide legal hold — block purges to preserve records (A.5.34)

Place or lift a litigation/investigation hold. While a hold is active, the
retention-purge, JIT-expiry, and login-prune jobs are blocked from hard-deleting
any records, so data subject to legal hold is preserved.

**Usage:** `keyorix legal-hold [command]`

**Subcommands:**

- [`keyorix legal-hold lift`](#keyorix-legal-hold-lift) — Lift the active legal hold (resume purges)
- [`keyorix legal-hold place`](#keyorix-legal-hold-place) — Place a legal hold (block all purges until lifted)
- [`keyorix legal-hold status`](#keyorix-legal-hold-status) — Show whether a legal hold is active

## `keyorix legal-hold lift`

Lift the active legal hold (resume purges)

**Usage:** `keyorix legal-hold lift [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--reason` | `string` | — | Why the hold is lifted (required, recorded for audit) |
| `--yes` | — | — | Skip the confirmation prompt |

## `keyorix legal-hold place`

Place a legal hold (block all purges until lifted)

**Usage:** `keyorix legal-hold place [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--reason` | `string` | — | Why the hold is placed (required, recorded for audit) |

## `keyorix legal-hold status`

Show whether a legal hold is active

**Usage:** `keyorix legal-hold status`

## `keyorix license`

Offline license: install and check status

Install and inspect a Keyorix offline license (ADR-062 Phase 2).

A license is a compact signed token validated locally against the license public key
embedded in this binary at build time -- no phone-home. Enforcement is fail-safe: a missing,
expired, or invalid license degrades to the community baseline with a warning; it never
denies access to existing secrets or stops the server. "license issue" (minting a new
license) is maintainer-only tooling and lives in the old CLI.

**Usage:** `keyorix license [command]`

**Subcommands:**

- [`keyorix license install`](#keyorix-license-install) — Validate a license token and store it for the server to load
- [`keyorix license status`](#keyorix-license-status) — Show the locally-evaluated license entitlement

## `keyorix license install`

Validate a license token and store it for the server to load

**Usage:** `keyorix license install <token-file> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--deployment-id` | `string` | — | this deployment's id, to check a bound license |
| `--dest` | `string` | — | path to store the validated license token (required) |
| `--grace-hours` | `int` | — | post-expiry grace window in hours (default 336 = 14d) |

## `keyorix license status`

Show the locally-evaluated license entitlement

**Usage:** `keyorix license status [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--deployment-id` | `string` | — | this deployment's id, to check a bound license |
| `--grace-hours` | `int` | — | post-expiry grace window in hours (default 336 = 14d) |
| `--license` | `string` | — | license token file to evaluate |

## `keyorix login`

Authenticate to a Keyorix server and store the resulting token

login exchanges a username and password for a session token via POST /auth/login,
verifies it against GET /api/v1/auth/profile, and stores it (with the server URL) at the
one credential-file location this CLI uses (see "keyorix status --help").

When the account has TOTP multi-factor authentication enabled, /auth/login answers with a
second-factor challenge instead of a token; login then asks for an authenticator code (or
an unused recovery code) and completes the challenge via POST /auth/mfa/verify. Pass
--mfa-code to supply it non-interactively. The code is used for that one request only: it
is never echoed, never logged, and never written to the credential file.

**Usage:** `keyorix login [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--mfa-code` | `string` | — | Authenticator (TOTP) code or an unused recovery code, for an MFA-enabled account (omit to be prompted) |
| `--password` | `string` | — | Password (omit to be prompted) |
| `--server` | `string` | — | Server base URL (or set KEYORIX_SERVER) |
| `--username` | `string` | — | Username |

## `keyorix logout`

Revoke the stored session and forget it locally

logout is the remote-only successor to the old CLI's "auth logout"
(docs/cli-split-inventory.md §2.3, §4): the old command only cleared local config and
never told the server (§8 Finding S12). This one calls POST /auth/logout to invalidate
the token server-side first, then deletes the local credentials file regardless of
whether that call succeeded -- a server that is unreachable or already rejects the
token must not leave a stale credential sitting on disk.

**Usage:** `keyorix logout`

## `keyorix machine`

Manage machine identities

Commands for listing, creating, and managing the lifecycle of project machine identities (CI, k8s, services, automation).

**Usage:** `keyorix machine [command]`

**Subcommands:**

- [`keyorix machine audit`](#keyorix-machine-audit) — Print a machine identity audit report (admin)
- [`keyorix machine binding`](#keyorix-machine-binding) — Manage a machine identity's OIDC federation bindings (ADR-031)
- [`keyorix machine create`](#keyorix-machine-create) — Create a machine identity in a project
- [`keyorix machine describe`](#keyorix-machine-describe) — Show details of a machine identity
- [`keyorix machine grant-role`](#keyorix-machine-grant-role) — Grant a machine identity a project-scoped role
- [`keyorix machine list`](#keyorix-machine-list) — List machine identities in a project
- [`keyorix machine migrate-from-user`](#keyorix-machine-migrate-from-user) — Convert a service-account-shaped user into a machine identity
- [`keyorix machine reactivate`](#keyorix-machine-reactivate) — Reactivate a suspended machine identity
- [`keyorix machine revoke`](#keyorix-machine-revoke) — Revoke a machine identity (terminal)
- [`keyorix machine revoke-role`](#keyorix-machine-revoke-role) — Remove a project-scoped role grant from a machine identity
- [`keyorix machine roles`](#keyorix-machine-roles) — List a machine identity's project-scoped roles
- [`keyorix machine suspend`](#keyorix-machine-suspend) — Suspend a machine identity
- [`keyorix machine token`](#keyorix-machine-token) — Manage machine identity tokens
- [`keyorix machine token-hygiene`](#keyorix-machine-token-hygiene) — List stale or expired-but-active machine tokens across all identities (admin)

## `keyorix machine audit`

Print a machine identity audit report (admin)

Generate a deployment-wide audit report of all machine identities.
Each row shows the identity's credential count, last-used timestamp,
whether it is stale (no activity \> 30 days), and its revocation status.

Requires global audit.read permission.

**Usage:** `keyorix machine audit [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | `string` | `json` | Output format: json or csv |

## `keyorix machine binding`

Manage a machine identity's OIDC federation bindings (ADR-031)

Bind external OIDC principals (issuer + subject) to a machine identity so workloads can authenticate with a platform-issued JWT instead of a stored secret.

**Usage:** `keyorix machine binding [command]`

**Subcommands:**

- [`keyorix machine binding add`](#keyorix-machine-binding-add) — Bind an OIDC (issuer, subject) to a machine identity
- [`keyorix machine binding list`](#keyorix-machine-binding-list) — List a machine identity's OIDC bindings
- [`keyorix machine binding rm`](#keyorix-machine-binding-rm) — Remove an OIDC binding from a machine identity

## `keyorix machine binding add`

Bind an OIDC (issuer, subject) to a machine identity

**Usage:** `keyorix machine binding add <machine> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--issuer` | `string` | — | OIDC issuer (the token's iss claim) (required) |
| `--project` | `string` | — | Project name or numeric ID |
| `--subject` | `string` | — | OIDC subject (the token's sub claim) (required) |

## `keyorix machine binding list`

List a machine identity's OIDC bindings

**Usage:** `keyorix machine binding list <machine> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine binding rm`

Remove an OIDC binding from a machine identity

**Usage:** `keyorix machine binding rm <machine> <binding-id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine create`

Create a machine identity in a project

**Usage:** `keyorix machine create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--classification` | `string` | — | Data classification: public \| internal \| confidential \| restricted |
| `--description` | `string` | — | Description |
| `--name` | `string` | — | Machine identity name (required) |
| `--project` | `string` | — | Project name or numeric ID |
| `--type` | `string` | `other` | Identity type: ci \| k8s \| service \| automation \| other \| node |

## `keyorix machine describe`

Show details of a machine identity

**Usage:** `keyorix machine describe <name|id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine grant-role`

Grant a machine identity a project-scoped role

Grant a machine identity a role at its project's scope, so tokens it issues can act with that role's permissions.

**Usage:** `keyorix machine grant-role <name|id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |
| `--role` | `string` | — | Role name to grant (required) |

## `keyorix machine list`

List machine identities in a project

**Usage:** `keyorix machine list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine migrate-from-user`

Convert a service-account-shaped user into a machine identity

Materialise a project machine identity (ADR-023) for an existing user and,
unless --keep-user is set, suspend the source user so it can no longer log in.
The user is never deleted; suspension is reversible via `keyorix user reactivate`.

**Usage:** `keyorix machine migrate-from-user <username> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--keep-user` | — | — | Leave the source user active (default: suspend it) |
| `--name` | `string` | — | Machine identity name (defaults to the username) |
| `--project` | `string` | — | Project for the new machine identity |
| `--type` | `string` | `service` | Identity type: ci \| k8s \| service \| automation \| other |

## `keyorix machine reactivate`

Reactivate a suspended machine identity

**Usage:** `keyorix machine reactivate <name|id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine revoke`

Revoke a machine identity (terminal)

**Usage:** `keyorix machine revoke <name|id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | — | — | Skip the confirmation prompt |
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine revoke-role`

Remove a project-scoped role grant from a machine identity

Revoke a previously granted project-scoped role (distinct from `machine revoke`, which revokes the whole machine identity).

**Usage:** `keyorix machine revoke-role <name|id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |
| `--role` | `string` | — | Role name to revoke (required) |

## `keyorix machine roles`

List a machine identity's project-scoped roles

**Usage:** `keyorix machine roles <name|id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine suspend`

Suspend a machine identity

**Usage:** `keyorix machine suspend <name|id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine token`

Manage machine identity tokens

Issue, list, and revoke bearer tokens for a machine identity (ADR-030).

**Usage:** `keyorix machine token [command]`

**Subcommands:**

- [`keyorix machine token issue`](#keyorix-machine-token-issue) — Issue a new bearer token for a machine identity
- [`keyorix machine token list`](#keyorix-machine-token-list) — List tokens for a machine identity
- [`keyorix machine token revoke`](#keyorix-machine-token-revoke) — Revoke a machine identity token

## `keyorix machine token issue`

Issue a new bearer token for a machine identity

**Usage:** `keyorix machine token issue <name|id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--classification` | `string` | — | Data classification: public \| internal \| confidential \| restricted |
| `--expires-in-days` | `int` | — | Token lifetime in days (0 = never expires) |
| `--name` | `string` | — | Token label (required) |
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine token list`

List tokens for a machine identity

**Usage:** `keyorix machine token list <name|id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine token revoke`

Revoke a machine identity token

**Usage:** `keyorix machine token revoke <name|id> <token-id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | — | — | Skip the confirmation prompt |
| `--project` | `string` | — | Project name or numeric ID |

## `keyorix machine token-hygiene`

List stale or expired-but-active machine tokens across all identities (admin)

Show the deployment-wide machine-identity credentials that should probably be
revoked: ones that have expired but were never revoked, and ones unused for a long
window (non-human token sprawl). Requires global audit.read. Never prints a secret.

**Usage:** `keyorix machine token-hygiene [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--days` | `int` | — | Staleness window in days (default server-side: 90, cap 3650) |

## `keyorix mfa`

Manage MFA (multi-factor authentication)

**Usage:** `keyorix mfa [command]`

**Subcommands:**

- [`keyorix mfa activate`](#keyorix-mfa-activate) — Confirm TOTP enrolment with a code, enabling MFA
- [`keyorix mfa enroll`](#keyorix-mfa-enroll) — Begin TOTP MFA enrolment
- [`keyorix mfa stepup`](#keyorix-mfa-stepup) — Re-verify your TOTP to unlock restricted secret reads

## `keyorix mfa activate`

Confirm TOTP enrolment with a code, enabling MFA

activate verifies a TOTP code (from the authenticator app you enrolled with
"keyorix mfa enroll") against the pending secret, together with your account
password, and enables MFA. On success it prints one-time-shown recovery codes --
save them now, they will not be shown again. Activation keeps the current session
signed in (you just proved the password and a code) and signs out every other
session for the account; your next "keyorix login" asks for a code. Exception: in
the setup session after a one-time password (recover-admin, forced reset) under
security.require_mfa, activating as the last setup step ends that session too.

**Usage:** `keyorix mfa activate [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--code` | `string` | — | TOTP code from the authenticator app (INSECURE on the command line -- prefer KEYORIX_MFA_CODE[_FILE], or omit to be prompted) |
| `--password` | `string` | — | Account password (INSECURE on the command line -- prefer KEYORIX_PASSWORD[_FILE], or omit to be prompted) |

## `keyorix mfa enroll`

Begin TOTP MFA enrolment

enroll generates a fresh TOTP secret and prints the otpauth:// URI (for a QR code)
and the base32 secret (for manual entry into an authenticator app). This only begins
enrolment -- the account is not protected by MFA until you confirm with a code via
"keyorix mfa activate". With security.require_mfa on (the default, ADR-112), a
session without MFA can reach only enroll/activate until this is done.

**Usage:** `keyorix mfa enroll`

## `keyorix mfa stepup`

Re-verify your TOTP to unlock restricted secret reads

Re-verify your authenticator code (or a recovery code) without re-logging in.
On success, a 15-minute window is opened server-side that allows reading
"restricted" classified secrets.

**Usage:** `keyorix mfa stepup [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--code` | `string` | — | TOTP or recovery code (INSECURE on the command line -- prefer KEYORIX_MFA_CODE[_FILE], or omit to be prompted) |

## `keyorix notification`

Manage notifications and notification channels

**Usage:** `keyorix notification [command]`

**Subcommands:**

- [`keyorix notification channel`](#keyorix-notification-channel) — Manage runtime notification channel destinations

## `keyorix notification channel`

Manage runtime notification channel destinations

**Usage:** `keyorix notification channel [command]`

**Subcommands:**

- [`keyorix notification channel add`](#keyorix-notification-channel-add) — Add a notification channel
- [`keyorix notification channel delete`](#keyorix-notification-channel-delete) — Delete a notification channel by name
- [`keyorix notification channel get`](#keyorix-notification-channel-get) — Get details of a notification channel by name
- [`keyorix notification channel list`](#keyorix-notification-channel-list) — List all notification channels
- [`keyorix notification channel update`](#keyorix-notification-channel-update) — Update a notification channel by name

## `keyorix notification channel add`

Add a notification channel

**Usage:** `keyorix notification channel add <name> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--email` | `string` | — | Email address (required for email type) |
| `--events` | `string` | — | Comma-separated event types, e.g. secret.rotated,anomaly.detected (empty = all) |
| `--type` | `string` | — | Channel type: webhook, slack, teams, or email (required) |
| `--url` | `string` | — | Webhook URL (required for webhook/slack/teams) |

## `keyorix notification channel delete`

Delete a notification channel by name

**Usage:** `keyorix notification channel delete <name> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--confirm` | — | — | Confirm deletion without interactive prompt |

## `keyorix notification channel get`

Get details of a notification channel by name

**Usage:** `keyorix notification channel get <name>`

## `keyorix notification channel list`

List all notification channels

**Usage:** `keyorix notification channel list`

## `keyorix notification channel update`

Update a notification channel by name

**Usage:** `keyorix notification channel update <name> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--disabled` | — | — | Disable the channel |
| `--email` | `string` | — | New email address |
| `--enabled` | — | — | Enable the channel |
| `--events` | `string` | — | New event filter (comma-separated) |
| `--url` | `string` | — | New webhook URL |

## `keyorix pat`

Create and manage personal access tokens

**Usage:** `keyorix pat [command]`

**Subcommands:**

- [`keyorix pat cleanup-expired`](#keyorix-pat-cleanup-expired) — Bulk-revoke all your expired personal access tokens
- [`keyorix pat create`](#keyorix-pat-create) — Create a personal access token (the raw token is shown once)
- [`keyorix pat hygiene`](#keyorix-pat-hygiene) — List stale or expired-but-active tokens across all users (admin)
- [`keyorix pat list`](#keyorix-pat-list) — List your personal access tokens
- [`keyorix pat list-expired`](#keyorix-pat-list-expired) — List your expired (non-revoked) personal access tokens
- [`keyorix pat revoke`](#keyorix-pat-revoke) — Revoke one of your tokens

## `keyorix pat cleanup-expired`

Bulk-revoke all your expired personal access tokens

**Usage:** `keyorix pat cleanup-expired`

## `keyorix pat create`

Create a personal access token (the raw token is shown once)

**Usage:** `keyorix pat create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--allowed-cidr` | `stringArray` | — | Restrict the token to source IPs in this CIDR (repeatable; e.g. --allowed-cidr 10.0.0.0/8). Omit = no network restriction |
| `--environment-id` | `int` | — | Confine the token to a single environment (0 = any; only with --project-id) |
| `--expires` | `string` | — | Expiry (RFC3339 or YYYY-MM-DD; omit = never) |
| `--name` | `string` | — | Token name (required) |
| `--project-id` | `int` | — | Confine the token to a single project (0 = any) |
| `--scope` | `stringArray` | — | Least-privilege permission (repeatable; e.g. --scope secrets.read). Omit = inherit all your permissions |

## `keyorix pat hygiene`

List stale or expired-but-active tokens across all users (admin)

Show the deployment-wide personal access tokens that should probably be
revoked: ones that have expired but were never revoked, and ones unused for a long
window (token sprawl). Requires global audit.read. Never prints a token's secret.

**Usage:** `keyorix pat hygiene [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--days` | `int` | — | Staleness window in days (default server-side: 90, cap 3650) |

## `keyorix pat list`

List your personal access tokens

**Usage:** `keyorix pat list`

## `keyorix pat list-expired`

List your expired (non-revoked) personal access tokens

**Usage:** `keyorix pat list-expired`

## `keyorix pat revoke`

Revoke one of your tokens

**Usage:** `keyorix pat revoke <token-id>`

## `keyorix project`

Manage projects

Commands for listing, creating, and inspecting Keyorix projects.

**Usage:** `keyorix project [command]`

**Subcommands:**

- [`keyorix project create`](#keyorix-project-create) — Create a new project
- [`keyorix project current`](#keyorix-project-current) — Show the currently active project
- [`keyorix project describe`](#keyorix-project-describe) — Show details of a project
- [`keyorix project env`](#keyorix-project-env) — Manage environments within a project
- [`keyorix project environments`](#keyorix-project-environments) — List environments for a project
- [`keyorix project health`](#keyorix-project-health) — Show the secret health summary for a project
- [`keyorix project hygiene`](#keyorix-project-hygiene) — Show a project's security-hygiene posture (counts)
- [`keyorix project list`](#keyorix-project-list) — List all projects
- [`keyorix project resume-secrets`](#keyorix-project-resume-secrets) — Resume every suspended secret in a project -- restore value reads
- [`keyorix project stats`](#keyorix-project-stats) — Show rich statistics for a project
- [`keyorix project suspend-secrets`](#keyorix-project-suspend-secrets) — Suspend every secret in a project -- block value reads project-wide
- [`keyorix project use`](#keyorix-project-use) — Set the active project for subsequent commands

## `keyorix project create`

Create a new project

**Usage:** `keyorix project create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--description` | `string` | — | Project description |
| `--envs` | `string` | — | Comma-separated environment names to seed (default: "development,staging,production") |
| `--name` | `string` | — | Project name (required) |

## `keyorix project current`

Show the currently active project

**Usage:** `keyorix project current`

## `keyorix project describe`

Show details of a project

Displays environments and description for the specified project (or the active project if none given).

**Usage:** `keyorix project describe [name]`

## `keyorix project env`

Manage environments within a project

**Usage:** `keyorix project env [command]`

**Subcommands:**

- [`keyorix project env clone`](#keyorix-project-env-clone) — Clone all secrets from one environment to another in the same project
- [`keyorix project env create`](#keyorix-project-env-create) — Create a new environment in the active (or specified) project
- [`keyorix project env delete`](#keyorix-project-env-delete) — Delete an environment by ID
- [`keyorix project env list`](#keyorix-project-env-list) — List environments for the active (or specified) project

## `keyorix project env clone`

Clone all secrets from one environment to another in the same project

Copies every secret from the source environment into the destination environment
within the same project. Secrets that already exist by name in the destination are
skipped (not overwritten). Only the latest version of each secret is copied.

**Usage:** `keyorix project env clone <src-env-name> <dst-env-name> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Override the active project |

## `keyorix project env create`

Create a new environment in the active (or specified) project

**Usage:** `keyorix project env create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--name` | `string` | — | Environment name (required) |
| `--project` | `string` | — | Override the active project |

## `keyorix project env delete`

Delete an environment by ID

**Usage:** `keyorix project env delete <env-id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--confirm` | — | — | Confirm deletion without interactive prompt |
| `--project` | `string` | — | Override the active project |

## `keyorix project env list`

List environments for the active (or specified) project

**Usage:** `keyorix project env list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Override the active project |

## `keyorix project environments`

List environments for a project

**Usage:** `keyorix project environments <project-id>`

## `keyorix project health`

Show the secret health summary for a project

**Usage:** `keyorix project health <name> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | `string` | `table` | Output format (table, json) |
| `--limit` | `int` | `20` | Maximum number of secrets to display (1-100) |

## `keyorix project hygiene`

Show a project's security-hygiene posture (counts)

Summarize a project's outstanding cleanup signals in one call: secrets whose owner
departed, secrets unused for a long window, secrets expiring/expired, and stale machine
identities. Requires secrets.read at the project scope.

**Usage:** `keyorix project hygiene <project-id>`

## `keyorix project list`

List all projects

**Usage:** `keyorix project list`

## `keyorix project resume-secrets`

Resume every suspended secret in a project -- restore value reads

**Usage:** `keyorix project resume-secrets [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Project ID (required) |

## `keyorix project stats`

Show rich statistics for a project

**Usage:** `keyorix project stats <name> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | `string` | `table` | Output format (table, json) |

## `keyorix project suspend-secrets`

Suspend every secret in a project -- block value reads project-wide

Freeze a whole project (a breach response): value reads of every active secret
in the project that you may write are refused until you resume them. Versions, shares
and the audit trail are preserved. Requires secrets.write on the project, the same as
suspending one secret.

With --clear-synced-copies the copies of those secrets synced to Kubernetes clusters
(by the operator or keyorix-k8s-sync) are also emptied for the duration of THIS
suspension, whatever each resource's own onSuspend setting says. Use it when the
secrets are compromised, and rotate them afterwards. Resuming removes the request and
the next sync restores the copies. Running suspend-secrets again with the flag adds
the request to secrets that are already suspended without it.

**Usage:** `keyorix project suspend-secrets [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--clear-synced-copies` | — | — | Also clear the copies synced to Kubernetes clusters for this suspension (compromise response; rotate the secrets afterwards) |
| `--id` | `int` | — | Project ID (required) |
| `--reason` | `string` | — | Optional reason recorded in the audit events |

## `keyorix project use`

Set the active project for subsequent commands

Saves the active project name to the credentials file (cli/internal/credstore).
All project-scoped commands inherit this context; override per-command with --project.

**Usage:** `keyorix project use <name>`

## `keyorix rbac`

Role-Based Access Control management commands

**Usage:** `keyorix rbac [command]`

**Subcommands:**

- [`keyorix rbac assign-role`](#keyorix-rbac-assign-role) — Assign a role to a user
- [`keyorix rbac assign-role-to-group`](#keyorix-rbac-assign-role-to-group) — Assign a role to a group
- [`keyorix rbac audit-logs`](#keyorix-rbac-audit-logs) — View RBAC audit logs
- [`keyorix rbac check-permission`](#keyorix-rbac-check-permission) — Check if a user has a specific permission
- [`keyorix rbac export-matrix`](#keyorix-rbac-export-matrix) — Export the deployment-wide RBAC permission matrix
- [`keyorix rbac list-group-roles`](#keyorix-rbac-list-group-roles) — List roles assigned to a group
- [`keyorix rbac list-permissions`](#keyorix-rbac-list-permissions) — List all permissions for a user
- [`keyorix rbac list-roles`](#keyorix-rbac-list-roles) — List all available roles
- [`keyorix rbac list-user-roles`](#keyorix-rbac-list-user-roles) — List roles assigned to a user
- [`keyorix rbac remove-role`](#keyorix-rbac-remove-role) — Remove a role from a user
- [`keyorix rbac remove-role-from-group`](#keyorix-rbac-remove-role-from-group) — Remove a role from a group

## `keyorix rbac assign-role`

Assign a role to a user

Assign a role to a user by email address.

With --project, the grant is scoped to that project only (rather than globally).
With --environment, the grant is further narrowed to a single environment within
that project (--project must also be supplied).

With --ttl, the grant is time-bound (just-in-time access): it stops authorizing
once the window passes and is swept automatically. Useful for emergency or
contractor access. Example: --ttl 4h grants the role for four hours.

**Usage:** `keyorix rbac assign-role [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment` | `string` | — | Scope the grant to this environment within --project (optional; requires --project) |
| `--project` | `string` | — | Scope the grant to this project (optional) |
| `--role` | `string` | — | Role name to assign (required) |
| `--ttl` | `duration` | — | Time-bound grant lifetime (e.g. 4h, 30m); omit for a permanent grant |
| `--user` | `string` | — | User email address (required) |

## `keyorix rbac assign-role-to-group`

Assign a role to a group

Assign a role to a group.

With --project, the grant is scoped to that project only.
With --environment, the grant is further narrowed to a single environment within
that project (--project must also be supplied).

With --ttl, the grant is time-bound (just-in-time access).

**Usage:** `keyorix rbac assign-role-to-group [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment` | `string` | — | Scope the grant to this environment within --project (optional; requires --project) |
| `--group` | `string` | — | Group name or numeric ID (required) |
| `--project` | `string` | — | Scope the grant to this project (optional) |
| `--role` | `string` | — | Role name to assign (required) |
| `--ttl` | `duration` | — | Time-bound grant lifetime (e.g. 4h, 30m); omit for a permanent grant |

## `keyorix rbac audit-logs`

View RBAC audit logs

View audit logs for RBAC operations (role assignments, removals, permission grants).

**Usage:** `keyorix rbac audit-logs [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--limit` | `int` | `50` | Maximum number of logs to retrieve |
| `--offset` | `int` | — | Number of logs to skip |

## `keyorix rbac check-permission`

Check if a user has a specific permission

Check if a user has a specific permission by email address and permission name

**Usage:** `keyorix rbac check-permission [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--permission` | `string` | — | Permission name to check (required) |
| `--user` | `string` | — | User email address (required) |

## `keyorix rbac export-matrix`

Export the deployment-wide RBAC permission matrix

Export every (user, role, permission, scope) tuple in the deployment.

Used by auditors for SOC2/ISO27001 access reviews. Output includes who holds
what role/permission in what scope (global, project, or environment).

Supports table (default), JSON, and CSV output formats.

Examples:
```text
  keyorix rbac export-matrix
  keyorix rbac export-matrix --format csv --output access-review.csv
  keyorix rbac export-matrix --format json --project production
```

**Usage:** `keyorix rbac export-matrix [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | `string` | `table` | Output format: table, csv, or json |
| `--output` | `string` | — | Write output to this file (default: stdout) |
| `--project` | `string` | — | Filter by project name (optional) |

## `keyorix rbac list-group-roles`

List roles assigned to a group

List all roles assigned to a specific group.

**Usage:** `keyorix rbac list-group-roles [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--group` | `string` | — | Group name or numeric ID (required) |

## `keyorix rbac list-permissions`

List all permissions for a user

List all permissions assigned to a user through their roles

**Usage:** `keyorix rbac list-permissions [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--user` | `string` | — | User email address (required) |

## `keyorix rbac list-roles`

List all available roles

List all roles in the system

**Usage:** `keyorix rbac list-roles`

## `keyorix rbac list-user-roles`

List roles assigned to a user

List all roles assigned to a specific user by email address

**Usage:** `keyorix rbac list-user-roles [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--user` | `string` | — | User email address (required) |

## `keyorix rbac remove-role`

Remove a role from a user

Remove a role assignment from a user by email address.

With --project, removes only the grant scoped to that project.
With --environment, removes only the grant scoped to that environment within
the project (--project must also be supplied).

**Usage:** `keyorix rbac remove-role [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment` | `string` | — | Remove the grant scoped to this environment within --project (optional; requires --project) |
| `--project` | `string` | — | Remove the grant scoped to this project (optional) |
| `--role` | `string` | — | Role name to remove (required) |
| `--user` | `string` | — | User email address (required) |

## `keyorix rbac remove-role-from-group`

Remove a role from a group

Remove a role assignment from a group.

With --project, removes only the grant scoped to that project.
With --environment, removes only the grant scoped to that environment within
the project (--project must also be supplied).

**Usage:** `keyorix rbac remove-role-from-group [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment` | `string` | — | Remove the grant scoped to this environment within --project (optional; requires --project) |
| `--group` | `string` | — | Group name or numeric ID (required) |
| `--project` | `string` | — | Remove the grant scoped to this project (optional) |
| `--role` | `string` | — | Role name to remove (required) |

## `keyorix request`

Manage project access requests

Request access to a project, list, withdraw, and review (approve/reject) requests (ADR-024).

**Usage:** `keyorix request [command]`

**Subcommands:**

- [`keyorix request access`](#keyorix-request-access) — Request access to a project
- [`keyorix request bulk-approve`](#keyorix-request-bulk-approve) — Approve multiple pending access requests at once
- [`keyorix request bulk-reject`](#keyorix-request-bulk-reject) — Reject multiple pending access requests at once
- [`keyorix request list`](#keyorix-request-list) — List a project's access requests
- [`keyorix request rejection-templates`](#keyorix-request-rejection-templates) — Manage rejection-reason templates
- [`keyorix request review`](#keyorix-request-review) — Approve or reject a pending access request
- [`keyorix request secret-access`](#keyorix-request-secret-access) — Request approval to read one restricted secret's value
- [`keyorix request withdraw`](#keyorix-request-withdraw) — Withdraw your own pending access request

## `keyorix request access`

Request access to a project

Create a pending access request for the caller to a project, optionally suggesting a role (ADR-024).

**Usage:** `keyorix request access [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name (or use KEYORIX_PROJECT) |
| `--project-id` | `uint` | — | Project ID -- use this instead of --project when the caller holds no project grant yet (nothing to list, so a name cannot be resolved); the project-scoped access-request routes themselves do not require it |
| `--reason` | `string` | — | Reason for the request (optional) |
| `--role` | `string` | — | Suggested project role (optional) |

## `keyorix request bulk-approve`

Approve multiple pending access requests at once

Approve several pending access requests in a single call (ADR-024 extension).
Provide a comma-separated list of request IDs with --ids.

**Usage:** `keyorix request bulk-approve [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ids` | `string` | — | Comma-separated list of access request IDs (required) |

## `keyorix request bulk-reject`

Reject multiple pending access requests at once

Reject several pending access requests in a single call (ADR-024 extension).
All rejected requests share the same --reason.

**Usage:** `keyorix request bulk-reject [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ids` | `string` | — | Comma-separated list of access request IDs (required) |
| `--reason` | `string` | — | Rejection reason shared across all requests (required) |

## `keyorix request list`

List a project's access requests

**Usage:** `keyorix request list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `string` | — | Project name (or use KEYORIX_PROJECT) |
| `--project-id` | `uint` | — | Project ID -- use this instead of --project when the caller holds no project grant yet (nothing to list, so a name cannot be resolved); the project-scoped access-request routes themselves do not require it |

## `keyorix request rejection-templates`

Manage rejection-reason templates

**Usage:** `keyorix request rejection-templates [command]`

**Subcommands:**

- [`keyorix request rejection-templates add`](#keyorix-request-rejection-templates-add) — Add a new rejection-reason template
- [`keyorix request rejection-templates delete`](#keyorix-request-rejection-templates-delete) — Delete a rejection-reason template by ID
- [`keyorix request rejection-templates list`](#keyorix-request-rejection-templates-list) — List all rejection-reason templates

## `keyorix request rejection-templates add`

Add a new rejection-reason template

**Usage:** `keyorix request rejection-templates add [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--name` | `string` | — | Short label for the template (required) |
| `--reason` | `string` | — | Template rejection text (required) |

## `keyorix request rejection-templates delete`

Delete a rejection-reason template by ID

**Usage:** `keyorix request rejection-templates delete <id>`

## `keyorix request rejection-templates list`

List all rejection-reason templates

**Usage:** `keyorix request rejection-templates list`

## `keyorix request review`

Approve or reject a pending access request

Resolve a pending access request (admin-driven, ADR-024).
Approving grants the role at the project scope (--role overrides the suggested role);
rejecting records a --reason.

**Usage:** `keyorix request review [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--action` | `string` | — | approve \| reject (required) |
| `--id` | `uint` | — | Access request ID (required) |
| `--project` | `string` | — | Project name (or use --project-id / KEYORIX_PROJECT) |
| `--project-id` | `uint` | — | Project ID -- use this instead of --project when the caller holds no project grant yet (nothing to list, so a name cannot be resolved); the project-scoped access-request routes themselves do not require it |
| `--reason` | `string` | — | Reason on reject |
| `--role` | `string` | — | Role to grant on approve (defaults to the suggested role) |
| `--ttl` | `string` | — | Time-bound the granted role on approve (Go duration, e.g. 4h); empty = permanent |

## `keyorix request secret-access`

Request approval to read one restricted secret's value

Create a pending, secret-scoped access request: approval to read ONE specific
secret's value, distinct from `request access`'s broader project/role request.
Only relevant when classification.restricted_requires_approval is enabled and
the target secret's classification is "restricted" — the gate this satisfies.

**Usage:** `keyorix request secret-access [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--reason` | `string` | — | Reason for the request (required) |
| `--ref` | `string` | — | Secret reference "project/environment/name" (or use --secret-id) |
| `--secret-id` | `uint` | — | Secret ID (or use --ref) |

## `keyorix request withdraw`

Withdraw your own pending access request

Cancel a pending access request you own, by ID (self-service, ADR-024).

**Usage:** `keyorix request withdraw [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `uint` | — | Access request ID (required) |
| `--project` | `string` | — | Project name (or use --project-id / KEYORIX_PROJECT) |
| `--project-id` | `uint` | — | Project ID -- use this instead of --project when the caller holds no project grant yet (nothing to list, so a name cannot be resolved); the project-scoped access-request routes themselves do not require it |

## `keyorix risk`

Risk register — governed, time-bound exceptions to control gaps (A.5.8)

Record and review accepted risk exceptions: a known control gap, accepted by
an owner with a justification, that sunsets at a fixed date. An active exception is
the evidence that a gap is governed (accepted with a deadline) rather than ignored.

**Usage:** `keyorix risk [command]`

**Subcommands:**

- [`keyorix risk add`](#keyorix-risk-add) — Record a risk exception (accept a control gap for a bounded time)
- [`keyorix risk approve`](#keyorix-risk-approve) — Approve a risk exception so it takes effect (dual control — must not be its own creator)
- [`keyorix risk list`](#keyorix-risk-list) — List risk exceptions (active by default; --all includes expired)
- [`keyorix risk revoke`](#keyorix-risk-revoke) — Revoke a risk exception before its expiry

## `keyorix risk add`

Record a risk exception (accept a control gap for a bounded time)

**Usage:** `keyorix risk add [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--category` | `string` | `other` | sod \| mfa \| rotation \| dormant_access \| classification \| other |
| `--expires` | `string` | — | When the exception sunsets (RFC3339, required) |
| `--justification` | `string` | — | Why the risk is accepted (required, recorded for audit) |
| `--reference` | `string` | — | What it applies to (a user, an SoD pair, a secret) |
| `--title` | `string` | — | Short name for the accepted risk (required) |

## `keyorix risk approve`

Approve a risk exception so it takes effect (dual control — must not be its own creator)

An exception is inert until approved: it does not suppress its matched
violation from the compliance posture until a DIFFERENT system.write holder than
the one who created it approves it. This prevents a single principal from
unilaterally creating and self-approving a suppression of their own risk.

**Usage:** `keyorix risk approve [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | ID of the exception to approve (required) |

## `keyorix risk list`

List risk exceptions (active by default; --all includes expired)

**Usage:** `keyorix risk list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all` | — | — | Include expired exceptions (history) |

## `keyorix risk revoke`

Revoke a risk exception before its expiry

**Usage:** `keyorix risk revoke [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | ID of the exception to revoke (required) |

## `keyorix rotation`

Manage secret-rotation policies and see rotation posture

**Usage:** `keyorix rotation [command]`

**Subcommands:**

- [`keyorix rotation create`](#keyorix-rotation-create) — Create a rotation policy
- [`keyorix rotation delete`](#keyorix-rotation-delete) — Delete a rotation policy
- [`keyorix rotation list`](#keyorix-rotation-list) — List rotation policies
- [`keyorix rotation order`](#keyorix-rotation-order) — Print a safe rotation sequence for a project's dependency graph
- [`keyorix rotation plan`](#keyorix-rotation-plan) — Print an automated rotation plan (dependency-safe waves, by urgency)
- [`keyorix rotation show`](#keyorix-rotation-show) — Show a rotation policy
- [`keyorix rotation status`](#keyorix-rotation-status) — Show policy-covered secrets that are overdue or approaching rotation

## `keyorix rotation create`

Create a rotation policy

**Usage:** `keyorix rotation create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--alert-days-before` | `int` | `7` | Warn this many days before the deadline (0-90) |
| `--description` | `string` | — | Policy description |
| `--environment-id` | `int` | — | Target environment (required when --scope environment) |
| `--interval-days` | `int` | — | Rotation interval in days, 1-365 (required) |
| `--name` | `string` | — | Policy name (required) |
| `--notify-on-breach` | — | `true` | Notify when a covered secret goes overdue |
| `--project-id` | `int` | — | Target project (required when --scope project) |
| `--scope` | `string` | — | Scope: project \| environment (required) |

## `keyorix rotation delete`

Delete a rotation policy

**Usage:** `keyorix rotation delete <id>`

## `keyorix rotation list`

List rotation policies

**Usage:** `keyorix rotation list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment-id` | `int` | — | Filter by environment |
| `--project-id` | `int` | — | Filter by project |

## `keyorix rotation order`

Print a safe rotation sequence for a project's dependency graph

Print the order in which a project's secrets should be rotated so that each secret
is rotated before anything that depends on it (a topological sort of the dependency
graph, ADR-052). Only secrets that appear in the graph are listed.

**Usage:** `keyorix rotation order <project-id>`

## `keyorix rotation plan`

Print an automated rotation plan (dependency-safe waves, by urgency)

Print the rotation plan for a project: its overdue and due-soon secrets, batched
into dependency-safe waves (rotate a wave at a time, top to bottom; within a wave the
most urgent first) and annotated with why each is due and what it must follow (ADR-053).

With --all-projects, print the deployment-wide roll-up instead: every project's plan
aggregated into install-wide totals, most pressing project first. Dependencies are
per-project, so each project keeps its own wave order.

**Usage:** `keyorix rotation plan [project-id] [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all-projects` | — | — | Plan rotation across every project (deployment-wide roll-up) |

## `keyorix rotation show`

Show a rotation policy

**Usage:** `keyorix rotation show <id>`

## `keyorix rotation status`

Show policy-covered secrets that are overdue or approaching rotation

**Usage:** `keyorix rotation status [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project-id` | `int` | — | Limit to a single project |

## `keyorix run`

Inject secrets as env vars and run a command

Fetch secrets for a project + environment, expose them as environment
variables, then execute the supplied command.

'keyorix run' does not inject anything by default -- pick exactly one:

```text
  --var NAME=secret-ref   (recommended) YOU choose the env var name.
    keyorix run --env production --var DATABASE_URL=db-password -- node app.js
    Repeatable. Only the named secrets are injected, under the names you gave
    them -- a secret's own NAME never determines what env var it lands under.

  --derive-names   (deprecated) inject every secret in the project + environment,
    with the env var key AUTO-DERIVED from the secret's own name. Deprecated
    because whoever can NAME a secret then controls which env var it becomes --
    including reserved ones like LD_PRELOAD -- not just its value. See
    https://github.com/keyorixhq/keyorix/issues/1816 for why this changed.

```
Project is resolved via: --project-id flag -\> --project flag -\> KEYORIX_PROJECT env.

--project-id bypasses the project-NAME lookup (GET /api/v1/projects). Since #2780
that listing serves a project-scoped caller their own projects, so --project works
for a token scoped to this project. --project-id is still the only path for a token
with NO project grant at all (it resolves nothing by name), and the cheaper one in
CI -- it skips a round trip. See
https://github.com/keyorixhq/keyorix/issues/2360 for the same shape on
'keyorix request'.

**Usage:** `keyorix run [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--clean-env` | — | — | Start the child process with ONLY the injected secrets (plus a minimal PATH/HOME baseline) instead of the full inherited parent environment |
| `--derive-names` | — | — | Deprecated: inject every secret in the project+environment, deriving the env var name from the secret's own name |
| `--env` | `string` | `development` | Environment name (e.g. production) |
| `--project` | `string` | — | Project name (overrides KEYORIX_PROJECT) |
| `--project-id` | `uint` | — | Project ID -- use this instead of --project to skip the name lookup (GET /api/v1/projects) entirely; required when the caller's token holds no project grant, since a name cannot be resolved without a listing |
| `--var` | `stringArray` | — | Inject one secret under an explicit env var name: --var NAME=secret-ref (repeatable, recommended) |

## `keyorix secret`

Manage secrets

Create, read, update, delete, and manage secrets and their metadata; bulk operations, rotation, export/import, and hygiene reports.

**Usage:** `keyorix secret [command]`

**Subcommands:**

- [`keyorix secret access`](#keyorix-secret-access) — List who can access a secret and at what effective level
- [`keyorix secret access-log`](#keyorix-secret-access-log) — Show a secret's recent reads (who/when/from where)
- [`keyorix secret acl`](#keyorix-secret-acl) — Manage per-secret ACL grants (RBAC Phase 3)
- [`keyorix secret audit`](#keyorix-secret-audit) — Show a secret's lifecycle events (created/rotated/suspended/shared/…)
- [`keyorix secret auto-rotate`](#keyorix-secret-auto-rotate) — Enable/disable automated rotation for a secret
- [`keyorix secret blast-radius`](#keyorix-secret-blast-radius) — Show the enriched blast radius of rotating or deleting a secret
- [`keyorix secret bulk-delete`](#keyorix-secret-bulk-delete) — Delete multiple secrets in one operation
- [`keyorix secret bulk-rename`](#keyorix-secret-bulk-rename) — Rename secrets toward naming-policy conformance
- [`keyorix secret bulk-rotate`](#keyorix-secret-bulk-rotate) — Trigger rotation for multiple secrets at once
- [`keyorix secret cert`](#keyorix-secret-cert) — Show a certificate secret's public X.509 metadata (expiry, issuer, SANs)
- [`keyorix secret classify`](#keyorix-secret-classify) — Set a secret's data-classification label (ISO 27001 A.5.12)
- [`keyorix secret clear-schedule`](#keyorix-secret-clear-schedule) — Remove the temporal access schedule for a secret (idempotent)
- [`keyorix secret comment`](#keyorix-secret-comment) — Manage secret version comments
- [`keyorix secret copy`](#keyorix-secret-copy) — Copy a secret's value and metadata into another environment
- [`keyorix secret copy-environment`](#keyorix-secret-copy-environment) — Copy every secret from one environment into another (same project)
- [`keyorix secret create`](#keyorix-secret-create) — Create a new secret
- [`keyorix secret delete`](#keyorix-secret-delete) — Delete a secret (soft-delete; restorable with 'secret restore')
- [`keyorix secret deps`](#keyorix-secret-deps) — Inspect and manage a secret's dependency graph
- [`keyorix secret description`](#keyorix-secret-description) — Show or set a secret's description
- [`keyorix secret diff`](#keyorix-secret-diff) — Diff metadata between two versions of a secret
- [`keyorix secret expiring`](#keyorix-secret-expiring) — List a project's secrets expiring (or already expired) within a window
- [`keyorix secret explain`](#keyorix-secret-explain) — Explain the risk of a discovered secret and how to fix it
- [`keyorix secret export`](#keyorix-secret-export) — Export secrets to a file or stdout
- [`keyorix secret fix`](#keyorix-secret-fix) — Fix a hardcoded secret by moving it to an environment variable
- [`keyorix secret folder`](#keyorix-secret-folder) — Manage secret folders
- [`keyorix secret get`](#keyorix-secret-get) — Get a secret
- [`keyorix secret get-schedule`](#keyorix-secret-get-schedule) — Show the temporal access schedule for a secret
- [`keyorix secret import`](#keyorix-secret-import) — Import secrets from a file
- [`keyorix secret info`](#keyorix-secret-info) — Show a secret's metadata (no value)
- [`keyorix secret list`](#keyorix-secret-list) — List secrets
- [`keyorix secret move`](#keyorix-secret-move) — Move a secret or folder to a different parent folder
- [`keyorix secret name-conformance`](#keyorix-secret-name-conformance) — List secrets whose names violate the current naming policy
- [`keyorix secret orphaned`](#keyorix-secret-orphaned) — List secrets whose owner is no longer a live user
- [`keyorix secret ownership-history`](#keyorix-secret-ownership-history) — Show a secret's ownership-transfer chain
- [`keyorix secret quota-report`](#keyorix-secret-quota-report) — Show secrets approaching or at their MaxReads quota
- [`keyorix secret reassign-owner`](#keyorix-secret-reassign-owner) — Re-home all of a departed user's secrets to a new owner
- [`keyorix secret render`](#keyorix-secret-render) — Render a template, expanding ${secret:\<environment\>/\<name\>} references
- [`keyorix secret restore`](#keyorix-secret-restore) — Restore a soft-deleted secret
- [`keyorix secret resume`](#keyorix-secret-resume) — Resume a suspended secret -- restore value reads
- [`keyorix secret rollback`](#keyorix-secret-rollback) — Restore a secret to the value of a prior version
- [`keyorix secret rotate`](#keyorix-secret-rotate) — Rotate a secret by providing a new value
- [`keyorix secret rotation-simulate`](#keyorix-secret-rotation-simulate) — Simulate a rotation dry-run for a secret
- [`keyorix secret scan`](#keyorix-secret-scan) — Scan a directory for secrets and hardcoded credentials
- [`keyorix secret score`](#keyorix-secret-score) — Show the risk score for a secret
- [`keyorix secret set-schedule`](#keyorix-secret-set-schedule) — Set a temporal access schedule for a secret
- [`keyorix secret suspend`](#keyorix-secret-suspend) — Suspend a secret -- block value reads without deleting it
- [`keyorix secret tags`](#keyorix-secret-tags) — List or set a secret's tags
- [`keyorix secret template`](#keyorix-secret-template) — Manage secret templates
- [`keyorix secret trash`](#keyorix-secret-trash) — List a project's soft-deleted (restorable) secrets
- [`keyorix secret update`](#keyorix-secret-update) — Update an existing secret
- [`keyorix secret versions`](#keyorix-secret-versions) — List secret versions

## `keyorix secret access`

List who can access a secret and at what effective level

Show the effective access list for a secret: every user who can read it, with
their EFFECTIVE permission (for a project member, the higher of their role and any
active share), the grant that gives it (SOURCE), and every grant they hold (GRANTS),
so a share that elevates a role is visible. Expired shares and shares to users who
are not project members grant nothing and are not listed. Global admins have
implicit access and are not listed. Requires secrets.read.

**Usage:** `keyorix secret access [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |

## `keyorix secret access-log`

Show a secret's recent reads (who/when/from where)

List the recent access-log entries for a secret. Requires secrets.read.

**Usage:** `keyorix secret access-log [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--days` | `int` | — | Lookback in days (default server-side: 30) |
| `--id` | `int` | — | Secret ID (required) |

## `keyorix secret acl`

Manage per-secret ACL grants (RBAC Phase 3)

Manage fine-grained per-secret access control (RBAC Phase 3).

An ACL grant allows a specific user to access one secret independently of
their project role. Requires secrets.manage at the secret's project scope.

**Usage:** `keyorix secret acl [command]`

**Subcommands:**

- [`keyorix secret acl grant`](#keyorix-secret-acl-grant) — Grant a user ACL access to a secret
- [`keyorix secret acl list`](#keyorix-secret-acl-list) — List ACL grants for a secret
- [`keyorix secret acl revoke`](#keyorix-secret-acl-revoke) — Revoke an ACL grant from a secret

## `keyorix secret acl grant`

Grant a user ACL access to a secret

**Usage:** `keyorix secret acl grant [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--perm` | `stringArray` | — | Permission to grant (secrets.read or secrets.write); may be repeated |
| `--secret` | `int` | — | Secret ID to grant access to |
| `--user` | `int` | — | User ID to grant access to |

## `keyorix secret acl list`

List ACL grants for a secret

**Usage:** `keyorix secret acl list <secret-id>`

## `keyorix secret acl revoke`

Revoke an ACL grant from a secret

**Usage:** `keyorix secret acl revoke [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--acl` | `int` | — | ACL entry ID to revoke (from `acl list`) |
| `--secret` | `int` | — | Secret ID to revoke the ACL from |

## `keyorix secret audit`

Show a secret's lifecycle events (created/rotated/suspended/shared/…)

List the audit trail for a secret: what happened to it and when (created, rotated,
rolled-back, suspended/resumed, shared, owner-transferred, reclassified), newest first.
Requires secrets.read at the secret's scope. Never prints a plaintext value.

**Usage:** `keyorix secret audit [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |
| `--limit` | `int` | — | Max events to show (default server-side: 50, cap 500) |

## `keyorix secret auto-rotate`

Enable/disable automated rotation for a secret

Opt a secret into automated rotation: when it is overdue under an active rotation
policy, Keyorix regenerates its value on schedule. Optionally set the generated
value's shape with --length and --charset. Use --off to disable.

Enable only for secrets whose value Keyorix owns — auto-rotation changes the stored
value without touching any upstream system. Requires secrets.write at the secret's scope.

**Usage:** `keyorix secret auto-rotate [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--backend` | `string` | — | Rotation backend name — rotate the upstream credential too |
| `--charset` | `string` | — | alphanumeric\|lower_alphanumeric\|hex\|alphanumeric_symbols (empty = default) |
| `--id` | `int` | — | Secret ID (required) |
| `--length` | `int` | — | Generated value length (8-256, 0 = default 32) |
| `--off` | — | — | Disable auto-rotation (default enables) |
| `--ref` | `string` | — | Upstream identifier the backend rotates (required with --backend) |

## `keyorix secret blast-radius`

Show the enriched blast radius of rotating or deleting a secret

Show all downstream dependents of a secret (recursive), each annotated with owner, project, hop depth, and risk level (critical/high/medium/low).

**Usage:** `keyorix secret blast-radius <secret-id>`

## `keyorix secret bulk-delete`

Delete multiple secrets in one operation

Delete one or more secrets in a project in a single call.

Pass secret IDs directly with --ids, or resolve by name with --names (requires
--project and --env — a secret name is only unique within one project's
environment, not across the whole project). --confirm is mandatory for the
deletion to proceed; without it the command prints what would be deleted and
exits.

**Usage:** `keyorix secret bulk-delete [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--confirm` | — | — | Required to actually delete (omit to preview) |
| `--env` | `int` | — | Environment ID (required for --names) |
| `--ids` | `intSlice` | — | Comma-separated secret IDs to delete |
| `--names` | `stringSlice` | — | Comma-separated secret names to delete (requires --project and --env) |
| `--project` | `int` | — | Project ID (required for --names and for cross-project guard) |

## `keyorix secret bulk-rename`

Rename secrets toward naming-policy conformance

Rename one or more secrets in a project in a single call — the remediation for the
secrets that "secret name-conformance" lists as violating the current naming policy.

Each new name must itself satisfy the policy (you can only rename TOWARD conformance) and
must not collide with another secret in the same environment; any entry failing a check
is skipped with a reason while the rest proceed.

Specify renames as --rename \<id\>=\<new-name\> (repeatable). By default this is a DRY RUN
that only reports what would change; pass --apply to actually rename. Requires
secrets.write at the project scope.

**Usage:** `keyorix secret bulk-rename [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--apply` | — | — | Actually rename (default is a dry run) |
| `--project` | `int` | — | Project ID (required) |
| `--rename` | `stringArray` | — | Rename as \<id\>=\<new-name\> (repeatable) |

## `keyorix secret bulk-rotate`

Trigger rotation for multiple secrets at once

Trigger rotation for all matching secrets in a project — the CLI surface for
incident response ("rotate everything tagged confidential in project X").

Secrets without auto-rotate configured are skipped (reported in the failure list,
not treated as errors) so the operation is always best-effort.

Without --names the command rotates every matching secret in the project; use
--env and/or --classification to narrow the scope.

--confirm is required: this is a bulk destructive operation and an accidental
wide rotation cannot be undone.

--names requires --env: a secret name is only unique within one project's
environment, not across the whole project.

**Usage:** `keyorix secret bulk-rotate [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--classification` | `string` | — | Classification label filter (e.g. confidential) |
| `--confirm` | — | — | Required: confirm you want to trigger bulk rotation |
| `--env` | `int` | — | Environment ID (optional filter) |
| `--names` | `string` | — | Comma-separated secret names to rotate (omit to rotate all matching) |
| `--project` | `int` | — | Project ID (required) |

## `keyorix secret cert`

Show a certificate secret's public X.509 metadata (expiry, issuer, SANs)

**Usage:** `keyorix secret cert <secret-id>`

## `keyorix secret classify`

Set a secret's data-classification label (ISO 27001 A.5.12)

Label a secret with its data-sensitivity classification: public, internal,
confidential, or restricted (or empty to clear). Requires secrets.write.

**Usage:** `keyorix secret classify [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |
| `--level` | `string` | — | public\|internal\|confidential\|restricted (empty clears) |

## `keyorix secret clear-schedule`

Remove the temporal access schedule for a secret (idempotent)

**Usage:** `keyorix secret clear-schedule <secret-id>`

## `keyorix secret comment`

Manage secret version comments

**Usage:** `keyorix secret comment [command]`

**Subcommands:**

- [`keyorix secret comment add`](#keyorix-secret-comment-add) — Add a comment to a secret version
- [`keyorix secret comment delete`](#keyorix-secret-comment-delete) — Delete a comment from a secret version
- [`keyorix secret comment list`](#keyorix-secret-comment-list) — List comments on a secret version

## `keyorix secret comment add`

Add a comment to a secret version

**Usage:** `keyorix secret comment add <secret-id> <version-id> <comment>`

## `keyorix secret comment delete`

Delete a comment from a secret version

**Usage:** `keyorix secret comment delete <secret-id> <version-id> <comment-id>`

## `keyorix secret comment list`

List comments on a secret version

**Usage:** `keyorix secret comment list <secret-id> <version-id>`

## `keyorix secret copy`

Copy a secret's value and metadata into another environment

Promote a secret into another environment of the same project (e.g. staging -\>
production) without re-typing the value. Creates a new, independently-owned
secret with the source's value, type, classification, and description.

**Usage:** `keyorix secret copy [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Source secret ID (required) |
| `--name` | `string` | — | Name for the copy (default: the source name) |
| `--to-environment` | `int` | — | Target environment ID, same project (required) |

## `keyorix secret copy-environment`

Copy every secret from one environment into another (same project)

Bulk-promote a whole environment -- copy every secret from one environment
into another of the same project (e.g. seed production from staging) in a
single call. Name clashes in the target are skipped, never overwritten.

**Usage:** `keyorix secret copy-environment [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--from-environment` | `int` | — | Source environment ID (required) |
| `--project` | `int` | — | Project ID (required) |
| `--to-environment` | `int` | — | Target environment ID, same project (required) |

## `keyorix secret create`

Create a new secret

**Usage:** `keyorix secret create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--description` | `string` | — | Optional free-text note about the secret |
| `--environment` | `int` | `1` | Environment ID. With --project and no --environment the project's "development" environment is used; if it has none, --environment is required (see `keyorix project environments \<project-id\>`). Without --project: 1 |
| `--expires` | `string` | — | Expiration time (RFC3339 format) |
| `--from-file` | `string` | — | Read secret value from file |
| `--interactive` | — | — | Interactive mode (value read from a hidden prompt) |
| `--max-reads` | `int` | — | Maximum number of reads (0 = unlimited) |
| `--name` | `string` | — | Secret name (required) |
| `--project` | `int` | `1` | Project ID |
| `--type` | `string` | `generic` | Secret type |
| `--value` | `string` | — | Secret value |

## `keyorix secret delete`

Delete a secret (soft-delete; restorable with 'secret restore')

**Usage:** `keyorix secret delete [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment` | `int` | `1` | Environment ID (required with --name) |
| `--force` | — | — | Skip confirmation prompt, and delete even if other secrets depend on this one |
| `--format` | `string` | `text` | Output format: text or json (json is non-interactive and requires --force) |
| `--id` | `int` | — | Secret ID |
| `--name` | `string` | — | Secret name |
| `--project` | `int` | `1` | Project ID (required with --name) |

## `keyorix secret deps`

Inspect and manage a secret's dependency graph

Manage the secret dependency graph (ADR-052): declare that one secret
depends on another, list a secret's dependencies and dependents, and see the
blast radius of rotating it.

**Usage:** `keyorix secret deps [command]`

**Subcommands:**

- [`keyorix secret deps add`](#keyorix-secret-deps-add) — Declare that \<secret-id\> depends on \<depends-on-id\>
- [`keyorix secret deps impact`](#keyorix-secret-deps-impact) — Show the blast radius of rotating a secret (transitive dependents)
- [`keyorix secret deps list`](#keyorix-secret-deps-list) — Show what a secret depends on and what depends on it
- [`keyorix secret deps rm`](#keyorix-secret-deps-rm) — Remove a dependency edge (edge id from `deps list`)

## `keyorix secret deps add`

Declare that \<secret-id\> depends on \<depends-on-id\>

**Usage:** `keyorix secret deps add <secret-id> <depends-on-id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--note` | `string` | — | Optional note describing the dependency |

## `keyorix secret deps impact`

Show the blast radius of rotating a secret (transitive dependents)

**Usage:** `keyorix secret deps impact <secret-id>`

## `keyorix secret deps list`

Show what a secret depends on and what depends on it

**Usage:** `keyorix secret deps list <secret-id>`

## `keyorix secret deps rm`

Remove a dependency edge (edge id from `deps list`)

**Usage:** `keyorix secret deps rm <secret-id> <edge-id>`

## `keyorix secret description`

Show or set a secret's description

Show a secret's free-text note, or replace it with --set.

Examples:
```text
  keyorix secret description --id 42                       # show the note
  keyorix secret description --id 42 --set "prod DB; dba@" # set the note
  keyorix secret description --id 42 --set ""              # clear it
```

**Usage:** `keyorix secret description [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |
| `--set` | `string` | — | Replace the description with this text ("" clears) |

## `keyorix secret diff`

Diff metadata between two versions of a secret

Compare metadata between two versions of a secret.

Values (encrypted ciphertext) are never compared -- only classification,
expiry, read count, and the current ACL snapshot.

\<name\> is resolved to a secret ID via --project/--environment (both
required, matching every other by-name lookup in this command group --
GET /api/v1/secrets/by-name needs a numeric project_id/environment_id, not
a name filter), unless --id is given directly.

**Usage:** `keyorix secret diff <name> <from-version> <to-version> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment` | `int` | — | Environment ID (required unless --id is set) |
| `--id` | `int` | — | Secret ID (skips the \<name\> lookup below when set) |
| `--project` | `int` | — | Project ID (required unless --id is set) |

## `keyorix secret expiring`

List a project's secrets expiring (or already expired) within a window

Show a project's secrets expiring soon (or already expired), soonest-first, so you
can renew or rotate them before they lapse. Requires secrets.read at the project scope.

**Usage:** `keyorix secret expiring [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--days` | `int` | — | Window in days (default server-side: 30, cap 3650) |
| `--project` | `int` | — | Project ID (required) |

## `keyorix secret explain`

Explain the risk of a discovered secret and how to fix it

**Usage:** `keyorix secret explain <key-name>`

## `keyorix secret export`

Export secrets to a file or stdout

Export secrets from Keyorix to dotenv, JSON, Vault YAML, or encrypted-json format.

Examples:
```text
  keyorix secret export --project 7 --env 3 --format dotenv
  keyorix secret export --project 7 --env 3 --format json --output secrets.json
  keyorix secret export --project 7 --env 3 --format vault --output vault-export.yaml
  keyorix secret export --project 7 --env 3 --encrypt-for recipient.pub.pem --output secrets.enc.json

```
Supported formats:
```text
  dotenv         .env files (KEY=VALUE)
  json           Flat key-value JSON object
  vault          Medusa/Vault YAML (importable back via 'keyorix secret import --format vault')
  encrypted-json RSA-OAEP-SHA256 + AES-256-GCM encrypted envelope (safe for airgap transfer)

```
Output goes to stdout unless --output is specified.
Warnings and summary are always printed to stderr.

**Usage:** `keyorix secret export [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--encrypt-for` | `string` | — | Path to RSA public key PEM (switches format to encrypted-json) |
| `--env` | `int` | — | Environment ID (required) |
| `--format` | `string` | `dotenv` | Output format: dotenv, json, vault, encrypted-json |
| `--output` | `string` | — | Output file path (default: stdout) |
| `--project` | `int` | — | Project ID (required) |

## `keyorix secret fix`

Fix a hardcoded secret by moving it to an environment variable

**Usage:** `keyorix secret fix <key-name> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--dry-run` | — | `true` | Preview changes without applying (default: true) |
| `--env-file` | `string` | `.env` | Target .env file for extracted secrets |
| `--interactive` | — | — | Step through each fix interactively |
| `--path` | `string` | `.` | Path to scan for the secret |

## `keyorix secret folder`

Manage secret folders

Commands for creating, listing, and deleting secret folder nodes.

**Usage:** `keyorix secret folder [command]`

**Subcommands:**

- [`keyorix secret folder create`](#keyorix-secret-folder-create) — Create a folder
- [`keyorix secret folder delete`](#keyorix-secret-folder-delete) — Delete a folder
- [`keyorix secret folder list`](#keyorix-secret-folder-list) — List folders

## `keyorix secret folder create`

Create a folder

**Usage:** `keyorix secret folder create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment` | `int` | `1` | Environment ID |
| `--name` | `string` | — | Folder name (required) |
| `--parent` | `int` | — | Parent folder ID (0 = root) |
| `--project` | `int` | `1` | Project ID |

## `keyorix secret folder delete`

Delete a folder

**Usage:** `keyorix secret folder delete [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | — | — | Skip confirmation prompt |
| `--id` | `int` | — | Folder ID to delete (required) |

## `keyorix secret folder list`

List folders

**Usage:** `keyorix secret folder list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--parent` | `int` | — | Filter by parent folder ID (0 = no filter) |
| `--project` | `int` | — | Filter by project ID |

## `keyorix secret get`

Get a secret

Retrieve a secret by ID, by name, or by a project/environment/name reference.

--ref reads the secret's value by a human-readable "project/environment/name"
reference (ADR-059) -- handy for scripts and automation. It always reads the
value (so it counts toward max_reads and is audited like any value read).

**Usage:** `keyorix secret get [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment` | `int` | `1` | Environment ID (required with --name) |
| `--id` | `int` | — | Secret ID |
| `--name` | `string` | — | Secret name |
| `--project` | `int` | `1` | Project ID (required with --name) |
| `--ref` | `string` | — | Reference: project/environment/name (reads the value) |
| `--show-value` | — | — | Show the decrypted secret value |

## `keyorix secret get-schedule`

Show the temporal access schedule for a secret

**Usage:** `keyorix secret get-schedule <secret-id>`

## `keyorix secret import`

Import secrets from a file

Import secrets from a local file.

```text
  keyorix secret import --file .env --format dotenv --project 7 --env 3
  keyorix secret import --file vault-export.yaml --format vault --project 7 --env 3
  keyorix secret import --file secrets.json --format json --project 7 --env 3
  keyorix secret import --file .env --format dotenv --project 7 --env 3 --dry-run
  keyorix secret import --file secrets.enc.json --decrypt-with private.pem --project 7 --env 3

```
Supported file formats (--format):
```text
  dotenv  .env files (KEY=VALUE, comments and blank lines ignored)
  vault   Medusa/Vault YAML export (path hierarchy, last two segments become name)
  json    Flat key-value JSON object

```
Encrypted imports (--decrypt-with):
```text
  When the file is a keyorix-encrypted-export-v1 envelope (produced by
  'keyorix secret export --format encrypted-json'), pass the RSA private key
  with --decrypt-with. The file is decrypted transparently and then imported
  as a standard JSON payload.

```
Importing from a live source (Vault/AWS/Azure/GCP) is not supported by this command —
use the old CLI's 'secret import --source' until the dedicated migration tool exists.

**Usage:** `keyorix secret import [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--decrypt-with` | `string` | — | Path to RSA private key PEM to decrypt an encrypted-json export |
| `--dry-run` | — | — | Show what would be imported without creating anything |
| `--env` | `int` | — | Environment ID (required) |
| `--file` | `string` | — | Path to the file to import (required) |
| `--format` | `string` | `dotenv` | File format: dotenv, vault, json |
| `--project` | `int` | — | Project ID (required) |
| `--skip-existing` | — | `true` | Skip secrets that already exist instead of failing |

## `keyorix secret info`

Show a secret's metadata (no value)

Print a one-shot summary of a secret's metadata -- type, classification,
status, description, owner, expiration, and tags -- without retrieving the
value. Requires secrets.read at the secret's scope.

**Usage:** `keyorix secret info [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |

## `keyorix secret list`

List secrets

List secrets with filtering and pagination.

The server applies authentication-based filtering automatically: you see
only what you're authorized to read.

**Usage:** `keyorix secret list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--environment` | `int` | — | Filter by environment ID (0 = all) |
| `--format` | `string` | `table` | Output format (table, json) |
| `--limit` | `int` | `50` | Maximum number of results |
| `--offset` | `int` | — | Number of results to skip |
| `--project` | `string` | — | Project name or numeric ID |
| `--search` | `string` | — | Search query |

## `keyorix secret move`

Move a secret or folder to a different parent folder

Move a secret or folder to a different parent folder.

Use --to 0 (or omit --to) to move the node to the root (no parent).

**Usage:** `keyorix secret move [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret or folder ID to move (required) |
| `--to` | `int` | — | Target parent folder ID (0 = root) |

## `keyorix secret name-conformance`

List secrets whose names violate the current naming policy

Show the live secrets whose names fail the current secret naming policy. The policy is
enforced only when a secret is created, so names can fall out of conformance after the
policy is added or tightened — this surfaces those stragglers so you can rename them.

With --project, scopes to one project (requires secrets.read at the project scope).
Without --project, reports across every project (requires audit.read — admin view).

**Usage:** `keyorix secret name-conformance [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `int` | — | Project ID (omit for an org-wide admin view) |

## `keyorix secret orphaned`

List secrets whose owner is no longer a live user

Show a project's secrets whose owner has been deleted (offboarding hygiene). Each is
left without an accountable owner — re-assign one with 'keyorix secret reassign-owner'.
Requires secrets.read at the project scope.

**Usage:** `keyorix secret orphaned [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--project` | `int` | — | Project ID (required) |

## `keyorix secret ownership-history`

Show a secret's ownership-transfer chain

List all ownership transfers for a secret in chronological order. Each record
shows who the secret was transferred from, who it was transferred to, who performed
the transfer, and when. Requires secrets.read at the secret's scope.

**Usage:** `keyorix secret ownership-history [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |

## `keyorix secret quota-report`

Show secrets approaching or at their MaxReads quota

List all secrets with a MaxReads cap configured, showing current read count,
quota percentage, and status (ok / warning / critical / exhausted). Requires
audit.read (a usage-report endpoint, not secret-value access).

**Usage:** `keyorix secret quota-report`

## `keyorix secret reassign-owner`

Re-home all of a departed user's secrets to a new owner

Transfer every secret in a project owned by one user to another, in one call —
the bulk completion of offboarding after 'keyorix secret orphaned' surfaces a gone
owner's secrets. Requires roles.assign at the project scope (the same blast radius
as a role grant, not secrets.write); each secret is authorized individually.

**Usage:** `keyorix secret reassign-owner [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--from` | `int` | — | Current owner's user ID (required) |
| `--project` | `int` | — | Project ID (required) |
| `--to` | `int` | — | New owner's user ID (required) |

## `keyorix secret render`

Render a template, expanding ${secret:\<environment\>/\<name\>} references

Render a template file (or stdin) to stdout (or --output), replacing each
${secret:\<environment\>/\<name\>} placeholder with that secret's current value.

References are resolved within a single project (--project, a numeric ID). Only
secrets you can read there are resolved; a missing or forbidden reference fails
the render without writing partial output.

Examples:
```text
  keyorix secret render app.env.tpl -o app.env --project 7
  cat app.env.tpl | keyorix secret render --project 7
```

**Usage:** `keyorix secret render [template-file] [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `-o`, `--output` | `string` | — | Write to this file instead of stdout |
| `--project` | `int` | — | Project ID (required) |

## `keyorix secret restore`

Restore a soft-deleted secret

Restore a soft-deleted secret by clearing its deletion, returning it to the
live list. Find restorable secrets with 'secret trash --project \<id\>'.

**Usage:** `keyorix secret restore [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |

## `keyorix secret resume`

Resume a suspended secret -- restore value reads

**Usage:** `keyorix secret resume [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |

## `keyorix secret rollback`

Restore a secret to the value of a prior version

Restore a secret to an earlier version's value. The old value is re-instated
as a NEW version (history stays append-only, so the rollback itself can be undone).

**Usage:** `keyorix secret rollback [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |
| `--version` | `int` | — | Version number to restore (required) |

## `keyorix secret rotate`

Rotate a secret by providing a new value

**Usage:** `keyorix secret rotate [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |
| `--value` | `string` | — | New secret value (omit to be prompted interactively) |

## `keyorix secret rotation-simulate`

Simulate a rotation dry-run for a secret

Validate a secret's rotation configuration without executing any live rotation.

Checks:
```text
  policy_exists  — at least one active rotation policy covers the secret
  backend_known  — the configured rotation backend is registered
  ref_non_empty  — the rotation ref is non-empty
  ref_valid      — the rotation ref passes metacharacter validation

```
Requires secrets.read at the secret's scope.

**Usage:** `keyorix secret rotation-simulate [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |

## `keyorix secret scan`

Scan a directory for secrets and hardcoded credentials

**Usage:** `keyorix secret scan [path] [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--commit` | `string` | — | Scan files changed in a specific commit (e.g. HEAD~1) |
| `--import` | — | — | Print a follow-up 'secret import' hint after scanning (does not import automatically) |
| `--report` | `string` | — | Save scan report to file (JSON format) |
| `--severity` | `string` | — | Filter by severity: low, medium, high |
| `--staged` | — | — | Scan only git staged files |

## `keyorix secret score`

Show the risk score for a secret

Print the composite risk score for a secret.

The score is 0-100 (higher = riskier) and is broken down into four weighted
factors: rotation age (30%), expiry (30%), usage (20%), and exposure (20%).

**Usage:** `keyorix secret score [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |

## `keyorix secret set-schedule`

Set a temporal access schedule for a secret

Restrict read access to a secret to a specific day-of-week + hour window.

The schedule applies to all permission-checked reads (human users); admin/
machine reads bypass it.

**Usage:** `keyorix secret set-schedule <secret-id> [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--days` | `string` | — | Allowed days: comma-separated day names (mon,tue,...) or ISO numbers (1-7), or "*" for all days (required) |
| `--end-hour` | `int` | `24` | End hour of the read window (1-24, exclusive) |
| `--start-hour` | `int` | — | Start hour of the read window (0-23, inclusive) |
| `--timezone` | `string` | `UTC` | IANA timezone name (default: UTC) |

## `keyorix secret suspend`

Suspend a secret -- block value reads without deleting it

Freeze a secret: value reads are refused until it is resumed. Versions,
shares, and the audit trail are preserved. Requires secrets.write.

With --clear-synced-copies the copies of this secret synced to Kubernetes clusters
(by the operator or keyorix-k8s-sync) are also emptied for the duration of THIS
suspension, whatever the resource's own onSuspend setting says. Use it when the
secret is compromised, and rotate it afterwards. Resuming removes the request and
the next sync restores the copies. Running suspend again with the flag on a secret
that is already suspended adds the request.

**Usage:** `keyorix secret suspend [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--clear-synced-copies` | — | — | Also clear the copies synced to Kubernetes clusters for this suspension (compromise response; rotate the secret afterwards) |
| `--id` | `int` | — | Secret ID (required) |
| `--reason` | `string` | — | Optional reason recorded in the audit event |

## `keyorix secret tags`

List or set a secret's tags

Show a secret's tags, or replace them with --set.

Examples:
```text
  keyorix secret tags --id 42                   # list the secret's tags
  keyorix secret tags --id 42 --set prod,tier1  # replace the tag set
  keyorix secret tags --id 42 --set ""          # clear all tags
```

**Usage:** `keyorix secret tags [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `int` | — | Secret ID (required) |
| `--set` | `string` | — | Replace the secret's tags with this comma-separated list ("" clears) |

## `keyorix secret template`

Manage secret templates

Commands for creating, listing, getting and deleting reusable secret templates.

**Usage:** `keyorix secret template [command]`

**Subcommands:**

- [`keyorix secret template create`](#keyorix-secret-template-create) — Create a secret template
- [`keyorix secret template delete`](#keyorix-secret-template-delete) — Delete a secret template by name
- [`keyorix secret template get`](#keyorix-secret-template-get) — Get a secret template by name
- [`keyorix secret template list`](#keyorix-secret-template-list) — List all secret templates

## `keyorix secret template create`

Create a secret template

**Usage:** `keyorix secret template create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--classification` | `string` | — | Default classification (public\|internal\|confidential\|restricted) |
| `--description` | `string` | — | Template description |
| `--description-pattern` | `string` | — | Hint text for the description field |
| `--name` | `string` | — | Template name (required) |
| `--rotation-hint-days` | `int` | — | Suggested rotation interval in days (informational) |
| `--tags` | `string` | — | Default tags (comma-separated, e.g. db,prod) |

## `keyorix secret template delete`

Delete a secret template by name

**Usage:** `keyorix secret template delete <name>`

## `keyorix secret template get`

Get a secret template by name

**Usage:** `keyorix secret template get <name>`

## `keyorix secret template list`

List all secret templates

**Usage:** `keyorix secret template list`

## `keyorix secret trash`

List a project's soft-deleted (restorable) secrets

Show the recycle bin for a project: secrets that were deleted but are still
restorable (until the purge job reaps them), newest-deleted first. Use the ID
with 'secret restore --id \<id\>'. Requires secrets.read at the project scope.

**Usage:** `keyorix secret trash [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--limit` | `int` | — | Max entries to show (default server-side: 100, cap 500) |
| `--project` | `int` | — | Project ID (required) |

## `keyorix secret update`

Update an existing secret

**Usage:** `keyorix secret update [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--clear-expiration` | — | — | Remove expiration |
| `--clear-max-reads` | — | — | Remove the read limit (unlimited) |
| `--expires` | `string` | — | Update expiration (RFC3339 format) |
| `--from-file` | `string` | — | Read new value from file |
| `--id` | `int` | — | Secret ID (required) |
| `--interactive` | — | — | Interactive mode (value read from a hidden prompt) |
| `--max-reads` | `int` | `-1` | Update max reads (-1 = no change, minimum 1; use --clear-max-reads to remove the limit) |
| `--value` | `string` | — | New secret value |

## `keyorix secret versions`

List secret versions

**Usage:** `keyorix secret versions [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | `string` | `table` | Output format (table, json) |
| `--id` | `int` | — | Secret ID (required) |

## `keyorix share`

Share secrets with users and groups

**Usage:** `keyorix share [command]`

**Subcommands:**

- [`keyorix share create`](#keyorix-share-create) — Share a secret with another user or group
- [`keyorix share group-shares`](#keyorix-share-group-shares) — List shares for a group
- [`keyorix share list`](#keyorix-share-list) — List shares for a secret
- [`keyorix share revoke`](#keyorix-share-revoke) — Revoke a share
- [`keyorix share self-remove`](#keyorix-share-self-remove) — Remove yourself from a secret shared with you
- [`keyorix share shared-secrets`](#keyorix-share-shared-secrets) — List secrets shared with a user (defaults to yourself)
- [`keyorix share update`](#keyorix-share-update) — Update a share's permission

## `keyorix share create`

Share a secret with another user or group

Share a secret with another user or group. The recipient must be a member of
the secret's project.

```text
  read   the recipient can read the secret.
  write  the recipient can also update its value and metadata (description, tags)
         and rotate it. A write share never lets them suspend or resume it, change
         its expiry or read limit, move it, roll it back, transfer ownership,
         re-share it, change access rules or delete it: those need a project role.
```

**Usage:** `keyorix share create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--expires` | `string` | — | Make the share time-bound: absolute expiry (RFC3339, e.g. 2026-07-01T15:00:00Z) |
| `--is-group` | — | — | Whether the recipient is a group |
| `--permission` | `string` | `read` | Permission level: read, or write (read + update value/metadata + rotate; see --help) |
| `--recipient-id` | `int` | — | Recipient ID (required) |
| `--secret-id` | `int` | — | Secret ID (required) |
| `--ttl` | `string` | — | Make the share time-bound: lifetime from now (Go duration, e.g. 24h, 30m); mutually exclusive with --expires |

## `keyorix share group-shares`

List shares for a group

**Usage:** `keyorix share group-shares [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--group-id` | `int` | — | Group ID (required) |

## `keyorix share list`

List shares for a secret

**Usage:** `keyorix share list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--secret-id` | `int` | — | Secret ID (required) |

## `keyorix share revoke`

Revoke a share

**Usage:** `keyorix share revoke [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--share-id` | `int` | — | Share ID (required) |

## `keyorix share self-remove`

Remove yourself from a secret shared with you

**Usage:** `keyorix share self-remove <secret-id>`

## `keyorix share shared-secrets`

List secrets shared with a user (defaults to yourself)

**Usage:** `keyorix share shared-secrets [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--user-id` | `int` | — | User ID (defaults to yourself; viewing another user's shared secrets requires an admin permission and rank over that user) |

## `keyorix share update`

Update a share's permission

**Usage:** `keyorix share update [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--clear-expiry` | — | — | Make the share permanent (remove its expiry) |
| `--expires` | `string` | — | Set/extend the time-bound expiry: absolute (RFC3339) |
| `--permission` | `string` | — | Permission level: read, or write (read + update value/metadata + rotate) (required) |
| `--share-id` | `int` | — | Share ID (required) |
| `--ttl` | `string` | — | Set/extend the time-bound expiry: lifetime from now (Go duration, e.g. 24h); mutually exclusive with --expires |

## `keyorix sod`

Separation-of-duties policies and violations (ISO 27001 A.5.3)

Define toxic permission combinations and find the principals who hold both sides.

**Usage:** `keyorix sod [command]`

**Subcommands:**

- [`keyorix sod policy`](#keyorix-sod-policy) — Manage separation-of-duties policies
- [`keyorix sod violations`](#keyorix-sod-violations) — List principals that violate a separation-of-duties policy

## `keyorix sod policy`

Manage separation-of-duties policies

**Usage:** `keyorix sod policy [command]`

**Subcommands:**

- [`keyorix sod policy create`](#keyorix-sod-policy-create) — Create a separation-of-duties policy (two conflicting permissions)
- [`keyorix sod policy delete`](#keyorix-sod-policy-delete) — Delete a separation-of-duties policy
- [`keyorix sod policy list`](#keyorix-sod-policy-list) — List separation-of-duties policies

## `keyorix sod policy create`

Create a separation-of-duties policy (two conflicting permissions)

**Usage:** `keyorix sod policy create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--description` | `string` | — | Description |
| `--name` | `string` | — | Policy name (required) |
| `--permission-a` | `string` | — | First permission, e.g. roles.assign (required) |
| `--permission-b` | `string` | — | Second permission, e.g. secrets.delete (required) |

## `keyorix sod policy delete`

Delete a separation-of-duties policy

**Usage:** `keyorix sod policy delete [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--id` | `uint32` | — | Policy ID to delete (required) |

## `keyorix sod policy list`

List separation-of-duties policies

**Usage:** `keyorix sod policy list`

## `keyorix sod violations`

List principals that violate a separation-of-duties policy

**Usage:** `keyorix sod violations`

## `keyorix status`

Show the configured server, login state, and version-skew check

status is the remote-only successor to the old CLI's "status" command
(docs/cli-split-inventory.md §2.7): it has no local/embedded branch to fall back to (ADR-108
Decision A removes local mode entirely). Unlike the old command, it actually parses GET
/health's response body instead of discarding it, and reports the GET /api/v1/version
skew check.

**Usage:** `keyorix status`

## `keyorix system`

Server info and on-demand admin job triggers

**Usage:** `keyorix system [command]`

**Subcommands:**

- [`keyorix system info`](#keyorix-system-info) — Show the connected server's build identity and configuration
- [`keyorix system init`](#keyorix-system-init) — Bootstrap a running Keyorix server (admin user + default workspace)
- [`keyorix system role-expiry-check`](#keyorix-system-role-expiry-check) — Trigger a role-expiry notification scan on the connected server
- [`keyorix system token-expiry-check`](#keyorix-system-token-expiry-check) — Trigger a PAT and machine-credential expiry notification scan on the connected server

## `keyorix system info`

Show the connected server's build identity and configuration

Display the remote Keyorix server's version, commit, runtime, and feature/security
configuration (GET /system/info). Useful for confirming which build you're talking to.
Requires a connection to a server and system.read.

**Usage:** `keyorix system info`

## `keyorix system init`

Bootstrap a running Keyorix server (admin user + default workspace)

Bootstrap a running Keyorix server: creates the admin user, default RBAC
roles, and default workspace (project + 3 environments) via POST /system/init.
Safe to run more than once -- idempotent.

This is the network-bootstrap half only. Local host setup (config file, encryption
keys, database) is "keyorix-server admin init", a separate host-filesystem tool this
network-only CLI does not run.

The admin password is read from KEYORIX_ADMIN_PASSWORD, or prompted for (hidden)
when that is unset. The bootstrap token is read from KEYORIX_BOOTSTRAP_TOKEN. Do
not pass either on the command line: arguments are visible via ps/proc and saved
in shell history.

Examples:
```text
  keyorix system init --server http://localhost:8080
  keyorix system init --server https://vault.example.com \
      --admin-username admin --admin-email admin@example.com
```

**Usage:** `keyorix system init [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--admin-email` | `string` | `admin@localhost` | Admin email address |
| `--admin-password` | `string` | — | Admin password (required; INSECURE on the command line -- prefer KEYORIX_ADMIN_PASSWORD, or omit to be prompted) |
| `--admin-username` | `string` | `admin` | Admin username to create |
| `--bootstrap-token` | `string` | — | Bootstrap token authorizing first-admin creation (or KEYORIX_BOOTSTRAP_TOKEN; printed in the server log on first boot; INSECURE on the command line) |
| `--server` | `string` | — | Server base URL to bootstrap (required) |

## `keyorix system role-expiry-check`

Trigger a role-expiry notification scan on the connected server

Send immediate role-expiry notifications for time-bound role grants
approaching their deadline (POST /api/v1/admin/jobs/role-expiry-check).

Warning notifications are sent for grants expiring within 7 days; critical
notifications for those expiring within 1 day. Requires system.write.

**Usage:** `keyorix system role-expiry-check`

## `keyorix system token-expiry-check`

Trigger a PAT and machine-credential expiry notification scan on the connected server

Send immediate expiry notifications for PersonalAccessTokens and
MachineIdentityCredentials approaching their deadline
(POST /api/v1/admin/jobs/token-expiry-check).

Warning notifications are sent for tokens expiring within 7 days; critical
notifications for those expiring within 1 day. Requires system.write.

**Usage:** `keyorix system token-expiry-check`

## `keyorix trust`

Air-gap signing-key tooling (ed25519 keypairs for update bundles / licenses)

Generate and inspect the asymmetric keys Keyorix uses to sign air-gapped update
bundles and offline licenses (ADR-062). The private key never ships; its public key is
embedded into release builds so an air-gapped deployment can verify offline.

**Usage:** `keyorix trust [command]`

**Subcommands:**

- [`keyorix trust keygen`](#keyorix-trust-keygen) — Generate an ed25519 signing keypair (update or license)

## `keyorix trust keygen`

Generate an ed25519 signing keypair (update or license)

**Usage:** `keyorix trust keygen [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--dir` | `string` | `.` | directory to write the keypair into |
| `--force` | — | — | overwrite an existing keypair at the target paths (dangerous) |
| `--key-id` | `string` | — | key identifier, e.g. update-2026 (required) |
| `--purpose` | `string` | — | key purpose: update \| license (required) |

## `keyorix usage`

View usage and activity reports

**Usage:** `keyorix usage [command]`

**Subcommands:**

- [`keyorix usage show`](#keyorix-usage-show) — Show per-project secret usage for a time window

## `keyorix usage show`

Show per-project secret usage for a time window

Display a per-project secret usage report (secret counts and read activity) for the
given reporting window (GET /admin/usage). Requires audit.read.

**Usage:** `keyorix usage show [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--days` | `int` | `30` | Reporting window in days (1-365) |
| `--format` | `string` | `table` | Output format: table or json |
| `--project-id` | `int` | — | Scope to a single project (0 = all) |

## `keyorix user`

Manage users

Create, read, update, delete, list, and manage the account lifecycle of users.

**Usage:** `keyorix user [command]`

**Subcommands:**

- [`keyorix user create`](#keyorix-user-create) — Create a new user
- [`keyorix user delete`](#keyorix-user-delete) — Delete a user
- [`keyorix user force-password-reset`](#keyorix-user-force-password-reset) — Require a user to change their password at next login
- [`keyorix user get`](#keyorix-user-get) — Get a user by id or email
- [`keyorix user list`](#keyorix-user-list) — List users
- [`keyorix user reactivate`](#keyorix-user-reactivate) — Reactivate a user (restores login)
- [`keyorix user reissue-one-time-password`](#keyorix-user-reissue-one-time-password) — Issue a new one-time password for an existing user
- [`keyorix user resend-setup-link`](#keyorix-user-resend-setup-link) — Reissue and redeliver a user's setup link (ADR-028)
- [`keyorix user revoke-sessions`](#keyorix-user-revoke-sessions) — Force-logout a user (revoke all active sessions)
- [`keyorix user suspend`](#keyorix-user-suspend) — Suspend a user (blocks login)
- [`keyorix user suspend-inactive`](#keyorix-user-suspend-inactive) — Suspend users who have been inactive beyond a threshold
- [`keyorix user update`](#keyorix-user-update) — Update a user

## `keyorix user create`

Create a new user

Create a new user. Supply --password to set an initial password, or use
--setup-link to provision an ADR-028 setup link instead: the account is created
in pending_first_login state and the user sets their own password via the link.
In out-of-band mode the link is printed for you to relay.

Or use --one-time-password to have the server generate an initial password
(ADR-028 Part E): the account is created in password_reset_required state, the
password is printed once for you to relay, and the user must change it on first
login.

**Usage:** `keyorix user create [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--by` | `string` | — | Acting admin email (unused in this REST-only CLI -- kept for flag compatibility; the session behind your bearer token is always the acting admin) |
| `--display-name` | `string` | — | Display name (defaults to username) |
| `--email` | `string` | — | Email (required) |
| `--one-time-password` | — | — | Generate a one-time password instead of an admin-set password (ADR-028 Part E); must be changed on first login |
| `--password` | `string` | — | Initial password (INSECURE on the command line — prefer KEYORIX_INITIAL_PASSWORD or the interactive prompt; required in some form unless --setup-link or --one-time-password) |
| `--setup-link` | — | — | Provision a setup link instead of an admin-set password (ADR-028) |
| `--username` | `string` | — | Username (required) |

## `keyorix user delete`

Delete a user

**Usage:** `keyorix user delete [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--by` | `string` | — | Acting admin email (required; unused in this REST-only CLI -- kept for flag compatibility) |
| `--force` | — | — | Skip the confirmation prompt |
| `--id` | `uint` | — | User ID (required) |

## `keyorix user force-password-reset`

Require a user to change their password at next login

Force a user into a restricted session until they change their password.
They can authenticate but every endpoint except change-password is blocked until then.

**Usage:** `keyorix user force-password-reset [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--by` | `string` | — | Acting admin email (required; unused in this REST-only CLI -- kept for flag compatibility) |
| `--id` | `uint` | — | Target user ID (required) |

## `keyorix user get`

Get a user by id or email

**Usage:** `keyorix user get [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--email` | `string` | — | User email |
| `--id` | `uint` | — | User ID |

## `keyorix user list`

List users

**Usage:** `keyorix user list [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--page` | `int` | `1` | Page number |
| `--page-size` | `int` | `20` | Page size (max 100) |

## `keyorix user reactivate`

Reactivate a user (restores login)

Return a suspended (or otherwise non-active) user to the active state.

**Usage:** `keyorix user reactivate [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--by` | `string` | — | Acting admin email (required; unused in this REST-only CLI -- kept for flag compatibility) |
| `--id` | `uint` | — | Target user ID (required) |

## `keyorix user reissue-one-time-password`

Issue a new one-time password for an existing user

Issue a new server-generated one-time password for an existing user, for when
the first one expired (see user create --one-time-password) or was lost.
\<user\> is a numeric user ID or an email address.

The password is printed once for you to relay out of band; it is never shown
again. It expires after security.one_time_password_ttl (default 72h). The
account is restricted to changing its password at the next login (and to MFA
enrolment where the deployment requires MFA), and all of the user's existing
sessions end. Needs the same permission as creating a user (users.write).

Refused for your own account (use `keyorix-server admin recover-admin`), for
users managed by an external identity provider (SSO), and for suspended users.

**Usage:** `keyorix user reissue-one-time-password <user>`

## `keyorix user resend-setup-link`

Reissue and redeliver a user's setup link (ADR-028)

Reissue an account's setup link, invalidating any prior link, and deliver it
again. In out-of-band mode the link is printed for you to relay. Throttled per
the ADR-028 resend limits.

**Usage:** `keyorix user resend-setup-link [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--by` | `string` | — | Acting admin email (required; unused in this REST-only CLI -- kept for flag compatibility) |
| `--id` | `uint` | — | Target user ID (required) |

## `keyorix user revoke-sessions`

Force-logout a user (revoke all active sessions)

Terminate every active session of a user immediately, without changing their
account state — for suspected session/token theft. The user can log back in after
re-authenticating. To block login entirely, use 'suspend' instead.

**Usage:** `keyorix user revoke-sessions [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--by` | `string` | — | Acting admin email (required; unused in this REST-only CLI -- kept for flag compatibility) |
| `--id` | `uint` | — | Target user ID (required) |

## `keyorix user suspend`

Suspend a user (blocks login)

Suspend a user account. A suspended user is refused login entirely until reactivated.

**Usage:** `keyorix user suspend [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--by` | `string` | — | Acting admin email (required; unused in this REST-only CLI -- kept for flag compatibility) |
| `--id` | `uint` | — | Target user ID (required) |

## `keyorix user suspend-inactive`

Suspend users who have been inactive beyond a threshold

Suspend all non-admin users whose last login (or account creation, if they
have never logged in) is older than --days days. Triggers the server-side job via
POST /api/v1/admin/jobs/suspend-inactive-users (requires system.write).

With --dry-run the command evaluates all users against the threshold but makes
no changes — it prints what would be suspended.

**Usage:** `keyorix user suspend-inactive [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--days` | `int` | — | Inactivity threshold in days (required, must be \> 0) |
| `--dry-run` | — | — | Preview which users would be suspended without making changes |

## `keyorix user update`

Update a user

**Usage:** `keyorix user update [flags]`

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--active` | `string` | — | Active status: true or false |
| `--display-name` | `string` | — | New display name |
| `--email` | `string` | — | New email |
| `--id` | `uint` | — | User ID (required) |
| `--username` | `string` | — | New username |

## `keyorix version`

Print the CLI version and the API version it targets

**Usage:** `keyorix version`
