# Break-glass runbook: emergency access, and what happens when the audit log is down

Break-glass lets a project member grant themselves the configured emergency role,
immediately and for a limited time, with a written justification. It is off by default
(`break_glass.enabled`). This runbook covers what operators see, and what to do, in the
normal case and in **degraded mode**: an activation made while the audit log refuses
writes. Configuration keys are in `docs/CONFIGURATION.md` (`break_glass`); the policy
behind it is ADR-112 §3 and its Amendment 6.

## 1. Normal activation

```bash
keyorix break-glass activate --project-id 3 --justification "INC-4711: prod DB down, paging on-call"
```

On success:

- The emergency role is granted at the project scope until `default_ttl` (or the requested
  `ttl`, capped at `max_ttl`). It expires on its own.
- Two audit rows are written **in the same database transaction** as the grant:
  `role.assigned` and `break_glass.activated` (with the justification).
- The project's administrators get a notification "Break-glass emergency access activated".
- The activation must be reviewed by someone other than the activator once it has ended
  (`POST /api/v1/projects/{id}/break-glass/{activationId}/review`, roles.assign on the
  project). Unreviewed past
  `review_window` (72h by default), it is a compliance posture deviation and a repeating
  reminder.

## 2. Degraded mode: the audit log refuses the activation

Emergency access has to work during an incident, and an incident can be the audit
subsystem itself (a full disk, a broken audit table, a stuck lock, or someone making it
refuse writes on purpose). It must also never be unrecorded. So when, and only when, the
activation's audit append fails (an error, a panic, or a chain lock that does not come
within the audit write path's 10-second bound), the server does this instead:

1. In **one** transaction it commits the activation, the role grant, and an **owed-audit
   record** (`pending_audit_events`) of each audit row it could not append. Never one
   without the other.
2. The activation is marked **degraded** and is **short-lived**: it expires after
   `break_glass.degraded_ttl` (default **15 minutes**), or after the lifetime it would have
   had normally if that is shorter. A longer request or setting never lengthens it. It
   cannot be renewed while it is active, as usual.
3. It is **loud**:
   - a server log line at level ERROR starting `SECURITY: break-glass activation <id> is DEGRADED`;
   - the Prometheus counter `keyorix_breakglass_degraded_activations_total` goes up by one;
   - the project's administrators get a notification titled
     "Break-glass activated in DEGRADED mode (audit log unavailable)";
   - administrators (system.write) see a red banner in the web UI, and
     `GET /api/v1/system/info` → `security.break_glass_degraded` shows
     `{unsettled, unreviewed, activation_ids}`; the existing audit-owed banner
     (`security.audit_owed`) counts its owed rows too;
   - the activation carries `"degraded": true` in the API (HTTP and gRPC) and a
     **Degraded · audit owed** badge in the project's break-glass tab.
4. Its post-activation **review is mandatory at once**: a degraded activation is listed as
   a posture deviation and in the review reminder from the moment it exists, with no grace
   window.

The user who activated sees the shortened expiry and a note that the audit log was not
accepting writes.

### What an operator should do

1. Treat the alert as two incidents: the one the user is handling, and the audit log.
   Check the server log for the `SECURITY: failed to persist audit event` lines that
   preceded it, the database's free disk space and health, and `audit_events` triggers or
   permissions nobody should have changed.
2. Fix the audit log. Nothing else is needed for the record: the **owed-audit backfill**
   (`audit_owed_backfill`, every minute, one replica at a time) writes each owed row into
   the hash chain as soon as the audit log accepts writes again:
   - in the order they were owed;
   - with their **original event time** (the moment of activation, not of the backfill),
     and a description that says they were recorded late;
   - exactly once (the claim of the owed record and the append share a transaction);
   - and in the same transaction as the activation's last owed row, the activation is
     marked **settled** (`audit_settled_at`).
   The server log says `Audit backfill: wrote owed audit event ...` for each row.
3. Review the activation (someone other than the activator), as for any activation. The
   banner goes away when every degraded activation is both settled and reviewed.
4. Confirm with the offline verifier:

   ```bash
   keyorix-server admin verify-audit --config ./keyorix.yaml
   ```

   While any degraded activation is unsettled the report says, under
   "Owed break-glass audit records", `N UNSETTLED -- activation ids [...]`, and the
   verdict is **INDETERMINATE** (exit code 2): the chain is intact but known to be missing
   those rows. When they are settled the section says `none` and the verdict is VALID
   again. On a database the verifier's role cannot read `break_glass_activations` from,
   the section says NOT CHECKED and the "does NOT prove" list says so.

An unsettled degraded activation is never removed by `data_retention.break_glass_days`.

### Settling by hand (mixed-version upgrade only)

During a rolling upgrade from a version without degraded mode, an older replica's
backfill can write a degraded activation's owed rows without marking the activation
settled (it does not know the column). The rows are in the chain; only the marker is
missing, so verify-audit keeps listing the activation. Nothing else clears it, on
purpose: a marker that set itself whenever the owed records disappeared would also hide
records deleted by someone covering their tracks. Confirm, then set it:

1. `keyorix audit logs --limit 50` (or the web audit log): find the `break_glass.activated`
   row whose description says `DEGRADED ... activation <id>` and `recorded late`, and its
   `role.assigned` row.
2. Check that no owed record is left for it:
   `SELECT count(*) FROM pending_audit_events WHERE break_glass_activation_id = <id>;` → 0.
3. `UPDATE break_glass_activations SET audit_settled_at = CURRENT_TIMESTAMP WHERE id = <id> AND degraded AND audit_settled_at IS NULL;`
   (SQLite: `degraded = 1`). Do this with the server stopped on SQLite.

## 3. Last resort: when even the owed record cannot be written

If the audit log refuses the activation **and** the database cannot store the owed-audit
record either, nothing is granted. The user gets:

- HTTP **503**, error code `BreakGlassUnrecordable` (gRPC: `Unavailable`), with a message
  that the database itself is failing and names `keyorix-server admin recover-admin`;
- the server logs `SECURITY: break-glass activation REFUSED ...` at level ERROR with both
  causes.

At that point the database is broken, not just the audit log, and break-glass cannot work
without giving up the "never unrecorded" rule. The way back in is offline, on the host,
with exclusive access to the database:

```bash
keyorix-server admin recover-admin --user admin@example.com --recovery-key - --config ./keyorix.yaml
```

See `docs/operator/j5-lost-admin.md` for the full procedure (it needs the recovery key you
generated in advance; every use is written to the audit trail as `admin.recover_admin` and
notifies every current admin). Fix the database
first (disk, permissions, storage health): the server cannot record anything until then.

## 4. Configuration

| key | default | meaning |
|---|---|---|
| `break_glass.enabled` | `false` | turn self-service emergency access on |
| `break_glass.emergency_role` | | the contained role granted (no `roles.assign`) |
| `break_glass.default_ttl` | `4h` | lifetime when none is requested |
| `break_glass.max_ttl` | `24h` | ceiling on a requested lifetime |
| `break_glass.review_window` | `72h` | unreviewed longer than this: posture deviation |
| `break_glass.degraded_ttl` | `15m` | lifetime of a degraded activation; never longer than the normal lifetime of the same request |
