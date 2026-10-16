# Keyorix alert runbook

One section per alert in [prometheus-alerts.yaml](prometheus-alerts.yaml); each alert's
`runbook_url` points at the heading with its name. Metric meanings are in
[docs/operations/metrics.md](../../docs/operations/metrics.md). Commands are
`keyorix-server admin <cmd> --config <path>` run on the server host (or in its container).

Every section has the same shape: what it means, what to check first, and what to do.

---

## KeyorixDown

**Means.** Prometheus cannot scrape the server.
**Check.** Is the process running? Does `GET /health` answer? If the process is up, did `/metrics`
start requiring a token (`server.http.metrics_token`) that the scrape job lacks (it then returns 401)?
**Do.** Restart a dead process and read its last log lines for the reason. For a token mismatch,
fix the scrape job's `authorization`.

## KeyorixHighErrorRate

**Means.** More than 5% of requests over 5 minutes returned 5xx.
**Check.** `sum by (route, status) (rate(keyorix_http_requests_total{status=~"5.."}[5m]))` shows
which route. Then the other alerts: a database pool at its limit (KeyorixDBPoolSaturated), audit
writes failing (KeyorixAuditWriteFailures) or the database being unreachable (`GET /readyz` returns 503).
**Do.** Fix the dependency named by the log line carrying the same `request_id` (JSON logs:
see [docs/operations/logging.md](../../docs/operations/logging.md)).

## KeyorixHighLatency

**Means.** p99 request latency above 2s for 10 minutes.
**Check.** Group the latency histogram by `route`. If every route is slow, look at
KeyorixDBPoolSaturated / KeyorixDBPoolWaiting and KeyorixAuditWriteSlow, since each secret read waits for
its audit append.
**Do.** Size the database pool (`storage.database.max_open_conns`) or fix the slow dependency.

## KeyorixAuditWriteFailures

**Means.** An audit append returned an error to the caller. The audited operation may already have
committed, so there can be an audit gap. The server log has a `SECURITY: failed to persist audit event`
line with the event type and the `request_id`.
**Check.** Database reachability and disk space; the error text in that log line.
**Do.** Restore the database, then run `keyorix-server admin verify-audit` to confirm the chain
is intact. Operations whose audit append failed in the window are the ones to review by request id.

## KeyorixAuditWriteSlow

**Means.** p99 audit append latency above 1s for 10 minutes.
**Check.** `keyorix_audit_group_commit_wait_seconds` (queueing) against
`keyorix_audit_write_duration_seconds` (end to end): if the wait is most of it, the flusher is the
bottleneck; if not, the commit (disk sync) is slow.
**Do.** Check disk latency on the database volume. On PostgreSQL the audit durability level
(`storage.database.audit_durability`, [fast-audit-mode spec](../../docs/specs/fast-audit-mode.md)) trades
sync cost for crash safety; change it only as that document describes.

## KeyorixAuditGroupCommitBacklog

**Means.** p95 queue time before an audit batch commits above 0.5s for 10 minutes.
**Check.** Write rate (`keyorix_http_requests_total`), the batch size
(`keyorix_audit_flusher_batch_size`) and database write latency.
**Do.** As KeyorixAuditWriteSlow. Sustained backlog means the database cannot absorb the write rate.

## KeyorixAuditChainBreakRecorded

**Means.** A verification detected a break in the tamper-evident audit chain. This is a possible
integrity incident, not an operational blip.
**Check.** Do not clear it. Run `keyorix-server admin verify-audit` to see the first broken id and
reason. Compare against backups and the SIEM copy (`keyorix_siem_forwards_total`) of the same events.
**Do.** Follow your incident process. The flag clears only after a passing full verification, so
it keeps alerting until the cause is understood. Design:
[audit incremental verification](../../docs/specs/audit-incremental-verification.md).

## KeyorixAuditVerifyStateRejected

**Means.** The stored verification state failed its signature or looked replayed or rolled back, so
the audit status is `not_proven`. The cause can be a KEK-provider migration, a database restore, or
someone editing the state row.
**Check.** An audit event `system.audit_verification_state_rejected` records the reason.
**Do.** After a known restore or migration, a passing full verification clears it. Without a known
cause, treat it as KeyorixAuditChainBreakRecorded.

## KeyorixAuditVerifyStale

**Means.** No passing tail check for 2 days, or no passing full verification for 10 days.
**Check.** Does the server log say `Audit-checkpoint scheduler enabled` at start, and are there
`Audit checkpoint written` / `Audit rolling verification` lines each tick? A signing key is required
(encryption enabled). The metric exists only on the replica running the scheduler, so the alert
uses `max()` across replicas.
**Do.** Fix the error in the tick's log line, or enable encryption and the scheduler.

## KeyorixAuditVerifyNeverPassed

**Means.** No `keyorix_audit_verify_last_success_timestamp_seconds{check="tail"}` series for 2 days.
**Check.** Most often the `keyorix-protected` scrape job is missing or unauthorised (the series is not on
`/metrics`). Otherwise the checkpoint scheduler is off or there is no checkpoint signing key.
**Do.** Add the scrape job (bearer token with `system.write` against
`/api/v1/admin/scheduler-metrics`), or enable encryption and the checkpoint scheduler.

## KeyorixDBPoolSaturated

**Means.** A database pool is above 90% in use.
**Check.** Which `pool`: `request` is the API's; `scheduler_lock` and `named_lock` are small fixed pools
for advisory locks. Look for slow queries holding connections.
**Do.** For `request`, raise `storage.database.max_open_conns` if the database has headroom, or fix the slow
query. The lock pools are fixed in size by design; a saturated one means background jobs are queueing.

## KeyorixDBPoolWaiting

**Means.** Goroutines are blocked waiting for a free connection (average above 0.5 for 5 minutes).
**Check and do.** As KeyorixDBPoolSaturated; this is the symptom users feel as latency.

## KeyorixTokenAuthFailureFlood

**Means.** Callers are being refused for sending invalid tokens at over 1 request/s.
**Check.** Server access log (JSON: `status` 401/429, `remote_addr`). One source suggests guessing;
many suggest a deployed client with an expired credential.
**Do.** Block the source at the edge or rotate the credential the client is using.

## KeyorixLoginBruteForce

**Means.** The login or account-lockout budget is refusing checks at a sustained rate.
**Check.** Access log for `/auth/login` failures by `remote_addr`. A locked account is cleared with
`keyorix-server admin clear-login-lockout`.
**Do.** Block abusive sources; confirm MFA is required (`security.require_mfa`).

## KeyorixAPIRateLimited

**Means.** The per-principal request limiter is refusing callers (informational).
**Do.** If the traffic is legitimate, raise `server.http.ratelimit.requests_per_second` and `burst`.

## KeyorixEncryptionDisabled

**Means.** `storage.encryption.enabled` is false: secrets are stored as plaintext.
**Do.** Enable encryption before storing real secrets. This is acceptable only for local development.

## KeyorixEncryptionNotReady

**Means.** Encryption is enabled but the service never initialised.
**Check.** Server log for the key-provider error. For the password provider, the master passphrase source.
**Do.** Fix the key source and restart.

## KeyorixDecryptFailures

**Means.** Stored data could not be decrypted.
**Check.** Was the database restored without the matching key files, or the KEK provider or passphrase
changed? Is only one `instance` affected (a replica with different keys)?
**Do.** Restore the matching key material. Do not rotate keys until the cause is known.
`keyorix-server admin diagnose` checks key files.

## KeyorixKEKProviderDowngrade

**Means.** The KEK fallback chain actually fired: key material now comes from a weaker provider.
The server also writes an audit event for it.
**Check.** Why the primary provider failed (KMS/TPM reachability, credentials).
**Do.** Restore the primary provider and restart. Review
`storage.encryption.key_provider` fallbacks if the weaker provider should never be used.

## KeyorixTLSCertificateExpiringSoon

**Means.** The certificate served on a listener (`http` or `grpc`) expires within 14 days.
**Do.** Renew the certificate file and restart the server: certificates are loaded at start. With
`autocert`, check the ACME challenge path instead.

## KeyorixTLSCertificateExpiryImminent

**Means.** The same, within 3 days. Clients will start failing.
**Do.** As above, now.

## KeyorixSingleWriterNotAuthoritative

**Means.** `single_writer` is on but the guard is not authoritative, so caches confirm every read.
The server stays correct, only slower.
**Check.** `keyorix_single_writer_last_poll_age_seconds` approaching the lease length means polls are
failing: database connectivity. [docs/single-writer.md](../../docs/single-writer.md).
**Do.** Restore database connectivity. If the guard left authoritative because of a direct database
change, it does not resume until restart, by design.

## KeyorixSingleWriterUnattributedWrites

**Means.** The write epoch moved without any write this process made: something else wrote to the
fenced tables.
**Check.** Whether an operator made an emergency change using the documented procedure
([docs/single-writer.md](../../docs/single-writer.md)); otherwise another writer or a superuser.
**Do.** Treat an unexplained one as a security incident.

## KeyorixSchedulerFailing

**Means.** A background job's ticks have failed every hour for an hour. Ticks skipped because another
replica holds the lock are not failures.
**Check.** The server log line for that scheduler name, and
`keyorix_scheduler_runs_total{scheduler="..."}` by `outcome`.
**Do.** Fix the error in the log. Last success times are at `/api/v1/admin/scheduler-metrics`.

## KeyorixSIEMForwardFailures

**Means.** Audit events are not reaching the SIEM.
**Check.** The SIEM endpoint, credentials and the spool directory. `spool_corrupt` means spooled
files could not be read.
**Do.** Restore delivery. Undelivered events stay in the audit chain; compare chain head to the SIEM
to find the gap.

## KeyorixNotificationDeliveryFailures

**Means.** Notifications on a channel (`webhook`, `email`, `slack`, `teams`) are failing or dropped.
**Check.** The channel's endpoint or SMTP settings and the retry metric
`keyorix_notify_delivery_retries_total`.
**Do.** Fix the channel configuration.

## KeyorixBestEffortStepFailing

**Means.** A step that runs after a successful commit keeps failing (label `step`). The operation
itself succeeded; the follow-up bookkeeping did not.
**Check.** The `step` name points at the code path; the log has the error.
**Do.** Fix the underlying error (often database permissions or a full disk).
