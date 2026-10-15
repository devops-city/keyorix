### Security
- **Refused secret-value reads are audited (#3273, ADR-112 Amendment 4).** A refused
  native read now writes a `secret.read` audit row with `success=false`, `outcome=denied`
  and a `reason=` class: `forbidden`, `not_found`, `outside_schedule`, `expired`,
  `suspended`, `max_reads_exhausted`, `classification_gate` or `mfa_required`. A read that
  breaks is recorded as `internal_error` with `outcome=failed`. This covers REST
  `GET /secrets/{id}?include_value=true`, `/secrets/value`, render, copy, environment copy
  and clone, and gRPC `GetSecretValue`, at both `insecure_audit_skip_reads` settings.
  Before this, only federated (`connect.secret_read`) denials were audited. Responses are
  unchanged. A missing and a forbidden secret still answer the same, and their rows name no
  secret or project on any column the caller can see. A burst is aggregated per principal,
  reason, path and target: the first refusal is written at once, then one summary row per
  60-second window carries the count, with per-principal and global caps. The row is
  best-effort: if it cannot be written, the refusal stands and the failure is logged.
  Dashboard read counts, top readers, billing machine reads and access-review activity now
  count only successful reads.
