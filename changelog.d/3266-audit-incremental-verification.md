### Changed
- **Audit-chain verification is incremental: no full walk on a request or at startup.** A
  full walk grows linearly with the audit table, so on large trails `GET /api/v1/audit/verify`,
  `POST /api/v1/audit/checkpoint` and `GET /api/v1/compliance/posture` hit the HTTP write
  timeout, and every start walked the whole chain.
  - The checkpoint scheduler now checks only the rows after the latest signed checkpoint,
    pinning the certified head row. It also re-walks 1/7 of the chain per tick, so every row
    is still re-hashed at least weekly (daily ticks).
  - Progress and results are kept in a signed state row. The row is bound to the signed
    checkpoint trail and carries a generation, so an older signed row that is put back
    (replay/rollback) is rejected. A rejected row is reported (`not_proven` plus a
    `system.audit_verification_state_rejected` audit event), never silently replaced.
    A recorded failure stays until a full verification that started after it and covers
    the failing row succeeds.
  - `/audit/verify` returns that state plus a bounded tail check. A new `status` field is
    `valid`, `broken` or `not_proven`; `valid` is true only for `valid`. Also new:
    `coverage`, `last_full_verification_at` and `rolling_cycle`.
  - `?full=true` runs a full walk as a background job (202 + `job_id`); poll
    `GET /api/v1/audit/verify/jobs/{id}`.
  - Posture reads the persisted result.
  - A restart with a fresh checkpoint defers the first tick.
  - `keyorix audit verify` prints NOT PROVEN (non-zero exit) and gains `--full`.
  - The web compliance page shows "Not yet proven".
  - **Upgrade note:** after upgrading, the status is `not_proven` until the first rolling
    cycle completes (about a week), or until `keyorix audit verify --full` succeeds.
  - Spec: `docs/specs/audit-incremental-verification.md`.
