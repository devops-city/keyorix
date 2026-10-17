- **INV-CORE-gate-read-decision-used-once-per-request** A human per-secret read is decided
  once per request. When the transport's gate (`AuthorizeSecretAction`, behind
  `RequireScopedSecretPermission` / `RequireScopedSecretRefPermission` and gRPC
  `authorizeSecretScoped`) allows a user `secrets.read` with no action, it records that allow
  on a memo that only `WithShareElevationRecorder` creates, i.e. one per HTTP request or gRPC
  call; core's read check (`checkSecretReadPermission`, behind `GetSecretWithPermissionCheck`
  and `GetSecretForValueRead`) takes it, once, for the same user and the same secret id,
  checks the PAT restriction against the secret's scope again, and does not evaluate owner,
  share, ACL and role again. Nothing else is recorded or reused: not a refusal, not a write,
  delete or owner decision, not a decision made for a machine actor, and nothing outside the
  request (the memo lives on the request context; INV-MW-02's live re-checks per request are
  untouched). A value read (`GetSecretForValueRead`, or `GetSecretForRead` with the value)
  reads the schedule together with the latest version and `GetPermittedSecretValue` judges its
  schedule guard on that snapshot and serves its version. Why: OPT-READPATH-2 — the gate's
  grant set (ACL, role, share) is contained in core's (live owner, share, ACL, role) and both
  read the same live rows with no transaction between them, so the second evaluation could not
  change an allow; it cost eight statements per read, and the schedule was read twice. Guard:
  `server/http` `TestHumanReadGateReuse_Equivalence` (every case of a generated matrix of
  grants direct/via group/expired, ACL, shares direct/group/expired, live and departed owners,
  secret states, suspended/deleted readers, MFA-required/deleted projects, read with the reuse
  off and on: same status, response, audit and access-log rows, SQLite and Postgres),
  `TestHumanReadGateReuse_MemoIsPerRequest`, `TestHumanReadStatementCount` (7 statements
  before the audit write on a warm human value read; 16 before). **Not covered**: a handler
  behind a read gate that changes the reader's grants and then calls
  `GetSecretWithPermissionCheck` in the same request would be served by the gate's allow; no
  such handler exists, nothing flags one. The equivalence does not drive a session with a
  second factor enrolled, or storage faults injected between the two evaluations (a fault in
  core's second evaluation used to fail an allowed read; that evaluation no longer runs).
