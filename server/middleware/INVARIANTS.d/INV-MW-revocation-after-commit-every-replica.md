- **INV-MW-revocation-after-commit-every-replica** Once the call that ends a credential has
  returned (its commit is done), no replica authenticates that credential again, on any
  transport, from the very next request: a revoked, rotated-away or expired machine token,
  PAT or session; a PAT or session whose owner was suspended or deleted; a machine token whose
  identity was suspended or revoked; a session logged out, revoked or rotated. A replica that
  did not run the change and holds a warm auth-cache entry refuses on its live cache-hit
  re-check (INV-MW-01..05) exactly as it refuses an unknown token of the same kind; gRPC has
  no auth cache and refuses on its per-call validation. The audit log never delays it: with
  every audit write refused, each of these changes still commits and takes effect at once
  (revocations are not audit-gated, INV-CORE-security-mutation-audit-same-tx). The exception
  is rotation with `ReplaceCredentialID`: it is a credential issue (fail-closed on its audit,
  AUDIT-TX-2), so with the audit refused it is refused as a whole and the old token stays
  live until a plain revoke. Any cache added to the credential path must keep this
  invariant. Why: ADR-112 "revocation takes effect immediately"; Andrei 2026-10-14 (revocation
  never blocked by the audit log); PERF-CRED-LOOKUP-1. Guard: `server/http`
  `revocation_after_commit_test.go` (`TestRevocationAfterCommit_EveryCredentialType`: 15
  changes x the folded and the by-ref REST read as the cache hit x gRPC, SQLite always,
  PostgreSQL when `KEYORIX_TEST_PG_DSN` is set; `_AuditRefused_EveryCredentialType`; red with
  the cache-hit re-check skipped, and per credential type with its own re-check disabled).
  Not covered: federated OIDC principals over HTTP (no issuer harness there;
  `cache_hit_fail_closed_test.go` covers their re-check), node/role/schedule changes on the
  folded path (`server/http/folded_credential_test.go`).
