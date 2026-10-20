### Testing

- Every way a credential ends (revoked, rotated, expired, owner suspended or deleted, machine
  identity suspended or revoked, session logged out, revoked or rotated) is now tested to be
  refused on another replica from the first request after the change, on the REST reads and
  gRPC, on SQLite and PostgreSQL, including while the audit log refuses every write
  (`server/http/revocation_after_commit_test.go`).
