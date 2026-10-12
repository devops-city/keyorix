- **INV-CORE-secret-decision-reuses-own-resolution** A per-secret decision fetches the secret
  at most once per decision and reuses only a resolution of that same secret.
  `AuthorizeSecretAction` uses the caller's resolution (`AuthorizeSecretPrincipalForSecretAction`
  passes the secret the HTTP gate or gRPC `authorizeSecretScoped` fetched by ID, or that
  `ResolveSecretRef` fetched by name) only when there is exactly one, it is non-nil and its ID
  is the secret being decided; anything else is ignored and the secret is fetched.
  `GetSecretWithPermissionCheck` returns the row its read check (`checkSecretPermission`)
  fetched, after the access-schedule check and `GetSecret`'s expiration check, in that order.
  Ownership, shares, ACL rows and roles are still read live by the decision. Why: PERF-FIX-5
  (PERF-FIX-3 collapses C2 + C3): both re-fetched a row the request had just read, with the same
  filters (secret_nodes by primary key or name, soft-delete scope only) and no transaction
  between the reads, so a write landing between them gives an outcome that main also gives when
  that write lands just after its re-fetch. Guard: `authz_resolved_secret_test.go:TestAuthorizeSecretAction_ReusesOnlyTheSameSecretsResolution`
  (another secret's row, several rows or nil are ignored; red when the ID check is dropped),
  `server/http` `TestResolvedSecretReuse_Equivalence` / `TestResolvedSecretReuse_CrossReplicaRace` /
  `TestResolvedSecretReuse_FetchCount` and `server/grpc/services`
  `TestGRPCResolvedSecretReuse_Equivalence` (outcome, response and audit rows per case,
  unchanged from before, SQLite and Postgres, two-pool race; 2 secret fetches per human
  metadata read, 4 before). The share-term shape guard `share_authz_guard_test.go` is
  unchanged. **Not covered**: a caller that passes `AuthorizeSecretPrincipalForSecretAction` a
  stale or hand-built row with the right ID is trusted for its scope, as the machine branch
  always was; nothing flags it.
