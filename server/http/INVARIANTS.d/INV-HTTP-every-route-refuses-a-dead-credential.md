- **INV-HTTP-every-route-refuses-a-dead-credential** Every route of the real router
  (`chi.Walk` over `NewRouter`, derived, not listed; GET and mutating) answers a dead
  credential 401, the same as an unknown token, and changes nothing (hash of every table
  plus the audit set, denial events excepted), in each dead state: suspended user session,
  deleted user session, expired session, revoked session, revoked PAT, expired PAT, PAT of
  a suspended user, PAT of a deleted user, revoked machine identity, suspended machine
  identity, machine token of a soft-deleted project (#3433: the delete suspends the
  project's machine identities, `INV-STORE-project-delete-suspends-machine-identities`).
  Each state is walked cold (the credential never reached the replica's auth
  cache) and warm (a second replica's cache holds it; the credential is ended through the
  first, so nothing evicts the second's entry: the cache-hit re-check is the only defence).
  Public routes (`awPublicRoutes`) are an explicit allowlist held to no-5xx and
  unchanged-state; `POST /auth/logout` on a dead session is 401 (INV-HTTP-17), except an
  expired one, which is an idempotent cleanup. `awDeadOpen` pins a state whose current
  behaviour is a filed finding (empty since #3433). Why: `credential_gone_cache_hit_test.go` found the cache-hit path
  serving ended credentials on one route; the path is shared by every route. Guard:
  `dead_credentials_walk_test.go:TestEveryRouteRefusesADeadCredential` (SQLite always,
  Postgres when `KEYORIX_TEST_PG_DSN` is set). Red proof: disabling the revoked check in
  `CurrentPATRestriction` makes 338 routes serve a revoked PAT on the warm variant only;
  without the #3433 cascade step, 338 routes per backend serve the deleted project's
  machine token, cold and warm.
  Not covered: one typed path per route, one union body, gRPC.
