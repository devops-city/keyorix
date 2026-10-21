- **INV-HTTP-every-write-route-refuses-and-changes-nothing** Every POST/PUT/PATCH/DELETE
  route of the real router (`chi.Walk` over `NewRouter`, derived, not listed) answers a
  caller that must be refused (a zero-grant machine token, a baseline viewer, a project
  viewer, and the global admin's PATs confined to another project, to another project's
  environment, or to `users.read`) with a 4xx (never 2xx, never 5xx), with every `{param}`
  bound to the real canary object of its kind and to every canary id, and leaves a hash of
  EVERY table (minus the named noise tables) and the audit event set unchanged, except for
  denial events. Routes a low-privilege caller is meant to call (own profile, own PATs,
  own break-glass request, request access, ...) are the commented `awSelfServiceWrites`
  allowlist; a restricted PAT may succeed only on its owner's own-credential revocation
  (`core.restrictedPATUngatedWrites`). A new mutating route that is neither refused nor
  allowlisted fails the walk. Why: write routes had no route-wide walk (reads did:
  `TestEveryGETRouteHonoursPATRestriction`); the first run found a machine token answered
  500 on three user-only routes (#3416) and 200 on `POST /notifications/read-all`. Guard:
  `write_routes_deny_walk_test.go:TestEveryWriteRouteRefusesAndChangesNothing_G0`..`_G3`
  (one test per route group so CI can shard the walk; `TestAWRouteGroups_PartitionTheRouter`
  proves every mutating route is in exactly one group and that each group has its test)
  and `_Control` (allowlist hygiene and the admin positive control over the whole surface;
  SQLite always, Postgres when `KEYORIX_TEST_PG_DSN` is set). Not covered: one union request body
  (a route whose handler needs another field is refused in validation before its gate;
  the control run lists them), query parameters, state outside the database.
