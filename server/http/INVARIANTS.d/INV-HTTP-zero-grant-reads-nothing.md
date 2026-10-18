- **INV-HTTP-zero-grant-reads-nothing** A credential holding no role grant reads no tenant
  object through any REST GET route: a fresh machine identity (in its own project or
  another), a user with every role removed (system_viewer included) and that user's PATs,
  and a machine identity whose last grant was just removed, with its token reused inside
  the middleware cache TTL. Grant-filtered lists (`GET /projects`, `GET /environments`)
  answer 200 with an empty list (#2780), gated routes 403. Why: the SDK contract suites
  read the 200 on `GET /projects` as a possible disclosure (MACHINE-IDENT-DENY-1).
  Guard: `TestEveryGETRouteWithholdsDataFromZeroGrantCredentials` and
  `TestZeroGrantAfterRevocation_CachedMachineTokenReadsNothing` (chi.Walk over the live
  router, every path parameter bound to canary objects, SQLite and Postgres; what it does
  not cover is listed in `zero_grant_read_family_test.go`'s header).
