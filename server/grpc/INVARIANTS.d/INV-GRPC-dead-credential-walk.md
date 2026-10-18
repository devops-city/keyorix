- **INV-GRPC-dead-credential-walk** Every RPC the real server registers (unary and streaming), called
  with a credential in a dead state, is answered Unauthenticated (the contract code of every state
  today, pinned per state in `deadStates`) and changes no table content and appends no audit row;
  only the pinned public methods answer OK, because they never read the credential. The dead
  states are: session logged out / idle-expired / absolute-expired; user suspended / deleted /
  deactivated (through the core API AND as a bare state flip with the credential left intact, so
  the account check is proven on its own); PAT revoked / expired / owner suspended / owner deleted;
  machine identity revoked / suspended and machine token revoked / expired. Each credential
  belongs to a principal that would be allowed (project admin / developer on the canary project),
  and is walked cold (never used) and warm (used once successfully before it died). The one
  tolerated effect is the owner notification an expired PAT triggers (`sideEffectTables`). Why:
  the completeness test covers a missing credential only; revocation/expiry/suspension are checked
  in three separate places (session, PAT, machine) and each could drop its check unnoticed.
  Guard: `authz_walk_dead_credential_test.go:TestEveryGRPCMethodRejectsDeadCredential` (SQLite, and
  Postgres when `KEYORIX_TEST_PG_DSN` is set). Not covered: the HTTP bearer cache (gRPC has none),
  a credential that dies while a stream is already open.
<!-- section: Interceptor chain (`server/grpc/interceptors`) -->
