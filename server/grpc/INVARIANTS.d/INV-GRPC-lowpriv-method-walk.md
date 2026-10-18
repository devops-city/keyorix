- **INV-GRPC-lowpriv-method-walk** Every RPC the real server registers (unary and streaming, read
  from `grpc.Server.GetServiceInfo`), called by an authenticated low-privilege caller (a zero-grant
  machine token, a project viewer user, a PAT restricted to a project other than the one holding
  the data), is answered PermissionDenied / NotFound / InvalidArgument, or with an empty response
  for a zero-grant read (ADR-096 Amendment 1); never Internal/Unknown, never a canary substring in
  a response or status message, and no table content changes whatever the status. The only
  tolerated trace is the audit row of a refused secret-value read. A method that a low-privilege
  caller may legitimately call is listed with its reason in `walkLowPrivAllowed`; a method whose
  verb is neither read nor write fails the walk. Why: `auth_interceptor_completeness_test.go`
  proves rejection of an UNAUTHENTICATED call only, and the protoreflect fuzzer's oracle samples
  the surface at random, so nothing walked the whole method set as a credentialed low-privilege
  caller. Guard: `authz_walk_lowpriv_test.go:TestEveryGRPCMethodRejectsLowPrivilegeCaller` (SQLite,
  and Postgres when `KEYORIX_TEST_PG_DSN` is set). Not covered: field values beyond ids (the
  fuzzer), responses that identify canary objects by number only.
<!-- section: Interceptor chain (`server/grpc/interceptors`) -->
