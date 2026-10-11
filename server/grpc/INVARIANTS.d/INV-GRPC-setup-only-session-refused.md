- **INV-GRPC-setup-only-session-refused** The auth interceptor applies the HTTP account-setup
  gate's rules (server/middleware INV-MW-account-setup-union-of-pending-steps) to every RPC. gRPC
  has no setup-step RPC, so its setup allowlist is empty: a setup-only session is refused every
  RPC (PermissionDenied while a step is owed, Unauthenticated once nothing is owed and its
  revocation has not landed), and an ordinary session owing both steps is sent to sign in
  again. The per-session facts come from one read (`core.ResolveSessionAuthFacts`); if it fails
  the RPC is refused with Unavailable and the refusal is audited. Why: #3041 review: the
  interceptor never checked `Session.SetupOnly`, so a setup session that owed nothing had full
  gRPC access. Guard: `setup_session_gate_test.go:TestEveryGRPCMethod_RefusesSetupOnlySession`
  (walks every RPC the real server registers; the allowed set is pinned in
  `expectedSetupGRPCMethods`), `TestGRPCSessionFactsReadFailure_FailsClosed`.
<!-- section: Interceptor chain (`server/grpc/interceptors`) -->
