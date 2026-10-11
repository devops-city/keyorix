- **INV-MW-session-facts-fail-closed** On the slow path, every per-session fact the
  middleware acts on after a session token validates (the row id for the INV-MW-04 liveness
  re-check, the impersonator, the #3024 setup-only flag, the F-TOK-1 cache-expiry clamp) comes
  from ONE read, `core.ResolveSessionAuthFacts`. If that read fails the request is refused with
  503, nothing is cached and the refusal is logged and audited
  (`auth.session_facts_unavailable`); the facts are never defaulted to "no restriction". Why:
  #3041 review: a failed read left `SetupOnly` false and cached it, so a setup-only session
  whose revocation had not landed got full access. Guard:
  `server/http/account_setup_session_facts_test.go:TestAccountSetup_SessionFactsReadFailure_FailsClosed`
  (red before: 200, and 200 again from the cache after the store recovered).
<!-- section: Auth-cache hit re-verification -->
