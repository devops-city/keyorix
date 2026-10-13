- **INV-HTTP-audit-client-ip-bare** The client IP written to `audit_events` and
  `secret_access_logs` is the bare IP, never `ip:port`. Handlers obtain it only through
  `clientIP(r)` (`core.CanonicalIP`), never `r.RemoteAddr`; behind a configured trusted
  proxy the `ClientIP` middleware has already replaced `RemoteAddr` with the forwarded
  client (INV-MW-18), and `X-Forwarded-For` from an untrusted peer is still ignored. Rows
  written before #3141 keep their stored `ip:port`; the access-log API shows them as bare
  IPs, exports return them as stored. Guard: `server/http` `TestSecretAudit_StoresClientIPWithoutPort`
  (direct, untrusted-XFF, trusted-proxy), `server/http/handlers`
  `TestStructural_HandlersNeverReadRemoteAddrDirectly`.
