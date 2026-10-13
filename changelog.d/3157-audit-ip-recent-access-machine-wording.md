### Fixed
- **Audit rows from the secret, version, folder, bulk and copy handlers now store the bare
  client IP.** They used to store `r.RemoteAddr` raw (`172.17.0.1:56508`) in
  `audit_events.ip_address` and `secret_access_logs.ip_address`. A direct request now stores
  `172.17.0.1`; behind a configured trusted proxy the forwarded client IP is stored exactly
  as before, and `X-Forwarded-For` from an untrusted peer is still ignored. Rows written
  before this change keep their `ip:port` value in storage and in exports (nothing is
  rewritten); `GET /api/v1/secrets/{id}/access-log` and the secret detail view show the bare
  IP for those old rows too. Filters or SIEM rules that matched an exact `ip:port` string
  must match the bare IP for new rows.
- **Secret detail "Recent access" lists reads only.** It also listed the `create` row;
  the other events are in History.
- **`machine_identity.*` audit descriptions say what happened.** `token_issued` used to read
  `machine identity "ci-app" (ci) in project 1 → active` (state, not event). It now reads
  e.g. `issued token for machine identity "ci-app" (ci) in project 1 (state: active)`, with
  its own wording for created, token rotated/revoked, role granted/removed, OIDC bound/unbound
  and activated/suspended/revoked. Name, type, project and state are all still in the text.
  Rows written earlier keep the old wording.
- A real-backend Playwright spec proves one Reveal click sends one `include_value` GET and
  writes exactly one `secret.read`.
