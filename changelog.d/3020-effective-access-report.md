### Added
- **Secret access shows each user's effective level and every grant behind it.**
  `GET /secrets/{id}/access` / `keyorix secret access` / the secret's Access panel list each
  user's effective level (max of role, per-secret ACL and active share; owner for a live
  owner) with a `grants` list such as `role:read, direct_share:write` or `owner:owner`.
  Every applying share is listed, so a direct read share and a group write share both appear.
- **An incomplete access list says so.** `keyorix secret access` prints
  `WARNING: this list is incomplete` with the server's reasons, and the web Access panel shows
  a "This list is incomplete" banner, whenever the report is `degraded`. The OpenAPI response
  now declares `total`, `degraded` and `degraded_reasons`.

### Security
- **The access report shows no more than the routes it summarises.** Project role levels and
  role-only members need `users.read` at the project; per-secret ACL holders and `acl:` grants
  need `secrets.manage` on the secret (the gate of `GET /secrets/{id}/acl`). Without them that
  part is left out and the report is flagged `degraded`. A departed owner is not reported as
  owner. A failed group-membership lookup now degrades the report instead of only being
  logged. Guarded by `internal/core/secret_access_list_test.go`.

### Changed
- **The access report reads a secret's shares once**, instead of once or twice per listed
  user, and evaluates each user's share grants from that list with the same rules as
  enforcement.
