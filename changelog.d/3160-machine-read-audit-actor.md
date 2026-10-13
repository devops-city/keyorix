### Fixed
- **A machine identity's secret read is attributed to the machine in the audit log.** A value
  read by a machine (`GET /api/v1/secrets/{id}?include_value=true`, by-ref, by-name lookups)
  showed actor `unknown` in `keyorix audit logs`, the HTTP audit API and gRPC, and read
  "User ci-app read secret ...". It now shows the machine's name as the actor (`ci-app`) and
  says "Machine identity ci-app read secret ...". Rows written earlier keep their stored
  wording; the actor of old machine rows is resolved from `machine_identity_id`, so they show
  the name too. Audit semantics are unchanged: `secret.read` is still written, before the
  value is returned, for value reads only; a plain `GET /api/v1/secrets/{id}` is metadata only
  and is not a `secret.read`.
- **GOLDEN-PATH section 5 and `up.sh` use the value-read call.** The documented machine
  `curl` was a metadata-only GET, which writes no audit row, so `audit logs` showed nothing.
  The doc now uses `?include_value=true` and `--actor-type machine_identity`;
  `scripts/demo/check.sh` asserts the machine read appears with actor `ci-app`.
