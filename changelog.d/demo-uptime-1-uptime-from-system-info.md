### Fixed
- **`scripts/demo/check.sh` "no open anomalies after 6 minutes" step works on the Postgres demo stack again.**
  It read the server uptime from `GET /health`, but behind the compose stack nginx answers `/health` itself
  with a static `healthy`, so the step failed with "could not read the server uptime" on every nightly run
  since the step was added (#3152). `demo_uptime_seconds` now reads `data.uptime` from the authenticated
  `GET /api/v1/system/info` (admin token); `/health` is unchanged and still exposes no new fields. When the
  uptime cannot be read, the helper now prints the HTTP status and the head of the response body to stderr
  instead of failing silently.
