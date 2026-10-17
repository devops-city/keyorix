### Security
- **Bootstrap-token and metrics-token guessing is throttled.** `POST /system/init` (before the system is initialised) and `GET /metrics` (with `metrics_token` set) accepted unlimited wrong tokens. Per client IP, 5 wrong bootstrap tokens (then one per 30s) and 10 wrong metrics tokens (then one per 6s) are allowed before the route answers `429` without checking the token. Correct tokens never spend the budget, so Prometheus scrapes and idempotent init calls are unaffected.

### Documentation
- **Production-hardening matrix: rate limits.** `docs/security/production-hardening-matrix.d/rate-limits.md` lists every unauthenticated or credential-checking endpoint with the limiter that bounds it and the test behind it, and the gaps still open.
