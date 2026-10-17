### Security
- **No internal error text in 5xx responses.** Bulk delete/rename/rotate, owner reassignment and the secret-dependency endpoints sent the underlying error's text (storage or driver messages) on their 500 branch; a 5xx now carries only the generic message and the error is logged. Every `sendError` call in the handlers is checked for this in CI.
- **Uniform error responses.** The router's own 404 (unknown API paths, missing static assets), 405 and the `/metrics` 401 now return the JSON error body with `Cache-Control: no-store` instead of `text/plain` or an empty body; a missing static asset's 404 is no longer marked cacheable for a year.

### Documentation
- **Production-hardening matrix: response hygiene.** `docs/security/production-hardening-matrix.d/response-hygiene.md`.
