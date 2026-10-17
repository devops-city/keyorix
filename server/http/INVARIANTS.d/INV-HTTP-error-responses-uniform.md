- **INV-HTTP-error-responses-uniform** Every error response the router serves, from a
  handler, a middleware envelope, or the router itself (unknown backend path, wrong
  method, missing static asset, `/metrics` 401), carries the baseline security headers,
  `Cache-Control: no-store` and the JSON error body (`error`, `message`, `code`); and no
  5xx carries an error's raw text: a handler whose status is decided at run time uses
  `errorMessageFor(status, err)`. Why: HARDEN-HTTP-1: the router's own 404/405/401 were
  text/plain or empty, a missing asset's 404 was marked cacheable for a year, and 14
  handler call sites passed `err.Error()` with a status that defaulted to 500. Guard:
  `error_response_hygiene_test.go:TestEveryErrorResponse_HeadersNoStoreAndJSONBody`
  (walks every route of the real router), `handlers/raw_error_text_guard_test.go:TestNoRawErrorTextOnServerErrors`
  (every `sendError` call in the package). Not covered: net/http's own pre-handler 400/431.
