### Added
- **Structured JSON logs.** `server.log.format: json` writes every server log line as one JSON object (`ts`, `level`, `msg`), and the HTTP access log and panic lines also carry `request_id`, `principal_type` and `route`. The default stays `text`. See `docs/operations/logging.md`.
- **Request correlation.** Each request gets an id (the caller's `X-Request-ID`, cleaned, or a random one), returned in the response's `X-Request-ID` header and carried through core into audit-write failure logs.
- **Secret scrubber and canary guard.** In JSON mode Keyorix tokens, bearer values, JWTs, PEM keys, `password=`-style pairs and URL passwords are redacted from log lines, and a real-server test fails if a canary password or secret value reaches the server's output.
