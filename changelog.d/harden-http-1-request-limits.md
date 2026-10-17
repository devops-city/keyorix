### Security
- **Request bodies are capped per route class.** The unauthenticated credential routes (`/auth/*`, `/system/init`) now accept at most 64 KiB (the SAML ACS 1 MiB) instead of the 10 MiB API default, and raising or disabling `server.http.max_request_body_bytes` no longer lifts those caps. A body whose `Content-Length` is over its route's cap is answered `413` with the standard JSON error body before authentication or any handler runs (handlers used to see the truncated body and mostly answered `400`).

### Fixed
- **gRPC: removed a message-size option that never took effect.** A `MaxRecvMsgSize` derived from `secrets.limits.max_secret_size` was always replaced by the later `server.grpc.max_request_body_bytes` option; the comment claiming wire-level parity with the HTTP secret routes was wrong. Oversized secret values over gRPC are still refused by core (`ResourceExhausted`).

### Documentation
- **Production-hardening matrix: request limits.** `docs/security/production-hardening-matrix.d/request-limits.md`.
