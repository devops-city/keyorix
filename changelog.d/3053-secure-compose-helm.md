### Security
- **Compose and Helm can run on the secure baseline** (`admin validate
  --posture`: no deviations, file permissions included, #2922):
  `docker-compose.secure.yml` (backend TLS with a generated certificate that
  nginx verifies, rate limiting, `/metrics` token, a private 0600 config copy)
  and the chart's `secureBaseline.enabled` (Helm-generated certificates and
  token kept across upgrades, bundled Postgres over TLS, an initContainer that
  copies runtime files to 0600). Both need a server image newer than v0.95.3,
  so they are opt-in until the next release makes them the default. New
  `keyorix-server admin init --secure-files` (generate only the files an
  existing config references); the server image's entrypoint is now its
  ENTRYPOINT (`docker run <image> <cmd>` runs `<cmd>` after the config copy).
  `docker-compose.secure.yml` mounts a small private tmpfs at `/app/data` for
  the config copy (the backend's root filesystem is read-only). With
  `secureBaseline.enabled=true` the server, web and bundled-Postgres pods carry a
  `checksum/secure-baseline` annotation, so rotating the Secret (delete it,
  `helm upgrade`) rolls them.
  `keyorix.docker.secure.yaml` sets `server.http.host: "0.0.0.0"` (the server's
  default bind is 127.0.0.1 since #2939, which left the web container and the
  health check unable to reach the TLS backend).
