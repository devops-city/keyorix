### Added
- **Helm: `externalDatabase.caSecret` mounts the external PostgreSQL's CA.** Set
  `externalDatabase.caSecret.name` (and `.key`, default `ca.crt`) to a Secret holding the CA's
  PEM: the chart mounts it read-only (0440) at `/app/db-ca/ca.crt` in the server pod and renders
  it as `storage.database.ssl_root_cert`, so `externalDatabase.sslMode: verify-full` against a
  private CA works without patching the Deployment. `externalDatabase.sslRootCert` (`system` or
  your own mount) still works; setting both, `caSecret` with the bundled PostgreSQL, or
  `caSecret` with a non-TLS `sslMode` fails the render, and so does `sslMode`
  `verify-full`/`verify-ca` with no CA at all (the server would refuse to start).
