### Security
- **TLS certificates rotated on disk are picked up without a restart.** Both the HTTP and gRPC listeners loaded the cert/key pair once at start and served it until the process restarted, so a renewed certificate (cert-manager, ACME, manual rotation) was not used and the old one could expire in service. The files are now re-checked at most every 30 seconds during handshakes; a rotated pair that does not load (half-written, key mismatch) is logged and the previous pair keeps being served.

### Fixed
- **TLS 1.2 with ECDSA certificates.** The default TLS 1.2 cipher list held only `ECDHE_RSA` suites, so a server with an ECDSA certificate failed every TLS 1.2 handshake (only TLS 1.3 clients could connect). The default now includes the matching `ECDHE_ECDSA` AEAD suites on both listeners.

### Documentation
- **Production-hardening matrix: TLS.** `docs/security/production-hardening-matrix.d/tls.md`.
