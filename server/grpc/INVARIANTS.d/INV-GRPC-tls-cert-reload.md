- **INV-GRPC-tls-cert-reload** The gRPC and HTTP TLS listeners serve their certificate
  through `internal/tlsreload` (`tls.Config.GetCertificate`), never a pair pinned at
  start: a cert/key pair rotated on disk reaches the next handshake within
  `tlsreload.CheckInterval`, a rotated pair that does not load leaves the previous one
  in service, and an unloadable pair at start still refuses to start. Both use
  `config.DefaultCipherSuites`, which covers ECDSA as well as RSA certificates for
  TLS 1.2. Why: HARDEN-HTTP-1: both listeners pinned the start-up pair until a restart,
  and the RSA-only suite list failed every TLS 1.2 handshake for an ECDSA certificate.
  Guard: `tls_reload_test.go:TestNewServer_TLS_ECDSAOverTLS12_H2_AndCertReload`,
  `server/tls_reload_ecdsa_test.go:TestStartHTTPServer_TLSReloadsRotatedCertificateAndNegotiatesH2`,
  `internal/tlsreload/tlsreload_test.go`. Not covered: an open gRPC connection keeps its
  certificate until `max_connection_age` recycles it.
