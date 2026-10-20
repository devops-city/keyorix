# TLS server configuration

Protocol floor, cipher suites, ALPN and certificate reload on the REST/web and gRPC
listeners. See `docs/security/production-hardening-matrix.md` for the row rules.

| Control | Where | Setting | Default | Test |
|---|---|---|---|---|
| TLS 1.2 floor; TLS 1.0/1.1 refused (HTTP) | `server/main.go` `applyTLSHardening` | `server.http.tls_mode` | `""` (1.2 floor) | `server/tls_mode_handshake_test.go:TestTLSHandshake_DefaultMode_RejectsBelowTLS12`, `server/tls_mode_handshake_test.go:TestTLSHandshake_DefaultMode_AcceptsTLS12WithAHardenedCipher` |
| `tls_mode: strict` = TLS 1.3 only (HTTP) | `applyTLSHardening` | `server.http.tls_mode: strict` | off | `server/tls_mode_handshake_test.go:TestTLSHandshake_StrictMode_RejectsTLS12`, `server/tls_mode_handshake_test.go:TestTLSHandshake_StrictMode_AcceptsTLS13` |
| `tls_mode: strict` = TLS 1.3 only (gRPC) | `server/grpc/server.go` `applyTLSHardening` | `server.grpc.tls_mode: strict` | off | `server/grpc/tls_reload_test.go:TestNewServer_TLS_StrictModeRefusesTLS12` |
| TLS 1.2 suites: forward-secret AEAD only, for RSA and ECDSA certificates | `internal/config` `DefaultCipherSuites` (both listeners) | `server.*.tls.allowed_ciphers` (AEAD names only) | ECDHE-{ECDSA,RSA} with AES-GCM / ChaCha20-Poly1305 | `server/tls_reload_ecdsa_test.go:TestTLSHandshake_ECDSACertificate_TLS12`, `server/grpc/tls_reload_test.go:TestNewServer_TLS_ECDSAOverTLS12_H2_AndCertReload`, `server/transport_tls_test.go:TestApplyTLSHardening_DefaultPreservedWhenAllowedCiphersUnset` |
| Weak, CBC, RC4/3DES or misspelled suite names refused at start | `config.TLSConfig.ResolveCipherSuites`, `checkTransportTLSPosture` | `allowed_ciphers` | — | `server/transport_tls_test.go:TestApplyTLSHardening_RejectsWeakOrUnknownCipher`, `server/transport_tls_test.go:TestCheckTransportTLSPosture_RejectsInvalidAllowedCiphers` |
| Same hardening on the AutoCert (ACME) path (HTTP); gRPC has no ACME, so `auto_cert` is refused rather than started without a certificate | `buildAutoCertTLSConfig`, `createGRPCTLSConfig` | `tls.auto_cert` | off | `server/transport_tls_test.go:TestBuildAutoCertTLSConfig_AppliesHardening`, `server/grpc/server_test.go:TestCreateGRPCTLSConfig_RefusesAutoCert` |
| ALPN: HTTP listener negotiates h2 (http/1.1 fallback); gRPC negotiates h2 | net/http `ServeTLS`, grpc `credentials.NewTLS` | fixed | on | `server/tls_reload_ecdsa_test.go:TestStartHTTPServer_TLSReloadsRotatedCertificateAndNegotiatesH2`, `server/grpc/tls_reload_test.go:TestNewServer_TLS_ECDSAOverTLS12_H2_AndCertReload` |
| Certificate rotated on disk is served without a restart; a pair that does not load keeps the previous one in service | `internal/tlsreload` (`GetCertificate`), both listeners | fixed `tlsreload.CheckInterval` | re-checked at most every 30s | `server/tls_reload_ecdsa_test.go:TestStartHTTPServer_TLSReloadsRotatedCertificateAndNegotiatesH2`, `internal/tlsreload/tlsreload_test.go:TestReloader_PicksUpRotatedPair`, `internal/tlsreload/tlsreload_test.go:TestReloader_BrokenRotationKeepsServingPrevious` |
| A missing or unloadable cert/key stops the server at start | `tlsreload.New` | — | — | `internal/tlsreload/tlsreload_test.go:TestNew_FailsOnUnloadablePair`, `server/server_s27_test.go:TestStartHTTPServer_S27_TLSBadCert` |
| Cleartext listener refused when `security.require_transport_tls` is set, warned otherwise | `checkTransportTLSPosture` | `security.require_transport_tls` | warn | `server/transport_tls_test.go:TestCheckTransportTLSPosture` |

## Not covered here

- `protocol_versions` is still not wired (the floor is the code above); start-up warns.
- Existing gRPC connections keep the certificate they were opened with until
  `max_connection_age` recycles them (1h default).
- TLS terminated at an ingress: the ingress's own TLS settings apply; checking the Helm
  ingress needs a cluster: pending e2e VM.
