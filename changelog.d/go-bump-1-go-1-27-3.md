### Security
- **Go toolchain bumped to 1.27.3**, fixing GO-2026-6809 (`crypto/x509`), reachable via notary receipt verification (`notary.VerifyReceipt` -> `pkcs7.VerifyWithOpts` -> `x509.Certificate.Verify`).
