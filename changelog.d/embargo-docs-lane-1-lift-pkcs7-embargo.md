### Security
- **`digitorus/pkcs7` advisory GHSA-3xqc-rpq8-wgp9 is public** (2026-09-14): the BER-length memory-amplification DoS in `pkcs7.Parse` is fixed in the pinned version. The security docs no longer describe the pkcs7 finding as embargoed, and the closure ledger records it with `FuzzDigitorusPKCS7BoundedWork` as the regression guard. Documentation only; no behaviour change.
