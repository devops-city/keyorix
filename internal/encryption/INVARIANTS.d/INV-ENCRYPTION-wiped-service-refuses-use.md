- **INV-ENCRYPTION-wiped-service-refuses-use** After `aead.EncryptionService.WipeDEK` every
  operation on that service (`Encrypt`, `EncryptWithAAD`, `EncryptChunked`, `Decrypt`,
  `DecryptWithAAD`, `DecryptChunked`) returns `aead.ErrDEKWiped`. Zeroing `dek` alone is not
  enough: `cipher.NewGCM` keeps its own expanded AES key schedule, which crypto/aes cannot
  zero, so before the latch a wiped service (`IsDEKWiped()==true`) still sealed and opened
  under the superseded DEK. Why: REVIEW-COVERAGE-1 (aead pass). Guard:
  `internal/encryption/aead/wipe_dek_failclosed_test.go:TestWipeDEK_ServiceRefusesUseAfterWipe`.
  **Not covered**: the key schedule stays in process memory until the GC reclaims the cipher;
  INV-ENCRYPTION-24's memory-scan tests check the `dek` bytes only.
<!-- section: Memory hygiene -->
