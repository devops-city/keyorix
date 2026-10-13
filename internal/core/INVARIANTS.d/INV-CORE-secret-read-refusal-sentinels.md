- **INV-CORE-secret-read-refusal-sentinels** Every refusal of a value read by the secret's own
  state wraps a sentinel `ClassifySecretReadRefusal` knows (`ErrAccessOutsideSchedule`,
  `ErrSecretExpired`, `ErrSecretSuspended`, `ErrSecretMaxReadsExhausted`), so transports map it
  by `errors.Is`, never by message text. The clock-regression refusal
  (`checkSecretExpiryClockNotRegressed`) is deliberately the expired one, same sentinel and
  text, so no transport can answer it differently (that difference would be an oracle). A
  storage failure while enforcing max reads is NOT a refusal and stays a server error. Why:
  ERRMAP-1. Guard: `secret_read_refusal_test.go` (`TestSecretReadRefusals_ClassifiedFromEveryGuard`).
