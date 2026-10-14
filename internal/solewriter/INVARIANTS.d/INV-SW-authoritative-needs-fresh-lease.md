- **INV-SW-authoritative-needs-fresh-lease** `Authoritative()` is true only in state authoritative and
  while the last good poll (holder pid unchanged, lock held, fence fingerprint unchanged, epoch
  incarnation unchanged) is younger than `LeaseDuration` on both the monotonic and the wall clock. A
  lost lock, a changed fence or a settle timeout leaves the state for good, until restart. Guard:
  `TestLease_ExpiresOnAStalledPollerAndAClockJump`, `TestPoll_FenceTamperingLeavesAuthoritativeForGood`
  (red without the fingerprint compare), `TestEmergencyTwoStep`, `TestSettle_TimeoutLeavesAuthoritativeForGood`.
