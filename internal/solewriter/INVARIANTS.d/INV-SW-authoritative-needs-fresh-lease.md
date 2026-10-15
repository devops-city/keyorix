- **INV-SW-authoritative-needs-fresh-lease** `Authoritative()` is true only in state authoritative and
  while the last good poll (holder pid unchanged, lock held, fence fingerprint unchanged, epoch
  incarnation unchanged) is younger than `LeaseDuration` on both the monotonic and the wall clock,
  counted from when that poll was SENT (a slow answer does not extend it). A good poll after the lease
  ran out calls `OnReenter` (outside the guard's lock, like `OnEpochChange`). A
  lost lock, a changed fence or a settle timeout leaves the state for good, until restart. Guard:
  `TestLease_ExpiresOnAStalledPollerAndAClockJump` (the wall-jump half moves the wall clock only),
  `TestLease_AnchoredAtPollSend`, `TestPoll_ReentryAfterALapseCallsOnReenter`,
  `TestPoll_CallbacksRunOutsideTheGuardLock`, `TestPoll_FenceTamperingLeavesAuthoritativeForGood`
  (red without the fingerprint compare), `TestEmergencyTwoStep`, `TestSettle_TimeoutLeavesAuthoritativeForGood`.
