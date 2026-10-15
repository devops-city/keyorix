- **INV-SW-epoch-row-version-flushes** The poller treats any change of the epoch row's `xmin`, not
  only of its value `n`, as a write: a session that passes the fence and moves `n` back in the same
  transaction still causes a flush at the next poll. Why: REVIEW-SINGLE-WRITER-2 N3. Guard:
  `TestPoll_EpochRewindIsSeen` (red with value equality only).
