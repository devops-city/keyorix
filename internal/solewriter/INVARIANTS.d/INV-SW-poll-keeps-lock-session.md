- **INV-SW-poll-keeps-lock-session** A poll that cannot complete (a role with UPDATE locks an own
  table) fails on the server through the holder session's `statement_timeout`
  (`pollStatementTimeout`, below `pollTimeout`), never through the client context cancel, which closes
  the connection and so releases the holder lock and opens the fence. The lease runs out meanwhile
  (fail closed), and the guard is authoritative again once the lock clears. Why:
  REVIEW-SINGLE-WRITER-3 N6. Guard: `TestPoll_OwnTableLockKeepsTheHolderLock` (red without the
  statement_timeout: the holder pid loses the lock and the guard never returns).
