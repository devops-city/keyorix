- **INV-SW-holder-row-only-the-holder-writes** While a holder lives, no session without its tag
  changes the holder row (`keyorix_sole_writer`) or the epoch row, in any column, by UPDATE, DELETE,
  INSERT ... ON CONFLICT, MERGE or TRUNCATE: the own tables' fence triggers fire BEFORE the change, so
  the fence decides from the holder row as it was, never from the pid or hash the write itself put
  there (an AFTER trigger read its own new row and let it through, which opened the fence to every
  session). The poller also compares the holder row's `holder_pid`, `nonce_hash` and `xmin` with its
  own and leaves the authoritative state on any difference, a rewrite to the same values included.
  Why: REVIEW-SINGLE-WRITER-3 N5. Guard: `TestFence_OwnTablesRefuseATablePrivilegedRole` (a
  table-privileged role over every column of both tables; the holder cases red with AFTER triggers),
  `TestPoll_HolderRowChangeLeavesAuthoritative`, `TestTriggerSpecs_OwnTablesAreFencedBefore`.
