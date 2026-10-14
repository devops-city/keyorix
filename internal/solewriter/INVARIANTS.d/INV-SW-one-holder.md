- **INV-SW-one-holder** Exactly one single-writer server per schema (`Start`, the holder lock), no
  other attached server when it starts (presence census), no server without the setting while it runs
  (`CheckOff`), and no `admin --force` next to it (`server/admin` `acquireDatabaseLock`). Guard:
  `TestStart_SecondHolderRefused`, `TestStart_RefusedWhileAnotherServerIsAttached`, `TestCheckOff`,
  `TestSingleWriter_Postgres_OperatorJourney`.
