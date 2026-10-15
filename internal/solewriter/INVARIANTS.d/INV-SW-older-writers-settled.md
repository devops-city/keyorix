- **INV-SW-older-writers-settled** A boot does not become authoritative before every transaction open at
  its start has ended (`Settle`; InstallFence's locks give the same ordering, so this is two barriers).
  Guard: `TestSettle_WaitsForATransactionOlderThanTheBoot`.
