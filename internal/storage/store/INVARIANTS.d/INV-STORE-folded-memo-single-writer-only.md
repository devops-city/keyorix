- **INV-STORE-folded-memo-single-writer-only** The folded credential statement is memoized
  (`local_folded_credential_memo.go`) only when a single-writer guard is registered in `swstate` and
  vouches for the entry; otherwise, and on any doubt, the statement runs exactly as before. The memo returns
  the same scanned rows, and every caller judges them with unchanged code. Root store only (`foldMemo`
  is set by `NewLocalStorage`, never on a transaction-scoped or derived store). See
  INV-SW-memo-only-while-vouched. Guard: `TestFoldedCredentialSQL_ReadsOnlyFencedTables`; `server/http`
  `TestSingleWriter_*`.
