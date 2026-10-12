- **INV-STORE-session-auth-liveness-one-snapshot** `GetSessionAuthLiveness(user, session)`
  answers exactly what `GetUser(user)` and `GetSessionByID(session)` answer
  (`storage.ComposeSessionAuthLiveness`): the user half is the row `GetUser` returns (a
  soft-deleted or absent row is an error wrapping `ErrUserNotFound`), the session half the
  row `GetSessionByID` returns (absent is an error wrapping `ErrSessionNotFound`), each with
  the same error text. Both rows come from ONE statement (a one-row probe LEFT JOIN users
  LEFT JOIN sessions on their primary keys), so they are one snapshot. No cache is read or
  published. If the combined statement fails, the answer is the two per-statement reads over
  the same store, so every failure mode (one table unreadable, a storage error) answers as
  before, error by error; the method itself returns no error. Why: PERF-FIX-7 (collapse C6)
  — the HTTP session cache hit issued 2 statements. Guard: `internal/storage/store`
  `TestGetSessionAuthLiveness_EqualsTheTwoReads` (every user state x every session state,
  plus deleted/absent rows and mismatched pairs, SQLite and Postgres),
  `_OneStatement`, `_StatementFailureFallsBackToTheTwoReads`. **Not covered**: a column the
  cache-hit verdict starts to depend on must be added to both the statement and
  `SessionAuthUser` / `SessionAuthSession`; nothing derives one from the other.
