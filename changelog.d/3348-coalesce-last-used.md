### Changed
- **"Last used" and "last seen" stamps no longer cost a database write per request.**
  `last_used_at` on personal access tokens and machine credentials and `last_seen_at`
  on sessions are recorded in memory and written in the background, at most once per
  credential every 30 seconds and on a graceful stop, so concurrent requests with one
  credential no longer queue on its row lock. A use shows in the PAT list, the machine
  token list and My Account → Sessions within about 30 seconds; a server killed without a
  graceful stop loses at most 30 seconds of these stamps; replicas never move the stored
  value backwards. No access decision reads these columns. See `docs/UPGRADING.md` §6h and
  `docs/specs/last-used-coalescing.md`.
