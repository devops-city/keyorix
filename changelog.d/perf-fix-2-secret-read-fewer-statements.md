### Changed
- **Fewer database round trips on the machine-token secret read path.** The statement that confirms the
  cached secret now also returns the machine's roles at its scope and, for a value read, the schedule and
  version state, so the permission and schedule/version reads no longer run as separate statements.
  Authorization decisions, per-request freshness (a revoked role is seen on the next request) and the
  per-read check that the cache trigger is present are unchanged.
