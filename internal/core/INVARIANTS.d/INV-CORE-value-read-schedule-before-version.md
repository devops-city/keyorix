- **INV-CORE-value-read-schedule-before-version** A latest-version value read
  (`getSecretValueForUser`: `GetSecretValue`, `GetSecretValueResolved`,
  `GetSecretValueWithPermissionCheck`) gets the access schedule and the latest version from
  one storage call (`GetSecretScheduleAndLatestVersion`), but judges them in the old order:
  the schedule is still the LAST step of the one guard bundle (`enforceSecretReadGuardsWith`,
  after clock regression, expiry, suspended and the classification gate), a failure of the
  shared read surfaces as the schedule-read error, and the version result (and its
  `ErrorVersionNotFound` error) is looked at only after every guard passed. Why: PERF-FIX-4
  (collapse C5); the plan's C8 forbids changing which error fires first.
  Guard: `server/http` `TestValueReadScheduleVersion_Equivalence` (incl. "outside window AND
  no versions: the schedule denial fires first"; outcomes recorded on the code before the
  change), `_CrossReplica`, `_ConcurrentVersionWrites`, `_OneStatement`.
