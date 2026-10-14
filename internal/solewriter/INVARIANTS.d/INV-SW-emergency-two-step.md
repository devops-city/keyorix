- **INV-SW-emergency-two-step** `pg_terminate_backend(holder_pid)` opens the fence at once, and the
  server stops answering authoritatively within the lease and never resumes without a restart. Why:
  Andrei 2026-10-15, decision 3. Guard: `TestEmergencyTwoStep` (measured, asserted ≤ lease + one poll),
  `TestSingleWriter_Postgres_OperatorJourney`.
