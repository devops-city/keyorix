### Testing
- **Server-presence polling no longer refuses the server it waits for.** The `server` admin integration tests' `waitForPresence` probed with `serverguard.ProbeRunning`, which takes the presence lock exclusively; on Postgres a probe landing on a starting server's shared try-lock made the server exit with "an admin operation is running", so `TestServerStartup_RefusedWhileAdminHoldsExclusiveLock_Postgres` failed intermittently in the merge queue. On Postgres the poll now reads `pg_locks` and takes no lock; `TestWaitForPresence_Postgres_NeverRefusesAStartingServer` pins it (the old poll refused 116 of 8112 simulated starts).

### Internal
- **faultops CI legs get the 3300 s per-binary timeout the core legs already have.** faultops-2 ran p90 27.9 min against a 30 min timeout and timed out in 3 merge-group runs on Oct 18–20; rebalancing the two shards is still open.
