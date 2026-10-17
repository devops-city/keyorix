- **INV-CORE-anomaly-pass-records-same-alerts-once-per-key** A detection pass sends one
  `CreateAnomalyAlert` per per-access alert key (secret, type, actor, IP) that succeeded,
  not one per access row, and records exactly the alert rows (and reports exactly the
  failures) a pass that sends every access row's alerts would. It holds because every
  per-access and ML alert of a pass is stamped with the pass's `now`, so they share
  `CreateAnomalyAlert`'s dedup cutoff: once a call for a key succeeded, an equivalent alert
  newer than that cutoff exists and every later call would insert nothing. A failed call
  does not settle its key (the next alert with that key is tried, as before). Why:
  OPT-READPATH-1, the dedup `count(*) FROM anomaly_alerts` ran once per read of the
  window under a steady read load.
  Guard: `anomaly_dedup_once_test.go` `TestRunDetection_DedupOnceEquivalence` (both modes
  over a matrix of principals, IPs, baselines, suppressing and expired pre-existing alerts
  and injected first-call failures), `TestRunDetection_OneDedupCheckPerAlertKey` (count).
  **Not covered**: alert rows deleted by something else during a pass (retention purges
  only rows older than days).
