### Fixed

- The HTTP access log now follows `log.SetOutput`/`SetPrefix`/`SetFlags` at write time instead of snapshotting them when the router is built (regression from #3231). This also restores the canary log-leak fuzzers' view of access-log lines.
