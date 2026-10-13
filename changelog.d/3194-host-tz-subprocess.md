### Testing
- **Host-TZ backup/restore tests no longer write `time.Local`.** The SQLite and Postgres
  `RoundTripAcrossHostTZ` tests now run each zone in a subprocess of the test binary started with
  `TZ=<zone>`, and the `backupfmt` codec test passes zone-located times explicitly. Assigning the
  `time.Local` global raced with timer goroutines (`-race` failure that removed #3168 from the merge
  queue). `TestNoTestAssignsTimeLocal` fails if any `_test.go` assigns it again.
