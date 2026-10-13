### Testing
- **Real-backend web smoke now runs in the merge queue.** `web-e2e-real-smoke` and its two shards ran on `pull_request` only, so a web spec broken by a PR-vs-main interaction (#3080) reached main unnoticed. They now also run on `merge_group` (docs-only and operator-only groups still skip). Neither job is a required check, so the queue is not stalled by them.
