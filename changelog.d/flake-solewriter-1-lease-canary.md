### Fixed
- **single_writer canary no longer counts the server's own write as unattributed.** The poller read the write tracker's commit count after the poll's answer, while the epoch it compares is as of the statement's snapshot; a commit landing in between could raise a false "epoch moved without a write" alarm, and a second one left the authoritative state until restart (fail closed, caches stopped working). The tracker is now read before the poll is sent. Guard: `TestPoll_CanaryCountsACommitInThePollThatSeesItsMove`.

### Testing
- **`TestLease_AnchoredAtPollSend` no longer depends on a wall-clock window.** It holds the lock until released and checks the anchor with an injected clock moved during the poll's lock wait (it flaked in the merge queue on loaded runners).
