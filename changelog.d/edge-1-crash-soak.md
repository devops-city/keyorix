### Testing
- **Edge crash soak.** `scripts/edge/crash-soak.sh` and `server/edge_crash_soak_integration_test.go` run the built server on SQLite under mixed writes, `kill -9` it at random points (including during start-up), restart it unattended, and check that it recovers with no manual step, no acknowledged write is lost, `admin verify-audit` stays valid and every acknowledged value disclosure has its audit row. It also reports that the audit row of an acknowledged create/update/delete can be missing after a crash (written after the commit); `--strict-mutation-audit` turns that into a failure.

### Documentation
- **Edge guide: crash testing.** `docs/edge-deployment.md` §4 says what the soak covers (process crash, not a power cut) and states the mutation-audit gap.
