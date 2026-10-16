### Added
- **Edge service definitions.** `deploy/edge/keyorix-server.service` (systemd) and `deploy/edge/io.keyorix.server.plist` (launchd) start the server at boot, restart it after any exit, wait for the data volume, run it unprivileged and pass the master passphrase as a credential file instead of through the environment. `deploy/edge/edge_units_test.go` runs the unit's real `ExecStart` against the built server, kills it and starts it again, and pins the directives an unattended device needs.

### Testing
- **Stuck-state tests for unattended devices.** `server/edge_unattended_integration_test.go` drives the built binary through stale (and corrupted) lock files after `kill -9`, `admin migrate` and server start-up killed mid-migration at random points, and a full data volume then freed (writes and value reads fail with an error, nothing acknowledged is lost, restart recovers).

### Documentation
- **Edge guide: unattended operation.** New §7a in `docs/edge-deployment.md`: start at boot, what each stuck state does, and what an operator must still monitor.
