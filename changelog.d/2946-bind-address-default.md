### Security
- **BREAKING: the HTTP and gRPC listeners now bind `127.0.0.1` by default (#2939).** `server.http.host` / `server.grpc.host` select the bind address; when omitted the server listens on loopback only instead of every interface. **Upgrade note:** installs with their own `keyorix.yaml` (or a mounted container config) and no `host:` line that are reached from another machine, a remote reverse proxy or a published container port must add `host: "0.0.0.0"` (or a specific interface address) under `server.http` / `server.grpc`. The shipped docker-compose config, Helm chart, DAST stack config and demo `up.sh` set it explicitly; `server/config/production.yaml` and `server/config/web-enabled.yaml` carry a commented `host:` line. See `docs/UPGRADING.md` §6a.

### Fixed
- **Demo `up.sh` fails loudly and heals old volumes.** The `host: "0.0.0.0"` insert now runs on every start (so demo volumes created before the default changed work again), is verified after the sed, and aborts with a clear message if it did not land; `up.sh` also reports a container that exits during startup instead of timing out silently.
- **DAST stack reachable again.** `scripts/dast/keyorix-dast.yaml` sets `server.http.host: "0.0.0.0"` so the scanner containers reach `keyorix:8080` over the compose network.

### Internal
- Removed the now-unused `resolveOutboundIP` helper from `server/main.go` and its test.
