### Changed
- Helm chart: the server container now has a startup probe (`/health`, 3 minutes for a first boot) in front of liveness (`/health`) and readiness (`/readyz`), all with explicit period, timeout and failure thresholds instead of fixed initial delays. Tune with `server.probes.{startup,liveness,readiness}`.
