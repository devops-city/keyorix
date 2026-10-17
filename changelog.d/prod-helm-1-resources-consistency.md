### Changed
- Helm chart: the built-in fallback resources of the server and web containers (used when `server.resources` / `web.resources` are unset) now equal the `values.yaml` defaults, ephemeral-storage limits included, so GOMEMLIMIT and pod sizing no longer depend on how the chart was installed.
