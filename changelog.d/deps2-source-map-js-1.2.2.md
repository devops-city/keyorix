### Security
- **source-map-js pinned to 1.2.2 in `web/`** (GHSA-68fv-2mgg-jv7q, Dependabot #25). The web build and test toolchain (postcss, tailwind, jsdom) pulled 1.2.1 transitively; `web/pnpm-workspace.yaml` now overrides it to 1.2.2. Dev/build-time dependency only, not shipped in the web bundle.
