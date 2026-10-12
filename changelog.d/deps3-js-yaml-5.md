### Internal
- **web: js-yaml 4 -> 5.** `web/scripts/check-api-contract.mjs` now uses the named `load` export (v5 has no default export). `load` keeps its safe default schema (no `!!js/*` tags); the OpenAPI spec uses no merge keys, timestamps or binary tags, so parsing is unchanged.
