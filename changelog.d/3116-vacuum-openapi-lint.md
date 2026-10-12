### Changed
- **OpenAPI lint uses vacuum instead of Spectral.** CI's `openapi-lint` job now runs vacuum (pinned in `devtools/vacuum/go.mod`, checksum-verified via `go.sum`, ruleset in `.vacuum.yaml`) and `@stoplight/spectral-cli` is removed from the root `package.json`, dropping a CI dependency whose `braces` dependency has an unfixed advisory (GHSA-vfj7-8cjw-p6xm). A canary spec guards against an inert ruleset. `make openapi-lint` runs it locally.

### Fixed
- **`GET /api/v1/audit/search` `success` parameter is a string enum.** The spec declared `enum: [true, false]` (YAML booleans) on a `type: string` parameter, which generated the TypeScript type `true | false`; it is now `"true" | "false"`. The server already parsed the query string, so behaviour is unchanged.
