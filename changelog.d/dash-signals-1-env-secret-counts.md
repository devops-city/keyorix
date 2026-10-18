### Added
- **Environment list returns per-environment secret counts.** `GET /api/v1/environments` and `GET /api/v1/projects/{id}/environments` now include `secret_count` (live secrets, folders and soft-deleted secrets excluded), computed in one grouped query. The Secrets tab picks its default environment from it instead of issuing one secrets request per environment.
