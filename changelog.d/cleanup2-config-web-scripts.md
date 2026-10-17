### Changed

- Helm chart: `postgresql.auth.password` no longer ships an empty placeholder in `values.yaml` (CodeQL js/empty-password-in-configuration-file); the key is documented in a comment and the render still fails when no database password is supplied.
