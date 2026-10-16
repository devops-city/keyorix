# Production-hardening matrix (network-facing surface)

What keyorix-server enforces on its network listeners, where, with which setting and
default, and the test that proves it. Scope: the REST API and web UI listener
(`server.http`), the gRPC listener (`server.grpc`), and the `keyorix-k8s-sync`
probe listener.

The rows live in one file per theme under
[`production-hardening-matrix.d/`](production-hardening-matrix.d/) (timeouts and
connection limits, request limits, rate limiting, response hygiene, TLS), so two
changes to different themes never edit the same file. Every `*.md` file in that
directory is part of the matrix; there is no index to keep in step.

## Rules for a row

- Columns: **Control**, **Where** (file or function), **Setting** (config key, or
  `fixed` for a constant), **Default**, **Test**.
- The **Test** cell names at least one test as `` `path/to/file_test.go:TestName` ``,
  repo-relative. A row without one is not a row: if a control cannot be tested, it
  does not belong in this matrix, it belongs in the threat model as a residual.
- `server/hardening_matrix_test.go:TestHardeningMatrixRowsNameExistingTests` parses
  every fragment and fails when a row names no test, or names a file or a `func
  TestName(` that does not exist. It checks existence only; CI's normal `go test`
  run is what makes each named test pass.
- Checks that need containers or a browser (Helm/kind, Playwright against a real
  server) are marked `pending e2e VM` in a **Note** after the table, never in place
  of a test.
