# Request limits

Body size per route class, header size, JSON shape, gRPC message size. See
`docs/security/production-hardening-matrix.md` for the row rules. The request-header cap (64 KiB) and the gRPC metadata cap are connection-level
and listed in `timeouts.md`.

## REST API and web UI (`server.http`)

Every route that can take a body sits behind one global middleware
(`MaxBodyBytesFor(requestBodyLimit(...))`, `server/http/router.go`), which picks the
cap from the route class. A body whose declared `Content-Length` is over the cap is
answered `413 {"success":false,"error":"PayloadTooLarge",...}` before authentication
or any handler runs; a chunked body is cut off at the cap by `http.MaxBytesReader`.

| Control | Where | Setting | Default | Test |
|---|---|---|---|---|
| Every body-taking route refuses a body over its class cap with 413, before auth or handler | `server/middleware/body_limit.go` `MaxBodyBytesFor`, `server/http/body_limits.go` `requestBodyLimit` | per class, below | per class, below | `server/http/body_limit_routes_test.go:TestEveryBodyRoute_RefusesOverItsClassCap`, `server/middleware/body_limit_test.go:TestMaxBodyBytes_DeclaredOversizeRefusedBeforeHandler` |
| Class: API default | `requestBodyLimit` | `server.http.max_request_body_bytes` (negative disables) | 10 MiB | `server/http/body_limit_routes_test.go:TestEveryBodyRoute_RefusesOverItsClassCap` |
| Class: public credential routes `/auth/*`, `/system/init` (not lifted by raising or disabling the default) | `server/http/body_limits.go` | fixed `publicAuthBodyLimit` | 64 KiB | `server/http/body_limit_routes_test.go:TestPublicAuthRoutes_TightBodyCap`, `server/http/body_limit_routes_test.go:TestRequestBodyLimit_ClassCapsSurviveGlobalOverride` |
| Class: SAML ACS `/auth/saml/{provider}/acs` | `server/http/body_limits.go` | fixed `samlACSBodyLimit` | 1 MiB | `server/http/body_limit_routes_test.go:TestPublicAuthRoutes_TightBodyCap` |
| Class: secret-value routes (create, update, rotate) | `server/http/router.go` `secretBodyLimit` | derived from `secrets.limits.max_secret_size` (`config.DeriveMaxRequestBodySize`) | base64(64 KiB) + envelope headroom | `server/http/body_limit_routes_test.go:TestSecretValueRoutes_TighterBodyCapThroughRouter`, `internal/config/max_secret_size_test.go:TestDeriveMaxRequestBodySize_ExactBase64PlusHeadroom` |
| Chunked (undeclared-length) body cut off at the cap | `server/middleware/body_limit.go` `http.MaxBytesReader` | as the class | as the class | `server/middleware/body_limit_test.go:TestMaxBodyBytes_RejectsOversize`, `server/http/handlers/secret_size_cap_test.go:TestCreateSecret_SecretSizeCap_BodyTooLarge_MaxBytesReaderTrips413` |
| JSON nesting depth bounded (encoding/json's 10000 levels, under the byte cap): 4xx, never 5xx | `encoding/json` in every handler decode | fixed | 10000 | `server/http/body_limit_routes_test.go:TestDeeplyNestedJSON_RefusedAsClientError` |
| Bulk-operation array sizes capped in core | `internal/core` `maxBulk*BatchSize` | fixed | 500 | `internal/core/bulk_delete_test.go:TestBulkDeleteSecrets_ExceedsMaxBatchSize`, `internal/core/bulk_access_requests_test.go:TestBulkApproveAccessRequests_TooManyIDs`, `server/http/handlers/secrets_bulk_rotate_test.go:TestBulkRotateSecrets_BatchTooLarge`, `internal/core/bulk_rename_batch_cap_test.go:TestBulkRenameSecrets_ExceedsMaxBatchSize` |
| SCIM group member / patch-operation counts capped (413) | `server/http/handlers/scim_groups.go` | fixed | see handler | `server/http/handlers/scim_adminjobs_hygiene_s16_test.go:TestSCIMGroups_PatchGroup_TooManyOps_S16`, `server/http/handlers/scim_adminjobs_hygiene_s16_test.go:TestSCIMGroups_PatchGroup_TooManyAccumulatedMembers_S16` |
| Real server: 413 JSON on `/auth/login`, `/system/init`, `/api/v1/secrets` | built `keyorix-server`, SQLite | as above | as above | `scripts/e2e/request_limits_test.go:TestRequestLimits_SQLite` |

## gRPC (`server.grpc`)

| Control | Where | Setting | Default | Test |
|---|---|---|---|---|
| Inbound message size (ResourceExhausted before auth) | `server/grpc/server.go` `grpc.MaxRecvMsgSize` | `server.grpc.max_request_body_bytes` | 10 MiB | `server/grpc/server_integration_test.go:TestGRPCServer_HonorsConfiguredMaxRecvMsgSize` |
| Outbound message size | `server/grpc/server.go` `grpc.MaxSendMsgSize` | same key | 10 MiB | `server/grpc/server_integration_test.go:TestGRPCServer_HonorsConfiguredMaxSendMsgSize` |
| Secret value over `max_secret_size` refused (ResourceExhausted) | `internal/core` size check via `services.SecretService` | `secrets.limits.max_secret_size` | 64 KiB | `server/grpc/services/secret_size_cap_test.go:TestSecretService_CreateSecret_SecretSizeCap_OneByteOverRejected`, `server/grpc/services/secret_size_cap_test.go:TestSecretService_UpdateSecret_SecretSizeCap_OneByteOverRejected` |

## Not covered here

- gRPC has one message-size cap per server, not per method, so a secret-value RPC is
  decoded up to `max_request_body_bytes` before core refuses an oversized value; the
  HTTP secret routes refuse it at the wire.
- Array lengths outside the bulk operations and SCIM are bounded only by the byte cap
  of their route class.
