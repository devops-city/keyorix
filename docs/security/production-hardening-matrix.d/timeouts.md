# Timeouts and connection limits

Slowloris, slow-body, idle-connection and stream exhaustion on every listener.
See [`../production-hardening-matrix.md`](../production-hardening-matrix.md) for the
row rules.

## REST API and web UI listener (`server.http`)

| Control | Where | Setting | Default | Test |
|---|---|---|---|---|
| Request headers must arrive within a deadline (slowloris) | `server/http_server.go` `newHTTPServer` | fixed `httpReadHeaderTimeout` | 10s | `server/http_server_test.go:TestNewHTTPServer_Timeouts` |
| Whole request (headers + body) read deadline (slow body) | `server/http_server.go` `newHTTPServer` | fixed `httpReadTimeout` | 15s | `server/http_server_test.go:TestNewHTTPServer_Timeouts` |
| Response write deadline, longer than the handler deadline so the 504 is delivered | `server/http_server.go` `newHTTPServer` | fixed `httpWriteTimeout` | 75s (`RequestTimeout` + 15s) | `server/http_server_test.go:TestNewHTTPServer_Timeouts` |
| Idle keep-alive connections reclaimed | `server/http_server.go` `newHTTPServer` | fixed `httpIdleTimeout` | 60s | `server/http_server_test.go:TestNewHTTPServer_Timeouts` |
| Request line + headers capped (431 before any handler) | `server/http_server.go` `newHTTPServer` | fixed `httpMaxHeaderBytes` | 64 KiB (net/http default 1 MiB) | `server/http_server_test.go:TestNewHTTPServer_MaxHeaderBytes` |
| Per-request handler deadline (504) | `server/http/router.go` `middleware.Timeout(RequestTimeout)` | fixed `RequestTimeout` (`server/http/timeouts.go`) | 60s | `server/http/request_timeout_wiring_test.go:TestRouterAppliesRequestTimeout` |
| Graceful shutdown bounded | `server/main.go` `startHTTPServer` | fixed | 10s | `server/server_s4_test.go:TestStartHTTPServer_CancelledContext` |

## gRPC listener (`server.grpc`)

| Control | Where | Setting | Default | Test |
|---|---|---|---|---|
| TLS handshake + HTTP/2 preface deadline (silent-connection hold) | `server/grpc/server.go` `grpc.ConnectionTimeout` | `server.grpc.keepalive.handshake_timeout` | 10s (grpc-go default 120s) | `server/grpc/connection_limits_test.go:TestNewServer_HandshakeTimeoutClosesSilentConnection`, `server/grpc/connection_limits_test.go:TestGRPCConnectionLimitDefaults` |
| Connection with no RPC in flight closed | `server/grpc/server.go` `keepalive.ServerParameters.MaxConnectionIdle` | `server.grpc.keepalive.max_connection_idle` | 15m (grpc-go default: never) | `server/grpc/connection_limits_test.go:TestNewServer_MaxConnectionIdleReclaimsIdleConnection`, `server/grpc/connection_limits_test.go:TestGRPCConnectionLimitDefaults` |
| Dead peers detected by keepalive ping | `server/grpc/server.go` `keepalive.ServerParameters.Time/Timeout` | `server.grpc.keepalive.time`, `.timeout` | 5m, 20s | `server/grpc/server_integration_test.go:TestGRPCServer_KeepaliveReclaimsAbandonedConnection`, `internal/config/grpc_keepalive_config_test.go:TestGRPCKeepaliveConfig_GetTime` |
| Connections recycled (re-handshake re-evaluates revoked credentials) | `server/grpc/server.go` `MaxConnectionAge/Grace` | `server.grpc.keepalive.max_connection_age`, `_grace` | 1h, 30s | `internal/config/grpc_keepalive_config_test.go:TestGRPCKeepaliveConfig_GetMaxConnectionAge`, `server/grpc/connection_limits_test.go:TestGRPCConnectionLimitDefaults` |
| Client ping flood rejected (GOAWAY ENHANCE_YOUR_CALM) | `server/grpc/server.go` `keepalive.EnforcementPolicy` | `server.grpc.keepalive.min_time`, `.permit_without_stream` | 5m, false | `internal/config/grpc_keepalive_config_test.go:TestGRPCKeepaliveConfig_GetMinTime` |
| In-flight RPCs per connection capped | `server/grpc/server.go` `grpc.MaxConcurrentStreams` | fixed `grpcMaxConcurrentStreams` | 128 (grpc-go default: unlimited) | `server/grpc/connection_limits_test.go:TestNewServer_AdvertisesStreamAndHeaderLimits` |
| Request metadata (HTTP/2 header list) capped | `server/grpc/server.go` `grpc.MaxHeaderListSize` | fixed `grpcMaxHeaderListSize` | 64 KiB (grpc-go default 16 MiB) | `server/grpc/connection_limits_test.go:TestNewServer_AdvertisesStreamAndHeaderLimits` |
| Unary RPC deadline (streams exempt: StreamAuditLogs is long-lived) | `server/grpc/interceptors/timeout.go` `TimeoutInterceptor` | fixed `grpcUnaryTimeout` | 60s | `server/grpc/interceptors/timeout_test.go:TestTimeoutInterceptor_CapsSlowHandler` |
| Graceful stop bounded, then forced | `server/main.go` `stopGRPCServerWithTimeout` | fixed | 10s | `server/server_s28_test.go:TestStopGRPCServerWithTimeout_S28_FallsBackOnTimeout` |

## `keyorix-k8s-sync` probe and metrics listener

| Control | Where | Setting | Default | Test |
|---|---|---|---|---|
| Header, read, write and idle deadlines; header size cap | `cmd/keyorix-k8s-sync/main.go` `newHealthServer` | fixed | 5s / 10s / 10s / 60s; 16 KiB | `cmd/keyorix-k8s-sync/health_server_test.go:TestNewHealthServer_AllTimeoutsSet` |

## Not covered here

- The Kubernetes operator (`operator/`, separate module) serves only the
  controller-runtime manager's probe and metrics endpoints; their limits are
  controller-runtime's.
- A reverse proxy or ingress in front of keyorix-server should set its own, tighter
  client timeouts; these are the server's floor, not a substitute.
