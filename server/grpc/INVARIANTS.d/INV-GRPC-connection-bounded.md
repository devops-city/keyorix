- **INV-GRPC-connection-bounded** Every gRPC connection is bounded in time and size
  regardless of who holds it: the handshake (TLS + HTTP/2 preface) must finish within
  `keepalive.handshake_timeout`, a connection with no RPC in flight is closed after
  `keepalive.max_connection_idle`, every connection is recycled after
  `max_connection_age`, and the server advertises MAX_CONCURRENT_STREAMS and
  MAX_HEADER_LIST_SIZE. None of these can be configured off (0 or a negative value
  falls back to the default). Why: HARDEN-HTTP-1: grpc-go's defaults are 120s, never,
  unlimited and 16 MiB, so one client could hold silent connections, park idle ones
  past keepalive pings, or open any number of RPCs on one connection. Guard:
  `connection_limits_test.go` (`TestNewServer_HandshakeTimeoutClosesSilentConnection`,
  `TestNewServer_MaxConnectionIdleReclaimsIdleConnection`,
  `TestNewServer_AdvertisesStreamAndHeaderLimits` reads the SETTINGS frame off the wire,
  `TestGRPCConnectionLimitDefaults`).
