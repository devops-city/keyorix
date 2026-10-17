package http

import "time"

// RequestTimeout is the per-request handler deadline the router applies to every
// route (chi middleware.Timeout): when it fires, the handler's context is cancelled
// and the client gets 504. It matches the gRPC unary timeout
// (server/grpc's grpcUnaryTimeout) so both transports bound a hung handler the same.
//
// keyorix-server's http.Server WriteTimeout must be strictly longer than this, or the
// connection's write deadline expires at the same instant the handler times out and
// the client sees a reset connection instead of the 504
// (server/main.go newHTTPServer, TestNewHTTPServer_Timeouts).
const RequestTimeout = 60 * time.Second
