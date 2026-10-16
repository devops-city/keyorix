package main

import (
	"net/http"
	"time"

	httpServer "github.com/keyorixhq/keyorix/server/http"
)

// Connection-level limits of the REST/web listener. They are fixed, not configurable:
// every value is a ceiling on a misbehaving or hostile client, and none of them
// constrains a well-behaved one (docs/security/production-hardening-matrix.d/).
const (
	// httpReadHeaderTimeout bounds how long a client may take to send its request
	// headers (gosec G112, slowloris: a client that dribbles headers one byte at a
	// time otherwise holds the connection and its goroutine open indefinitely).
	httpReadHeaderTimeout = 10 * time.Second
	// httpReadTimeout bounds reading the whole request, headers plus body, so a
	// slow-body upload cannot hold the connection either.
	httpReadTimeout = 15 * time.Second
	// httpWriteTimeout bounds writing the response. It must be longer than the
	// router's per-request handler deadline (httpServer.RequestTimeout): with the two
	// equal, the write deadline expires as the handler times out and the client sees
	// a reset connection instead of the 504.
	httpWriteTimeout = httpServer.RequestTimeout + 15*time.Second
	// httpIdleTimeout closes a keep-alive connection with no request in flight, so
	// idle connections cannot pile up until the process runs out of descriptors.
	httpIdleTimeout = 60 * time.Second
	// httpMaxHeaderBytes caps the request line plus headers. net/http's default is
	// 1 MiB; the largest legitimate header set (a session cookie, a CSRF cookie and
	// header, a bearer token) is a few KiB.
	httpMaxHeaderBytes = 64 << 10
)

// newHTTPServer builds the http.Server for the REST API and web UI with the
// connection-level limits above. TLS is configured by the caller.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}
