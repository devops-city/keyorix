package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
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

// errHTTPServerFailedToStart wraps every error startHTTPServer can return
// BEFORE it ever starts serving (router construction, TLS config, listener
// bind) — as opposed to server.Shutdown()'s own error return at the very
// bottom of the function, which only happens during an already-intentional
// shutdown. main()'s caller uses errors.Is against this to fail the process
// fatally on a genuine startup failure while leaving a slow-shutdown timeout
// logged only, as before (RELEASE-QA finding: a bind failure like "address
// already in use" left the process running indefinitely with nothing bound,
// since the only caller just log.Printf'd a non-nil return and fell through
// to waiting on a shutdown signal that would never come).
var errHTTPServerFailedToStart = errors.New("HTTP server failed to start")

func startHTTPServer(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) error { // NOSONAR -- cognitive complexity 188, suppress go:S3776
	// Create HTTP router
	router, err := httpServer.NewRouter(cfg, coreService)
	if err != nil {
		return fmt.Errorf("%w: failed to create HTTP router: %v", errHTTPServerFailedToStart, err)
	}

	server := newHTTPServer(cfg.Server.HTTP.ListenAddr(), router)

	// Configure TLS if enabled
	if cfg.Server.HTTP.TLS.Enabled {
		tlsConfig, err := createTLSConfig(cfg)
		if err != nil {
			return fmt.Errorf("%w: failed to create TLS config: %v", errHTTPServerFailedToStart, err)
		}
		server.TLSConfig = tlsConfig
	}

	// Bind the listener early so we can confirm the address before serving.
	ln, err := bindListener(cfg.Server.HTTP)
	if err != nil {
		return fmt.Errorf("%w: failed to bind HTTP listener: %v", errHTTPServerFailedToStart, err)
	}

	scheme := "http"
	if cfg.Server.HTTP.TLS.Enabled {
		scheme = "https"
	}
	log.Printf("HTTP server listening on %s://%s%s", scheme, ln.Addr().String(), bindScopeNote(cfg.Server.HTTP.BindHost()))

	// Start server
	go func() {
		var serveErr error
		if cfg.Server.HTTP.TLS.Enabled {
			if cfg.Server.HTTP.TLS.AutoCert {
				// checkTransportTLSPosture already validated tls.allowed_ciphers at boot,
				// so this should never fail in practice; handled defensively anyway.
				autoCertTLSConfig, err := buildAutoCertTLSConfig(cfg.Server.HTTP.TLS.Domains, cfg.Server.HTTP.TLS, cfg.Server.HTTP.TLSMode)
				if err != nil {
					log.Printf("HTTP server error: %v", err)
					return
				}
				server.TLSConfig = autoCertTLSConfig
				serveErr = server.ServeTLS(ln, "", "")
			} else {
				// Empty file names: the certificate comes from TLSConfig.GetCertificate
				// (tlsreload). Passing the files here would pin the pair loaded now.
				serveErr = server.ServeTLS(ln, "", "")
			}
		} else {
			serveErr = server.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", serveErr)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // NOSONAR
	defer cancel()

	log.Println("Shutting down HTTP server...")
	return server.Shutdown(shutdownCtx)
}
