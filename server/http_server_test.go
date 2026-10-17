package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	httpServer "github.com/keyorixhq/keyorix/server/http"
)

// TestNewHTTPServer_Timeouts pins the REST/web listener's connection-level
// timeouts: every one is set (a zero value means "no limit" in net/http), the
// header deadline is no longer than the whole-request deadline, and the write
// deadline outlives the router's per-request handler deadline so a timed-out
// handler's 504 reaches the client instead of a reset connection.
func TestNewHTTPServer_Timeouts(t *testing.T) {
	srv := newHTTPServer("127.0.0.1:0", http.NotFoundHandler())

	for name, d := range map[string]time.Duration{
		"ReadHeaderTimeout": srv.ReadHeaderTimeout,
		"ReadTimeout":       srv.ReadTimeout,
		"WriteTimeout":      srv.WriteTimeout,
		"IdleTimeout":       srv.IdleTimeout,
	} {
		if d <= 0 {
			t.Errorf("%s = %v: unset means unlimited (slowloris / idle-connection exhaustion)", name, d)
		}
	}
	if srv.ReadHeaderTimeout > srv.ReadTimeout {
		t.Errorf("ReadHeaderTimeout %v > ReadTimeout %v", srv.ReadHeaderTimeout, srv.ReadTimeout)
	}
	if srv.WriteTimeout <= httpServer.RequestTimeout {
		t.Errorf("WriteTimeout %v must exceed the handler deadline httpServer.RequestTimeout %v, "+
			"or a timed-out request ends in a reset connection instead of a 504",
			srv.WriteTimeout, httpServer.RequestTimeout)
	}
	if srv.ReadHeaderTimeout > 10*time.Second {
		t.Errorf("ReadHeaderTimeout %v: headers must arrive within 10s", srv.ReadHeaderTimeout)
	}
	if srv.IdleTimeout > 2*time.Minute {
		t.Errorf("IdleTimeout %v: idle keep-alive connections must be reclaimed within 2m", srv.IdleTimeout)
	}
}

// TestNewHTTPServer_MaxHeaderBytes drives a real listener built by newHTTPServer:
// a request whose headers exceed httpMaxHeaderBytes is refused with 431 before
// any handler runs, and one just under it is served. net/http's default
// (MaxHeaderBytes 0 = 1 MiB) accepts the oversized request.
func TestNewHTTPServer_MaxHeaderBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reached := make(chan struct{}, 4)
	srv := newHTTPServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	send := func(headerValueLen int) int {
		t.Helper()
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: x\r\nX-Pad: %s\r\nConnection: close\r\n\r\n",
			strings.Repeat("a", headerValueLen))
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if got := send(httpMaxHeaderBytes / 2); got != http.StatusNoContent {
		t.Fatalf("headers under the cap: status %d, want 204", got)
	}
	<-reached
	// Well past the cap plus net/http's 4 KiB slack, still far under the 1 MiB default.
	if got := send(httpMaxHeaderBytes * 2); got != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("headers over httpMaxHeaderBytes (%d): status %d, want 431", httpMaxHeaderBytes, got)
	}
	select {
	case <-reached:
		t.Fatal("handler ran for a request whose headers exceed the cap")
	default:
	}
}
