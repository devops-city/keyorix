package main

import (
	"net/http"
	"testing"
	"time"
)

// TestNewHealthServer_AllTimeoutsSet: the probe/metrics listener sets every
// connection-level bound (a zero value means unlimited in net/http), not only
// ReadHeaderTimeout.
func TestNewHealthServer_AllTimeoutsSet(t *testing.T) {
	srv := newHealthServer(":0", http.NotFoundHandler())
	for name, d := range map[string]time.Duration{
		"ReadHeaderTimeout": srv.ReadHeaderTimeout,
		"ReadTimeout":       srv.ReadTimeout,
		"WriteTimeout":      srv.WriteTimeout,
		"IdleTimeout":       srv.IdleTimeout,
	} {
		if d <= 0 {
			t.Errorf("%s unset: a probe client could hold the connection indefinitely", name)
		}
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 64<<10 {
		t.Errorf("MaxHeaderBytes = %d, want a cap of at most 64 KiB (0 means net/http's 1 MiB)", srv.MaxHeaderBytes)
	}
}
