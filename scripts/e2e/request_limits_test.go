//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestRequestLimits_SQLite drives the request-body caps against a real
// keyorix-server binary (docs/security/production-hardening-matrix.d/request-limits.md):
// a declared-oversize body is answered 413 with the JSON error body before any
// handler runs, on an unauthenticated credential route (64 KiB class) and on an
// API route (server.http.max_request_body_bytes, 10 MiB). The body is never sent:
// the server answers on the headers alone, which is the point.
func TestRequestLimits_SQLite(t *testing.T) {
	serverBin, _ := harness.BuildBinaries(t)
	srv := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite", NoMFAReason: "no login needed: every request here is refused before authentication"})
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.BaseURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path     string
		declared int64
	}{
		{"/auth/login", 64<<10 + 1},
		{"/system/init", 64<<10 + 1},
		{"/api/v1/secrets", 10<<20 + 1},
	} {
		status, body := postHeadersOnly(t, u.Host, tc.path, tc.declared)
		if status != http.StatusRequestEntityTooLarge {
			t.Errorf("POST %s declaring %d bytes: status %d, want 413 (body %q)", tc.path, tc.declared, status, body)
			continue
		}
		var e struct {
			Error string `json:"error"`
			Code  int    `json:"code"`
		}
		if err := json.Unmarshal([]byte(body), &e); err != nil || e.Error != "PayloadTooLarge" || e.Code != 413 {
			t.Errorf("POST %s: 413 body %q is not the JSON error shape", tc.path, body)
		}
	}
}

// postHeadersOnly sends a POST whose headers declare n body bytes and no body,
// and returns the response the server sends anyway.
func postHeadersOnly(t *testing.T, host, path string, n int64) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", path, host, n)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("POST %s: reading response: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var sb strings.Builder
	_, _ = bufio.NewReader(resp.Body).WriteTo(&sb)
	return resp.StatusCode, strings.TrimSpace(sb.String())
}
