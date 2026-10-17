package apiclient

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDescribeTransportError(t *testing.T) {
	uerr := func(raw string, inner error) error {
		return &url.Error{Op: "Get", URL: raw, Err: inner}
	}
	cases := []struct {
		name string
		err  error
		want []string // all must appear
	}{
		{"connection refused",
			uerr("http://127.0.0.1:1/api/v1/version", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}),
			[]string{"cannot reach the Keyorix server at http://127.0.0.1:1", "connection refused", "Next step"}},
		{"dns",
			uerr("https://nope.invalid/health", &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}}),
			[]string{"cannot resolve the host name", "https://nope.invalid", "keyorix status"}},
		{"private CA",
			uerr("https://kx.internal/health", x509.UnknownAuthorityError{}),
			[]string{"cannot trust the TLS certificate", "--ca-file", "kx.internal"}},
		{"wrong host in certificate",
			uerr("https://10.0.0.5/health", x509.HostnameError{Host: "10.0.0.5", Certificate: &x509.Certificate{}}),
			[]string{"cannot trust the TLS certificate", "--ca-file"}},
		{"https to a plain http server",
			uerr("https://127.0.0.1:8080/health", errors.New("http: server gave HTTP response to HTTPS client")),
			[]string{"plain HTTP", "http:// URL"}},
		{"timeout",
			uerr("http://slow.example/health", context.DeadlineExceeded),
			[]string{"timed out", "Next step"}},
		{"redirect refused",
			uerr("http://old.example/health", errors.New(`keyorix: refusing to follow redirect to "https://new.example/health"`)),
			[]string{"does not follow redirects", "keyorix login --server"}},
		{"connection closed",
			uerr("http://x.example/health", io.EOF),
			[]string{"cannot reach", "EOF"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Wrapped the way the commands wrap it.
			wrapped := errors.Join(errors.New("ignored"), c.err)
			got, ok := DescribeTransportError(wrapped)
			if !ok {
				t.Fatalf("not recognised as a transport error: %v", c.err)
			}
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("message %q lacks %q", got, w)
				}
			}
			if strings.Contains(got, "dial tcp") || strings.Contains(got, "&{") {
				t.Errorf("message leaks Go error internals: %q", got)
			}
		})
	}

	for _, plain := range []error{nil, errors.New("something else"), ErrResponseTooLarge,
		&url.Error{Op: "Get", URL: "http://x/", Err: errors.New("some unrelated failure")}} {
		if msg, ok := DescribeTransportError(plain); ok {
			t.Errorf("DescribeTransportError(%v) = %q, want not recognised", plain, msg)
		}
	}
}

// The classification must hold for the errors the real hardened client returns, not only
// for hand-built ones.
func TestDescribeTransportError_RealClient(t *testing.T) {
	// A listener that is closed straight away: nothing accepts the connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	_, err = NewHardenedHTTPClient().Get("http://" + addr + "/health")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	msg, ok := DescribeTransportError(err)
	if !ok || !strings.Contains(msg, "connection refused") || !strings.Contains(msg, "http://"+addr) {
		t.Fatalf("real refused connection: ok=%v msg=%q err=%v", ok, msg, err)
	}

	// An https URL against a plain-HTTP server.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c := NewHardenedHTTPClient()
	c.Timeout = 5 * time.Second
	_, err = c.Get("https://" + strings.TrimPrefix(srv.URL, "http://") + "/health")
	if err == nil {
		t.Fatal("expected a TLS error")
	}
	if msg, ok := DescribeTransportError(err); !ok || !strings.Contains(msg, "plain HTTP") {
		t.Fatalf("https against http: ok=%v msg=%q err=%v", ok, msg, err)
	}

	// A TLS server whose certificate the client does not trust.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsSrv.Close()
	_, err = NewHardenedHTTPClient().Get(tlsSrv.URL + "/health")
	if err == nil {
		t.Fatal("expected a certificate error")
	}
	if msg, ok := DescribeTransportError(err); !ok || !strings.Contains(msg, "--ca-file") {
		t.Fatalf("untrusted certificate: ok=%v msg=%q err=%v", ok, msg, err)
	}
}
