//go:build !(noaws && noazure && nogcp)

package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// The two tests below drive server.http.tls.auto_cert: true through
// initializeCoreService, which the air-gapped profile (-tags
// noaws,noazure,nogcp) refuses with config.ErrAutoCertInAirgapBuild. They
// moved here from server_s27_test.go so they build only where auto_cert is
// allowed; autocert_failclosed_airgap_test.go holds the air-gap counterparts
// (same configs, asserting the refusal) so both profiles stay covered.

// ── startHTTPServer: AutoCert TLS path exercises https scheme + TLSConfig=nil ─

// TestStartHTTPServer_S27_AutoCertTLS exercises the TLS enabled+AutoCert=true
// path in startHTTPServer: createTLSConfig returns nil,nil for AutoCert,
// so server.TLSConfig is set to nil (line 1307) and scheme="https" (line 1318).
// The server goroutine then calls server.ServeTLS which fails immediately
// (no cert in autocert.Manager for 127.0.0.1), so it exits. We use a
// pre-cancelled context so the test completes quickly.
func TestStartHTTPServer_S27_AutoCertTLS(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := autoCertTLSFixtureConfig(itoa(port), "httptest_s27_autocert.db", "s27-autocert-tls.test.invalid")

	coreService := mustInitCoreService(t, cfg)

	// #1475: confirm this fixture's placeholder Domains didn't change what the
	// test actually exercises — AutoCert must still make createTLSConfig return a
	// nil *tls.Config, independent of Domains being set.
	if tlsCfg, err := createTLSConfig(cfg); err != nil || tlsCfg != nil {
		t.Fatalf("createTLSConfig with AutoCert must still return (nil, nil), got (%v, %v)", tlsCfg, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the server exits immediately after <-ctx.Done()

	done := make(chan error, 1)
	go func() { done <- startHTTPServer(ctx, cfg, coreService) }()

	select {
	case err := <-done:
		_ = err // shutdown error is acceptable
	case <-context.Background().Done():
		t.Fatal("startHTTPServer with AutoCert did not return")
	}
}

// ── startHTTPServer: AutoCert TLS with invalid cipher → goroutine error ──────

// TestStartHTTPServer_S27_AutoCertBadCipher exercises the AutoCert TLS serve
// goroutine error path (lines 1331-1334) where buildAutoCertTLSConfig fails
// because AllowedCiphers names an unrecognised cipher suite. The goroutine
// starts, calls buildAutoCertTLSConfig, hits the error, logs it, and returns
// early — never calling ServeTLS. The context timer (200 ms) lets the goroutine
// run before the main body's <-ctx.Done() returns.
func TestStartHTTPServer_S27_AutoCertBadCipher(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := autoCertTLSFixtureConfig("0", "httptest_s27_autocert_badcipher.db", "s27-autocert-badcipher.test.invalid")

	coreService := mustInitCoreService(t, cfg)
	// Validate() refuses an unrecognised cipher name since BOOT-REFUSALS-1 item 8,
	// so the bad name is set after the core service is built: this test exercises
	// the serve goroutine's own (defence-in-depth) cipher check.
	cfg.Server.HTTP.TLS.AllowedCiphers = []string{"INVALID_CIPHER_XYZ_S27"} // not a recognised cipher suite

	// #1475: confirm this fixture's placeholder Domains didn't change what the
	// test actually exercises — the invalid cipher name must still make
	// buildAutoCertTLSConfig fail at cipher-suite resolution.
	if _, err := buildAutoCertTLSConfig(cfg.Server.HTTP.TLS.Domains, cfg.Server.HTTP.TLS, ""); err == nil {
		t.Fatal("buildAutoCertTLSConfig must still fail for an unrecognised cipher suite name")
	} else if !strings.Contains(err.Error(), "invalid TLS configuration") {
		t.Fatalf("expected a cipher-resolution error, got: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	_ = startHTTPServer(ctx, cfg, coreService)
}
