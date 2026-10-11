package main

import (
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// #2939: the HTTP and gRPC listeners used to bind ":port" (every interface)
// while the startup log claimed 127.0.0.1. The listener must bind the
// configured host, and loopback when none is configured.

func TestBindListener_DefaultIsLoopbackOnly(t *testing.T) {
	for name, inst := range map[string]config.ServerInstanceConfig{
		"http": {Enabled: true, Port: "0"},
		"grpc": {Enabled: true, Port: "0"},
	} {
		t.Run(name, func(t *testing.T) {
			ln, err := bindListener(inst)
			if err != nil {
				t.Fatalf("bindListener: %v", err)
			}
			defer func() { _ = ln.Close() }()
			addr := ln.Addr().(*net.TCPAddr)
			if !addr.IP.IsLoopback() {
				t.Fatalf("default listener bound %s; want a loopback address only", addr)
			}
			if addr.IP.IsUnspecified() {
				t.Fatalf("default listener bound all interfaces: %s", addr)
			}
		})
	}
}

func TestBindListener_HonoursConfiguredHost(t *testing.T) {
	ln, err := bindListener(config.ServerInstanceConfig{Host: "0.0.0.0", Port: "0"})
	if err != nil {
		t.Fatalf("bindListener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if !ln.Addr().(*net.TCPAddr).IP.IsUnspecified() {
		t.Fatalf("host 0.0.0.0 bound %s; want all interfaces", ln.Addr())
	}
}

func TestBindListener_LoggedAddressIsTheBoundAddress(t *testing.T) {
	inst := config.ServerInstanceConfig{Port: "0"}
	ln, err := bindListener(inst)
	if err != nil {
		t.Fatalf("bindListener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if host != inst.BindHost() {
		t.Fatalf("bound host %q != configured/logged host %q", host, inst.BindHost())
	}
}

func TestBindScopeNote(t *testing.T) {
	for host, wantWarn := range map[string]bool{
		"127.0.0.1": false, "::1": false, "localhost": false,
		"0.0.0.0": true, "::": true, "192.168.1.5": true,
	} {
		if got := bindScopeNote(host) != ""; got != wantWarn {
			t.Errorf("bindScopeNote(%q) warns=%v, want %v", host, got, wantWarn)
		}
	}
}

// TestNoWildcardListenInServerMain is the family guard: every listener in
// server/main.go goes through bindListener, so a new `net.Listen("tcp", ":%s")`
// (all interfaces, silently) cannot come back.
func TestNoWildcardListenInServerMain(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	calls := regexp.MustCompile(`net\.Listen\(`).FindAllIndex(src, -1)
	if len(calls) != 1 {
		t.Fatalf("server/main.go has %d net.Listen calls; want exactly 1 (inside bindListener)", len(calls))
	}
	if !strings.Contains(string(src), "func bindListener(") {
		t.Fatal("bindListener missing")
	}
	if regexp.MustCompile(`Addr:\s+fmt\.Sprintf\(":%s"`).Match(src) {
		t.Fatal(`server/main.go builds a wildcard ":port" address`)
	}
}

func TestConfigRejectsNonIPBindHost(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.HTTP = config.ServerInstanceConfig{Enabled: true, Port: "8080", Host: "not an ip"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "server.http.host") {
		t.Fatalf("Validate() = %v, want a server.http.host error", err)
	}
}
