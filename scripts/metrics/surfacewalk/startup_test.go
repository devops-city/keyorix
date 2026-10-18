package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as a fake server: when SURFACEWALK_FAKE_SERVER is set the
// test binary serves /health on that address (after SURFACEWALK_FAKE_DELAY) and
// otherwise runs the tests. This lets the startup measurement be tested without
// a real Keyorix build.
func TestMain(m *testing.M) {
	if addr := os.Getenv("SURFACEWALK_FAKE_SERVER"); addr != "" {
		if mode := os.Getenv("SURFACEWALK_FAKE_MODE"); mode == "crash" {
			fmt.Fprintln(os.Stderr, "fatal: missing master password")
			os.Exit(3)
		}
		delay, _ := time.ParseDuration(os.Getenv("SURFACEWALK_FAKE_DELAY"))
		time.Sleep(delay)
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
		_ = http.ListenAndServe(addr, mux) //nolint:gosec // test fake on loopback
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

func fakeParams(t *testing.T, addr, delay, mode string) startupParams {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return startupParams{
		Bin: self, Dir: t.TempDir(), URL: "http://" + addr + "/health",
		Runs: 3, Idle: 600 * time.Millisecond, Timeout: 20 * time.Second,
		Env: []string{
			"SURFACEWALK_FAKE_SERVER=" + addr,
			"SURFACEWALK_FAKE_DELAY=" + delay,
			"SURFACEWALK_FAKE_MODE=" + mode,
		},
	}
}

func TestMeasureStartup_TimesFirst200AndReportsPeakRSS(t *testing.T) {
	res, err := measureStartup(fakeParams(t, freeAddr(t), "300ms", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ReadyMS) != 3 {
		t.Fatalf("runs = %d, want 3", len(res.ReadyMS))
	}
	for _, ms := range res.ReadyMS {
		if ms < 300 {
			t.Errorf("ready after %d ms, but the fake server waits 300 ms before listening", ms)
		}
		if ms > 15000 {
			t.Errorf("ready after %d ms: implausibly slow for the fake server", ms)
		}
	}
	if res.PeakRSSKB <= 0 {
		t.Errorf("peak RSS = %d KiB, want a positive sample", res.PeakRSSKB)
	}
	if m := res.medianMS(); m < 300 {
		t.Errorf("median %d ms below the 300 ms floor", m)
	}
}

// A server that dies at start must fail the measurement with its own log in
// the message, not hang until the timeout or report a bogus time.
func TestMeasureStartup_CrashingServerFailsWithItsLog(t *testing.T) {
	_, err := measureStartup(fakeParams(t, freeAddr(t), "0s", "crash"))
	if err == nil {
		t.Fatal("a server that exits before /health answers must be an error")
	}
	if !strings.Contains(err.Error(), "missing master password") {
		t.Fatalf("error should carry the server's log tail, got: %v", err)
	}
}

func TestMedianMS(t *testing.T) {
	r := startupResult{ReadyMS: []int64{900, 100, 500, 300, 700}}
	if got := r.medianMS(); got != 500 {
		t.Fatalf("median = %d, want 500", got)
	}
}

func TestPeakRSSKB_NilStateIsAnError(t *testing.T) {
	if _, err := peakRSSKB(nil); err == nil {
		t.Fatal("a missing process state must be an error, not zero")
	}
}
