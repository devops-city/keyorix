package main

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// TestAwaitShutdown_LostProcessLockEndsTheServer: a lost presence lock or a
// lost single_writer holder lock ends the wait and is reported (main exits 1
// after the graceful shutdown); a signal ends it unreported (exit 0); a nil
// channel (no such lock) never fires.
func TestAwaitShutdown_LostProcessLockEndsTheServer(t *testing.T) {
	closed := func() <-chan struct{} { c := make(chan struct{}); close(c); return c }
	for _, tc := range []struct {
		name               string
		sig                bool
		presence, soleWrtr <-chan struct{}
		want               string
	}{
		{"signal", true, nil, nil, ""},
		{"presence lock lost", false, closed(), nil, lostPresenceLock},
		{"single_writer lock lost", false, nil, closed(), lostSoleWriterLock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := make(chan os.Signal, 1)
			if tc.sig {
				sig <- syscall.SIGTERM
			}
			got := make(chan string, 1)
			go func() { got <- awaitShutdown(sig, tc.presence, tc.soleWrtr) }()
			select {
			case g := <-got:
				if g != tc.want {
					t.Fatalf("awaitShutdown = %q, want %q", g, tc.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("awaitShutdown did not return")
			}
		})
	}

	// No signal and no lost lock: it keeps waiting (nil channels never fire).
	done := make(chan struct{})
	go func() { awaitShutdown(make(chan os.Signal), nil, nil); close(done) }()
	select {
	case <-done:
		t.Fatal("awaitShutdown returned with no signal and no lost lock")
	case <-time.After(200 * time.Millisecond):
	}
}
