//go:build e2e

// #2459 regression coverage: FreeTCPPort hands out a port number that is
// free AT THE MOMENT IT'S CHECKED, then closes its own probe listener --
// leaving a gap where a different process can bind that exact port before
// this package's own server does. Before this fix, WaitHealthy treated any
// 200 from /health as proof of a successful boot, so a journey could end up
// silently running against ANOTHER journey's server and database (doubled
// audit-event counts, a tamper check that "passed" against the wrong DB).
package harness

import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestWaitHealthy_PortConflictDetection exercises pollHealthOrBindFailure's
// instance_nonce check directly, both ways:
//   - a server checking its OWN nonce against its OWN port must see no
//     conflict (the calibration case -- a check that never fires proves
//     nothing by itself).
//   - a second *Server struct pointed at that SAME port, but with a
//     different nonce (simulating two journeys' servers handed the same
//     port by FreeTCPPort's TOCTOU -- #2459's exact failure), must be
//     caught as a conflict, not silently accepted as healthy.
//
// Starting two real keyorix-server processes and racing them for a
// literally identical port would make this test itself flaky -- exactly
// the class of bug under test. Pointing a hand-built *Server at a real,
// already-running server's own port/nonce mismatch is deterministic and
// exercises the identical code path WaitHealthy uses in production.
func TestWaitHealthy_PortConflictDetection(t *testing.T) {
	serverBin, _ := BuildBinaries(t)
	a := StartServer(t, serverBin, DBBackend{Name: "sqlite"})
	t.Cleanup(a.Close)

	t.Run("matching nonce is healthy (calibration)", func(t *testing.T) {
		if err := pollHealthOrBindFailure(a, time.Now().Add(5*time.Second)); err != nil {
			t.Fatalf("pollHealthOrBindFailure on A's own server/nonce: want nil, got %v", err)
		}
	})

	t.Run("foreign nonce on the same port is caught, not silently accepted", func(t *testing.T) {
		b := &Server{BaseURL: a.BaseURL, nonce: newInstanceNonce(t), exited: make(chan struct{})}
		err := pollHealthOrBindFailure(b, time.Now().Add(5*time.Second))
		var conflict *portConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("expected a *portConflictError (another server answered b's port), got %T: %v", err, err)
		}
		if conflict.got != a.nonce {
			t.Errorf("portConflictError.got = %q, want A's real nonce %q", conflict.got, a.nonce)
		}
		if conflict.want != b.nonce {
			t.Errorf("portConflictError.want = %q, want B's own nonce %q", conflict.want, b.nonce)
		}
	})
}

// TestWaitHealthy_RetriesOnBindFailure covers the OTHER half of #2459's fix:
// when this boot's own child dies before ever answering healthy (a real
// bind failure, not a foreign-nonce conflict), WaitHealthy must retry on a
// fresh port rather than hang or fail outright. Deterministic: this
// occupies a real port itself first and points the server at that exact
// port, so the bind failure is guaranteed, not raced.
func TestWaitHealthy_RetriesOnBindFailure(t *testing.T) {
	serverBin, _ := BuildBinaries(t)
	dir := t.TempDir()
	env := append(BaseServerEnv(dir), "KEYORIX_MASTER_PASSWORD=e2e-bind-retry-test")
	const configPath = "./keyorix.yaml"

	run := func(args ...string) {
		out, err := RunAdminCmd(serverBin, dir, env, args...)
		if err != nil {
			t.Fatalf("keyorix-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "--config", configPath)
	run("encryption", "init", "--config", configPath)
	run("migrate", "--config", configPath)

	// Wildcard bind (":0"), not "127.0.0.1:0" -- server/main.go's own
	// startHTTPServer binds server.Addr = ":PORT" (wildcard, all
	// interfaces). A listener scoped to 127.0.0.1 specifically does NOT
	// reliably collide with that on every OS (confirmed live on macOS: the
	// server's wildcard bind succeeded anyway, and 127.0.0.1 traffic was
	// routed to the more-specific listener instead -- no EADDRINUSE, no
	// bind failure, just an unrelated hang). Matching the real bind shape
	// exactly is what makes this deterministic.
	occupied, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	occupiedPort := strconv.Itoa(occupied.Addr().(*net.TCPAddr).Port)
	RewritePort(t, dir, occupiedPort)

	s := &Server{
		T: t, Dir: dir, ConfigPath: configPath, BaseURL: "http://127.0.0.1:" + occupiedPort,
		Binary: serverBin, Env: env, LogPath: filepath.Join(dir, "e2e-server-bind-retry.log"),
		Backend: DBBackend{Name: "bind-retry"},
	}
	serverEnv := append(append([]string{}, env...),
		"KEYORIX_BOOTSTRAP_TOKEN=e2e-bind-retry-token",
		"KEYORIX_CONFIG_PATH="+configPath,
	)
	StartBackgroundProcess(t, s, serverEnv)
	t.Cleanup(s.Close)

	WaitHealthy(t, s) // must retry onto a new port internally, not hang or fail

	if s.BaseURL == "http://127.0.0.1:"+occupiedPort {
		t.Error("WaitHealthy reported healthy on the deliberately-occupied port -- it should have retried on a new one")
	}
}
