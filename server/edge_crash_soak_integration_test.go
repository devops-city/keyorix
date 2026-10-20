package main

// edge_crash_soak_integration_test.go -- EDGE-1 crash soak.
//
// What an unattended edge site depends on is that `kill -9` (OOM killer, a
// watchdog, a power cut that leaves the disk intact) at ANY point is followed
// by a plain restart that needs no operator. This drives the real built
// binary on SQLite through mixed writes (create / update / delete), SIGKILLs it
// at random points, restarts it with nothing but the config and environment a
// service manager would give it, and checks after every cycle:
//
//   - the server comes back healthy with no manual step;
//   - every write the server ACKNOWLEDGED before the kill is still there
//     (value and deletion), and the one in-flight write per secret is either
//     applied or not, never torn;
//   - `admin verify-audit` reports the chain VALID, on the files exactly as
//     the kill left them;
//   - every acknowledged write has its audit row (SQLite is strict-only, so an
//     acknowledged write whose audit row is missing is a durability bug).
//
// Every 4th cycle kills the server during start-up instead (before it is
// healthy), which is where stale lock files and half-applied boot work show up.
//
// Scope, stated so nobody reads more into a green run: SIGKILL stops the
// PROCESS; the kernel still flushes the page cache. That is the "server crash"
// row of docs/edge-deployment.md §3, not a power cut. A power cut needs a
// device that drops unsynced writes (dm-flakey) and is pending the e2e VM. The
// "standard audit loses a documented tail" half of the brief is a
// PostgreSQL-only, OS-crash-only property for the same reason (SQLite refuses
// `standard`; a process kill loses nothing at either level), so it is not
// assertable here.
//
// Size: KEYORIX_SOAK_CYCLES (default 2, kept small for the default test run),
// KEYORIX_SOAK_SEED (default time-based; always logged so a failure replays).
// scripts/edge/crash-soak.sh wraps this with bigger defaults.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const (
	soakAdminUser     = "soakadmin"
	soakAdminEmail    = "soakadmin@example.invalid"
	soakAdminPassword = "Quartz-Falcon-77-Ridge!"
	soakBootstrapTok  = "soak-bootstrap-token-0123456789-abcdef0123456789"
	soakHealthTimeout = 45 * time.Second
)

func soakEnvInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// soakServer is one keyorix-server subprocess that can be SIGKILLed and
// restarted in place, logging every incarnation to the same file.
type soakServer struct {
	t       *testing.T
	bin     string
	dir     string
	env     []string
	port    string
	logPath string

	cmd    *exec.Cmd
	exited chan struct{}
}

func (s *soakServer) baseURL() string { return "http://127.0.0.1:" + s.port }

func (s *soakServer) start(extraEnv ...string) {
	s.t.Helper()
	logFile, err := os.OpenFile(s.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test-generated path under t.TempDir()
	if err != nil {
		s.t.Fatalf("open server log: %v", err)
	}
	cmd := exec.Command(s.bin) //nolint:gosec // bin is this suite's own freshly built binary
	cmd.Dir = s.dir
	cmd.Env = append(append(append([]string{}, s.env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml"), extraEnv...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		s.t.Fatalf("start server: %v", err)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
		close(exited)
	}()
	s.cmd, s.exited = cmd, exited
}

// kill9 SIGKILLs the current incarnation and waits until it is really gone.
func (s *soakServer) kill9() {
	s.t.Helper()
	if s.cmd == nil {
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGKILL)
	select {
	case <-s.exited:
	case <-time.After(10 * time.Second):
		s.t.Fatalf("server did not exit after SIGKILL")
	}
	s.cmd = nil
}

func (s *soakServer) logTail() string {
	b, _ := os.ReadFile(s.logPath) //nolint:gosec // test-generated path
	if len(b) > 6000 {
		b = b[len(b)-6000:]
	}
	return string(b)
}

// waitHealthy returns how long the current incarnation took to answer /health.
// A process that exits first is a failed unattended restart.
func (s *soakServer) waitHealthy() time.Duration {
	s.t.Helper()
	begin := time.Now()
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Since(begin) < soakHealthTimeout {
		select {
		case <-s.exited:
			s.t.Fatalf("server exited during an unattended restart (needed a manual step). Log tail:\n%s", s.logTail())
		default:
		}
		if resp, err := client.Get(s.baseURL() + "/health"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return time.Since(begin)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("server not healthy %s after an unattended restart. Log tail:\n%s", soakHealthTimeout, s.logTail())
	return 0
}

// soakAPI is a bearer-token client; callers treat any transport error as "not
// acknowledged".
type soakAPI struct {
	base  string
	token string
	http  *http.Client
}

func newSoakAPI(base string) *soakAPI {
	return &soakAPI{base: base, http: &http.Client{Timeout: 5 * time.Second}}
}

func (a *soakAPI) do(method, path string, body any) (int, json.RawMessage, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.base+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(raw, &env)
	return resp.StatusCode, env.Data, nil
}

func (a *soakAPI) login(t *testing.T) {
	t.Helper()
	code, data, err := a.do(http.MethodPost, "/auth/login", map[string]string{"username": soakAdminUser, "password": soakAdminPassword})
	if err != nil || code != http.StatusOK {
		t.Fatalf("login after restart failed (code=%d err=%v): the admin account must survive a kill -9", code, err)
	}
	var d struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &d); err != nil || d.Token == "" {
		t.Fatalf("login returned no token: %s", data)
	}
	a.token = d.Token
}

// soakRec is the ledger entry for one secret. Each secret is owned by exactly
// one writer goroutine, so its operations are sequential and the ledger never
// has to reason about interleavings.
type soakRec struct {
	id      uint
	value   string // last ACKNOWLEDGED value
	pending string // value of an in-flight, unacknowledged update ("" = none)
	updates int    // acknowledged updates
	reads   int    // acknowledged value disclosures (GET ?include_value=true -> 200)
	// delAcked: DELETE acknowledged. delPending: DELETE sent, outcome unknown.
	delAcked, delPending bool
}

type soakLedger struct {
	mu      sync.Mutex
	recs    map[uint]*soakRec
	gapSeen map[string]bool
	bad     []string // non-crash failures (an unexpected status): they must fail the run, not just stop a writer
}

func (l *soakLedger) unexpected(msg string) {
	l.mu.Lock()
	l.bad = append(l.bad, msg)
	l.mu.Unlock()
}

func (l *soakLedger) snapshot() []soakRec {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]soakRec, 0, len(l.recs))
	for _, r := range l.recs {
		out = append(out, *r)
	}
	return out
}

// soakWriters runs mixed writes from `n` goroutines until stop closes or the
// server stops answering. Returns when every writer has finished.
func soakWriters(a *soakAPI, led *soakLedger, projectID, envID uint, n int, cycle int, seed int64, stop <-chan struct{}) {
	var wg sync.WaitGroup
	for w := range n {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(w))) //nolint:gosec // test randomness, seed is logged for replay
			var owned []*soakRec
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				live := owned[:0:0]
				for _, r := range owned {
					if !r.delAcked && !r.delPending {
						live = append(live, r)
					}
				}
				op := rng.Intn(10)
				switch {
				case len(live) > 0 && op >= 7: // read the value back (a disclosure)
					r := live[rng.Intn(len(live))]
					code, _, err := a.do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", r.id), nil)
					if err != nil {
						return
					}
					led.mu.Lock()
					if code == http.StatusOK {
						r.reads++
					} else {
						led.bad = append(led.bad, fmt.Sprintf("read secret %d: status %d", r.id, code))
					}
					led.mu.Unlock()
				case len(live) == 0 || op < 4: // create
					name := fmt.Sprintf("soak-c%d-w%d-%d", cycle, w, i)
					val := fmt.Sprintf("value-%s-v0", name)
					code, data, err := a.do(http.MethodPost, "/api/v1/secrets", map[string]any{
						"name": name, "value": val, "project_id": projectID, "environment_id": envID, "type": "generic",
					})
					if err != nil {
						return // transport error: the server was killed under us
					}
					if code != http.StatusCreated {
						led.unexpected(fmt.Sprintf("create %s: status %d", name, code))
						return
					}
					var d struct {
						ID uint `json:"id"`
					}
					if json.Unmarshal(data, &d) != nil || d.ID == 0 {
						return
					}
					r := &soakRec{id: d.ID, value: val}
					led.mu.Lock()
					led.recs[r.id] = r
					led.mu.Unlock()
					owned = append(owned, r)
				case op < 6: // update value
					r := live[rng.Intn(len(live))]
					nv := fmt.Sprintf("value-%d-v%d", r.id, r.updates+1)
					led.mu.Lock()
					r.pending = nv
					led.mu.Unlock()
					code, _, err := a.do(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", r.id), map[string]any{"value": nv})
					if err != nil {
						return // outcome unknown: pending stays set
					}
					led.mu.Lock()
					if code == http.StatusOK {
						r.value, r.pending = nv, ""
						r.updates++
					} else {
						r.pending = ""
						led.bad = append(led.bad, fmt.Sprintf("update secret %d: status %d", r.id, code))
					}
					led.mu.Unlock()
				default: // delete
					r := live[rng.Intn(len(live))]
					led.mu.Lock()
					r.delPending = true
					led.mu.Unlock()
					code, _, err := a.do(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", r.id), nil)
					if err != nil {
						return
					}
					led.mu.Lock()
					if code == http.StatusOK || code == http.StatusNoContent {
						r.delAcked, r.delPending = true, false
					} else {
						r.delPending = false
						led.bad = append(led.bad, fmt.Sprintf("delete secret %d: status %d", r.id, code))
					}
					led.mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
}

// soakCheckLedger verifies every acknowledged outcome against the restarted
// server, then folds what it observed back into the ledger (the observation IS
// the truth for the in-flight ops; the acknowledged ones were checked first).
func soakCheckLedger(t *testing.T, a *soakAPI, led *soakLedger, cycle int) {
	t.Helper()
	led.mu.Lock()
	defer led.mu.Unlock()
	for _, r := range led.recs {
		code, data, err := a.do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", r.id), nil)
		if err != nil {
			t.Fatalf("cycle %d: GET secret %d: %v", cycle, r.id, err)
		}
		gone := code == http.StatusNotFound || code == http.StatusGone
		if code >= 500 || (!gone && code != http.StatusOK) {
			t.Fatalf("cycle %d: GET secret %d returned %d after restart", cycle, r.id, code)
		}
		switch {
		case r.delAcked:
			if !gone {
				t.Fatalf("cycle %d: secret %d: DELETE was acknowledged but the secret is back after kill -9", cycle, r.id)
			}
		case gone && r.delPending:
			r.delAcked, r.delPending = true, false // in-flight delete applied
		case gone:
			t.Fatalf("cycle %d: secret %d: acknowledged create is gone after kill -9 (no delete was in flight)", cycle, r.id)
		default:
			var d struct {
				Value string `json:"value"`
			}
			if err := json.Unmarshal(data, &d); err != nil {
				t.Fatalf("cycle %d: decode secret %d: %v", cycle, r.id, err)
			}
			switch {
			case d.Value == r.value:
			case r.pending != "" && d.Value == r.pending:
				r.value = r.pending // in-flight update applied
				r.updates++         // its audit row must exist too: it committed
			default:
				t.Fatalf("cycle %d: secret %d: value after kill -9 is %q, want the acknowledged %q (or in-flight %q): lost or torn write",
					cycle, r.id, d.Value, r.value, r.pending)
			}
			r.delPending = false
		}
		r.pending = ""
	}
}

// soakStrictMutationAudit makes a missing mutation audit row a failure. The
// secret.created / secret.updated / secret.deleted / secret.restored rows are
// written in the mutation's own transaction (AUDIT-MUTATION-TX-1, #3297; restore
// in AUDIT-CORE-3), so a kill can never leave an acknowledged mutation without
// its row. On by default; KEYORIX_SOAK_STRICT_MUTATION_AUDIT=0 opts out and
// only logs the gap.
func soakStrictMutationAudit() bool { return os.Getenv("KEYORIX_SOAK_STRICT_MUTATION_AUDIT") != "0" }

// soakCheckAuditRows opens the database exactly as the kill left it (server is
// dead).
//
// Always enforced: every acknowledged value DISCLOSURE has its secret.read
// audit row -- that is what strict audit durability promises (audit commits
// and syncs before the value is released).
//
// Enforced unless KEYORIX_SOAK_STRICT_MUTATION_AUDIT=0 (then only logged):
// the audit row of an acknowledged create/update/delete (see
// soakStrictMutationAudit).
func soakCheckAuditRows(t *testing.T, dbPath string, led *soakLedger, cycle int) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	count := func(evt string, id uint) int {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE event_type = ? AND secret_node_id = ?", evt, id).Scan(&n); err != nil {
			t.Fatalf("cycle %d: count %s audit rows for %d: %v", cycle, evt, id, err)
		}
		return n
	}
	seen := led.gapSeen
	mutationGap := func(key string, format string, args ...any) {
		if soakStrictMutationAudit() {
			t.Errorf(format, args...)
			return
		}
		if !seen[key] { // a gap persists across cycles; say it once
			seen[key] = true
			t.Logf("known gap (AUDIT-MUTATION-TX-1): "+format, args...)
		}
	}
	for _, r := range led.snapshot() {
		if n := count("secret.read", r.id); n < r.reads {
			t.Errorf("cycle %d: secret %d: %d acknowledged value disclosures but only %d secret.read audit rows (strict audit-before-disclosure violated)", cycle, r.id, r.reads, n)
		}
		if n := count("secret.created", r.id); n < 1 {
			mutationGap(fmt.Sprintf("c%d", r.id), "cycle %d: secret %d acknowledged as created but has no secret.created audit row", cycle, r.id)
		}
		if n := count("secret.updated", r.id); n < r.updates {
			mutationGap(fmt.Sprintf("u%d", r.id), "cycle %d: secret %d: %d acknowledged updates but only %d secret.updated audit rows", cycle, r.id, r.updates, n)
		}
		if r.delAcked {
			if n := count("secret.deleted", r.id); n < 1 {
				mutationGap(fmt.Sprintf("d%d", r.id), "cycle %d: secret %d: acknowledged delete has no secret.deleted audit row", cycle, r.id)
			}
		}
	}
}

// soakPrepareInstall runs the operator's install sequence once, with the
// bootstrap admin claimed over HTTP, and returns the server handle (stopped).
func soakPrepareInstall(t *testing.T, bin string) (*soakServer, string) {
	t.Helper()
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=soak-test-passphrase-edge-crash")
	for _, args := range [][]string{
		{"init", "--dev", "--config", "./keyorix.yaml"},
		{"encryption", "init", "--config", "./keyorix.yaml"},
		{"migrate", "--config", "./keyorix.yaml"},
	} {
		if out, err := runAdmin(t, bin, dir, env, args...); err != nil {
			t.Fatalf("admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfgPath) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	port := freeTCPPort(t)
	text := strings.Replace(string(raw), `port: "8080"`, `port: "`+port+`"`, 1)
	// The soak logs in with a password; MFA enrolment is not what is under test.
	text = strings.Replace(text, "\n  require_mfa: true\n", "\n  require_mfa: false\n", 1)
	if text == string(raw) {
		t.Fatalf("config template no longer has the port/require_mfa lines this soak rewrites")
	}
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return &soakServer{t: t, bin: bin, dir: dir, env: env, port: port, logPath: filepath.Join(dir, "soak-server.log")}, filepath.Join(dir, "keyorix.db")
}

func TestEdgeCrashSoak_SQLite(t *testing.T) {
	if testing.Short() {
		t.Skip("crash soak spawns real server processes; skipped with -short")
	}
	cycles := soakEnvInt("KEYORIX_SOAK_CYCLES", 2)
	writers := soakEnvInt("KEYORIX_SOAK_WRITERS", 4)
	seed := int64(soakEnvInt("KEYORIX_SOAK_SEED", int(time.Now().UnixNano()%1_000_000)+1))
	t.Logf("crash soak: cycles=%d writers=%d seed=%d (replay with KEYORIX_SOAK_SEED=%d)", cycles, writers, seed, seed)
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // test randomness

	bin := buildServerBinary(t)
	srv, dbPath := soakPrepareInstall(t, bin)
	t.Cleanup(srv.kill9)

	// First boot: claim the admin and create the project/environment.
	srv.start("KEYORIX_BOOTSTRAP_TOKEN=" + soakBootstrapTok)
	srv.waitHealthy()
	api := newSoakAPI(srv.baseURL())
	body, _ := json.Marshal(map[string]string{"username": soakAdminUser, "email": soakAdminEmail, "password": soakAdminPassword, "display_name": soakAdminUser})
	req, _ := http.NewRequest(http.MethodPost, srv.baseURL()+"/system/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", soakBootstrapTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap admin failed: err=%v\n%s", err, srv.logTail())
	}
	_ = resp.Body.Close()
	api.login(t)
	idOf := func(path string, payload map[string]string) uint {
		code, data, err := api.do(http.MethodPost, path, payload)
		var d struct {
			ID uint `json:"id"`
		}
		if err != nil || code != http.StatusCreated || json.Unmarshal(data, &d) != nil || d.ID == 0 {
			t.Fatalf("POST %s: code=%d err=%v", path, code, err)
		}
		return d.ID
	}
	projectID := idOf("/api/v1/projects", map[string]string{"name": "soak-project"})
	envID := idOf(fmt.Sprintf("/api/v1/projects/%d/environments", projectID), map[string]string{"name": "soak-env"})
	srv.kill9() // the first kill is part of the soak: nothing was shut down cleanly

	led := &soakLedger{recs: map[uint]*soakRec{}, gapSeen: map[string]bool{}}
	var healthy []time.Duration
	for cycle := 1; cycle <= cycles; cycle++ {
		// Unattended restart: only the config + environment a service manager has.
		srv.start()
		if cycle%4 == 0 {
			// Kill DURING start-up, before the server is healthy.
			time.Sleep(time.Duration(rng.Intn(400)) * time.Millisecond)
			srv.kill9()
			t.Logf("cycle %d: killed during start-up", cycle)
			srv.start()
		}
		healthy = append(healthy, srv.waitHealthy())

		api = newSoakAPI(srv.baseURL())
		api.login(t)
		soakCheckLedger(t, api, led, cycle)

		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			soakWriters(api, led, projectID, envID, writers, cycle, seed+int64(cycle)*1000, stop)
			close(done)
		}()
		time.Sleep(time.Duration(150+rng.Intn(1200)) * time.Millisecond)
		srv.kill9() // random point in the middle of whatever the writers were doing
		close(stop)
		<-done
		if len(led.bad) > 0 {
			t.Fatalf("cycle %d: writers saw unexpected statuses (not crash symptoms): %v\nserver log tail:\n%s", cycle, led.bad, srv.logTail())
		}

		// The files are exactly as the kill left them.
		out, err := runAdmin(t, bin, srv.dir, srv.env, "verify-audit", "--config", "./keyorix.yaml")
		if err != nil || !strings.Contains(out, "VALID") {
			t.Fatalf("cycle %d: verify-audit after kill -9 failed (err=%v):\n%s\nserver log tail:\n%s", cycle, err, out, srv.logTail())
		}
		soakCheckAuditRows(t, dbPath, led, cycle)
		t.Logf("cycle %d ok: %d secrets tracked, restart healthy in %s", cycle, len(led.recs), healthy[len(healthy)-1].Round(time.Millisecond))
		if t.Failed() {
			t.FailNow()
		}
	}

	// Final unattended restart: everything acknowledged across all cycles is still there.
	srv.start()
	srv.waitHealthy()
	api = newSoakAPI(srv.baseURL())
	api.login(t)
	soakCheckLedger(t, api, led, cycles+1)
}
