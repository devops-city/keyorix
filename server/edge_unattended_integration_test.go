package main

// edge_unattended_integration_test.go -- EDGE-1 item 2: the stuck states an
// unattended device actually reaches, driven against the real built binary.
//
//   - Stale lock files. Every lock Keyorix takes is a kernel flock, which the
//     kernel releases when the process dies, so a `kill -9` leaves lock FILES
//     behind but no lock. The test leaves them behind (with junk in them, the
//     shape a hand-rolled PID lock would leave) and requires a plain restart
//     and the offline admin commands to work.
//   - Interrupted migration. A power cut during a first start or an upgrade
//     kills the process mid-migration. The test kills `admin migrate` and the
//     server's own start-up at random points on an unmigrated database, N
//     times, and requires the next run to finish the job with no manual step.
//   - Disk full, then freed. A full data volume must make writes FAIL (never
//     acknowledge and lose), must not corrupt the database, and the device must
//     recover after space is freed. A real full filesystem needs root, so this
//     simulates the write failure with the process's file-size limit
//     (RLIMIT_FSIZE, the writes that cross it fail); a real ENOSPC is pending
//     the e2e VM.
//
// Kept apart from edge_crash_soak_integration_test.go (a separate PR) so each
// stands on main alone; the small helpers below are deliberately local.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	edgeAdminUser = "edgeadmin"
	edgeAdminPass = "Quartz-Falcon-77-Ridge!"
	edgeBootTok   = "edge-unattended-bootstrap-token-0123456789"
)

// edgeInstall is one operator-style install (init, encryption init, optional
// migrate) in its own temp dir, with a free port and MFA off.
type edgeInstall struct {
	t    *testing.T
	bin  string
	dir  string
	port string
	env  []string
	log  string
}

func newEdgeInstall(t *testing.T, bin string, migrate bool) *edgeInstall {
	t.Helper()
	dir := t.TempDir()
	e := &edgeInstall{t: t, bin: bin, dir: dir, port: freeTCPPort(t), log: filepath.Join(dir, "edge-server.log")}
	e.env = append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=edge-unattended-test-passphrase")
	steps := [][]string{
		{"init", "--dev", "--config", "./keyorix.yaml"},
		{"encryption", "init", "--config", "./keyorix.yaml"},
	}
	if migrate {
		steps = append(steps, []string{"migrate", "--config", "./keyorix.yaml"})
	}
	for _, args := range steps {
		if out, err := runAdmin(t, bin, dir, e.env, args...); err != nil {
			t.Fatalf("admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfgPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(raw), `port: "8080"`, `port: "`+e.port+`"`, 1)
	text = strings.Replace(text, "\n  require_mfa: true\n", "\n  require_mfa: false\n", 1)
	if text == string(raw) {
		t.Fatal("config template no longer has the port/require_mfa lines this test rewrites")
	}
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

type edgeProc struct {
	cmd    *exec.Cmd
	exited chan struct{}
}

// start runs the server the way a service manager would: config path and
// passphrase from the environment, nothing else. wrap, if set, is a shell
// prefix (for example `ulimit -f N;`) that runs before an exec of the server.
func (e *edgeInstall) start(wrap string, extraEnv ...string) *edgeProc {
	e.t.Helper()
	logf, err := os.OpenFile(e.log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test path
	if err != nil {
		e.t.Fatal(err)
	}
	var cmd *exec.Cmd
	if wrap == "" {
		cmd = exec.Command(e.bin) //nolint:gosec // this suite's own binary
	} else {
		cmd = exec.Command("/bin/sh", "-c", wrap+` exec "$0"`, e.bin) //nolint:gosec // fixed wrapper, this suite's own binary
	}
	cmd.Dir = e.dir
	cmd.Env = append(append(append([]string{}, e.env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml"), extraEnv...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	p := &edgeProc{cmd: cmd, exited: make(chan struct{})}
	go func() { _ = cmd.Wait(); _ = logf.Close(); close(p.exited) }()
	return p
}

func (p *edgeProc) alive() bool {
	select {
	case <-p.exited:
		return false
	default:
		return true
	}
}

func (e *edgeInstall) kill9(p *edgeProc) {
	e.t.Helper()
	if p.alive() {
		_ = p.cmd.Process.Signal(syscall.SIGKILL)
	}
	select {
	case <-p.exited:
	case <-time.After(10 * time.Second):
		e.t.Fatal("server did not exit after SIGKILL")
	}
}

func (e *edgeInstall) logTail() string {
	b, _ := os.ReadFile(e.log) //nolint:gosec // test path
	if len(b) > 5000 {
		b = b[len(b)-5000:]
	}
	return string(b)
}

func (e *edgeInstall) waitHealthy(p *edgeProc) {
	e.t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if !p.alive() {
			e.t.Fatalf("server exited instead of becoming healthy (a manual step was needed). Log tail:\n%s", e.logTail())
		}
		if resp, err := client.Get("http://127.0.0.1:" + e.port + "/health"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	e.t.Fatalf("server not healthy after 45s. Log tail:\n%s", e.logTail())
}

type edgeAPI struct {
	base, token string
	c           *http.Client
}

func (a *edgeAPI) do(method, path string, body any) (int, json.RawMessage, error) {
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
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
	resp, err := a.c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(raw, &env)
	return resp.StatusCode, env.Data, err
}

func (e *edgeInstall) api() *edgeAPI {
	return &edgeAPI{base: "http://127.0.0.1:" + e.port, c: &http.Client{Timeout: 5 * time.Second}}
}

func (a *edgeAPI) must(t *testing.T, method, path string, body any, want int) json.RawMessage {
	t.Helper()
	code, data, err := a.do(method, path, body)
	if err != nil || code != want {
		t.Fatalf("%s %s: code=%d err=%v, want %d", method, path, code, err, want)
	}
	return data
}

func (a *edgeAPI) login(t *testing.T) {
	t.Helper()
	var d struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(a.must(t, http.MethodPost, "/auth/login", map[string]string{"username": edgeAdminUser, "password": edgeAdminPass}, http.StatusOK), &d); err != nil || d.Token == "" {
		t.Fatalf("login returned no token: %v", err)
	}
	a.token = d.Token
}

// bootstrap claims the first admin; the server must be running with edgeBootTok.
func (a *edgeAPI) bootstrap(t *testing.T) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": edgeAdminUser, "email": "edgeadmin@example.invalid", "password": edgeAdminPass, "display_name": edgeAdminUser})
	req, _ := http.NewRequest(http.MethodPost, a.base+"/system/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", edgeBootTok)
	resp, err := a.c.Do(req)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		t.Fatalf("bootstrap returned %d: %s", resp.StatusCode, raw)
	}
}

func (a *edgeAPI) id(t *testing.T, path string, payload any) uint {
	t.Helper()
	var d struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(a.must(t, http.MethodPost, path, payload, http.StatusCreated), &d); err != nil || d.ID == 0 {
		t.Fatalf("POST %s returned no id", path)
	}
	return d.ID
}

// findLockFiles lists every *.lock under dir (flock sidecar files).
func findLockFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".lock") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func requireVerifyAuditValid(t *testing.T, e *edgeInstall, when string) {
	t.Helper()
	out, err := runAdmin(t, e.bin, e.dir, e.env, "verify-audit", "--config", "./keyorix.yaml")
	if err != nil || !strings.Contains(out, "VALID") {
		t.Fatalf("%s: verify-audit not VALID (err=%v):\n%s", when, err, out)
	}
}

// TestEdgeUnattended_StaleLockFilesDoNotBlockRestart: kill -9 leaves lock files
// but no lock; junk inside them (a dead PID, text) must not matter either.
func TestEdgeUnattended_StaleLockFilesDoNotBlockRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real server processes")
	}
	e := newEdgeInstall(t, buildServerBinary(t), true)
	p := e.start("", "KEYORIX_BOOTSTRAP_TOKEN="+edgeBootTok)
	e.waitHealthy(p)
	e.api().bootstrap(t)
	e.kill9(p)

	locks := findLockFiles(t, e.dir)
	if len(locks) == 0 {
		t.Fatal("no *.lock files after a server run: the premise of this test (files left behind) is gone; update it")
	}
	for _, l := range locks {
		if err := os.WriteFile(l, []byte("pid 99999 (stale)\n"), 0o600); err != nil {
			t.Fatalf("plant stale content in %s: %v", l, err)
		}
	}
	t.Logf("left behind and corrupted %d lock file(s)", len(locks))

	// Offline commands first (what an operator, or a unit's ExecStartPre, would run).
	begin := time.Now()
	requireVerifyAuditValid(t, e, "after kill -9 with stale lock files")
	t.Logf("verify-audit took %s", time.Since(begin).Round(time.Millisecond))
	begin = time.Now()
	if out, err := runAdmin(t, e.bin, e.dir, e.env, "validate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin validate after kill -9 with stale lock files: %v\n%s", err, out)
	}
	t.Logf("validate took %s", time.Since(begin).Round(time.Millisecond))
	begin = time.Now()
	p = e.start("")
	e.waitHealthy(p)
	t.Logf("restart to healthy took %s", time.Since(begin).Round(time.Millisecond))
	a := e.api()
	a.login(t)
	e.kill9(p)
}

// TestEdgeUnattended_InterruptedMigrationCompletes kills first-time migration
// at random points, both as `admin migrate` and as the server's own start-up,
// and requires that the next unattended start finishes it.
func TestEdgeUnattended_InterruptedMigrationCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real server processes")
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // test randomness
	e := newEdgeInstall(t, buildServerBinary(t), false)    // NOT migrated

	interrupted := 0
	for range 4 {
		cmd := exec.Command(e.bin, "admin", "migrate", "--config", "./keyorix.yaml") //nolint:gosec // this suite's binary
		cmd.Dir, cmd.Env = e.dir, e.env
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-time.After(time.Duration(20+rng.Intn(500)) * time.Millisecond):
			_ = cmd.Process.Signal(syscall.SIGKILL)
			<-done
			interrupted++
		case <-done:
		}
	}
	t.Logf("%d of 4 `admin migrate` runs were killed mid-way", interrupted)
	for range 3 {
		p := e.start("")
		time.Sleep(time.Duration(20+rng.Intn(600)) * time.Millisecond)
		e.kill9(p)
	}

	// The unattended start after all that.
	p := e.start("", "KEYORIX_BOOTSTRAP_TOKEN="+edgeBootTok)
	e.waitHealthy(p)
	a := e.api()
	a.bootstrap(t) // needs the complete schema (users, roles, audit, ...)
	a.login(t)
	projectID := a.id(t, "/api/v1/projects", map[string]string{"name": "mig-project"})
	envID := a.id(t, fmt.Sprintf("/api/v1/projects/%d/environments", projectID), map[string]string{"name": "mig-env"})
	a.id(t, "/api/v1/secrets", map[string]any{"name": "mig-secret", "value": "v", "project_id": projectID, "environment_id": envID, "type": "generic"})
	e.kill9(p)

	// And migrate stays idempotent afterwards.
	if out, err := runAdmin(t, e.bin, e.dir, e.env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate after the interrupted runs: %v\n%s", err, out)
	}
	requireVerifyAuditValid(t, e, "after interrupted migrations")
}

// TestEdgeUnattended_DiskFullThenFreed: with writes failing, no write may be
// acknowledged and then lost, the process must not corrupt anything, and after
// the limit is lifted the device recovers with no manual step.
func TestEdgeUnattended_DiskFullThenFreed(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real server processes")
	}
	e := newEdgeInstall(t, buildServerBinary(t), true)
	p := e.start("", "KEYORIX_BOOTSTRAP_TOKEN="+edgeBootTok)
	e.waitHealthy(p)
	a := e.api()
	a.bootstrap(t)
	a.login(t)
	projectID := a.id(t, "/api/v1/projects", map[string]string{"name": "full-project"})
	envID := a.id(t, fmt.Sprintf("/api/v1/projects/%d/environments", projectID), map[string]string{"name": "full-env"})
	e.kill9(p)

	// Headroom of a few hundred KiB over the database as it stands: enough for
	// a while of writes, then the limit is hit mid-run.
	size := int64(0)
	for _, f := range []string{"keyorix.db", "keyorix.db-wal"} {
		if st, err := os.Stat(filepath.Join(e.dir, f)); err == nil && st.Size() > size {
			size = st.Size()
		}
	}
	limitBlocks := (size + 256*1024) / 512 // /bin/sh's ulimit -f counts 512-byte blocks
	p = e.start(fmt.Sprintf("ulimit -f %d;", limitBlocks))
	e.waitHealthy(p)
	a = e.api()
	a.login(t) // a session row is a write too: if even this fails the limit is too tight

	acked := map[uint]string{}
	failures := 0
	payload := strings.Repeat("x", 2048)
	for i := 0; i < 600 && failures < 5; i++ {
		val := fmt.Sprintf("full-%d-%s", i, payload)
		code, data, err := a.do(http.MethodPost, "/api/v1/secrets", map[string]any{
			"name": fmt.Sprintf("full-secret-%d", i), "value": val, "project_id": projectID, "environment_id": envID, "type": "generic",
		})
		switch {
		case err != nil:
			failures++ // connection dropped: the process died under the failing writes
		case code == http.StatusCreated:
			var d struct {
				ID uint `json:"id"`
			}
			if json.Unmarshal(data, &d) == nil && d.ID != 0 {
				acked[d.ID] = val
			}
		default:
			if failures == 0 {
				t.Logf("first failing write: HTTP %d", code)
			}
			failures++
		}
	}
	if failures == 0 {
		t.Fatalf("600 writes of 2 KiB never failed under a %d KiB file limit: the simulated full disk did not bite (limit applied to the server? ulimit -f units?)", limitBlocks/2)
	}
	t.Logf("%d writes acknowledged, then the disk 'filled'; server alive=%v", len(acked), p.alive())
	// A value disclosure writes its audit row first: with the disk full it must
	// be refused, never served unaudited.
	for id := range acked {
		code, data, err := a.do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil)
		t.Logf("read of an acknowledged secret while full: HTTP %d err=%v", code, err)
		if err == nil && code == http.StatusOK && strings.Contains(string(data), `"value"`) {
			t.Errorf("a value was disclosed while the audit write for it was failing")
		}
		break
	}
	e.kill9(p) // the operator (or watchdog) restarts it; the limit is gone: space was freed

	p = e.start("")
	e.waitHealthy(p)
	a = e.api()
	a.login(t)
	for id, want := range acked {
		var d struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(a.must(t, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil, http.StatusOK), &d); err != nil || d.Value != want {
			t.Fatalf("secret %d acknowledged during the full-disk run is lost or changed after space was freed", id)
		}
	}
	a.id(t, "/api/v1/secrets", map[string]any{"name": "after-free", "value": "ok", "project_id": projectID, "environment_id": envID, "type": "generic"})
	e.kill9(p)
	requireVerifyAuditValid(t, e, "after a full-disk episode")
	if out, err := runAdmin(t, e.bin, e.dir, e.env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose after a full-disk episode: %v\n%s", err, out)
	}
}
