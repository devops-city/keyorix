package main

// log_json_integration_test.go — OBS-1 item 4, driven against a real server (built
// binary, SQLite, server.log.format: json).
//
// It checks the three things an operator relies on:
//  1. Shape: after start-up every log line is one JSON object with ts, level, msg,
//     and every access-log line also carries request_id, principal_type and route.
//  2. Correlation: the X-Request-ID the client sent (or the server minted and echoed)
//     is the request_id on that request's log line; principal_type reflects who
//     authenticated.
//  3. Secrecy (the guard): canary credentials and a canary secret VALUE pushed through
//     bootstrap, login (right and wrong password), secret create, a bad bearer token
//     and a bad PAT never appear anywhere in the server's output.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// injectServerLogFormat adds `log: {format: json}` under the generated config's top
// level `server:` key, the way an operator would edit the file.
func injectServerLogFormat(t *testing.T, cfgPath string) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath) //nolint:gosec // test-generated path under t.TempDir()
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	var out []string
	done := false
	for l := range strings.SplitSeq(string(raw), "\n") {
		if l == "  require_mfa: true" {
			// Same opt-out the web e2e harness uses (scripts/e2e/web-real-smoke.sh): the
			// shared bootstrap admin has no MFA, which security.require_mfa would confine
			// to the enrolment endpoints, and this test needs ordinary API calls.
			l = "  require_mfa: false"
		}
		out = append(out, l)
		if !done && l == "server:" {
			out = append(out, "  log:", "    format: json")
			done = true
		}
	}
	if !done {
		t.Fatalf("no top-level `server:` key in the generated config:\n%s", raw)
	}
	if err := os.WriteFile(cfgPath, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func doJSON(t *testing.T, method, url, token, reqID, body string) (int, http.Header, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if reqID != "" {
		req.Header.Set("X-Request-ID", reqID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, resp.Header, m
}

func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func TestJSONLogs_ShapeCorrelationAndNoSecrets(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	const (
		masterPass     = "canary-master-passphrase-Q9z-Zq81"
		adminPass      = "Zebra-Quartz-Pelican-Q9z-x7Q41"
		wrongPass      = "Walrus-Ember-Thicket-Q9z-m3K82"
		secretValue    = "canary-secret-VALUE-Q9z-9fT2pLw4"
		badBearer      = "canarybearerTOKEN0Q9zabcdef123456"
		badPAT         = "kx_pat_CanaryPATvalueQ9zZZZ99887766"
		bootstrapToken = "canary-bootstrap-token-Q9z-55aa77"
	)
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+masterPass)

	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	injectServerLogFormat(t, filepath.Join(dir, "keyorix.yaml"))
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	port := pinFreeHTTPPort(t, dir)
	logPath := filepath.Join(dir, "json-server.log")
	logFile, err := os.Create(logPath) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()    //nolint:errcheck
	cmd := exec.Command(bin) //nolint:gosec // bin is this suite's own freshly built binary
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, env...), "KEYORIX_BOOTSTRAP_TOKEN="+bootstrapToken, "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	base := "http://127.0.0.1:" + port
	awaitServerHealthy(t, cmd, logPath, base)

	// --- traffic carrying canaries ---------------------------------------------------
	req, _ := http.NewRequest(http.MethodPost, base+"/system/init", strings.NewReader(fmt.Sprintf(
		`{"username":"obsadmin","email":"obs1@example.com","password":%q,"display_name":"Operator One"}`, adminPass)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", bootstrapToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		srvLog, _ := os.ReadFile(logPath) //nolint:gosec // test-generated path
		t.Fatalf("bootstrap = %d: %s\nserver log:\n%s", resp.StatusCode, body, srvLog)
	}
	_ = resp.Body.Close()

	// A wrong password (anonymous principal, 401) with a caller-chosen request id.
	const wrongLoginID = "obs1-wrong-login-001"
	code, hdr, _ := doJSON(t, http.MethodPost, base+"/auth/login", "", wrongLoginID,
		fmt.Sprintf(`{"username":"obsadmin","password":%q}`, wrongPass))
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong-password login = %d, want 401", code)
	}
	if got := hdr.Get("X-Request-ID"); got != wrongLoginID {
		t.Errorf("response X-Request-ID = %q, want the caller's %q echoed", got, wrongLoginID)
	}

	code, _, login := doJSON(t, http.MethodPost, base+"/auth/login", "", "",
		fmt.Sprintf(`{"username":"obsadmin","password":%q}`, adminPass))
	token, _ := dig(login, "data", "token").(string)
	if code != http.StatusOK || token == "" {
		t.Fatalf("login = %d token=%q", code, token)
	}

	_, _, proj := doJSON(t, http.MethodPost, base+"/api/v1/projects", token, "", `{"name":"obs1-proj","description":"d"}`)
	pid := dig(proj, "data", "id")
	if pid == nil {
		t.Fatalf("project create returned no id: %v", proj)
	}
	_, _, envs := doJSON(t, http.MethodGet, fmt.Sprintf("%s/api/v1/projects/%v/environments", base, pid), token, "", "")
	var envID any
	if list, ok := dig(envs, "data", "environments").([]any); ok && len(list) > 0 {
		envID = list[0].(map[string]any)["id"]
	}
	const secretReqID = "obs1-create-secret-002"
	code, _, _ = doJSON(t, http.MethodPost, base+"/api/v1/secrets", token, secretReqID,
		fmt.Sprintf(`{"name":"obs1-secret","value":%q,"type":"password","project_id":%v,"environment_id":%v}`, secretValue, pid, envID))
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("secret create = %d", code)
	}

	// Bad credentials on authenticated routes.
	doJSON(t, http.MethodGet, base+"/api/v1/projects", badBearer, "obs1-bad-bearer-003", "")
	doJSON(t, http.MethodGet, base+"/api/v1/projects", badPAT, "obs1-bad-pat-004", "")

	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	raw, err := os.ReadFile(logPath) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatal(err)
	}
	logText := string(raw)

	// --- 3. secrecy: no canary anywhere in the output ---------------------------------
	for _, leaked := range leakedCanaries(logText, map[string]string{
		"master passphrase": masterPass, "admin password": adminPass, "wrong password": wrongPass,
		"secret value": secretValue, "session token": token, "bad bearer": badBearer,
		"bad PAT": badPAT, "bootstrap token": bootstrapToken,
	}) {
		t.Errorf("the %s canary appears in the server log", leaked)
	}

	// --- 1. shape ---------------------------------------------------------------------
	type line = map[string]any
	var recs []line
	started := false // lines before logging.Setup runs (config load/validate) are text
	for i, l := range strings.Split(strings.TrimSpace(logText), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var m line
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			if started {
				t.Errorf("line %d is not JSON after the format switch: %q", i, l)
			}
			continue
		}
		started = true
		for _, k := range []string{"ts", "level", "msg"} {
			if s, _ := m[k].(string); s == "" {
				t.Errorf("line %d lacks %q: %s", i, k, l)
			}
		}
		if _, err := time.Parse(time.RFC3339Nano, fmt.Sprint(m["ts"])); err != nil {
			t.Errorf("line %d ts %q is not RFC3339: %v", i, m["ts"], err)
		}
		recs = append(recs, m)
	}
	if !started {
		t.Fatalf("no JSON log line at all; server output:\n%s", logText)
	}
	access := map[string]line{} // request_id -> access-log record
	for _, m := range recs {
		if m["msg"] != "http request" {
			continue
		}
		for _, k := range []string{"request_id", "principal_type", "route", "method", "status", "duration_ms"} {
			if m[k] == nil || m[k] == "" {
				t.Errorf("access-log record lacks %q: %v", k, m)
			}
		}
		access[fmt.Sprint(m["request_id"])] = m
	}
	if len(access) == 0 {
		t.Fatalf("no access-log records; server output:\n%s", logText)
	}

	// --- 2. correlation ----------------------------------------------------------------
	wrong := access[wrongLoginID]
	if wrong == nil {
		t.Fatalf("no access-log record for the caller's request id %q", wrongLoginID)
	}
	if wrong["principal_type"] != "anonymous" {
		t.Errorf("failed login principal_type = %v, want anonymous", wrong["principal_type"])
	}
	if wrong["status"].(float64) != http.StatusUnauthorized {
		t.Errorf("failed login status = %v", wrong["status"])
	}
	create := access[secretReqID]
	if create == nil {
		t.Fatalf("no access-log record for %q", secretReqID)
	}
	if create["principal_type"] != "user" {
		t.Errorf("secret create principal_type = %v, want user", create["principal_type"])
	}
	if route, _ := create["route"].(string); route != "/api/v1/secrets" {
		t.Errorf("secret create route = %q, want the chi pattern /api/v1/secrets", route)
	}
	var minted int
	for id := range access {
		if !strings.HasPrefix(id, "obs1-") {
			minted++
		}
	}
	if minted == 0 {
		t.Error("requests without an X-Request-ID must get a server-minted id")
	}

	// A line from core carries the same id: the bad bearer's audit/auth failure logging
	// is not guaranteed, so assert the weaker, always-true property that no record
	// carries a request_id the access log did not issue.
	for _, m := range recs {
		if id, ok := m["request_id"].(string); ok && id != "" {
			if _, known := access[id]; !known && m["msg"] != "http request" {
				t.Errorf("record carries request_id %q that no request produced: %v", id, m)
			}
		}
	}
}

// leakedCanaries names every canary that appears verbatim in logText.
func leakedCanaries(logText string, canaries map[string]string) []string {
	var leaked []string
	for name, canary := range canaries {
		if canary != "" && strings.Contains(logText, canary) {
			leaked = append(leaked, name)
		}
	}
	return leaked
}

// TestLeakedCanaries_Detector: the secrecy guard above is only worth something if it
// can fail, so watch it fail on a log that leaks and pass on one that does not.
func TestLeakedCanaries_Detector(t *testing.T) {
	canaries := map[string]string{"pw": "hunter2-canary-value", "tok": "kx_pat_canary123456"}
	leaky := `{"ts":"2026-01-01T00:00:00Z","level":"info","msg":"login ok for bob with hunter2-canary-value"}`
	if got := leakedCanaries(leaky, canaries); len(got) != 1 || got[0] != "pw" {
		t.Errorf("leaky log: leakedCanaries = %v, want [pw]", got)
	}
	clean := `{"ts":"2026-01-01T00:00:00Z","level":"info","msg":"login ok for bob"}`
	if got := leakedCanaries(clean, canaries); len(got) != 0 {
		t.Errorf("clean log: leakedCanaries = %v, want none", got)
	}
}
