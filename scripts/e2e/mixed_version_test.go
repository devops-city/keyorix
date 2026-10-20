//go:build e2e

// mixed_version_test.go (HA-READY-1 item 3): a rolling upgrade's middle state.
// Two replicas share one PostgreSQL database: the previous release (N-1) and
// this checkout (N). Each has its own copy of the same key set, as two pods
// with read-only copies of one Secret would. The test measures the N-1
// replica's error window right after N migrates (pgx-cached plans over
// altered tables), drives reads, writes and deletes through both (also
// concurrently), reproduces #3362 (N-1 resume + plain suspend after an N
// clear-copies suspend) and #3359 (an N-1 audit purge over N's v2 retention
// anchor), checks that a restarted N-1 binary is refused by the schema-epoch
// floor, verifies the audit chain with both verifiers, and runs a DEK rotation
// (refused while any replica runs) that N then reads back.
//
// Needs KEYORIX_TEST_PG_DSN (keyword/value form). The N-1 binary is
// KEYORIX_E2E_MIXED_OLD_BIN when set (e.g. built from the tag:
// `git archive v0.96.1 | tar -x -C old && go -C old build -o ../kx-old ./server`),
// otherwise the release asset for KEYORIX_E2E_MIXED_FROM_TAG (default
// defaultMixedVersionOldTag). docs/SELF_HOSTING.md "Running more than one
// replica" lists what this covers and the required upgrade order.
package e2e

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// defaultMixedVersionOldTag is the N-1 release: the latest tag.
const defaultMixedVersionOldTag = "v0.96.1"

const mixedAdminPassword = "Lantern-Quartz-58-Harbor!"

type mixedReplica struct {
	name string
	srv  *harness.Server
	c    *client
}

func TestMixedVersion_RollingUpgrade_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- the mixed-version test needs one PostgreSQL database shared by two binaries")
	}
	oldBin := os.Getenv("KEYORIX_E2E_MIXED_OLD_BIN")
	if oldBin == "" {
		tag := os.Getenv("KEYORIX_E2E_MIXED_FROM_TAG")
		if tag == "" {
			tag = defaultMixedVersionOldTag
		}
		oldBin = downloadReleaseBinary(t, tag)
	}
	newBin, _ := harness.BuildBinaries(t)
	dsn = mixedIsolatedDatabase(t, dsn)

	dbPassword := parseLibpqDSN(dsn)["password"]
	storageBlock := fmt.Sprintf("storage:\n  type: postgres\n  database:\n%s\n  encryption:\n    enabled: true\n    dek_path: keys/dek.key\n    salt_path: keys/kek.salt\n", pgDatabaseYAML(dsn))

	dirOld, dirNew := t.TempDir(), t.TempDir()
	env := func(dir string) []string {
		return append(harness.BaseServerEnv(dir),
			"KEYORIX_MASTER_PASSWORD=e2e-mixed-version-master-password",
			"KEYORIX_DB_PASSWORD="+dbPassword)
	}
	admin := func(bin, dir string, args ...string) string {
		t.Helper()
		out, err := harness.RunAdminCmd(bin, dir, env(dir), args...)
		if err != nil {
			t.Fatalf("%s admin %v: %v\n%s", filepath.Base(bin), args, err, out)
		}
		return out
	}

	// 1. The N-1 release provisions the install, exactly as a deployment that
	// existed before the upgrade.
	admin(oldBin, dirOld, "init", "--dev", "--config", "./keyorix.yaml")
	rewriteMixedConfig(t, dirOld, storageBlock)
	admin(oldBin, dirOld, "encryption", "init", "--config", "./keyorix.yaml")
	admin(oldBin, dirOld, "migrate", "--config", "./keyorix.yaml")
	portOld := harness.FreeTCPPort(t)
	harness.RewritePort(t, dirOld, portOld)
	const bootstrapToken = "e2e-mixed-version-bootstrap-token-0123456789"
	oldSrv := harness.BootAndBootstrap(t, oldBin, dirOld, env(dirOld), "./keyorix.yaml", portOld, bootstrapToken,
		"mixedadmin", "mixedadmin@example.invalid", mixedAdminPassword)
	t.Cleanup(oldSrv.Close)
	dumpLogOnFailure(t, oldSrv)
	old := &mixedReplica{name: "N-1", srv: oldSrv, c: newClient(t, oldSrv.BaseURL)}
	old.c.login("mixedadmin", mixedAdminPassword)

	proj := createID(t, old.c, "POST /api/v1/projects", "/api/v1/projects", map[string]string{"name": "mixed-version"})
	envID := createID(t, old.c, "POST /api/v1/projects/{id}/environments", fmt.Sprintf("/api/v1/projects/%d/environments", proj), map[string]string{"name": "mixed-main"})
	secretOf := func(r *mixedReplica, name, value string) uint {
		return createID(t, r.c, "POST /api/v1/secrets", "/api/v1/secrets", map[string]any{
			"name": name, "value": value, "project_id": proj, "environment_id": envID, "type": "generic",
		})
	}
	s1 := secretOf(old, "written-by-old-before-upgrade", "v1-old")

	// 2. The N replica starts on the same database (it migrates on open) with
	// its own copy of the key set, while N-1 keeps running.
	copyMixedDir(t, dirOld, dirNew)
	portNew := harness.FreeTCPPort(t)
	harness.RewritePort(t, dirNew, portNew)
	newSrv := startMixedServer(t, newBin, dirNew, env(dirNew), portNew, "new")
	nw := &mixedReplica{name: "N", srv: newSrv, c: newClient(t, newSrv.BaseURL)}
	nw.c.login("mixedadmin", mixedAdminPassword)

	// 2b. N added columns to existing tables (secret_nodes.suspend_clear_synced_copies
	// since v0.96.1). The N-1 replica's pooled connections hold pgx-cached prepared
	// statements for GORM's SELECT * over those tables, and PostgreSQL refuses each
	// one once ("cached plan must not change result type", SQLSTATE 0A000); pgx then
	// drops it from that connection's cache. Measure that window: it must close.
	probeSchemaChangeWindow(t, old, s1, proj, envID)

	// 3. Reads and writes across versions.
	expectValue(t, nw, s1, "v1-old")
	s2 := secretOf(nw, "written-by-new", "v1-new")
	expectValue(t, old, s2, "v1-new")
	nw.c.callExpect("PUT", "PUT /api/v1/secrets/{id}", fmt.Sprintf("/api/v1/secrets/%d", s1), map[string]string{"value": "v2-new"}, 200)
	expectValue(t, old, s1, "v2-new")
	old.c.callExpect("PUT", "PUT /api/v1/secrets/{id}", fmt.Sprintf("/api/v1/secrets/%d", s2), map[string]string{"value": "v2-old"}, 200)
	expectValue(t, nw, s2, "v2-old")
	s3 := secretOf(old, "deleted-by-new", "gone")
	nw.c.callExpect("DELETE", "DELETE /api/v1/secrets/{id}", fmt.Sprintf("/api/v1/secrets/%d", s3), nil, 200, 204)
	old.c.callExpect("GET", "GET /api/v1/secrets/{id}", fmt.Sprintf("/api/v1/secrets/%d?include_value=true", s3), nil, 404)
	for _, r := range []*mixedReplica{old, nw} {
		r.c.callExpect("GET", "GET /api/v1/secrets", "/api/v1/secrets", nil, 200)
		r.c.callExpect("GET", "GET /api/v1/audit/logs", "/api/v1/audit/logs?limit=50", nil, 200)
	}

	// Concurrent writes through both replicas: the audit chain's append lock
	// and the secret write paths of two versions interleave.
	var wg sync.WaitGroup
	written := map[uint]string{}
	var mu sync.Mutex
	for _, r := range []*mixedReplica{old, nw} {
		wg.Go(func() {
			for i := range 15 {
				v := fmt.Sprintf("%s-concurrent-%d", r.name, i)
				id := secretOf(r, fmt.Sprintf("concurrent-%s-%d", strings.ReplaceAll(r.name, "-", ""), i), v)
				mu.Lock()
				written[id] = v
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	for id, v := range written {
		expectValue(t, old, id, v)
		expectValue(t, nw, id, v)
	}

	// 3b. #3362: N suspends with clear_synced_copies, the still-running N-1
	// replica (which knows nothing of the marker) resumes and then plainly
	// suspends. N's refusal must not tell the operator to clear the copies.
	sp := fmt.Sprintf("/api/v1/secrets/%d", s2)
	nw.c.callExpect("POST", "POST /api/v1/secrets/{id}/suspend", sp+"/suspend", map[string]any{"reason": "compromise", "clear_synced_copies": true}, 200)
	if raw := rawBody(t, nw.c, "GET /api/v1/secrets/{id}", sp+"?include_value=true"); !strings.Contains(string(raw), "clear_synced_copies") {
		t.Fatalf("fixture: N's suspend with clear_synced_copies is not reported: %s", raw)
	}
	old.c.callExpect("POST", "POST /api/v1/secrets/{id}/resume", sp+"/resume", nil, 200)
	old.c.callExpect("POST", "POST /api/v1/secrets/{id}/suspend", sp+"/suspend", map[string]any{"reason": "plain"}, 200)
	if raw := rawBody(t, nw.c, "GET /api/v1/secrets/{id}", sp+"?include_value=true"); strings.Contains(string(raw), "clear_synced_copies") {
		t.Fatalf("#3362: a plain suspend by the N-1 replica after its resume still tells clients to clear synced copies: %s", raw)
	}
	nw.c.callExpect("POST", "POST /api/v1/secrets/{id}/resume", sp+"/resume", nil, 200)

	// 4. Once N has migrated, an N-1 binary can no longer START (schema epoch
	// floor 3: #3359, #3362): a crash-looping or evicted N-1 pod is refused
	// rather than rejoining. The N-1 replica that was already running keeps
	// serving until the rollout replaces it.
	dirOld2 := t.TempDir()
	copyMixedDir(t, dirOld, dirOld2)
	harness.RewritePort(t, dirOld2, harness.FreeTCPPort(t))
	if out, err := runMixedServerUntilExit(oldBin, dirOld2, env(dirOld2), 60*time.Second); err == nil || !strings.Contains(out, "minimum compatible schema epoch of 3") {
		t.Fatalf("an N-1 binary started against the database N migrated (want the ADR-101 floor refusal): err=%v\n%s", err, out)
	}
	expectValue(t, old, s1, "v2-new")
	s4 := secretOf(old, "written-by-running-old", "v1-old-running")
	expectValue(t, nw, s4, "v1-old-running")

	// 5. The audit chain the two versions wrote verifies with both verifiers.
	verifyMixedAudit(t, newBin, dirNew, env(dirNew), dsn)
	verifyMixedAudit(t, oldBin, dirOld, env(dirOld), dsn)

	// 5b. #3359: N purges old audit events, writing a v2 retention anchor (with
	// the purged count); then the still-running N-1 replica runs a purge. Its
	// v1 anchor would drop the count for good, so the database refuses it and
	// its whole purge rolls back: nothing deleted, the anchor stays v2, and N's
	// verify stays VALID. (The rows are backdated in SQL; event_time is outside
	// what the purge leaves behind, so the surviving chain is untouched.)
	pg, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close() //nolint:errcheck
	backdate := func(n int) {
		t.Helper()
		if _, err := pg.Exec(`UPDATE audit_events SET event_time = now() - interval '30 days'
WHERE id IN (SELECT id FROM audit_events WHERE event_time > now() - interval '1 day' ORDER BY id LIMIT $1)`, n); err != nil {
			t.Fatal(err)
		}
	}
	anchorLayout := func() string {
		t.Helper()
		var v string
		if err := pg.QueryRow("SELECT value FROM system_metadata WHERE key = 'audit_retention_anchor'").Scan(&v); err != nil {
			t.Fatalf("read retention anchor: %v", err)
		}
		return strings.SplitN(v, "\x1f", 2)[0]
	}
	purge := map[string]any{"retention_days": 7}
	backdate(5)
	nw.c.callExpect("POST", "POST /api/v1/admin/jobs/purge-audit-logs", "/api/v1/admin/jobs/purge-audit-logs", purge, 200)
	if l := anchorLayout(); l != "v2" {
		t.Fatalf("N's purge wrote a %q anchor, want v2", l)
	}
	expectAPIAuditValid(t, nw)
	backdate(5)
	resp := old.c.doRaw("POST", "POST /api/v1/admin/jobs/purge-audit-logs", "/api/v1/admin/jobs/purge-audit-logs", []byte(`{"retention_days":7}`), old.c.token)
	_ = resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("#3359: the N-1 replica's purge succeeded (%d) over a v2 retention anchor", resp.StatusCode)
	}
	if l := anchorLayout(); l != "v2" {
		t.Fatalf("#3359: the N-1 replica's purge replaced the v2 anchor with %q, dropping the purged count", l)
	}
	var stillOld int
	if err := pg.QueryRow("SELECT count(*) FROM audit_events WHERE event_time < now() - interval '7 days'").Scan(&stillOld); err != nil || stillOld != 5 {
		t.Fatalf("the refused N-1 purge must roll back its delete: %d backdated rows left (err %v), want 5", stillOld, err)
	}
	// The rows the refused purge left behind are backdated (a hashed field), so
	// purge them with N, which keeps the cumulative count in the v2 anchor.
	nw.c.callExpect("POST", "POST /api/v1/admin/jobs/purge-audit-logs", "/api/v1/admin/jobs/purge-audit-logs", purge, 200)
	expectAPIAuditValid(t, nw)
	nw.c.callExpect("POST", "POST /api/v1/audit/checkpoint", "/api/v1/audit/checkpoint", nil, 200, 201)
	if out, err := harness.RunAdminCmd(oldBin, dirOld, env(dirOld), "verify-audit", "--json", "--pg-dsn", dsn); err == nil && strings.Contains(out, `"verdict": "VALID"`) {
		t.Logf("N-1 verify-audit after a v2 anchor: VALID")
	} else {
		t.Logf("N-1 verify-audit after a v2 anchor (expected false alarm until the rollout completes, docs/SELF_HOSTING.md): %v", err)
	}

	// 6. Rotation. Refused while any replica runs (either version holds the
	// shared presence lock); run by N once the rollout is complete (the N-1
	// replica stopped), then N reads every value back under the new DEK.
	if out, err := harness.RunAdminCmd(newBin, dirNew, env(dirNew), "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml"); err == nil {
		t.Fatalf("rotation ran while two replicas were live:\n%s", out)
	}
	oldSrv.Close()
	if out, err := harness.RunAdminCmd(newBin, dirNew, env(dirNew), "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml"); err == nil {
		t.Fatalf("rotation ran while the N replica was live:\n%s", out)
	}
	newSrv.Close()
	admin(newBin, dirNew, "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	newSrv = startMixedServer(t, newBin, dirNew, env(dirNew), portNew, "new-after-rotation")
	nw = &mixedReplica{name: "N", srv: newSrv, c: newClient(t, newSrv.BaseURL)}
	nw.c.login("mixedadmin", mixedAdminPassword)
	written[s1], written[s4] = "v2-new", "v1-old-running"
	for id, v := range written {
		expectValue(t, nw, id, v)
	}
	expectAPIAuditValid(t, nw)
}

// expectAPIAuditValid runs a full audit-chain verification on r
// (GET /api/v1/audit/verify?full=true, then its job) and asserts "valid". The
// server holds the checkpoint key, so a purged prefix is authenticated; the
// offline verifier without --checkpoint-key-file reports it indeterminate.
func expectAPIAuditValid(t *testing.T, r *mixedReplica) {
	t.Helper()
	c := r.c
	type result struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	full := c.callExpect("GET", "GET /api/v1/audit/verify", "/api/v1/audit/verify?full=true", nil, 202, 200)
	if full.StatusCode == 200 {
		var rep result
		c.unmarshalData(full, &rep, "audit verify")
		if rep.Status != "valid" {
			r.srv.DumpLogAndFatal("%s replica: audit chain %s: %s", r.name, rep.Status, rep.Reason)
		}
		return
	}
	var job struct {
		JobID  string  `json:"job_id"`
		State  string  `json:"state"`
		Result *result `json:"result"`
	}
	c.unmarshalData(full, &job, "start full audit verification")
	id := job.JobID
	for deadline := time.Now().Add(60 * time.Second); ; {
		env := c.callExpect("GET", "GET /api/v1/audit/verify/jobs/{id}", "/api/v1/audit/verify/jobs/"+id, nil, 200)
		c.unmarshalData(env, &job, "audit verification job")
		if job.State != "running" || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if job.State != "succeeded" || job.Result == nil || job.Result.Status != "valid" {
		r.srv.DumpLogAndFatal("%s replica: full audit verification job %s: state=%q result=%+v", r.name, id, job.State, job.Result)
	}
}

// rawBody GETs path and returns the response body as sent.
func rawBody(t *testing.T, c *client, routeKey, path string) []byte {
	t.Helper()
	resp := c.doRaw("GET", routeKey, path, nil, c.token)
	defer resp.Body.Close() //nolint:errcheck
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// runMixedServerUntilExit starts bin as a server in dir and returns its output
// once it exits, or an error-free result if it is still running after wait
// (then it is killed: it started, which the caller treats as the failure).
func runMixedServerUntilExit(bin, dir string, env []string, wait time.Duration) (string, error) {
	cmd := exec.Command(bin) // #nosec G204 -- the harness's own binary // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e test built or was given, no external input
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(wait):
		_ = cmd.Process.Kill()
		<-done
		return out.String(), nil
	}
}

// startMixedServer starts bin in dir (already bootstrapped) and waits for /health.
func startMixedServer(t *testing.T, bin, dir string, env []string, port, label string) *harness.Server {
	t.Helper()
	serverEnv := append(append([]string{}, env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	s := &harness.Server{
		T: t, Dir: dir, ConfigPath: "./keyorix.yaml", BaseURL: "http://127.0.0.1:" + port,
		Binary: bin, Env: env, LogPath: filepath.Join(dir, "e2e-mixed-"+label+".log"),
		Backend: harness.DBBackend{Name: "postgres-mixed-" + label},
	}
	harness.StartBackgroundProcess(t, s, serverEnv)
	t.Cleanup(s.Close)
	dumpLogOnFailure(t, s)
	harness.WaitHealthy(t, s)
	return s
}

// dumpLogOnFailure logs the tail of s's log when the test has failed (the
// client's 5xx check fails the test without the server's side of the story).
func dumpLogOnFailure(t *testing.T, s *harness.Server) {
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		b, _ := os.ReadFile(s.LogPath) // #nosec G304 -- test temp dir
		if len(b) > 8000 {
			b = b[len(b)-8000:]
		}
		t.Logf("--- %s log tail ---\n%s", s.LogPath, b)
	})
}

func createID(t *testing.T, c *client, routeKey, path string, body any) uint {
	t.Helper()
	env := c.callExpect("POST", routeKey, path, body, 200, 201)
	var out idOnly
	c.unmarshalData(env, &out, routeKey)
	if out.ID == 0 {
		t.Fatalf("%s: no id in response: %s", routeKey, env.Raw)
	}
	return out.ID
}

func expectValue(t *testing.T, r *mixedReplica, id uint, want string) {
	t.Helper()
	env := r.c.callExpect("GET", "GET /api/v1/secrets/{id}", fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil, 200)
	var got struct {
		Value string `json:"value"`
	}
	r.c.unmarshalData(env, &got, "get secret value")
	if got.Value != want {
		r.srv.DumpLogAndFatal("%s replica: secret %d = %q, want %q", r.name, id, got.Value, want)
	}
}

func verifyMixedAudit(t *testing.T, bin, dir string, env []string, dsn string) {
	t.Helper()
	out, err := harness.RunAdminCmd(bin, dir, env, "verify-audit", "--json", "--pg-dsn", dsn)
	if err != nil || !strings.Contains(out, `"verdict": "VALID"`) {
		t.Fatalf("%s admin verify-audit over the mixed-version chain: %v\n%s", filepath.Base(bin), err, out)
	}
	t.Logf("%s verify-audit: %s", filepath.Base(bin), strings.TrimSpace(out))
}

// rewriteMixedConfig swaps admin init's SQLite storage block for PostgreSQL and
// turns require_mfa off (the driver logs in with a password only), the same
// rewrites harness.StartServer applies.
func rewriteMixedConfig(t *testing.T, dir, storageBlock string) {
	t.Helper()
	path := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(raw), "\n  require_mfa: true\n", "\n  require_mfa: false\n", 1)
	start := strings.Index(text, "storage:")
	end := strings.Index(text[start:], "\nsecrets:")
	if start < 0 || end < 0 {
		t.Fatalf("generated config layout changed:\n%s", text)
	}
	text = text[:start] + storageBlock + text[start+end+1:]
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil { // #nosec G703 -- test temp dir
		t.Fatal(err)
	}
}

// copyMixedDir copies the config and key set of one replica's directory to
// another (the second pod of the same deployment).
func copyMixedDir(t *testing.T, from, to string) {
	t.Helper()
	copyMixedFile(t, filepath.Join(from, "keyorix.yaml"), filepath.Join(to, "keyorix.yaml"))
	copyMixedKeys(t, from, to)
}

func copyMixedKeys(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(to, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dek.key", "kek.salt"} {
		copyMixedFile(t, filepath.Join(from, "keys", name), filepath.Join(to, "keys", name))
	}
}

func copyMixedFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil { // #nosec G703 -- test temp dir
		t.Fatal(err)
	}
}

// mixedIsolatedDatabase creates a fresh database next to base's and returns
// base with dbname replaced; the database is dropped when the test ends.
func mixedIsolatedDatabase(t *testing.T, base string) string {
	t.Helper()
	name := fmt.Sprintf("e2e_mixed_version_%d_%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	db, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE DATABASE " + name); err != nil {
		_ = db.Close()
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		_ = db.Close()
	})
	fields := strings.Fields(base)
	for i, f := range fields {
		if strings.HasPrefix(f, "dbname=") {
			fields[i] = "dbname=" + name
			return strings.Join(fields, " ")
		}
	}
	return base + " dbname=" + name
}

// probeSchemaChangeWindow sends reads, lists and creates through r until 40 in a
// row succeed, logging how many returned 5xx before that. It fails the test if
// the replica has not recovered after 600 requests.
func probeSchemaChangeWindow(t *testing.T, r *mixedReplica, secretID, proj, envID uint) {
	t.Helper()
	failures, streak := 0, 0
	for i := range 600 {
		var method, routeKey, path string
		var body []byte
		switch i % 3 {
		case 0:
			method, routeKey, path = "GET", "GET /api/v1/secrets/{id}", fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secretID)
		case 1:
			method, routeKey, path = "GET", "GET /api/v1/secrets", "/api/v1/secrets"
		default:
			method, routeKey, path = "POST", "POST /api/v1/secrets", "/api/v1/secrets"
			body = []byte(fmt.Sprintf(`{"name":"schema-window-probe-%d","value":"p","project_id":%d,"environment_id":%d,"type":"generic"}`, i, proj, envID))
		}
		resp := r.c.doRaw(method, routeKey, path, body, r.c.token)
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			failures++
			streak = 0
			continue
		}
		streak++
		if streak == 40 {
			t.Logf("%s replica after the N migration: %d of %d requests returned 5xx before 40 in a row succeeded", r.name, failures, i+1)
			return
		}
	}
	r.srv.DumpLogAndFatal("%s replica still failing after 600 requests (%d 5xx): the schema-change window did not close", r.name, failures)
}
