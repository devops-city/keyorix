//go:build e2e

// Package journeys contains Session N's customer-journey E2E tests. Unlike
// scripts/e2e's route-coverage smoke driver (which asserts "no 5xx anywhere"),
// each journey here asserts the RESULT of a realistic end-to-end scenario --
// read-back values, audit event counts, denial status codes -- exercised
// through the real keyorix-server binary, the real keyorix CLI binary, and
// the keyorix-sdks/go SDK, on a freshly bootstrapped install. Reuses
// scripts/e2e/harness for server boot/bootstrap (one boot sequence, not two
// -- see docs/TESTING_GUIDE.md's "Customer journeys" section).
package journeys

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// maxRespBytes caps how much of any single API response a journey reads
// (16 MiB, matching scripts/e2e's client.go -- far above any real response
// here, just a backstop against an unbounded read).
const maxRespBytes = 16 << 20

// adminLogin performs POST /auth/login and returns the bearer token --
// journeys use this once, right after boot, to get an authenticated session
// for every admin-performed setup step (REST lookups and CLI env alike).
func adminLogin(t *testing.T, s *harness.Server, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(s.BaseURL+"/auth/login", "application/json", bytes.NewReader(body)) // #nosec G107 -- fixed test harness URL
	if err != nil {
		s.DumpLogAndFatal("POST /auth/login: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
		s.DumpLogAndFatal("POST /auth/login: HTTP %d: %s", resp.StatusCode, raw)
	}
	var env struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&env); err != nil {
		t.Fatalf("decode /auth/login response: %v", err)
	}
	if env.Data.Token == "" {
		t.Fatal("/auth/login: no token in response")
	}
	return env.Data.Token
}

// restEnvelope mirrors server/http/handlers/helpers.go's sendSuccess/sendError
// JSON shape, same as scripts/e2e's own envelope type.
type restEnvelope struct {
	StatusCode int
	Success    bool            `json:"success"`
	Data       json.RawMessage `json:"data"`
	Message    string          `json:"message"`
	Raw        []byte
}

// restCall issues an authenticated REST request against s and returns the
// decoded envelope. Journeys use this for admin setup lookups (resolving a
// name to an ID after a CLI mutation) and for the REST leg of each journey's
// "read the same value N ways" assertion.
func restCall(t *testing.T, s *harness.Server, token, method, path string, body interface{}) restEnvelope {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("%s %s: marshal request body: %v", method, path, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.BaseURL+path, reader)
	if err != nil {
		t.Fatalf("%s %s: build request: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: request failed: %v", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		t.Fatalf("%s %s: read response body: %v", method, path, err)
	}
	var env restEnvelope
	env.StatusCode = resp.StatusCode
	env.Raw = respBytes // always the full raw body, regardless of whether it parses as an envelope -- callers asserting a denial leaks nothing need this even when the body DID parse cleanly
	if len(respBytes) > 0 {
		_ = json.Unmarshal(respBytes, &env) // best-effort; env.Raw above already covers the non-JSON/decode-failure case
	}
	return env
}

// restExpect wraps restCall and fatally fails if the response status isn't
// one of want -- used for admin setup steps a journey has no reason to
// expect anything but success from (unlike a denial-path assertion, which
// calls restCall directly and checks the status itself).
func restExpect(t *testing.T, s *harness.Server, token, method, path string, body interface{}, want int) restEnvelope {
	t.Helper()
	env := restCall(t, s, token, method, path, body)
	if env.StatusCode != want {
		t.Fatalf("%s %s: expected HTTP %d, got %d: %s", method, path, want, env.StatusCode, string(env.Raw))
	}
	return env
}

// listedProjectNames decodes the `{"projects":[{"name":…}]}` payload of a 200
// GET /api/v1/projects and returns the project names it served. Since #2780
// that listing is least-privilege rather than admin-only -- it answers 200 with
// only the caller's visible projects instead of 403 -- so the assertion a
// journey wants is about WHICH projects came back, not the status code alone.
func listedProjectNames(t *testing.T, env restEnvelope) []string {
	t.Helper()
	var data struct {
		Projects []struct {
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/projects: %v\nraw: %s", err, env.Data)
	}
	names := make([]string, 0, len(data.Projects))
	for _, p := range data.Projects {
		names = append(names, p.Name)
	}
	return names
}

// runCLI runs the built keyorix CLI binary with args against server s,
// using env (which must carry KEYORIX_SERVER and KEYORIX_TOKEN on top of
// s.CLIEnv()'s isolated HOME/PATH). Fails the test with the combined
// output on a non-zero exit -- every CLI step in a journey is expected to
// succeed unless the caller is specifically testing a denial, in which case
// use runCLIExpectErr instead.
func runCLI(t *testing.T, cliBin string, env []string, args ...string) string {
	t.Helper()
	out, err := runCLIRaw(cliBin, env, args...)
	if err != nil {
		t.Fatalf("keyorix %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// runCLIExpectErr runs the CLI expecting a non-zero exit (a denial path) and
// returns its combined output for the caller to assert on -- fails the test
// if the command unexpectedly succeeds.
func runCLIExpectErr(t *testing.T, cliBin string, env []string, args ...string) string {
	t.Helper()
	out, err := runCLIRaw(cliBin, env, args...)
	if err == nil {
		t.Fatalf("keyorix %s: expected a failure, command succeeded:\n%s", strings.Join(args, " "), out)
	}
	return out
}

func runCLIRaw(cliBin string, env []string, args ...string) (string, error) {
	cmd := exec.Command(cliBin, args...) // #nosec G204 -- cliBin is this test's own built binary path, args are the test's own fixed arguments nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e journey itself built, with the journey's own fixed arguments; no external input reaches it
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ── Secrets the CLI accepts (never as a flag: #3325) ──────────────────────
//
// A secret reaches the CLI on stdin (--from-file -, or the rotate prompt read from a
// pipe) or in a KEYORIX_* variable. These helpers keep a call site one line.

// withEnv returns a copy of env with the KEY=value pairs appended (the last entry for a
// key wins), so a call site can add KEYORIX_PASSWORD= without touching the shared slice.
func withEnv(env []string, kv ...string) []string {
	return append(append([]string{}, env...), kv...)
}

// runCLIWithStdin runs the CLI with stdin piped in and returns combined output and the
// error. Use runCLIWithStdinOK / runCLIWithStdinExpectErr to assert on the exit status.
func runCLIWithStdin(cliBin string, env []string, stdin string, args ...string) (string, error) {
	cmd := exec.Command(cliBin, args...) // #nosec G204 -- cliBin is this test's own built binary path, args are the test's own fixed arguments nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e journey itself built, with the journey's own fixed arguments; no external input reaches it
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runCLIWithStdinOK is runCLI with stdin piped in: it fails the test on a non-zero exit.
func runCLIWithStdinOK(t *testing.T, cliBin string, env []string, stdin string, args ...string) string {
	t.Helper()
	out, err := runCLIWithStdin(cliBin, env, stdin, args...)
	if err != nil {
		t.Fatalf("keyorix %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// runCLIWithStdinExpectErr is runCLIExpectErr with stdin piped in.
func runCLIWithStdinExpectErr(t *testing.T, cliBin string, env []string, stdin string, args ...string) string {
	t.Helper()
	out, err := runCLIWithStdin(cliBin, env, stdin, args...)
	if err == nil {
		t.Fatalf("keyorix %s: expected a failure, command succeeded:\n%s", strings.Join(args, " "), out)
	}
	return out
}

// runCLISecret runs a `secret create` / `secret update` with value piped on stdin through
// --from-file - (the replacement for --value). Pass the command and its other flags in args.
func runCLISecret(t *testing.T, cliBin string, env []string, value string, args ...string) string {
	t.Helper()
	return runCLIWithStdinOK(t, cliBin, env, value, append(append([]string{}, args...), "--from-file", "-")...)
}

// runCLISecretExpectErr is runCLISecret for a denial path.
func runCLISecretExpectErr(t *testing.T, cliBin string, env []string, value string, args ...string) string {
	t.Helper()
	return runCLIWithStdinExpectErr(t, cliBin, env, value, append(append([]string{}, args...), "--from-file", "-")...)
}

// runCLIRotate runs `secret rotate --id <id>` with the new value piped on stdin (rotate has
// no file flag: its hidden prompt reads a pipe).
func runCLIRotate(t *testing.T, cliBin string, env []string, id, value string) string {
	t.Helper()
	// The prompt reads a line from a pipe, so the value needs its newline (create/update drop
	// one trailing newline themselves, but rotate would see EOF without it).
	return runCLIWithStdinOK(t, cliBin, env, value+"\n", "secret", "rotate", "--id", id)
}

// tokenEnv returns the environment a `keyorix` CLI invocation needs to act
// under ANY bearer token -- human session or machine credential alike, the
// CLI/server don't distinguish the two by shape. adminEnv/machineEnv/
// tokenEnv (used directly by N2 for its editor/viewer/outsider HUMAN
// session tokens, which are neither "the admin" nor a machine identity) are
// all the same env shape under a more call-site-accurate name.
func tokenEnv(s *harness.Server, token string) []string {
	return append(s.CLIEnv(), "KEYORIX_SERVER="+s.BaseURL, "KEYORIX_TOKEN="+token)
}

// adminEnv returns the environment a `keyorix` CLI invocation needs to act
// as the admin session token (project/secret/machine setup steps).
func adminEnv(s *harness.Server, adminToken string) []string {
	return tokenEnv(s, adminToken)
}

// machineEnv returns the environment a `keyorix` CLI invocation needs to act
// as a machine identity's issued bearer token (the three-readers steps).
func machineEnv(s *harness.Server, machineToken string) []string {
	return tokenEnv(s, machineToken)
}

// ── ID resolution (admin REST lookups after a CLI mutation) ────────────────

// projectID resolves a project name to its numeric ID via GET /api/v1/projects,
// the same route the CLI's own resolveMachineProjectID uses.
func projectID(t *testing.T, s *harness.Server, adminToken, name string) int {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/projects", nil, http.StatusOK)
	var data struct {
		Projects []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/projects: %v\nraw: %s", err, env.Data)
	}
	for _, p := range data.Projects {
		if p.Name == name {
			return p.ID
		}
	}
	t.Fatalf("project %q not found in GET /api/v1/projects response: %s", name, env.Data)
	return 0
}

// environmentID resolves an environment name (within a project) to its
// numeric ID via GET /api/v1/projects/{id}/environments.
func environmentID(t *testing.T, s *harness.Server, adminToken string, projID int, envName string) int {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/environments", projID), nil, http.StatusOK)
	var data struct {
		Environments []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/projects/%d/environments: %v\nraw: %s", projID, err, env.Data)
	}
	for _, e := range data.Environments {
		if e.Name == envName {
			return e.ID
		}
	}
	t.Fatalf("environment %q not found in project %d's environments: %s", envName, projID, env.Data)
	return 0
}

// secretID resolves a secret's name (within a project/environment) to its
// numeric ID via GET /api/v1/secrets?project_id=..&environment_id=...
func secretID(t *testing.T, s *harness.Server, adminToken string, projID, envID int, name string) int {
	t.Helper()
	path := fmt.Sprintf("/api/v1/secrets?project_id=%d&environment_id=%d", projID, envID)
	env := restExpect(t, s, adminToken, http.MethodGet, path, nil, http.StatusOK)
	var data struct {
		Secrets []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET %s: %v\nraw: %s", path, err, env.Data)
	}
	for _, sec := range data.Secrets {
		if sec.Name == name {
			return sec.ID
		}
	}
	t.Fatalf("secret %q not found in project %d env %d: %s", name, projID, envID, env.Data)
	return 0
}

// machineIdentityID resolves a machine identity's name (within a project) to
// its numeric ID via GET /api/v1/projects/{id}/machine-identities.
func machineIdentityID(t *testing.T, s *harness.Server, adminToken string, projID int, name string) int {
	t.Helper()
	path := fmt.Sprintf("/api/v1/projects/%d/machine-identities", projID)
	env := restExpect(t, s, adminToken, http.MethodGet, path, nil, http.StatusOK)
	var data struct {
		MachineIdentities []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"machine_identities"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET %s: %v\nraw: %s", path, err, env.Data)
	}
	for _, m := range data.MachineIdentities {
		if m.Name == name {
			return m.ID
		}
	}
	t.Fatalf("machine identity %q not found in project %d: %s", name, projID, env.Data)
	return 0
}

// ── CLI stdout parsing (steps whose result is only ever shown once) ────────

var (
	tokenLineRe = regexp.MustCompile(`(?m)^Token:\s+(\S+)$`)
	tokenIDRe   = regexp.MustCompile(`(?m)^ID:\s+(\d+)$`)
)

// parseIssuedToken extracts the raw bearer token and its numeric ID from
// `machine token issue`'s stdout -- the token is shown exactly once (it is
// hashed at rest, per ADR-030) so this is the only way a caller can obtain
// it, mirroring how a real operator would have to copy it from the terminal.
func parseIssuedToken(t *testing.T, cliOutput string) (token string, id int) {
	t.Helper()
	tm := tokenLineRe.FindStringSubmatch(cliOutput)
	if tm == nil {
		t.Fatalf("could not find 'Token:' line in `machine token issue` output:\n%s", cliOutput)
	}
	im := tokenIDRe.FindStringSubmatch(cliOutput)
	if im == nil {
		t.Fatalf("could not find 'ID:' line in `machine token issue` output:\n%s", cliOutput)
	}
	var idVal int
	if _, err := fmt.Sscanf(im[1], "%d", &idVal); err != nil {
		t.Fatalf("parse token ID %q: %v", im[1], err)
	}
	return tm[1], idVal
}

// decryptedValueRe matches the value line `secret get --ref ...`/`secret get
// --show-value` prints under the "Decrypted Value" / "---------------"
// header (cli/cmd/secret_crud.go's displaySecret).
var decryptedValueRe = regexp.MustCompile(`(?s)Decrypted Value\n-+\n(.*?)\n`)

// parseDecryptedValue extracts the secret value from `secret get`'s stdout.
func parseDecryptedValue(t *testing.T, cliOutput string) string {
	t.Helper()
	m := decryptedValueRe.FindStringSubmatch(cliOutput)
	if m == nil {
		t.Fatalf("could not find 'Decrypted Value' block in `secret get` output:\n%s", cliOutput)
	}
	return m[1]
}

var _ = context.Background // keep context imported for callers that need it

// pgConn is the connection target KEYORIX_TEST_PG_DSN names, with libpq's defaults
// filled in for anything the DSN leaves out.
type pgConn struct{ Host, Port, DBName, User, Password, SSLMode string }

// parsePGDSN reads a Postgres DSN in either form the test DB setting can take: a
// postgres:// (or postgresql://) URL -- what `kpg dsn` and most CI services print -- or
// libpq key=value pairs. Every PG-gated journey builds its server config from this, so
// none of them can quietly fall back to localhost:5432 as user "keyorix" when the DSN is
// in the other form.
func parsePGDSN(t *testing.T, dsn string) pgConn {
	t.Helper()
	c := pgConn{}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("KEYORIX_TEST_PG_DSN is not a valid URL: %v", err)
		}
		c.Host, c.Port, c.DBName = u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
		c.User = u.User.Username()
		c.Password, _ = u.User.Password()
		c.SSLMode = u.Query().Get("sslmode")
	} else {
		kv := map[string]string{}
		for _, field := range strings.Fields(dsn) {
			if k, v, ok := strings.Cut(field, "="); ok {
				kv[k] = strings.Trim(v, "'\"")
			}
		}
		c.Host, c.Port, c.DBName, c.User, c.Password, c.SSLMode =
			kv["host"], kv["port"], kv["dbname"], kv["user"], kv["password"], kv["sslmode"]
	}
	for p, def := range map[*string]string{&c.Host: "localhost", &c.Port: "5432", &c.DBName: "keyorix", &c.User: "keyorix", &c.SSLMode: "disable"} {
		if *p == "" {
			*p = def
		}
	}
	return c
}

// yaml renders the storage.database fields of the server config for this target (the
// password travels in KEYORIX_DB_PASSWORD, never in the file).
func (c pgConn) yaml() string {
	return fmt.Sprintf("    host: %s\n    port: \"%s\"\n    name: %s\n    user: %s\n    ssl_mode: %s\n",
		c.Host, c.Port, c.DBName, c.User, c.SSLMode)
}

var isolatedPGDBCounter int64

// isolatedPGDatabase creates a fresh, empty database on the Postgres server
// at base, dropped on cleanup. Journeys that enrol MFA must not reuse a shared
// database: the enrolment would persist into the next run.
func isolatedPGDatabase(t *testing.T, base, prefix string) string {
	t.Helper()
	name := fmt.Sprintf("%s_%d_%d", prefix, os.Getpid(), atomic.AddInt64(&isolatedPGDBCounter, 1))
	open := func() *gorm.DB {
		db, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatalf("open %s: %v", base, err)
		}
		return db
	}
	closeDB := func(db *gorm.DB) {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}
	admin := open()
	defer closeDB(admin)
	if err := admin.Exec("CREATE DATABASE " + name).Error; err != nil { //nolint:gosec // generated name, not external input
		t.Fatalf("create database %s: %v", name, err)
	}
	t.Cleanup(func() {
		c := open()
		defer closeDB(c)
		_ = c.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)").Error
	})
	return pgdsn.PGReplaceDBName(base, name)
}
