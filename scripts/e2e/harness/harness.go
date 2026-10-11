//go:build e2e

// Package harness is the shared fresh-install boot/bootstrap/port/cleanup
// mechanism for this repo's Go-based e2e drivers: SESSION-I's feature smoke
// suite (scripts/e2e) and SESSION-N's customer-journey suite
// (scripts/e2e/journeys). It boots a REAL keyorix-server binary (built from
// this checkout) against a freshly migrated database -- SQLite by default,
// PostgreSQL when the caller supplies a DBBackend with a postgres
// configExtra -- bootstraps an admin exactly the way a real operator would
// (admin init / admin encryption init / admin migrate / start / POST
// system/init, the same sequence scripts/smoke.sh and
// server/admin_recover_admin_integration_test.go's bootstrapAdminViaHTTP
// already use and have proven works).
//
// Extracted from scripts/e2e/harness.go (a pure move, no behavior change) so
// two independent test packages share one boot sequence instead of each
// maintaining its own -- see docs/TESTING_GUIDE.md's "Fresh-install /
// real-backend E2E smoke" and "Customer journeys" sections.
//
// Excluded from the default build (this whole package requires the `e2e`
// build tag) because it shells out to `go build`, spawns real server
// subprocesses, binds real TCP ports, and (for the PostgreSQL leg) requires
// a real Postgres instance -- unsuitable for `go test ./...`'s default fast
// inner loop.
package harness

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Binary build (once per test binary run, shared across SQLite/Postgres legs) ──

var (
	buildOnce    sync.Once
	serverBinary string
	cliBinary    string
	buildErr     error
	buildDir     string
)

// RunMain is the body every e2e test package's TestMain must be:
//
//	func TestMain(m *testing.M) { os.Exit(harness.RunMain(m)) }
//
// BuildBinaries compiles into a directory under os.TempDir() (so $TMPDIR is
// honoured) that is shared by every test in the package and therefore cannot
// be removed by any one test's t.Cleanup; RunMain removes it once the whole
// package has finished. Without it each `go test` run leaked ~113 MB of
// keyorix-e2e-bin-* into the temp dir (#3039), enough to fill a small tmpfs.
func RunMain(m *testing.M) int {
	code := m.Run()
	CleanupBinaries()
	return code
}

// CleanupBinaries removes the directory BuildBinaries compiled into. Safe to
// call when nothing was built.
func CleanupBinaries() {
	if buildDir != "" {
		_ = os.RemoveAll(buildDir)
		buildDir = ""
	}
}

// RepoRoot walks up from this file's own directory to find go.mod, so the
// build works regardless of how `go test` was invoked (cwd-independent, same
// approach as server/admin_integration_test.go's findServerRepoRoot).
func RepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) walking up from caller's package")
		}
		dir = parent
	}
}

// BuildBinaries compiles the real keyorix-server and keyorix (CLI) binaries
// exactly once for the whole `go test` run -- every smoke leg (SQLite,
// Postgres) exercises the identical build; paying the build cost twice would
// only slow the suite down, never change what's tested.
func BuildBinaries(t *testing.T) (server, cli string) {
	t.Helper()
	buildOnce.Do(func() {
		root := RepoRoot(t)
		dir, err := os.MkdirTemp("", "keyorix-e2e-bin-*")
		if err != nil {
			buildErr = fmt.Errorf("create build tmpdir: %w", err)
			return
		}
		buildDir = dir // removed by RunMain, also when a build below fails

		serverPath := filepath.Join(dir, "keyorix-server")
		cmd := exec.Command("go", "build", "-o", serverPath, "./server") // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built or downloaded, with the harness's own fixed arguments; no external input reaches it
		cmd.Dir = root
		if out, berr := cmd.CombinedOutput(); berr != nil {
			buildErr = fmt.Errorf("build keyorix-server: %w\n%s", berr, out)
			return
		}

		cliPath := filepath.Join(dir, "keyorix")
		cliCmd := exec.Command("go", "build", "-o", cliPath, ".") // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built or downloaded, with the harness's own fixed arguments; no external input reaches it
		cliCmd.Dir = filepath.Join(root, "cli")
		cliCmd.Env = append(os.Environ(), "GOWORK=off")
		if out, berr := cliCmd.CombinedOutput(); berr != nil {
			buildErr = fmt.Errorf("build keyorix (cli): %w\n%s", berr, out)
			return
		}

		serverBinary, cliBinary = serverPath, cliPath
	})
	if buildErr != nil {
		t.Fatalf("%v", buildErr)
	}
	return serverBinary, cliBinary
}

// ── Server lifecycle ──────────────────────────────────────────────────────

// DBBackend describes which storage backend a smoke leg targets.
type DBBackend struct {
	Name string // "sqlite" or "postgres", used only in test/failure output
	// ConfigExtra is the storage: block appended to the generated config,
	// e.g. "storage:\n  type: sqlite\n  database:\n    path: keyorix.db\n"
	// for sqlite, or the postgres field-by-field form for postgres. Empty
	// means keep whatever `admin init` generated (sqlite default).
	ConfigExtra string
	// ExtraEnv carries backend-specific secrets that must never land in the
	// config file (e.g. KEYORIX_DB_PASSWORD for postgres).
	ExtraEnv []string
	// VerifyAuditFlag is the --db or --pg-dsn flag verify-audit needs to open
	// the same database directly, without the running server's lock.
	VerifyAuditFlag func(dir string) []string
	// NoMFAReason opts a server OUT of the shipped security.require_mfa default
	// (true, ADR-112): when non-empty the harness writes require_mfa: false. The
	// default is the shipped config, so a journey that logs in must enrol through
	// the real API (requireMFAEnrolmentPremise + enrolTOTPAndLogin). Set this only
	// for a journey that genuinely tests a non-MFA configuration, with a one-line
	// reason; it is logged and listed in the PR that touches it.
	NoMFAReason string
}

// Server is a running keyorix-server subprocess plus everything the caller
// needs to talk to it and clean it up.
type Server struct {
	T          *testing.T
	Cmd        *exec.Cmd
	Dir        string
	ConfigPath string
	BaseURL    string
	Binary     string
	Env        []string
	LogPath    string
	Backend    DBBackend

	// PreNonceBinary marks Binary as a release older than /health's
	// instance_nonce echo (KEYORIX_E2E_INSTANCE_NONCE), e.g. the upgrade
	// path's previous-release binary (#2596). Such a binary always answers
	// with an empty nonce, so WaitHealthy proves the answer came from this
	// boot's child via the child's own access log instead (see
	// checkHealthIdentity). Never set it for a binary built from this
	// checkout: those must echo the nonce.
	PreNonceBinary bool

	// bootEnv is the full environment startProcess launches Binary with,
	// EXCLUDING KEYORIX_E2E_INSTANCE_NONCE (regenerated fresh every
	// attempt). Set by StartBackgroundProcess; read by WaitHealthy's
	// port-collision retry (#2459) so it can restart Binary against a
	// freshly chosen port without the caller re-supplying its environment.
	bootEnv []string
	// nonce is the current boot attempt's expected /health instance_nonce
	// (see pollHealthOrBindFailure).
	nonce string
	// exited is closed when Cmd exits; exitErr is set before it's closed,
	// so it's only safe to read exitErr after observing exited closed.
	exited  chan struct{}
	exitErr error
}

// newInstanceNonce returns a fresh random token for this boot attempt --
// crypto/rand, not math/rand, so a timing-based PRNG seed can never produce
// the same value two journeys pick close together in time.
func newInstanceNonce(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		t.Fatalf("generate instance nonce: %v", err)
	}
	return hex.EncodeToString(buf)
}

// FreeTCPPort returns a port number no listener is bound to (same approach
// as server/admin_integration_test.go's freeTCPPort) -- avoids hardcoding a
// port that could collide with a real dev server, another test run, or the
// SQLite and Postgres legs running back to back.
func FreeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free TCP port: %v", err)
	}
	defer l.Close() //nolint:errcheck
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// portLineRe matches server.http.port's value specifically -- anchored to
// the "enabled: true" line immediately above it in the generated template
// (configs/keyorix.yaml.tpl), not a bare `port: "\d+"` pattern. A bare
// pattern also matches storage.database.port (written by a PostgreSQL
// backend's ConfigExtra, e.g. `port: "15433"`) and server.grpc.port (whose
// own "enabled: false" line would need excluding some other way) -- both
// at the exact same indentation depth as server.http.port, so a
// content-blind regex silently rewrites the WRONG port whenever a Postgres
// backend or a second rewrite (the upgrade-path test picks a second free
// port for the NEW binary after the OLD binary already rewrote it once) is
// in play. grpc defaults to "enabled: false", so anchoring to
// "enabled: true" uniquely selects http's port even though grpc has the
// identical enabled/port shape.
//
// The earlier "enabled: true\n\s*port:" anchor broke when #2946 put comment
// lines (the host: explanation) between the two keys: it silently matched
// nothing, every server kept the template's 8080 while the harness polled its
// random port, and e2e-smoke timed out waiting for /health. The anchor is now
// the structure itself: the first 4-space-indented `port:` key after the
// top-level `server:` / 2-space `http:` keys, whatever comments or sibling
// keys sit in between. grpc's port is under `  grpc:` and the database port
// is under `storage:`, so neither can be reached from `http:`'s block.
var portLineRe = regexp.MustCompile(`(?ms)(^server:[^\n]*\n(?:[^\n]*\n)*?  http:[^\n]*\n(?:(?:    |\s*#|\s*\n)[^\n]*\n)*?    port: )"\d+"`)

// rewriteHTTPPort returns text with server.http.port set to port, and whether
// the port line was found. A no-match is a harness bug the caller must fail
// on, never skip: the server would otherwise keep its template port.
func rewriteHTTPPort(text, port string) (string, bool) {
	if !portLineRe.MatchString(text) {
		return text, false
	}
	return portLineRe.ReplaceAllString(text, fmt.Sprintf(`${1}"%s"`, port)), true
}

// BootstrapAdminPassword deliberately shares no substring with the
// bootstrap admin's username/email/display_name (see StartServer's
// /system/init call) -- internal/core/rules.DefaultPasswordPolicy rejects
// any password containing the account's username/email/display name.
const BootstrapAdminPassword = "Quartz-Falcon-77-Ridge!"

// SmokeUserPassword is the second (non-admin) test user's password, same
// "shares no substring with username/email/display_name" constraint as
// BootstrapAdminPassword above -- that account is named "e2esmokeuser".
const SmokeUserPassword = "Cobalt-Harbor-42-Ember!"

// BaseServerEnv is the minimal environment every server/admin process the
// harness spawns runs with: an isolated HOME, PATH, and -- only when the caller
// has one -- TMPDIR. The child (admin backup/restore, os.MkdirTemp("", ...))
// otherwise falls back to /tmp, which a sandboxed runner may not allow writing;
// an environment without TMPDIR (CI) is unchanged. Nothing else is forwarded.
func BaseServerEnv(dir string) []string {
	env := []string{"HOME=" + dir, "PATH=" + os.Getenv("PATH")}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		env = append(env, "TMPDIR="+tmp)
	}
	return env
}

// StartServer runs the exact operator-facing bootstrap sequence QUICK_START.md
// documents and scripts/smoke.sh already proves works end to end: admin init
// -> admin encryption init -> admin migrate -> start the server -> poll
// /health -> POST /system/init. Returns a *Server the caller must Close().
func StartServer(t *testing.T, binary string, backend DBBackend) *Server {
	t.Helper()
	dir := t.TempDir()
	env := append(BaseServerEnv(dir),
		"KEYORIX_MASTER_PASSWORD=e2e-smoke-master-password-"+backend.Name)
	env = append(env, backend.ExtraEnv...)

	configPath := "./keyorix.yaml"

	run := func(args ...string) {
		t.Helper()
		out, err := RunAdminCmd(binary, dir, env, args...)
		if err != nil {
			t.Fatalf("keyorix-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	// --dev: the harness drives the API over plain HTTP. The secure default
	// (TLS + metrics token) is covered by server/admin_init_secure_baseline_test.go
	// and scripts/smoke.sh (SECURE-DEFAULT-1).
	run("init", "--dev", "--config", configPath)

	if backend.NoMFAReason != "" {
		t.Logf("require_mfa disabled for this server (%s): %s", backend.Name, backend.NoMFAReason)
		path := filepath.Join(dir, "keyorix.yaml")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read generated config: %v", err)
		}
		const on, off = "\n  require_mfa: true\n", "\n  require_mfa: false\n"
		if !strings.Contains(string(raw), on) {
			t.Fatalf("generated config has no %q line to override (did configs/keyorix.yaml.tpl change?)", strings.TrimSpace(on))
		}
		if err := os.WriteFile(path, []byte(strings.Replace(string(raw), on, off, 1)), 0o600); err != nil { // #nosec G703 -- dir is always t.TempDir(), never attacker input
			t.Fatalf("override require_mfa: %v", err)
		}
	}

	if backend.ConfigExtra != "" {
		raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
		if err != nil {
			t.Fatalf("read generated config: %v", err)
		}
		// Replace the whole storage: block admin init wrote (sqlite default)
		// with the backend's own. The generated template always starts
		// storage: at top level with 2-space-indented children ending
		// before the next top-level key ("secrets:") -- see
		// configs/keyorix.yaml.tpl, which admin init writes verbatim.
		text := string(raw)
		start := strings.Index(text, "storage:")
		if start < 0 {
			t.Fatalf("generated config has no storage: block:\n%s", text)
		}
		rest := text[start:]
		end := strings.Index(rest, "\nsecrets:")
		if end < 0 {
			t.Fatalf("generated config's storage: block has no following secrets: key:\n%s", text)
		}
		newText := text[:start] + backend.ConfigExtra + rest[end+1:]
		if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(newText), 0o600); err != nil { // #nosec G703 -- dir is always t.TempDir(), never attacker input; flagged only because StartServer is now exported across the harness package boundary (gosec's taint check treats exported-function string params as untrusted, unlike the identical unexported call this had before the extraction)
			t.Fatalf("rewrite config for backend %s: %v", backend.Name, err)
		}
	}

	run("encryption", "init", "--config", configPath)
	run("migrate", "--config", configPath)

	port := FreeTCPPort(t)
	RewritePort(t, dir, port)

	const bootstrapToken = "e2e-smoke-bootstrap-token-0123456789"
	// Password is deliberately unrelated to username/email/display_name --
	// internal/core/rules.DefaultPasswordPolicy rejects a password
	// containing any of those (confirmed live: "E2E-Smoke-Adm1n-Passw0rd!"
	// was rejected because it embeds the "e2e" prefix of the username
	// "e2eadmin"), same trap scripts/smoke.sh's own header comment warns
	// about for its admin password.
	s := BootAndBootstrap(t, binary, dir, env, configPath, port, bootstrapToken,
		"smoketestadmin", "smoketestadmin@example.invalid", BootstrapAdminPassword)
	s.Backend = backend
	return s
}

// RunAdminCmd runs `binary admin <args...>` in dir with env, returning its
// combined output. Shared by StartServer (fresh install) and the
// upgrade-path test's old-binary provisioning + new-binary in-place migrate.
func RunAdminCmd(binary, dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command(binary, append([]string{"admin"}, args...)...) // #nosec G204 -- binary/args are this test's own fixed, non-attacker-controlled arguments nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built or downloaded, with the harness's own fixed arguments; no external input reaches it
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// RewritePort overwrites the generated config's listen port in place --
// admin init's template always listens on 8080, which every parallel test
// leg (SQLite, Postgres, the upgrade path) needs its own free port instead
// of, to avoid colliding with each other or a real dev server.
func RewritePort(t *testing.T, dir, port string) {
	t.Helper()
	path := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		t.Fatalf("read config before port rewrite: %v", err)
	}
	rewritten, ok := rewriteHTTPPort(string(raw), port)
	if !ok {
		t.Fatalf("server.http.port not found in generated config (template layout changed?); refusing to boot on the template's default port:\n%s", raw)
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil { // #nosec G703 -- path is derived from dir, always t.TempDir(), never attacker input; flagged only because RewritePort is now exported across the harness package boundary (gosec's taint check treats exported-function string params as untrusted, unlike the identical unexported call this had before the extraction)
		t.Fatalf("rewrite config port: %v", err)
	}
}

// StartBackgroundProcess starts s.Binary as a subprocess (cwd s.Dir, the
// given serverEnv -- which must already carry KEYORIX_CONFIG_PATH/
// KEYORIX_BOOTSTRAP_TOKEN if needed, unlike s.Env which does not), logging
// to s.LogPath, and records the running *exec.Cmd on s for Close/
// WaitHealthy to use. Does not wait for readiness -- call WaitHealthy next.
//
// serverEnv is retained on s as bootEnv (minus the per-attempt instance
// nonce, added fresh each time) so WaitHealthy can restart Binary against a
// new port, with the same environment otherwise, if this attempt loses the
// FreeTCPPort race (#2459) -- without the caller having to re-supply it.
func StartBackgroundProcess(t *testing.T, s *Server, serverEnv []string) {
	t.Helper()
	s.bootEnv = serverEnv
	startProcess(t, s)
}

// startProcess generates a fresh per-boot nonce, starts s.Binary with
// s.bootEnv plus that nonce, and arms s.exited to close (with s.exitErr set
// first) when the process exits. Used both by StartBackgroundProcess's
// first boot and by WaitHealthy's retries after losing a port race.
func startProcess(t *testing.T, s *Server) {
	t.Helper()
	s.nonce = newInstanceNonce(t)
	env := append(append([]string{}, s.bootEnv...), "KEYORIX_E2E_INSTANCE_NONCE="+s.nonce)

	logFile, err := os.Create(s.LogPath) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	cmd := exec.Command(s.Binary) // #nosec G204 -- s.Binary is this test's own built/downloaded fixed path nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built or downloaded, with the harness's own fixed arguments; no external input reaches it
	cmd.Dir = s.Dir
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start keyorix-server (%s): %v", s.Backend.Name, err)
	}
	s.Cmd = cmd
	s.exited = make(chan struct{})
	go func() {
		s.exitErr = cmd.Wait()
		close(s.exited)
	}()
}

// errBindLostRace is pollHealthOrBindFailure's sentinel for "s's own child
// process exited before ever answering healthy" -- WaitHealthy's cue to
// retry on a new port, never to treat this boot as healthy.
var errBindLostRace = errors.New("keyorix-server exited before answering healthy")

// errHealthTimeout is pollHealthOrBindFailure's sentinel for "deadline
// passed, child still running, nothing ever answered 200" -- a genuine
// startup hang, not a port race.
var errHealthTimeout = errors.New("timed out waiting for /health")

// healthPollClient bounds a SINGLE /health request, separately from
// pollHealthOrBindFailure's own overall deadline -- plain http.Get has no
// timeout, so a port occupied by a listener that accepts connections but
// never responds (a real possibility: that's exactly what a competing
// process's half-started listener can look like for the brief window before
// it closes) would otherwise hang the one request past the intended 30s
// budget instead of letting the loop's own deadline or s.exited check fire.
var healthPollClient = &http.Client{Timeout: 2 * time.Second}

// pollHealthOrBindFailure polls s.BaseURL/health until deadline. Returns nil
// the moment a 200 response's instance_nonce matches s's own nonce (proof
// the answering process is the child THIS boot started, not another
// process that won the FreeTCPPort race -- #2459) -- or, for an
// s.PreNonceBinary, the moment a 200 with no nonce is confirmed by the
// child's own access log (checkHealthIdentity, #2596). Returns errBindLostRace
// if s's own child exits first -- the caller's cue to retry on a new port.
// Returns a *portConflictError the first time a 200 answers with a
// DIFFERENT nonce, regardless of whether s's own child is still alive: a
// live, already-healthy foreign server on this exact port is never safe to
// treat as ours, and is exactly the silent-wrong-server failure #2459
// reported (doubled audit-event counts, a tamper check against the wrong
// database) -- so this is never retried silently, only surfaced.
func pollHealthOrBindFailure(s *Server, deadline time.Time) error {
	for time.Now().Before(deadline) {
		select {
		case <-s.exited:
			return errBindLostRace
		default:
		}
		// clientAddr is this probe connection's own local ip:port, which a
		// pre-nonce binary's access log records (see checkHealthIdentity).
		var clientAddr string
		req, rerr := http.NewRequest(http.MethodGet, s.BaseURL+"/health", nil) // #nosec G107 -- fixed localhost test URL
		if rerr != nil {
			return fmt.Errorf("build /health request: %w", rerr)
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { clientAddr = info.Conn.LocalAddr().String() },
		}))
		resp, herr := healthPollClient.Do(req)
		if herr == nil {
			body, _ := readAll(resp)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return checkHealthIdentity([]byte(body), s.nonce, s.PreNonceBinary, func() bool {
					return childLoggedRequestFrom(s, clientAddr)
				})
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errHealthTimeout
}

// accessLogWait bounds how long childLoggedRequestFrom waits for the
// child's access-log line: the server's request logger writes it after the
// handler returns, so it can land a moment after the client has already
// read the response.
const accessLogWait = 5 * time.Second

// childLoggedRequestFrom reports whether s's own child process logged
// serving a 200 to clientAddr, polling s.LogPath for up to accessLogWait.
// Gives up early (false) if the child exits.
func childLoggedRequestFrom(s *Server, clientAddr string) bool {
	deadline := time.Now().Add(accessLogWait)
	for {
		logBytes, _ := os.ReadFile(s.LogPath)
		if accessLogShowsClient(logBytes, clientAddr) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-s.exited:
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// maxPortRetries bounds how many times WaitHealthy restarts Binary against
// a freshly chosen port after its own child exits before answering healthy
// -- the bind-failure side of #2459's FreeTCPPort TOCTOU (FreeTCPPort closes
// its own probe listener before Binary binds the same port number, leaving
// a gap another process racing for an ephemeral port can win). Each retry
// gets its own fresh FreeTCPPort() call, so a one-off collision clears
// almost immediately; failing after this many retries is a structural
// problem, not a race.
const maxPortRetries = 5

// WaitHealthy polls s.BaseURL/health until it answers 200 with s's own
// instance_nonce, fatally killing the process and dumping its log on
// timeout. Retries on a freshly chosen port (up to maxPortRetries times) if
// s's own child exits before ever answering healthy -- the expected shape
// of a lost FreeTCPPort race (#2459). Fatals immediately, without retrying,
// if a 200 EVER answers with a different nonce: that means a different,
// already-healthy process is bound to this exact port right now, and
// silently treating it as "our" server is exactly the bug #2459 reported.
func WaitHealthy(t *testing.T, s *Server) {
	t.Helper()
	for attempt := 1; ; attempt++ {
		deadline := time.Now().Add(30 * time.Second)
		err := pollHealthOrBindFailure(s, deadline)
		if err == nil {
			return
		}

		var conflict *portConflictError
		if errors.As(err, &conflict) {
			logBytes, _ := os.ReadFile(s.LogPath)
			t.Fatalf("health check on %s: %v -- a different process is bound to this port (#2459); our own server's log:\n%s",
				s.BaseURL, conflict, logBytes)
		}

		if errors.Is(err, errBindLostRace) {
			if attempt >= maxPortRetries {
				logBytes, _ := os.ReadFile(s.LogPath)
				t.Fatalf("keyorix-server (%s) lost the free-port race %d times in a row; last log:\n%s", s.Backend.Name, maxPortRetries, logBytes)
			}
			newPort := FreeTCPPort(t)
			RewritePort(t, s.Dir, newPort)
			s.BaseURL = "http://127.0.0.1:" + newPort
			t.Logf("keyorix-server (%s) lost the free-port race on attempt %d/%d; retrying on a new port", s.Backend.Name, attempt, maxPortRetries)
			startProcess(t, s)
			continue
		}

		// errHealthTimeout or a decode error: neither the child exited nor
		// did a conflicting nonce ever answer -- it just never became
		// healthy. Not a port race, so no retry.
		logBytes, _ := os.ReadFile(s.LogPath)
		if s.Cmd != nil && s.Cmd.Process != nil {
			_ = s.Cmd.Process.Kill()
		}
		t.Fatalf("keyorix-server (%s) never became healthy: %v\nlog:\n%s", s.Backend.Name, err, logBytes)
	}
}

// BootOption adjusts a *Server that BootAndBootstrap builds, before it boots.
type BootOption func(*Server)

// WithPreNonceBinary marks the binary as predating /health's instance_nonce
// echo -- see Server.PreNonceBinary.
func WithPreNonceBinary() BootOption {
	return func(s *Server) { s.PreNonceBinary = true }
}

// BootAndBootstrap starts binary as a background server (serving at
// 127.0.0.1:port, config at configPath inside dir), waits for it to become
// healthy, then claims the first admin via POST /system/init (bootstrapToken
// via header, InitSystem's preferred path). Returns the running *Server
// (caller must eventually Close it). opts adjust the *Server before boot.
func BootAndBootstrap(t *testing.T, binary, dir string, env []string, configPath, port, bootstrapToken, username, email, password string, opts ...BootOption) *Server {
	t.Helper()
	serverEnv := append(append([]string{}, env...),
		"KEYORIX_BOOTSTRAP_TOKEN="+bootstrapToken,
		"KEYORIX_CONFIG_PATH="+configPath,
	)
	s := &Server{
		T: t, Dir: dir, ConfigPath: configPath, BaseURL: "http://127.0.0.1:" + port,
		Binary: binary, Env: env, LogPath: filepath.Join(dir, "e2e-server-"+filepath.Base(binary)+".log"),
		Backend: DBBackend{Name: username},
	}
	for _, opt := range opts {
		opt(s)
	}
	StartBackgroundProcess(t, s, serverEnv)
	WaitHealthy(t, s)

	body, _ := json.Marshal(map[string]string{
		"username": username, "email": email, "password": password, "display_name": username,
	})
	req, err := http.NewRequest(http.MethodPost, s.BaseURL+"/system/init", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build /system/init request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", bootstrapToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.DumpLogAndFatal("POST /system/init failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		respBody, _ := readAll(resp)
		s.DumpLogAndFatal("POST /system/init returned %d: %s", resp.StatusCode, respBody)
	}

	return s
}

// DumpLogAndFatal fails the test with msg plus the server's captured log --
// used whenever a step after boot fails and the log might explain why.
func (s *Server) DumpLogAndFatal(format string, args ...interface{}) {
	s.T.Helper()
	logBytes, _ := os.ReadFile(s.LogPath)
	msg := fmt.Sprintf(format, args...)
	s.T.Fatalf("%s\nserver log:\n%s", msg, logBytes)
}

// Close stops the server subprocess. Registered via t.Cleanup by the
// caller. Reaping is left to startProcess's own background goroutine (via
// s.exited) rather than calling Process.Wait() here too -- exec.Cmd.Wait
// and os.Process.Wait are documented as unsafe to call concurrently for the
// same process, and startProcess's goroutine is already blocked in Wait()
// from the moment the process starts.
func (s *Server) Close() {
	if s.Cmd == nil || s.Cmd.Process == nil {
		return
	}
	_ = s.Cmd.Process.Kill()
	if s.exited == nil {
		// Only possible if a caller built *Server by hand and started the
		// process some other way than startProcess -- fall back to the old
		// direct wait.
		_, _ = s.Cmd.Process.Wait()
		return
	}
	select {
	case <-s.exited:
	case <-time.After(5 * time.Second):
	}
}

// Exited returns a channel that is closed once this boot attempt's child
// process exits. Callers that need to know whether/when Cmd exited should
// select on this instead of calling Process.Wait() or Cmd.Wait()
// themselves: both are documented as unsafe to call concurrently for the
// same process, and startProcess's own background goroutine is already the
// sole waiter from the moment the process starts.
func (s *Server) Exited() <-chan struct{} {
	return s.exited
}

// CLIEnv returns the environment a `keyorix` CLI invocation needs to talk to
// this running server: isolated HOME (so it never touches a real
// ~/.keyorix/cli.yaml -- see the repo's own "Local ~/.keyorix/cli.yaml breaks
// CLI tests" lesson) plus PATH.
func (s *Server) CLIEnv() []string {
	return []string{"HOME=" + s.Dir, "PATH=" + os.Getenv("PATH")}
}

func readAll(resp *http.Response) (string, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	return buf.String(), err
}
