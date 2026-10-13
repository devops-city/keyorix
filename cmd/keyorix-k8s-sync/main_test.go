package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/k8ssync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- envOr ----

func TestEnvOr_ReturnsEnvValueWhenSet(t *testing.T) {
	t.Setenv("KEYORIX_K8S_SYNC_CONFIG_TEST", "/custom/path.yaml")
	assert.Equal(t, "/custom/path.yaml", envOr("KEYORIX_K8S_SYNC_CONFIG_TEST", "/etc/keyorix/k8s-sync.yaml"))
}

func TestEnvOr_ReturnsDefaultWhenUnset(t *testing.T) {
	assert.Equal(t, "/etc/keyorix/k8s-sync.yaml", envOr("KEYORIX_K8S_SYNC_CONFIG_TEST_UNSET", "/etc/keyorix/k8s-sync.yaml"))
}

// ---- resolveToken ----

func TestResolveToken_FromEnv(t *testing.T) {
	t.Setenv("KEYORIX_TOKEN", "env-token")
	t.Setenv("KEYORIX_TOKEN_FILE", "")

	token, err := resolveToken()
	require.NoError(t, err)
	assert.Equal(t, "env-token", token)
}

func TestResolveToken_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(path, []byte("file-token\n"), 0600))
	t.Setenv("KEYORIX_TOKEN_FILE", path)
	t.Setenv("KEYORIX_TOKEN", "")

	token, err := resolveToken()
	require.NoError(t, err)
	assert.Equal(t, "file-token", token, "trailing whitespace from the mounted file must be trimmed")
}

func TestResolveToken_FileTakesPrecedenceOverEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(path, []byte("file-token"), 0600))
	t.Setenv("KEYORIX_TOKEN_FILE", path)
	t.Setenv("KEYORIX_TOKEN", "env-token")

	token, err := resolveToken()
	require.NoError(t, err)
	assert.Equal(t, "file-token", token)
}

func TestResolveToken_FileMissing_ReturnsError(t *testing.T) {
	t.Setenv("KEYORIX_TOKEN_FILE", filepath.Join(t.TempDir(), "does-not-exist"))
	t.Setenv("KEYORIX_TOKEN", "env-token")

	_, err := resolveToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read KEYORIX_TOKEN_FILE")
}

func TestResolveToken_FileEmpty_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(path, []byte("   \n"), 0600))
	t.Setenv("KEYORIX_TOKEN_FILE", path)

	_, err := resolveToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is empty")
}

// KEYORIX_TOKEN_FILE is read under internal/secretenv's file rules: a mis-pointed
// path (a log, a device, a FIFO) is refused instead of being slurped into memory or
// blocking startup.
func TestResolveToken_FileTooLarge_ReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("a"), 2<<20), 0600))
	t.Setenv("KEYORIX_TOKEN_FILE", path)
	t.Setenv("KEYORIX_TOKEN", "")

	_, err := resolveToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestResolveToken_FileIsFIFO_ReturnsErrorWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, syscall.Mkfifo(path, 0o600))
	t.Setenv("KEYORIX_TOKEN_FILE", path)
	t.Setenv("KEYORIX_TOKEN", "")
	t.Cleanup(func() { unblockFIFOReader(path) })

	done := make(chan error, 1)
	go func() { _, err := resolveToken(); done <- err }()
	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("resolveToken blocked on a FIFO instead of refusing it")
	}
}

// unblockFIFOReader opens path for writing (non-blocking) and closes it, so a reader
// stuck opening the FIFO (the pre-fix behaviour) returns instead of leaking.
func unblockFIFOReader(path string) {
	if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		_ = f.Close()
	}
}

func TestResolveToken_NeitherSet_ReturnsError(t *testing.T) {
	t.Setenv("KEYORIX_TOKEN_FILE", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, err := resolveToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_TOKEN is required")
}

// ---- fakes for runAgent ----

// fakeFetcher serves values from a map; a ref absent from the map returns err (or a
// generic not-found error when err is nil).
type fakeFetcher struct {
	values map[string][]byte
	err    error
}

func (f *fakeFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	if v, ok := f.values[ref]; ok {
		return v, nil
	}
	if f.err != nil {
		return nil, f.err
	}
	return nil, fmt.Errorf("fakeFetcher: no value for ref %q", ref)
}

// fakeSink is a minimal in-memory k8ssync.Sink: Get always reports "not found" (nil,
// nil) so every apply is a Create, and List/Delete are recorded so cleanup wiring can
// be asserted without needing a real orphan to reap.
type fakeSink struct {
	mu        sync.Mutex
	applied   map[string]map[string][]byte
	listCalls int
	deleted   []string
}

func newFakeSink() *fakeSink {
	return &fakeSink{applied: map[string]map[string][]byte{}}
}

func (s *fakeSink) Get(_ context.Context, _, _ string) (map[string][]byte, error) {
	return nil, nil
}

func (s *fakeSink) Apply(_ context.Context, ns, name string, data map[string][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied[ns+"/"+name] = data
	return nil
}

func (s *fakeSink) List(_ context.Context, _ string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCalls++
	return nil, nil
}

func (s *fakeSink) Delete(_ context.Context, ns, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, ns+"/"+name)
	return nil
}

func (s *fakeSink) applyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.applied)
}

func (s *fakeSink) listCallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listCalls
}

func testConfig(healthPort int) *k8ssync.Config {
	return &k8ssync.Config{
		KeyorixURL: "https://keyorix.example.com",
		ProjectID:  1,
		HealthPort: healthPort,
		Mappings: []k8ssync.SecretMapping{
			{Ref: "production/db-password", Namespace: "default", Name: "db-secret", Key: "password"},
		},
	}
}

// captureLog redirects the standard logger to a buffer for the duration of fn and
// restores it afterward. runAgent and main() both log via the standard "log" package.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

// ---- runAgent: once mode ----

func TestRunAgent_OnceMode_AllSucceed_ReturnsZero(t *testing.T) {
	cfg := testConfig(0)
	fetcher := &fakeFetcher{values: map[string][]byte{"production/db-password": []byte("s3cr3t")}}
	sink := newFakeSink()

	var code int
	out := captureLog(t, func() {
		code = runAgent(cfg, fetcher, sink, true, false, false, "")
	})

	assert.Equal(t, 0, code)
	assert.Equal(t, 1, sink.applyCount(), "the single mapping must have been applied")
	assert.Equal(t, 0, sink.listCallCount(), "cleanup disabled: List must never be called")
	assert.Contains(t, out, "one-shot reconcile of 1 mapping(s)")
	assert.NotContains(t, out, "(dry-run)")
}

func TestRunAgent_OnceMode_FetchFailure_ReturnsOne(t *testing.T) {
	cfg := testConfig(0)
	fetcher := &fakeFetcher{err: errors.New("upstream unreachable")}
	sink := newFakeSink()

	var code int
	out := captureLog(t, func() {
		code = runAgent(cfg, fetcher, sink, true, false, false, "")
	})

	assert.Equal(t, 1, code, "a failed mapping must produce a non-zero exit code")
	assert.Equal(t, 0, sink.applyCount())
	assert.Contains(t, out, "one-shot reconcile of 1 mapping(s)")
}

// ---- runAgent: dry-run wiring ----

func TestRunAgent_DryRun_DoesNotApply(t *testing.T) {
	cfg := testConfig(0)
	fetcher := &fakeFetcher{values: map[string][]byte{"production/db-password": []byte("s3cr3t")}}
	sink := newFakeSink()

	var code int
	out := captureLog(t, func() {
		code = runAgent(cfg, fetcher, sink, true, true, false, "")
	})

	assert.Equal(t, 0, code)
	assert.Equal(t, 0, sink.applyCount(), "dry-run must never write a Secret")
	assert.Contains(t, out, "one-shot reconcile of 1 mapping(s) from https://keyorix.example.com (dry-run)")
}

// ---- runAgent: cleanup wiring (config vs flag) ----

func TestRunAgent_CleanupViaConfig_ListsOwnedSecrets(t *testing.T) {
	cfg := testConfig(0)
	cfg.Cleanup = true
	fetcher := &fakeFetcher{values: map[string][]byte{"production/db-password": []byte("s3cr3t")}}
	sink := newFakeSink()

	code := runAgent(cfg, fetcher, sink, true, false, false, "")

	assert.Equal(t, 0, code)
	assert.Equal(t, 1, sink.listCallCount(), "cfg.Cleanup=true must enable orphan reaping")
}

func TestRunAgent_CleanupViaFlag_ListsOwnedSecrets(t *testing.T) {
	cfg := testConfig(0)
	fetcher := &fakeFetcher{values: map[string][]byte{"production/db-password": []byte("s3cr3t")}}
	sink := newFakeSink()

	code := runAgent(cfg, fetcher, sink, true, false, true, "")

	assert.Equal(t, 0, code)
	assert.Equal(t, 1, sink.listCallCount(), "-cleanup must enable orphan reaping even when the config doesn't")
}

// ---- runAgent: loop mode + health server + signal shutdown ----

// TestRunAgent_LoopMode_ShutdownOnSignal drives the non-once branch: it starts the
// health server and the reconcile loop, sends this process a SIGTERM shortly after
// (mirroring how Kubernetes stops a Pod), and asserts runAgent returns cleanly rather
// than hanging. This is the only way to exercise the loop/health-server branch without
// a real Kubernetes cluster to run forever against.
func TestRunAgent_LoopMode_ShutdownOnSignal(t *testing.T) {
	cfg := testConfig(18765)
	fetcher := &fakeFetcher{values: map[string][]byte{"production/db-password": []byte("s3cr3t")}}
	sink := newFakeSink()

	done := make(chan int, 1)
	var out string
	completed := make(chan struct{})
	go func() {
		out = captureLog(t, func() {
			done <- runAgent(cfg, fetcher, sink, false, false, false, "")
		})
		close(completed)
	}()

	// Give the loop time to run its first sync pass and start the health server.
	time.Sleep(150 * time.Millisecond)
	self, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, self.Signal(syscall.SIGTERM))

	select {
	case code := <-done:
		<-completed
		assert.Equal(t, 0, code)
	case <-time.After(10 * time.Second):
		t.Fatal("runAgent did not return within 10s of SIGTERM")
	}

	assert.Equal(t, 1, sink.applyCount(), "the first immediate sync pass must have run")
	assert.Contains(t, out, "k8s-sync: syncing 1 mapping(s)")
	assert.Contains(t, out, "k8s-sync: shutdown signal received")
	assert.Contains(t, out, "k8s-sync: stopped")
}

// TestRunAgent_LoopMode_HealthServerBindError_LogsButContinues occupies the health
// port before starting runAgent so ListenAndServe fails immediately, covering the
// "health server error" log branch (the loop itself must still run and shut down
// cleanly on signal, same as when the port is free). It also runs with dryRun=true
// in loop mode, covering the "(dry-run)" loop-log branch that the plain loop-mode
// test above (dryRun=false) doesn't exercise.
func TestRunAgent_LoopMode_HealthServerBindError_LogsButContinues(t *testing.T) {
	// Same address form the health server itself binds to (main.go: Addr:
	// fmt.Sprintf(":%d", ...), all interfaces) -- a "127.0.0.1"-only listener
	// here does not reliably collide with that wildcard bind on every OS.
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer l.Close() //nolint:errcheck
	port := l.Addr().(*net.TCPAddr).Port

	cfg := testConfig(port)
	fetcher := &fakeFetcher{values: map[string][]byte{"production/db-password": []byte("s3cr3t")}}
	sink := newFakeSink()

	done := make(chan int, 1)
	completed := make(chan struct{})
	var out string
	go func() {
		out = captureLog(t, func() {
			done <- runAgent(cfg, fetcher, sink, false, true, false, "")
		})
		close(completed)
	}()

	time.Sleep(150 * time.Millisecond)
	self, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, self.Signal(syscall.SIGTERM))

	select {
	case code := <-done:
		<-completed
		assert.Equal(t, 0, code)
	case <-time.After(10 * time.Second):
		t.Fatal("runAgent did not return within 10s of SIGTERM")
	}

	assert.Contains(t, out, "k8s-sync: health server error")
	assert.Contains(t, out, "k8s-sync: syncing 1 mapping(s) from https://keyorix.example.com every")
	assert.Contains(t, out, "(dry-run)")
}

// ---- main(): subprocess re-exec, mirrors cmd/keyorix-mcp/main_test.go's pattern ----
//
// main() itself only ever reaches the log.Fatalf branches in this environment: past
// KEYORIX_TOKEN validation it calls k8ssync.NewInClusterSink(), which requires a real
// in-cluster Kubernetes API and mounted service-account files
// (/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt}, hardcoded constants
// in internal/k8ssync/rest_sink.go) that cannot be faked from a test process. The same
// function is only 41.2% covered by internal/k8ssync's own test suite for the same
// reason (verified via go tool cover -func) -- this is a pre-existing, documented wall
// in this codebase, not something new to this package. The interesting logic that used
// to live after that call was extracted into runAgent (tested directly, above) so it
// doesn't sit behind the same wall.

// runMainSubprocess re-execs this test binary scoped to a single test via
// -test.run. It deliberately never passes any of main()'s own flags (-config,
// -once, -dry-run, -cleanup) as extra argv: main() calls flag.Parse() a second
// time inside the subprocess against the SAME os.Args the testing package already
// parsed once (to consume -test.run) using flag.CommandLine, so any extra argv this
// process doesn't already recognize -- including main()'s own flags, since they
// aren't registered until main() runs, after testing's own parse -- would make
// THAT first parse fail with "flag provided but not defined" before main() ever
// gets to run. The config path is instead driven via KEYORIX_K8S_SYNC_CONFIG (the
// flag's own documented env-var fallback, see envOr), which sidesteps argv
// entirely.
func runMainSubprocess(t *testing.T, testName string, extraEnv []string) (stderr string, exitCode int, runErr error) {
	t.Helper()

	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KEYORIX_") || strings.HasPrefix(kv, "KUBERNETES_") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, extraEnv...)
	env = append(env, "KEYORIX_K8S_SYNC_MAIN_SUBPROCESS=1")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = env
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	runErr = cmd.Run()
	exitCode = 0
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		exitCode = exitErr.ExitCode()
	}
	return stderrBuf.String(), exitCode, runErr
}

// A config file that fails to parse/validate must abort startup via log.Fatalf.
func TestMainSubprocess_ConfigLoadError(t *testing.T) {
	if os.Getenv("KEYORIX_K8S_SYNC_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_ConfigLoadError",
		[]string{"KEYORIX_K8S_SYNC_CONFIG=/does/not/exist.yaml"})
	require.Error(t, runErr, "main() must exit non-zero when the config file can't be loaded")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "k8s-sync: config:")
}

// A missing KEYORIX_TOKEN must be a fatal, immediate startup error (checked after the
// config loads successfully).
func TestMainSubprocess_MissingToken(t *testing.T) {
	if os.Getenv("KEYORIX_K8S_SYNC_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "k8s-sync.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(validConfigYAML), 0600))

	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_MissingToken",
		[]string{"KEYORIX_K8S_SYNC_CONFIG=" + cfgPath})
	require.Error(t, runErr, "main() must exit non-zero when KEYORIX_TOKEN is unset")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "KEYORIX_TOKEN is required")
}

// With a valid config and a token, main() reaches k8ssync.NewInClusterSink(), which
// fails outside a real cluster (no KUBERNETES_SERVICE_HOST/PORT, no mounted
// service-account files) -- see the block comment above.
func TestMainSubprocess_KubernetesSinkError(t *testing.T) {
	if os.Getenv("KEYORIX_K8S_SYNC_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "k8s-sync.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(validConfigYAML), 0600))

	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_KubernetesSinkError",
		[]string{"KEYORIX_K8S_SYNC_CONFIG=" + cfgPath, "KEYORIX_TOKEN=t"})
	require.Error(t, runErr, "main() must exit non-zero when not running in-cluster")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "k8s-sync: kubernetes:")
}

const validConfigYAML = `
keyorix_url: "https://keyorix.example.com"
project_id: 1
mappings:
  - ref: "production/db-password"
    namespace: "default"
    name: "db-secret"
    key: "password"
`

// The metrics bearer token from KEYORIX_METRICS_TOKEN must never be a flag's
// registered default: flag's usage output (printed on -h and on ANY unknown or
// malformed flag, e.g. a typo in the container args) prints every non-empty default
// verbatim, so the token would land in the container log.
func TestMainSubprocess_UsageNeverPrintsMetricsToken(t *testing.T) {
	if os.Getenv("KEYORIX_K8S_SYNC_MAIN_SUBPROCESS") == "1" {
		os.Args = []string{os.Args[0], "-no-such-flag"}
		main()
		return
	}
	const token = "metrics-token-must-not-leak-7f3a"
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_UsageNeverPrintsMetricsToken",
		[]string{"KEYORIX_METRICS_TOKEN=" + token})
	require.Error(t, runErr, "an unknown flag must still stop the agent")
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, "-metrics-bearer-token", "the usage text is printed (otherwise this test proves nothing)")
	assert.NotContains(t, stderr, token)
}

func TestFlagOrEnv(t *testing.T) {
	newFS := func() (*flag.FlagSet, *string) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		return fs, fs.String("tok", "", "")
	}
	t.Setenv("KEYORIX_TEST_FLAG_OR_ENV", "from-env")

	fs, v := newFS()
	require.NoError(t, fs.Parse(nil))
	assert.Equal(t, "from-env", flagOrEnv(fs, "tok", *v, "KEYORIX_TEST_FLAG_OR_ENV"), "flag not given: the environment variable")

	fs, v = newFS()
	require.NoError(t, fs.Parse([]string{"-tok", "from-flag"}))
	assert.Equal(t, "from-flag", flagOrEnv(fs, "tok", *v, "KEYORIX_TEST_FLAG_OR_ENV"), "flag given: the flag wins")

	fs, v = newFS()
	require.NoError(t, fs.Parse([]string{"-tok="}))
	assert.Equal(t, "", flagOrEnv(fs, "tok", *v, "KEYORIX_TEST_FLAG_OR_ENV"), "an explicit empty flag still wins (as with the old env-backed default)")
}
