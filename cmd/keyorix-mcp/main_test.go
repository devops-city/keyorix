package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// KEYORIX_MCP_MAX_READS unset must apply defaultMaxReads (a bounded, non-infinite
// ceiling) rather than "unlimited" — see the defaultMaxReads comment for rationale.
func TestResolveMaxReads_UnsetAppliesDefault(t *testing.T) {
	n, usedDefault, err := resolveMaxReads("")
	require.NoError(t, err)
	assert.True(t, usedDefault)
	assert.Equal(t, defaultMaxReads, n)
}

func TestResolveMaxReads_ValidOverride(t *testing.T) {
	n, usedDefault, err := resolveMaxReads("500")
	require.NoError(t, err)
	assert.False(t, usedDefault)
	assert.Equal(t, 500, n)
}

func TestResolveMaxReads_InvalidIsFatal(t *testing.T) {
	for _, raw := range []string{"not-a-number", "0", "-5", "3.5"} {
		_, _, err := resolveMaxReads(raw)
		assert.Error(t, err, "raw=%q must be rejected, not silently fall back to unlimited", raw)
	}
}

// An unset KEYORIX_MCP_ALLOWED_REFS means "not configured" — no restriction, no error.
func TestResolveAllowedRefs_UnsetIsNoRestriction(t *testing.T) {
	patterns, err := resolveAllowedRefs("")
	require.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestResolveAllowedRefs_ValidPatterns(t *testing.T) {
	patterns, err := resolveAllowedRefs("app/production/*, app/staging/db-*")
	require.NoError(t, err)
	assert.Equal(t, []string{"app/production/*", "app/staging/db-*"}, patterns)
}

// A set-but-empty-after-parsing value (e.g. a stray trailing comma from templating an
// empty list) must be a fatal misconfiguration, not a silent fail-open to "no
// restriction" — see the resolveAllowedRefs comment for why (#122 finding).
func TestResolveAllowedRefs_ZeroPatternsIsFatal(t *testing.T) {
	for _, raw := range []string{",", ",,", "   ", " , "} {
		patterns, err := resolveAllowedRefs(raw)
		assert.Error(t, err, "raw=%q must be rejected, not silently allow everything", raw)
		assert.Nil(t, patterns)
	}
}

// KEYORIX_MCP_MAX_LIST_CALLS unset must apply defaultMaxListCalls (a bounded,
// non-infinite ceiling) rather than "unlimited" — mirrors resolveMaxReads (#G44).
func TestResolveMaxListCalls_UnsetAppliesDefault(t *testing.T) {
	n, usedDefault, err := resolveMaxListCalls("")
	require.NoError(t, err)
	assert.True(t, usedDefault)
	assert.Equal(t, defaultMaxListCalls, n)
}

func TestResolveMaxListCalls_ValidOverride(t *testing.T) {
	n, usedDefault, err := resolveMaxListCalls("250")
	require.NoError(t, err)
	assert.False(t, usedDefault)
	assert.Equal(t, 250, n)
}

func TestResolveMaxListCalls_InvalidIsFatal(t *testing.T) {
	for _, raw := range []string{"not-a-number", "0", "-5", "3.5"} {
		_, _, err := resolveMaxListCalls(raw)
		assert.Error(t, err, "raw=%q must be rejected, not silently fall back to unlimited", raw)
	}
}

// runMainSubprocess re-executes this test binary with -test.run scoped to a single
// test, whose body detects KEYORIX_MCP_MAIN_SUBPROCESS=1 and calls main() directly
// instead of running normal test assertions. This lets us exercise main()'s log.Fatal
// (os.Exit(1)) and normal-return paths from the OUTSIDE, by inspecting the subprocess's
// exit code and stderr, without terminating the actual test process. Mirrors the
// existing subprocess pattern in internal/cli/system/system_s17_test.go
// (TestRunAudit_ExitOnFailure).
//
// extraEnv are additional KEY=VALUE entries; any KEYORIX_-prefixed variable already in
// this process's environment is stripped first so ambient developer config (e.g. a
// local KEYORIX_TOKEN) can't leak into the subprocess and change its behavior.
func runMainSubprocess(t *testing.T, testName string, extraEnv []string, stdin *bytes.Reader) (stderr string, exitCode int, runErr error) {
	t.Helper()

	var env []string
	for _, kv := range os.Environ() {
		if len(kv) >= 8 && kv[:8] == "KEYORIX_" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, extraEnv...)
	env = append(env, "KEYORIX_MCP_MAIN_SUBPROCESS=1")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = stdin
	} else {
		cmd.Stdin = bytes.NewReader(nil)
	}
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr = cmd.Run()
	exitCode = 0
	if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
		exitCode = exitErr.ExitCode()
	}
	return stderrBuf.String(), exitCode, runErr
}

// A missing KEYORIX_URL must be a fatal, immediate startup error.
func TestMainSubprocess_MissingURL(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_MissingURL", nil, nil)
	require.Error(t, runErr, "main() must exit non-zero when KEYORIX_URL is unset")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "KEYORIX_URL is required")
}

// A missing KEYORIX_TOKEN must be a fatal, immediate startup error (checked after URL).
func TestMainSubprocess_MissingToken(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_MissingToken",
		[]string{"KEYORIX_URL=http://127.0.0.1:1"}, nil)
	require.Error(t, runErr, "main() must exit non-zero when KEYORIX_TOKEN is unset")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "KEYORIX_TOKEN is required")
}

// A KEYORIX_URL that fails NewKeyorixClient's own validation (non-https, non-loopback)
// must abort startup via the client-construction error path, not silently proceed.
func TestMainSubprocess_InvalidClientURL(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_InvalidClientURL",
		[]string{"KEYORIX_URL=http://example.com", "KEYORIX_TOKEN=t"}, nil)
	require.Error(t, runErr, "main() must exit non-zero when KEYORIX_URL fails client validation")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "must use https")
}

// A set-but-empty-after-parsing KEYORIX_MCP_ALLOWED_REFS must abort startup rather than
// silently run unrestricted (#122).
func TestMainSubprocess_InvalidAllowedRefs(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_InvalidAllowedRefs",
		[]string{"KEYORIX_URL=http://127.0.0.1:1", "KEYORIX_TOKEN=t", "KEYORIX_MCP_ALLOWED_REFS=,"}, nil)
	require.Error(t, runErr, "main() must exit non-zero on an unusable KEYORIX_MCP_ALLOWED_REFS")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "refusing to start unrestricted")
}

// A non-numeric KEYORIX_MCP_MAX_READS must abort startup, not silently fall back.
func TestMainSubprocess_InvalidMaxReads(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_InvalidMaxReads",
		[]string{"KEYORIX_URL=http://127.0.0.1:1", "KEYORIX_TOKEN=t", "KEYORIX_MCP_MAX_READS=abc"}, nil)
	require.Error(t, runErr, "main() must exit non-zero on an invalid KEYORIX_MCP_MAX_READS")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "KEYORIX_MCP_MAX_READS must be a positive integer")
}

// A non-numeric KEYORIX_MCP_MAX_LIST_CALLS must abort startup, not silently fall back.
func TestMainSubprocess_InvalidMaxListCalls(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_InvalidMaxListCalls",
		[]string{"KEYORIX_URL=http://127.0.0.1:1", "KEYORIX_TOKEN=t", "KEYORIX_MCP_MAX_LIST_CALLS=abc"}, nil)
	require.Error(t, runErr, "main() must exit non-zero on an invalid KEYORIX_MCP_MAX_LIST_CALLS")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "KEYORIX_MCP_MAX_LIST_CALLS must be a positive integer")
}

// With only the required KEYORIX_URL/KEYORIX_TOKEN set, main() must start up cleanly
// using the documented defaults (defaultMaxReads/defaultMaxListCalls, no ref
// allowlist) and, once stdin hits EOF, return normally (exit 0) rather than treating a
// clean disconnect as fatal.
func TestMainSubprocess_SuccessWithDefaults(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_SuccessWithDefaults",
		[]string{"KEYORIX_URL=http://127.0.0.1:1", "KEYORIX_TOKEN=t"}, bytes.NewReader(nil))
	require.NoError(t, runErr, "stderr: %s", stderr)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stderr, "ready (server dev)")
	assert.Contains(t, stderr, "applying default per-process read cap of 100")
	assert.Contains(t, stderr, "applying default per-process list-call cap of 100")
	assert.NotContains(t, stderr, "ref allowlist active")
}

// Explicit overrides for KEYORIX_MCP_MAX_READS, KEYORIX_MCP_MAX_LIST_CALLS, and
// KEYORIX_MCP_ALLOWED_REFS must all take effect and be logged as active (not the
// default-applied branch), and SetAllowedRefs must actually be invoked.
func TestMainSubprocess_SuccessWithExplicitOverrides(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_SuccessWithExplicitOverrides",
		[]string{
			"KEYORIX_URL=http://127.0.0.1:1",
			"KEYORIX_TOKEN=t",
			"KEYORIX_MCP_MAX_READS=5",
			"KEYORIX_MCP_MAX_LIST_CALLS=7",
			"KEYORIX_MCP_ALLOWED_REFS=app/prod/*",
		}, bytes.NewReader(nil))
	require.NoError(t, runErr, "stderr: %s", stderr)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stderr, "ready (server dev)")
	assert.Contains(t, stderr, "per-process read cap active: 5")
	assert.Contains(t, stderr, "per-process list-call cap active: 7")
	assert.Contains(t, stderr, "ref allowlist active: 1 pattern(s)")
	assert.NotContains(t, stderr, "applying default")
}

// A stdin stream that fails to parse as JSON-RPC (rather than cleanly hitting EOF) makes
// Server.Serve return a non-nil error; main() must treat that as fatal
// (log.Fatalf("serve: ...")) instead of exiting cleanly.
func TestMainSubprocess_ServeErrorIsFatal(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		main()
		return
	}
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_ServeErrorIsFatal",
		[]string{"KEYORIX_URL=http://127.0.0.1:1", "KEYORIX_TOKEN=t"},
		bytes.NewReader([]byte("this is not json-rpc\n")))
	require.Error(t, runErr, "main() must exit non-zero when Serve reports a non-EOF error")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "serve:")
}
