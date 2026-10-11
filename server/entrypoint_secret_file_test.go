package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveSecretFunc returns the resolve_secret shell function exactly as
// shipped in entrypoint.sh (between its BEGIN/END markers), so the test runs the
// real code, not a copy.
func resolveSecretFunc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("entrypoint.sh")
	require.NoError(t, err)
	s := string(b)
	begin := strings.Index(s, "# --- BEGIN resolve_secret")
	end := strings.Index(s, "# --- END resolve_secret ---")
	require.True(t, begin >= 0 && end > begin, "resolve_secret markers missing from entrypoint.sh")
	return s[begin:end]
}

// runResolve runs resolve_secret KX_SECRET KX_OUT in sh with the given extra
// environment and prints
// "rc=<status> value=[<KX_OUT>] child=[<KX_SECRET>|<KX_OUT> as a child process sees them]".
// The child view is what the server process would inherit: it must never hold a
// value resolved from a file.
func runResolve(t *testing.T, env ...string) (out, errOut string) {
	t.Helper()
	return runResolveWithPath(t, os.Getenv("PATH"), env...)
}

func runResolveWithPath(t *testing.T, path string, env ...string) (out, errOut string) {
	t.Helper()
	if err := exec.Command("stat", "-c", "%a", ".").Run(); err != nil {
		t.Skip("stat -c is not available on this host (the entrypoint targets alpine/busybox and runs in Linux CI)")
	}
	script := resolveSecretFunc(t) + `
resolve_secret KX_SECRET KX_OUT
rc=$?
printf 'rc=%s value=[%s] child=[%s]' "$rc" "$KX_OUT" "$(sh -c 'printf "%s|%s" "$KX_SECRET" "$KX_OUT"')"
`
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append([]string{"PATH=" + path}, env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	_ = cmd.Run()
	return so.String(), se.String()
}

func entrypointSecret(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte(content), mode))
	require.NoError(t, os.Chmod(p, mode))
	return p
}

func TestEntrypointResolveSecret(t *testing.T) {
	t.Run("file value, one newline stripped, not exported", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET_FILE="+entrypointSecret(t, "pa ss\n\n", 0o600))
		assert.Equal(t, "rc=0 value=[pa ss\n] child=[|]", out)
	})
	t.Run("CRLF stripped as one terminator", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET_FILE="+entrypointSecret(t, "pass\r\n", 0o400))
		assert.Equal(t, "rc=0 value=[pass] child=[|]", out)
	})
	t.Run("lone CR stripped, as --passphrase-file does", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET_FILE="+entrypointSecret(t, "pass\r", 0o400))
		assert.Equal(t, "rc=0 value=[pass] child=[|]", out)
	})
	t.Run("direct env value untouched", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET=direct")
		assert.Equal(t, "rc=0 value=[direct] child=[direct|]", out, "the operator's own variable is passed through as set")
	})
	t.Run("neither set", func(t *testing.T) {
		out, _ := runResolve(t)
		assert.Equal(t, "rc=0 value=[] child=[|]", out)
	})
	// docker-compose.yml passes KEYORIX_ADMIN_PASSWORD / KEYORIX_BOOTSTRAP_TOKEN as
	// ${VAR:-}, so with the _FILE form the plain name is EXPORTED and EMPTY. The value
	// must not be written into it: the server would then inherit both NAME and
	// NAME_FILE (refusing to start on the bootstrap token) and hold the admin password
	// in its environ.
	t.Run("exported empty NAME plus NAME_FILE: value not exported", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET=", "KX_SECRET_FILE="+entrypointSecret(t, "TOPSECRET\n", 0o600))
		assert.Equal(t, "rc=0 value=[TOPSECRET] child=[|]", out)
	})
	t.Run("OUT inherited from the environment is not re-exported", func(t *testing.T) {
		out, _ := runResolve(t, "KX_OUT=stale", "KX_SECRET_FILE="+entrypointSecret(t, "TOPSECRET\n", 0o600))
		assert.Equal(t, "rc=0 value=[TOPSECRET] child=[|]", out)
	})
	t.Run("failed read refuses", func(t *testing.T) {
		// A head that writes part of the file and fails: the status checked must be
		// head's, not that of the command after it.
		bin := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(bin, "head"), []byte("#!/bin/sh\nprintf partial\nexit 1\n"), 0o700))
		out, _ := runResolveWithPath(t, bin+":"+os.Getenv("PATH"), "KX_SECRET_FILE="+entrypointSecret(t, "TOPSECRET\n", 0o600))
		assert.Contains(t, out, "rc=1")
		assert.Contains(t, out, "value=[] ")
	})
	t.Run("both set refuses", func(t *testing.T) {
		out, errOut := runResolve(t, "KX_SECRET=direct", "KX_SECRET_FILE="+entrypointSecret(t, "TOPSECRET\n", 0o600))
		assert.Contains(t, out, "rc=1")
		assert.Contains(t, errOut, "both KX_SECRET and KX_SECRET_FILE")
		assert.NotContains(t, out+errOut, "TOPSECRET")
	})
	t.Run("missing file refuses", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET_FILE="+filepath.Join(t.TempDir(), "nope"))
		assert.Contains(t, out, "rc=1")
	})
	t.Run("empty file refuses", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET_FILE="+entrypointSecret(t, "\n", 0o600))
		assert.Contains(t, out, "rc=1")
	})
	for _, mode := range []os.FileMode{0o644, 0o604, 0o660, 0o640, 0o440} {
		t.Run("too open "+mode.String(), func(t *testing.T) {
			out, errOut := runResolve(t, "KX_SECRET_FILE="+entrypointSecret(t, "TOPSECRET\n", mode))
			assert.Contains(t, out, "rc=1", "own-file group access and any other access are refused")
			assert.Contains(t, errOut, "refusing to trust")
			assert.NotContains(t, out+errOut, "TOPSECRET")
		})
	}
}
