package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEntrypointResolveSecret_PermissionMatrix runs resolve_secret (the shipped
// function, extracted from entrypoint.sh) over the secret-file trust table that
// internal/secretenv and the CLI are held to
// (internal/secretenv/testdata/permission-matrix.tsv). The entrypoint's copy had
// drifted: it never got the #3393 owner rule, so a KEYORIX_ADMIN_PASSWORD_FILE
// owned by an unrelated account (which can rewrite it, and so choose the first
// admin's password) was trusted (SECRETENV-REVIEW-1).
//
// The identities are faked with PATH shims: `id` reports the process uid and
// groups the row asks for, and `stat` reports the file's owner and group, passing
// the mode query (%a) to the real stat (GNU, or BSD's %Lp, so this also runs on
// macOS; the matrix has no setuid/setgid/sticky rows, which %Lp would drop).
func TestEntrypointResolveSecret_PermissionMatrix(t *testing.T) {
	realStat, err := exec.LookPath("stat")
	require.NoError(t, err)
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "id"), []byte(`#!/bin/sh
case "$1" in
-u) echo "$KX_FAKE_EUID" ;;
-G) echo "$KX_FAKE_GROUPS" ;;
*) exit 2 ;;
esac
`), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "stat"), []byte(`#!/bin/sh
# called as: stat -L -c FORMAT PATH
case "$3" in
%u) echo "$KX_FAKE_FILE_UID"; exit 0 ;;
%g) echo "$KX_FAKE_FILE_GID"; exit 0 ;;
esac
if `+realStat+` -c %a / >/dev/null 2>&1; then exec `+realStat+` "$@"; fi
exec `+realStat+` -L -f %Lp "$4"
`), 0o700))

	f, err := os.Open("../internal/secretenv/testdata/permission-matrix.tsv")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	script := resolveSecretFunc(t) + `
resolve_secret KX_SECRET KX_OUT
printf 'rc=%s value=[%s]' "$?" "$KX_OUT"
`
	rows := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := strings.Split(line, "\t")
		require.Len(t, c, 6, "malformed matrix row %q", line)
		mode, err := strconv.ParseUint(c[0], 8, 32)
		require.NoError(t, err, "row %q", line)
		process, owner, group, verdict, why := c[1], c[2], c[3], c[4], c[5]
		rows++
		t.Run(c[0]+"/"+process+"/"+owner+"/"+group, func(t *testing.T) {
			euid := "4000"
			if process == "root" {
				euid = "0"
			}
			fileUID := map[string]string{"self": euid, "root": "0", "other": "4242"}[owner]
			groups := "5556"
			if group == "held" {
				groups = "5556 5555"
			}
			p := filepath.Join(t.TempDir(), "s")
			require.NoError(t, os.WriteFile(p, []byte("TOPSECRET\n"), 0o600))
			require.NoError(t, os.Chmod(p, os.FileMode(mode)))

			cmd := exec.Command("sh", "-c", script)
			cmd.Env = []string{
				"PATH=" + bin + ":" + os.Getenv("PATH"),
				"KX_SECRET_FILE=" + p,
				"KX_FAKE_EUID=" + euid, "KX_FAKE_GROUPS=" + groups,
				"KX_FAKE_FILE_UID=" + fileUID, "KX_FAKE_FILE_GID=5555",
			}
			var so, se bytes.Buffer
			cmd.Stdout, cmd.Stderr = &so, &se
			_ = cmd.Run()
			out := so.String()
			if verdict == "accept" {
				require.Equal(t, "rc=0 value=[TOPSECRET]", out, "must accept (%s); stderr: %s", why, se.String())
				return
			}
			require.Contains(t, out, "rc=1", "must refuse (%s)", why)
			require.Contains(t, out, "value=[]")
			require.Contains(t, se.String(), "refusing to trust")
			require.NotContains(t, out+se.String(), "TOPSECRET")
		})
	}
	require.NoError(t, sc.Err())
	require.NotZero(t, rows)
}
