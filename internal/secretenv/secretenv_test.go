package secretenv

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVar = "KEYORIX_TEST_SECRETENV"

func writeSecret(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(p, []byte(content), mode))
	require.NoError(t, os.Chmod(p, mode))
	return p
}

func TestLookup_Unset(t *testing.T) {
	v, found, err := Lookup(testVar)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Empty(t, v)
}

func TestLookup_EnvOnly(t *testing.T) {
	t.Setenv(testVar, "from-env")
	v, found, err := Lookup(testVar)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "from-env", v)
}

func TestLookup_EmptyEnvIsUnset(t *testing.T) {
	t.Setenv(testVar, "")
	t.Setenv(testVar+"_FILE", "")
	_, found, err := Lookup(testVar)
	require.NoError(t, err)
	assert.False(t, found, "empty X and empty X_FILE are both 'not set' (compose ${X:-} passthrough)")
}

func TestLookup_FileOnly_TrimsOneTrailingNewline(t *testing.T) {
	cases := map[string]string{
		"hunter2":         "hunter2",
		"hunter2\n":       "hunter2",
		"hunter2\r\n":     "hunter2",
		"hunter2\n\n":     "hunter2\n", // exactly one terminator
		" spaced pw \n":   " spaced pw ",
		"multi\nline\n":   "multi\nline",
		"no-newline-here": "no-newline-here",
	}
	for content, want := range cases {
		t.Run(strings.ReplaceAll(content, "\n", `\n`), func(t *testing.T) {
			t.Setenv(testVar+"_FILE", writeSecret(t, content, 0o600))
			v, found, err := Lookup(testVar)
			require.NoError(t, err)
			assert.True(t, found)
			assert.Equal(t, want, v)
		})
	}
}

func TestLookup_BothSet_Refuses(t *testing.T) {
	t.Setenv(testVar, "plain-secret-value")
	t.Setenv(testVar+"_FILE", writeSecret(t, "file-secret-value\n", 0o600))
	v, found, err := Lookup(testVar)
	require.Error(t, err)
	assert.Empty(t, v)
	assert.False(t, found)
	assert.Contains(t, err.Error(), testVar)
	assert.Contains(t, err.Error(), testVar+"_FILE")
	assert.NotContains(t, err.Error(), "plain-secret-value")
	assert.NotContains(t, err.Error(), "file-secret-value")
}

func TestLookup_UnreadableFile_Refuses(t *testing.T) {
	t.Setenv(testVar+"_FILE", filepath.Join(t.TempDir(), "does-not-exist"))
	v, found, err := Lookup(testVar)
	require.Error(t, err)
	assert.Empty(t, v)
	assert.False(t, found)
	assert.Contains(t, err.Error(), testVar+"_FILE")
}

func TestLookup_UnreadableFile_NoFallbackToYAML(t *testing.T) {
	// A caller that falls back to a config-file value on (found=false, err=nil)
	// must NOT get that chance on error.
	t.Setenv(testVar+"_FILE", filepath.Join(t.TempDir(), "nope"))
	_, found, err := Lookup(testVar)
	require.Error(t, err)
	assert.False(t, found)
}

func TestLookup_EmptyFile_Refuses(t *testing.T) {
	for _, content := range []string{"", "\n", "\r\n"} {
		t.Setenv(testVar+"_FILE", writeSecret(t, content, 0o600))
		_, _, err := Lookup(testVar)
		require.Error(t, err, "content %q", content)
		assert.Contains(t, err.Error(), "empty")
	}
}

func TestLookup_Directory_Refuses(t *testing.T) {
	t.Setenv(testVar+"_FILE", t.TempDir())
	_, _, err := Lookup(testVar)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regular file")
}

func TestLookup_FollowsSymlink(t *testing.T) {
	// Kubernetes Secret volumes expose every key as a symlink into ..data/.
	target := writeSecret(t, "via-symlink\n", 0o600)
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(target, link))
	t.Setenv(testVar+"_FILE", link)
	v, found, err := Lookup(testVar)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "via-symlink", v)
}

func TestLookup_TooLarge_Refuses(t *testing.T) {
	t.Setenv(testVar+"_FILE", writeSecret(t, strings.Repeat("a", maxSecretFileSize+1), 0o600))
	_, _, err := Lookup(testVar)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestLookup_ErrorNeverContainsFileContents(t *testing.T) {
	// A directory path error / empty error must not echo anything but the path.
	p := writeSecret(t, "TOPSECRET-CONTENT", 0o600)
	t.Setenv(testVar, "TOPSECRET-ENV")
	t.Setenv(testVar+"_FILE", p)
	_, _, err := Lookup(testVar)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "TOPSECRET")
}

func TestCheckPermissions(t *testing.T) {
	// Files created by the test are owned by the running user, so the
	// group-readable orchestrator exception does not apply to them.
	cases := []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{"0600 owner rw", 0o600, false},
		{"0400 owner r", 0o400, false},
		{"0440 own file group-readable", 0o440, true},
		{"0640 own file group-readable", 0o640, true},
		{"0644 world readable", 0o644, true},
		{"0444 world readable", 0o444, true},
		{"0604 world readable", 0o604, true},
		{"0660 group writable", 0o660, true},
		{"0620 group writable", 0o620, true},
		{"0666 everyone", 0o666, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPermissions(writeSecret(t, "x", tc.mode))
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "refusing")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// asOrchestratorMount makes the test file look foreign-owned: the running
// "user" is someone else, and the file's group is one the process holds (or not).
func asOrchestratorMount(t *testing.T, path string, holdsGroup bool) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	st := info.Sys().(*syscall.Stat_t)
	oldUID, oldGroups := processUID, processGroups
	t.Cleanup(func() { processUID, processGroups = oldUID, oldGroups })
	processUID = func() int { return int(st.Uid) + 1 }
	processGroups = func() []int {
		if holdsGroup {
			return []int{int(st.Gid)}
		}
		return []int{int(st.Gid) + 1}
	}
}

func TestCheckPermissions_OrchestratorMountedGroupRead(t *testing.T) {
	t.Run("0440 foreign-owned, group held (k8s fsGroup, Docker group_add)", func(t *testing.T) {
		p := writeSecret(t, "x", 0o440)
		asOrchestratorMount(t, p, true)
		require.NoError(t, CheckPermissions(p))
	})
	t.Run("0640 foreign-owned, group held", func(t *testing.T) {
		p := writeSecret(t, "x", 0o640)
		asOrchestratorMount(t, p, true)
		require.NoError(t, CheckPermissions(p))
	})
	t.Run("0440 foreign-owned, group NOT held", func(t *testing.T) {
		p := writeSecret(t, "x", 0o440)
		asOrchestratorMount(t, p, false)
		require.Error(t, CheckPermissions(p))
	})
	t.Run("0444 foreign-owned, group held: other-readable still refused", func(t *testing.T) {
		p := writeSecret(t, "x", 0o444)
		asOrchestratorMount(t, p, true)
		require.Error(t, CheckPermissions(p))
	})
	t.Run("0460 foreign-owned, group held: group-writable still refused", func(t *testing.T) {
		p := writeSecret(t, "x", 0o460)
		asOrchestratorMount(t, p, true)
		require.Error(t, CheckPermissions(p))
	})
}

func TestLookupChecked_RefusesLooseFile_LookupDoesNot(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o644} {
		t.Setenv(testVar+"_FILE", writeSecret(t, "TOPSECRET\n", mode))
		_, _, err := LookupChecked(testVar)
		require.Error(t, err, "mode %04o", mode)
		assert.Contains(t, err.Error(), "refusing")
		assert.NotContains(t, err.Error(), "TOPSECRET")

		v, found, err := Lookup(testVar)
		require.NoError(t, err, "plain Lookup leaves the policy to the caller")
		assert.True(t, found)
		assert.Equal(t, "TOPSECRET", v)
	}
}

func TestLookupChecked_AcceptsStrictFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		t.Setenv(testVar+"_FILE", writeSecret(t, "TOPSECRET\n", mode))
		v, found, err := LookupChecked(testVar)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "TOPSECRET", v)
	}
}

func TestLookupChecked_AcceptsOrchestratorMount(t *testing.T) {
	p := writeSecret(t, "TOPSECRET\n", 0o440)
	asOrchestratorMount(t, p, true)
	t.Setenv(testVar+"_FILE", p)
	v, _, err := LookupChecked(testVar)
	require.NoError(t, err)
	assert.Equal(t, "TOPSECRET", v)
}

func TestLookupChecked_EnvValueNeedsNoFile(t *testing.T) {
	t.Setenv(testVar, "direct")
	v, found, err := LookupChecked(testVar)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "direct", v)
}

func TestCheckPermissions_Missing(t *testing.T) {
	require.Error(t, CheckPermissions(filepath.Join(t.TempDir(), "nope")))
}

func TestCheckPermissions_FollowsSymlinkAndChecksTarget(t *testing.T) {
	good := writeSecret(t, "x", 0o400)
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(good, link))
	require.NoError(t, CheckPermissions(link))

	bad := writeSecret(t, "x", 0o644)
	badLink := filepath.Join(t.TempDir(), "badlink")
	require.NoError(t, os.Symlink(bad, badLink))
	require.Error(t, CheckPermissions(badLink))
}

func TestFilePaths_ReturnsOnlySetFileVars(t *testing.T) {
	a, b := "KEYORIX_TEST_SECRETENV_A", "KEYORIX_TEST_SECRETENV_B"
	p := writeSecret(t, "x", 0o600)
	t.Setenv(a+"_FILE", p)
	t.Setenv(b+"_FILE", "")
	assert.Equal(t, []string{p}, FilePaths(a, b))
}
