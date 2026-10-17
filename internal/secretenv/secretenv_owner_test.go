package secretenv

import (
	"os"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #3393: the owner of a file can always chmod and rewrite it, so a key-material
// file is trusted only when it is owned by the running user or by root. These
// tests make the running "user" someone else through the processUID seam: the
// file the test writes is then owned by a uid that is neither the process nor 0,
// which is what a KEK or master-password file owned by an unprivileged account
// looks like to a server running as root.

// asForeignNonRootOwner makes the test file's real owner (the test user) look
// like an unrelated account: the process claims another euid. It skips when the
// test runs as root, since a root-owned file is trusted by design.
func asForeignNonRootOwner(t *testing.T, path string) (owner int) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid == 0 {
		t.Skip("running as root: the test file is root-owned, which is trusted")
	}
	old := processUID
	t.Cleanup(func() { processUID = old })
	processUID = func() int { return int(st.Uid) + 1 }
	return int(st.Uid)
}

func TestCheckPermissions_RefusesForeignNonRootOwner(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		t.Run(mode.String(), func(t *testing.T) {
			p := writeSecret(t, "TOPSECRET\n", mode)
			owner := asForeignNonRootOwner(t, p)
			err := CheckPermissions(p)
			require.Error(t, err, "a %04o file owned by uid %d (not the process, not root) must be refused", mode, owner)
			assert.Contains(t, err.Error(), p, "the refusal names the file")
			assert.Contains(t, err.Error(), "uid "+strconv.Itoa(owner), "the refusal names the owner uid")
			assert.Contains(t, err.Error(), "refusing")
			assert.NotContains(t, err.Error(), "TOPSECRET")
		})
	}
}

func TestLookupChecked_RefusesForeignNonRootOwner(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		t.Run(mode.String(), func(t *testing.T) {
			p := writeSecret(t, "TOPSECRET\n", mode)
			owner := asForeignNonRootOwner(t, p)
			t.Setenv(testVar+"_FILE", p)
			v, found, err := LookupChecked(testVar)
			require.Error(t, err, "a %04o key-material file owned by uid %d (not the process, not root) must be refused", mode, owner)
			assert.False(t, found)
			assert.Empty(t, v)
			assert.Contains(t, err.Error(), p, "the refusal names the file")
			assert.Contains(t, err.Error(), testVar+"_FILE", "the refusal names the variable")
			assert.Contains(t, err.Error(), "uid "+strconv.Itoa(owner), "the refusal names the owner uid")
			assert.NotContains(t, err.Error(), "TOPSECRET")
		})
	}
}

// Plain Lookup keeps leaving the policy to its caller: the owner rule applies
// where permissions are judged (CheckPermissions, LookupChecked), not to every read.
func TestLookup_ForeignNonRootOwner_LeftToCaller(t *testing.T) {
	p := writeSecret(t, "TOPSECRET\n", 0o600)
	asForeignNonRootOwner(t, p)
	t.Setenv(testVar+"_FILE", p)
	v, found, err := Lookup(testVar)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "TOPSECRET", v)
}

// withOwner makes every file report owner uid/gid and the process run as euid,
// holding the file's group.
func withOwner(t *testing.T, uid, gid, euid int) {
	t.Helper()
	oldUID, oldGroups, oldOwner := processUID, processGroups, fileOwner
	t.Cleanup(func() { processUID, processGroups, fileOwner = oldUID, oldGroups, oldOwner })
	fileOwner = func(os.FileInfo) (int, int, bool) { return uid, gid, true }
	processUID = func() int { return euid }
	processGroups = func() []int { return []int{gid} }
}

// The second shape in #3393: a group-readable file in a group the process holds
// used to pass whenever its owner was anyone but the running user. Only root
// (the kubelet, Docker Swarm) is a trusted foreign owner now.
func TestCheckPermissions_GroupReadableForeignNonRootOwner_Refuses(t *testing.T) {
	for _, mode := range []os.FileMode{0o440, 0o640} {
		p := writeSecret(t, "x", mode)
		withOwner(t, 1000, 4242, 1001)
		err := CheckPermissions(p)
		require.Error(t, err, "mode %04o", mode)
		assert.Contains(t, err.Error(), "uid 1000")
		assert.Contains(t, err.Error(), "uid 1001")
	}
}

func TestCheckPermissions_TrustedOwners(t *testing.T) {
	cases := []struct {
		name           string
		mode           os.FileMode
		uid, euid      int
		wantErrContain string
	}{
		{"0400 root-owned, server non-root", 0o400, 0, 1001, ""},
		{"0440 root-owned, server non-root (k8s fsGroup)", 0o440, 0, 1001, ""},
		{"0600 root-owned, server root", 0o600, 0, 0, ""},
		{"0600 own file", 0o600, 1001, 1001, ""},
		{"0400 own file", 0o400, 1001, 1001, ""},
		{"0400 owned by uid 1000, server root", 0o400, 1000, 0, "uid 1000"},
		{"0600 owned by uid 1000, server 1001", 0o600, 1000, 1001, "uid 1000"},
		{"0440 root-owned, server root: group-readable own file", 0o440, 0, 0, "owned by the running user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeSecret(t, "x", tc.mode)
			withOwner(t, tc.uid, 4242, tc.euid)
			err := CheckPermissions(p)
			if tc.wantErrContain == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrContain)
		})
	}
}

func TestLookupChecked_RootOwnedFileAccepted(t *testing.T) {
	p := writeSecret(t, "TOPSECRET\n", 0o400)
	withOwner(t, 0, 4242, 1001)
	t.Setenv(testVar+"_FILE", p)
	v, found, err := LookupChecked(testVar)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "TOPSECRET", v)
}

// Fail closed when the platform does not say who owns the file.
func TestCheckPermissions_UnknownOwner_Refuses(t *testing.T) {
	p := writeSecret(t, "x", 0o600)
	old := fileOwner
	t.Cleanup(func() { fileOwner = old })
	fileOwner = func(os.FileInfo) (int, int, bool) { return 0, 0, false }
	err := CheckPermissions(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "owner cannot be determined")
}
