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
