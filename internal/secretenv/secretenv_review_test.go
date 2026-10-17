package secretenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cases from the REVIEW-COVERAGE-1 pass (2026-10-17) that secretenv_test.go did
// not pin: device files, the lone-CR terminator, the exact size cap, precedence
// when the file is also broken, and LookupChecked judging a symlink's target.

// A character device opens without blocking (unlike a FIFO), so only the
// regular-file check on the opened descriptor stands between a mis-pointed
// X_FILE=/dev/zero and a 1 MiB read of zeros used as a secret.
func TestLookup_CharDevice_Refuses(t *testing.T) {
	for _, dev := range []string{"/dev/null", "/dev/zero"} {
		if _, err := os.Stat(dev); err != nil {
			t.Skipf("%s not present: %v", dev, err)
		}
		for name, read := range map[string]func() error{
			"Lookup":        func() error { _, _, err := Lookup(testVar); return err },
			"LookupChecked": func() error { _, _, err := LookupChecked(testVar); return err },
			"ReadFile":      func() error { _, err := ReadFile(dev); return err },
		} {
			t.Run(dev+"/"+name, func(t *testing.T) {
				t.Setenv(testVar+"_FILE", dev)
				err := read()
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrNotRegular)
			})
		}
	}
}

func TestLookup_TerminatorEdgeCases(t *testing.T) {
	for content, want := range map[string]string{
		"pw\r":   "pw",   // lone CR (old Mac editors)
		"pw\n\r": "pw\n", // "\n" is stripped only when it is last; then one "\r"
		"pw\r\r": "pw\r", // one terminator, not all of them
		"\tpw\t": "\tpw\t",
	} {
		t.Run(strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(content), func(t *testing.T) {
			t.Setenv(testVar+"_FILE", writeSecret(t, content, 0o600))
			v, _, err := Lookup(testVar)
			require.NoError(t, err)
			assert.Equal(t, want, v)
		})
	}
}

func TestLookup_SizeCapIsInclusive(t *testing.T) {
	t.Setenv(testVar+"_FILE", writeSecret(t, strings.Repeat("a", maxSecretFileSize), 0o600))
	v, _, err := Lookup(testVar)
	require.NoError(t, err, "a file of exactly the cap is accepted")
	assert.Len(t, v, maxSecretFileSize)
}

// Precedence is decided before the file is touched: both set is a refusal even
// when the file is missing, so the error names the real misconfiguration.
func TestLookup_BothSet_RefusesBeforeReadingTheFile(t *testing.T) {
	t.Setenv(testVar, "direct-value")
	t.Setenv(testVar+"_FILE", filepath.Join(t.TempDir(), "missing"))
	_, found, err := Lookup(testVar)
	require.Error(t, err)
	assert.False(t, found)
	assert.Contains(t, err.Error(), "both")
	assert.NotContains(t, err.Error(), "direct-value")
}

// LookupChecked follows a symlink (the Kubernetes layout) and judges the mode
// of the target it actually opened, not of the link.
func TestLookupChecked_SymlinkToLooseTarget_Refuses(t *testing.T) {
	target := writeSecret(t, "TOPSECRET\n", 0o644)
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(target, link))
	t.Setenv(testVar+"_FILE", link)
	_, _, err := LookupChecked(testVar)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too open")
	assert.NotContains(t, err.Error(), "TOPSECRET")
}
