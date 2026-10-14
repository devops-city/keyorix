//go:build !noaws && !noazure && !nogcp && !nok8s

package dynamic

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew_UnsupportedBackend validates that an unsupported backend type is rejected.
func TestNew_UnsupportedBackend(t *testing.T) {
	_, err := New("cassandra", false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
	assert.Contains(t, err.Error(), "cassandra")
}

// TestNew_AllBackendTypes validates all supported backend types can be constructed.
func TestNew_AllBackendTypes(t *testing.T) {
	backends := []struct {
		name      string
		ephemeral bool
	}{
		{"postgres", false},
		{"mysql", false},
		{"mongodb", false},
		{"redis", false},
		{"aws-sts", true},
		{"gcp", true},
		{"azure", true},
		{"kubernetes", true},
	}
	for _, b := range backends {
		eng, err := New(b.name, false, false)
		require.NoErrorf(t, err, "backend %q must be constructable", b.name)
		assert.Equal(t, b.name, eng.BackendType())
		if b.ephemeral {
			assert.Truef(t, eng.IsEphemeralBackend(), "%s must be ephemeral", b.name)
		} else {
			assert.Falsef(t, eng.IsEphemeralBackend(), "%s must not be ephemeral", b.name)
		}
	}
}

// TestRandString_Length validates that randString returns exactly n characters.
func TestRandString_Length(t *testing.T) {
	for _, n := range []int{0, 1, 8, 16, 64} {
		s, err := randString(n)
		require.NoError(t, err)
		assert.Lenf(t, s, n, "randString(%d)", n)
	}
}

// TestRandString_Alphabet validates that randString only uses safe characters.
func TestRandString_Alphabet(t *testing.T) {
	for range 20 {
		s, err := randString(32)
		require.NoError(t, err)
		for _, r := range s {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			assert.Truef(t, ok, "unexpected character %q in randString output", r)
		}
	}
}
