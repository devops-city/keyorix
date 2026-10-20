package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BOOT-REFUSALS-1 "Misleading messages" item 8: a tls.allowed_ciphers typo was
// refused only by the transport-security check, after start-up lines that read
// as readiness. It is a config error, so Validate() refuses it.
func TestValidate_RefusesUnknownCipherSuite(t *testing.T) {
	for _, grpc := range []bool{false, true} {
		c := validLocalConfig()
		inst := &c.Server.HTTP
		want := "server.http.tls.allowed_ciphers"
		if grpc {
			inst = &c.Server.GRPC
			want = "server.grpc.tls.allowed_ciphers"
		}
		inst.Enabled = true
		inst.Port = "18443"
		inst.TLS.AllowedCiphers = []string{"TLS_RSA_WITH_RC4_128_SHA"}
		err := c.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), want)
		assert.Contains(t, err.Error(), "is not a recognized, secure TLS 1.2 cipher suite", "the page's Match text")
		assert.False(t, strings.HasPrefix(err.Error(), "server.http.server"), err.Error())
	}
	// A disabled listener's leftover allowlist is not an error.
	c := validLocalConfig()
	c.Server.GRPC.Enabled = false
	c.Server.GRPC.TLS.AllowedCiphers = []string{"nope"}
	require.NoError(t, c.Validate())
}
