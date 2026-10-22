//go:build noaws && noazure && nogcp

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAirgapProfile_RefusesHTTPAutoCert is the guard for AIRGAP-PROOF-1 F1: under
// `-tags noaws,noazure,nogcp` the profile constant must be on and Config.Validate
// (the call server/main.go makes before listening) must refuse auto_cert, with and
// without tls.enabled. Red on a tree without the refusal, green with it.
func TestAirgapProfile_RefusesHTTPAutoCert(t *testing.T) {
	require.True(t, airgapProfile, "noaws+noazure+nogcp must select the air-gapped profile")
	for _, tlsEnabled := range []bool{true, false} {
		err := autoCertConfig(tlsEnabled).Validate()
		require.ErrorIs(t, err, ErrAutoCertInAirgapBuild, "tls.enabled=%v", tlsEnabled)
	}

	// Calibration: the same config with static certificate files validates.
	c := autoCertConfig(true)
	c.Server.HTTP.TLS.AutoCert = false
	c.Server.HTTP.TLS.Domains = nil
	c.Server.HTTP.TLS.CertFile, c.Server.HTTP.TLS.KeyFile = "cert.pem", "key.pem"
	require.NoError(t, c.Validate())
}
