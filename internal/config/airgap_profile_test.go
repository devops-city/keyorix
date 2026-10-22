package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// autoCertConfig is a config that validates except for what the test changes.
func autoCertConfig(tlsEnabled bool) *Config {
	c := &Config{}
	c.Server.HTTP.Port = "8080"
	c.Storage.Type = "local"
	c.Storage.Database.Path = "./test.db"
	c.Server.HTTP.TLS.Enabled = tlsEnabled
	c.Server.HTTP.TLS.AutoCert = true
	c.Server.HTTP.TLS.Domains = []string{"keyorix.example.com"}
	return c
}

// TestValidateAutoCertForProfile pins the decision for both profiles in every
// build, so the default `go test` covers the air-gapped branch too. Calibration
// rows (auto_cert off, or the full profile) must pass: a guard that refuses
// everything is not a guard.
func TestValidateAutoCertForProfile(t *testing.T) {
	for _, tlsEnabled := range []bool{true, false} {
		c := autoCertConfig(tlsEnabled)
		require.ErrorIs(t, validateAutoCertForProfile(c, true), ErrAutoCertInAirgapBuild,
			"air-gapped profile must refuse auto_cert (tls.enabled=%v)", tlsEnabled)
		require.NoError(t, validateAutoCertForProfile(c, false),
			"full profile must accept auto_cert (tls.enabled=%v)", tlsEnabled)

		c.Server.HTTP.TLS.AutoCert = false
		require.NoError(t, validateAutoCertForProfile(c, true), "no auto_cert: nothing to refuse")
	}
}

// TestErrAutoCertInAirgapBuild_Message: the refusal names the option, says why,
// and says what to configure instead (same style as the cloud-KMS refusal).
func TestErrAutoCertInAirgapBuild_Message(t *testing.T) {
	msg := ErrAutoCertInAirgapBuild.Error()
	assert.Contains(t, msg, "server.http.tls.auto_cert")
	assert.Contains(t, msg, "not available in this build")
	assert.Contains(t, msg, "certificate authority")
	assert.Contains(t, msg, "cert_file")
	assert.Contains(t, msg, "internal CA")
}

// TestValidate_HTTPAutoCertMatchesProfile drives the real Config.Validate with
// whatever profile this binary was built for: refused in the air-gapped build
// (see airgap_profile_airgap_test.go for the tagged assertion), accepted
// everywhere else.
func TestValidate_HTTPAutoCertMatchesProfile(t *testing.T) {
	err := autoCertConfig(true).Validate()
	if airgapProfile {
		require.ErrorIs(t, err, ErrAutoCertInAirgapBuild)
		return
	}
	require.NoError(t, err, "the non-air-gapped build must still accept auto_cert")
}
