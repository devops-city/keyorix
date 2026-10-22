//go:build noaws && noazure && nogcp

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestAirgapServer_RefusesHTTPAutoCert: the air-gapped server binary refuses
// server.http.tls.auto_cert through the same Config.Validate call main() makes
// before listening (AIRGAP-PROOF-1 F1). Lives in package server because the
// release-dry-run workflow runs `go test -tags noaws,noazure,nogcp ./server/...`;
// the same assertion sits next to the code in internal/config.
func TestAirgapServer_RefusesHTTPAutoCert(t *testing.T) {
	c := &config.Config{}
	c.Server.HTTP.Port = "8080"
	c.Storage.Type = "local"
	c.Storage.Database.Path = "./test.db"
	c.Server.HTTP.TLS.Enabled = true
	c.Server.HTTP.TLS.AutoCert = true
	c.Server.HTTP.TLS.Domains = []string{"keyorix.example.com"}

	require.ErrorIs(t, c.Validate(), config.ErrAutoCertInAirgapBuild)

	// Calibration: static certificate files validate.
	c.Server.HTTP.TLS.AutoCert = false
	c.Server.HTTP.TLS.Domains = nil
	c.Server.HTTP.TLS.CertFile, c.Server.HTTP.TLS.KeyFile = "cert.pem", "key.pem"
	require.NoError(t, c.Validate())
}

// TestAirgapServer_S27_AutoCertTLSRefused and
// TestAirgapServer_S27_AutoCertBadCipherRefused are the air-gap counterparts of
// TestStartHTTPServer_S27_AutoCertTLS / _AutoCertBadCipher (autocert_tls_full_test.go,
// not built under these tags). They take the same fixture config and assert that
// initializeCoreService, the boot step those tests rely on, refuses it with
// config.ErrAutoCertInAirgapBuild instead of starting an ACME server.
func TestAirgapServer_S27_AutoCertTLSRefused(t *testing.T) {
	initI18n(t)
	t.Chdir(t.TempDir())

	cfg := autoCertTLSFixtureConfig("0", "httptest_s27_autocert.db", "s27-autocert-tls.test.invalid")

	core, _, err := initializeCoreService(cfg)
	require.ErrorIs(t, err, config.ErrAutoCertInAirgapBuild)
	require.Nil(t, core, "no core service may be built for a refused auto_cert config")
}

func TestAirgapServer_S27_AutoCertBadCipherRefused(t *testing.T) {
	initI18n(t)
	t.Chdir(t.TempDir())

	cfg := autoCertTLSFixtureConfig("0", "httptest_s27_autocert_badcipher.db", "s27-autocert-badcipher.test.invalid")

	// The original sets the bad cipher only AFTER initializeCoreService (Validate
	// rejects it earlier), so the config init sees is exactly this one.
	core, _, err := initializeCoreService(cfg)
	require.ErrorIs(t, err, config.ErrAutoCertInAirgapBuild)
	require.Nil(t, core)
}
