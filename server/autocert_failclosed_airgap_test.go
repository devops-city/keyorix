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
