package grpc

import (
	"math"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewServer_ClampsOversizedMaxRequestBodyBytes exercises the branch that clamps
// MaxRequestBodyBytes when the configured value exceeds math.MaxInt32. Without the
// clamp the int64→int conversion at grpc.MaxRecvMsgSize/MaxSendMsgSize would overflow
// on 32-bit platforms.
func TestNewServer_ClampsOversizedMaxRequestBodyBytes(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	cfg := &config.Config{}
	// Set a value larger than MaxInt32 to force the clamp branch.
	cfg.Server.GRPC.MaxRequestBodyBytes = math.MaxInt32 + 1

	srv, err := NewServer(cfg, h.CoreService)
	require.NoError(t, err, "NewServer must not error when MaxRequestBodyBytes exceeds MaxInt32")
	require.NotNil(t, srv)
	srv.Stop()
}

// TestNewServer_RefusesAutoCert: there is no ACME on gRPC, so auto_cert used to
// start a server whose every handshake failed (AUTH-2 item 3). NewServer must
// refuse it, so a caller that skipped Config.Validate still fails at start-up.
func TestNewServer_RefusesAutoCert(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = true

	srv, err := NewServer(cfg, h.CoreService)
	require.ErrorIs(t, err, config.ErrGRPCAutoCertUnsupported, "NewServer must refuse gRPC auto_cert")
	require.Nil(t, srv)
}

// TestNewServer_TLSEnabledManualCert exercises the TLS-enabled branch using a real
// self-signed cert/key pair loaded from disk (the non-AutoCert path in NewServer).
func TestNewServer_TLSEnabledManualCert(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = false
	cfg.Server.GRPC.TLS.CertFile = certPath
	cfg.Server.GRPC.TLS.KeyFile = keyPath

	srv, err := NewServer(cfg, h.CoreService)
	require.NoError(t, err, "NewServer must succeed with a valid manual TLS cert/key")
	require.NotNil(t, srv)
	srv.Stop()
}

// TestNewServer_TLSEnabledBadCert exercises the error path inside NewServer when TLS
// is enabled but the certificate files do not exist — createGRPCTLSConfig must return
// an error that NewServer propagates.
func TestNewServer_TLSEnabledBadCert(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = false
	cfg.Server.GRPC.TLS.CertFile = "/nonexistent/cert.pem"
	cfg.Server.GRPC.TLS.KeyFile = "/nonexistent/key.pem"

	_, err := NewServer(cfg, h.CoreService)
	require.Error(t, err, "NewServer must propagate the createGRPCTLSConfig error for a bad cert")
	assert.Contains(t, err.Error(), "failed to create gRPC TLS config")
}

// TestNewServer_ReflectionEnabled exercises the cfg.Server.GRPC.ReflectionEnabled
// branch, verifying that NewServer succeeds and registers reflection without error.
func TestNewServer_ReflectionEnabled(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	cfg := &config.Config{}
	cfg.Server.GRPC.ReflectionEnabled = true

	srv, err := NewServer(cfg, h.CoreService)
	require.NoError(t, err, "NewServer must succeed when reflection is enabled")
	require.NotNil(t, srv)
	srv.Stop()
}

// TestCreateGRPCTLSConfig_ManualCertWithInvalidCipherFails exercises the error path
// in createGRPCTLSConfig's non-AutoCert branch when a valid cert is loaded but
// applyTLSHardening rejects the configured AllowedCiphers (e.g. an unknown cipher name).
func TestCreateGRPCTLSConfig_ManualCertWithInvalidCipherFails(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = false
	cfg.Server.GRPC.TLS.CertFile = certPath
	cfg.Server.GRPC.TLS.KeyFile = keyPath
	cfg.Server.GRPC.TLS.AllowedCiphers = []string{"not-a-real-cipher"}

	_, err := createGRPCTLSConfig(cfg)
	require.Error(t, err, "createGRPCTLSConfig must return an error when a cert is valid but AllowedCiphers is invalid")
	assert.Contains(t, err.Error(), "invalid gRPC TLS configuration")
}
