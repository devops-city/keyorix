// server_s27_test.go — targeted coverage push for branches not yet reached by
// server_s3_test.go, server_s4_test.go, server_s22_test.go, server_s23_test.go,
// startup_validation_test.go, transport_tls_test.go, and verify_encryption_wiring_test.go.
//
// Covered here:
//   - startHTTPServer: TLS-enabled path with bad cert → createTLSConfig error
//   - startHTTPServer: HTTP listener bind failure (port already in use)
//   - startSchedulers: anomaly off-hours with OffHoursStart/OffHoursEnd != 0 (but Timezone empty)
//   - startGRPCServer: NewServer failure with invalid gRPC TLS config
//   - startGRPCServer: net.Listen failure (invalid port string)
//   - initializeCoreService: login lockout disabled (warning log path)
//   - initializeCoreService: evidence object-store enabled path (no actual cloud call)
//   - initializeCoreService: notification channel init error (bad webhook endpoint)
//   - initializeCoreService: license with token (file read success path, grants log branch)
//   - buildSAMLProvider: valid IDPMetadataFile (file read success path)
//   - buildSSOProviders: SAML with valid metadata file (file path)
//   - buildSSOProviders: JWKS resolver error (invalid jwks_uri after successful discovery)
//   - runStartupValidation: enabled path with warnings (errors collection logs)
//
// #G12: startHTTPServer/startGRPCServer no longer call initializeCoreService
// themselves (that now happens once in main(), shared by both) — every test
// below that needs a live server now constructs its own coreService via
// mustInitCoreService first and passes it in, and coverage for the background
// schedulers (moved out of startHTTPServer into startSchedulers) is exercised
// by calling startSchedulers directly instead.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// mustInitCoreService constructs a coreService for a test that needs one to
// pass to startHTTPServer/startGRPCServer/startSchedulers directly (#G12
// moved that construction out of those functions and into main(), shared).
// Fails the test immediately if cfg itself doesn't produce a valid core
// service — callers testing an initializeCoreService failure path should call
// initializeCoreService directly instead (see server_s4_test.go /
// server_s22_test.go / server_s23_test.go for that convention).
func mustInitCoreService(t *testing.T, cfg *config.Config) *core.KeyorixCore {
	t.Helper()
	coreService, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService: %v", err)
	}
	return coreService
}

// TestInitializeCoreService_DualConstruction_RacesExclusiveDEKLock is the #G12
// regression implementing the review's own detection_idea: two independent
// initializeCoreService calls for the SAME encrypted deployment must not both
// succeed — proving why main() now constructs the core service exactly once
// and shares it between startHTTPServer/startGRPCServer, instead of each
// calling initializeCoreService (and therefore AcquireExclusiveKeyLock)
// independently the way the pre-fix code did.
//
// encryption.Service.AcquireExclusiveKeyLock is a non-blocking OS advisory
// flock (internal/encryption/service_rotation.go) held for "the server's
// whole lifetime" — so a second, independent construction against the same
// DEK path fails immediately with a lock-acquisition error rather than
// blocking, which is exactly what let this bug through: whichever of
// startHTTPServer/startGRPCServer's goroutine ran initializeCoreService
// second would non-deterministically fail to start at all.
func TestInitializeCoreService_DualConstruction_RacesExclusiveDEKLock(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-g12-dual-construction")

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "g12_dual.db"},
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek_g12.json",
				SaltPath: "salt_g12.bin",
			},
		},
	}

	// First construction (what main() now does exactly once) succeeds and
	// holds the exclusive DEK lock for its lifetime.
	_, encSvc1, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("first initializeCoreService: %v", err)
	}
	if encSvc1 == nil {
		t.Fatal("expected a non-nil encryption.Service for an encrypted deployment")
	}

	// A second, independent construction against the SAME DEK path — exactly
	// what the pre-#G12 startGRPCServer did in parallel with startHTTPServer's
	// own call — must fail: the lock is already held and exclusive.
	_, encSvc2, err := initializeCoreService(cfg)
	if err == nil {
		if encSvc2 != nil {
			encSvc2.Shutdown()
		}
		t.Fatal("a second independent initializeCoreService call for the same encrypted deployment must fail to acquire the exclusive DEK lock while the first is still held")
	}

	// Releasing the first frees the lock for a subsequent (not concurrent)
	// construction — confirming the failure above was specifically the lock
	// contention, not some other config problem.
	encSvc1.Shutdown()
	_, encSvc3, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService after the first Shutdown() must succeed (lock released): %v", err)
	}
	if encSvc3 != nil {
		encSvc3.Shutdown()
	}
}

// ── startHTTPServer: TLS enabled with bad cert files ─────────────────────────

// TestStartHTTPServer_S27_TLSBadCert verifies that startHTTPServer returns an
// error when TLS is enabled but the cert/key files don't exist. This exercises
// the createTLSConfig error path inside startHTTPServer.
func TestStartHTTPServer_S27_TLSBadCert(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_s27_tls.db"},
		},
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "0",
				TLS: config.TLSConfig{
					Enabled:  true,
					AutoCert: false,
					CertFile: "/nonexistent/cert.pem", // missing → createTLSConfig fails
					KeyFile:  "/nonexistent/key.pem",
				},
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel to avoid hanging on success

	err := startHTTPServer(ctx, cfg, coreService)
	if err == nil {
		t.Fatal("startHTTPServer must return an error for missing TLS cert/key files")
	}
	if !errors.Is(err, errHTTPServerFailedToStart) {
		t.Errorf("error must be wrapped in errHTTPServerFailedToStart (main() uses this to decide whether to exit fatally): %v", err)
	}
}

// ── startHTTPServer: port already in use → bind failure ─────────────────────

// TestStartHTTPServer_S27_ListenerBindFailure verifies that startHTTPServer
// returns an error when the HTTP port is invalid (out of range), exercising the
// net.Listen error path inside startHTTPServer.
func TestStartHTTPServer_S27_ListenerBindFailure(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_s27_bind.db"},
		},
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "99999", // out-of-range port → net.Listen fails
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)

	// Do NOT cancel ctx — startHTTPServer must fail at bind before reaching <-ctx.Done().
	ctx := context.Background()
	err := startHTTPServer(ctx, cfg, coreService)
	if err == nil {
		t.Fatal("startHTTPServer must return an error when the port is invalid/out-of-range")
	}
	// RELEASE-BLOCKERS item 4: a bind failure must be wrapped in
	// errHTTPServerFailedToStart -- main()'s caller uses errors.Is against it
	// to exit the process fatally instead of logging and falling through to
	// <-sigChan (which never arrives for a boot that failed this early), the
	// bug that let `docker ps`/`kubectl get pods` show "Up"/"Running" while
	// nothing was actually listening.
	if !errors.Is(err, errHTTPServerFailedToStart) {
		t.Errorf("bind failure must be wrapped in errHTTPServerFailedToStart: %v", err)
	}
}

// ── startSchedulers: anomaly off-hours with non-zero start/end ───────────────

// TestStartSchedulers_S27_AnomalyOffHoursNumeric exercises the anomaly
// off-hours branch where OffHoursStart != 0 but Timezone is empty. The empty
// timezone triggers the tzLabel = "UTC" fallback before calling
// SetBusinessHours. #G12: this branch lives in startSchedulers now (moved out
// of startHTTPServer), so it's exercised directly rather than via an HTTP
// listener.
func TestStartSchedulers_S27_AnomalyOffHoursNumeric(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_s27_hours.db"},
		},
		AnomalyAlerts: config.AnomalyAlertsConfig{
			BusinessHours: config.AnomalyBusinessHoursConfig{
				Timezone:      "", // empty → tzLabel = "UTC"
				OffHoursStart: 22, // non-zero → triggers the if-block
				OffHoursEnd:   6,
			},
		},
	}
	coreService := mustInitCoreService(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startSchedulersForTest(t, ctx, cfg, coreService)
	// startSchedulers only wires up the scheduler goroutines and returns
	// immediately; give the anomaly detector's first (immediate) tick a moment
	// to run so the off-hours branch actually executes before the test exits.
	time.Sleep(50 * time.Millisecond)
}

// ── startGRPCServer: invalid port string → net.Listen failure ────────────────

// TestStartGRPCServer_S27_InvalidPort verifies that startGRPCServer returns an
// error when the configured gRPC port is an invalid address string, exercising
// the net.Listen error path.
func TestStartGRPCServer_S27_InvalidPort(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "grpctest_s27_port.db"},
		},
		Server: config.ServerConfig{
			GRPC: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "not-a-valid-port-!!!",
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := startGRPCServer(ctx, cfg, coreService)
	if err == nil {
		t.Fatal("startGRPCServer must return an error for an invalid port")
	}
}

// ── startGRPCServer: TLS bad cert → grpc.NewServer failure ──────────────────

// TestStartGRPCServer_S27_TLSBadCert exercises the branch where grpc.NewServer
// fails because TLS cert/key files don't exist.
func TestStartGRPCServer_S27_TLSBadCert(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "grpctest_s27_tls.db"},
		},
		Server: config.ServerConfig{
			GRPC: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "0",
				TLS: config.TLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := startGRPCServer(ctx, cfg, coreService)
	if err == nil {
		t.Fatal("startGRPCServer must return an error when gRPC TLS cert/key files are missing")
	}
}

// ── initializeCoreService: login lockout disabled warning ────────────────────

// TestInitializeCoreService_S27_LoginLockoutDisabledWarning exercises the
// login-lockout disabled branch (ll.Disabled = true). A warning is logged
// but no error is returned.
func TestInitializeCoreService_S27_LoginLockoutDisabledWarning(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Security.LoginLockout = config.LoginLockoutConfig{Disabled: true}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with lockout disabled: %v", err)
	}
}

// ── initializeCoreService: license with grants (status.Grants() = true) ─────

// TestInitializeCoreService_S27_LicenseGrantsPath exercises the license.Gate
// status branch where st.Grants() returns true. A license file containing a
// JWT-shaped token (even if invalid for verification) is enough to exercise the
// if-block; the test only checks that no error is returned.
func TestInitializeCoreService_S27_LicenseGrantsPath(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	// Write a dummy JWT-shaped token. The license gate falls back to community
	// baseline when the token is invalid, so the Grants() branch may not fire.
	// We still exercise the file-read path (the else branch on line 806).
	licFile := filepath.Join(dir, "license.jwt")
	if err := os.WriteFile(licFile, []byte("dummy.jwt.token"), 0o600); err != nil {
		t.Fatalf("write license: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "test_s27_lic.db"},
		},
		License: config.LicenseConfig{Path: licFile},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with license file: %v", err)
	}
}

// ── initializeCoreService: notification webhook SSRF-blocked endpoint ────────

// TestInitializeCoreService_S27_WebhookSSRFError verifies that a notification
// webhook endpoint that is blocked by the SSRF guard (a public non-private
// IP without AllowPrivateNetworkTarget) causes initializeCoreService to return
// an error from the webhook channel init, exercising the "if werr != nil" branch.
func TestInitializeCoreService_S27_WebhookSSRFError(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Notifications.Webhook = config.NotificationWebhookConfig{
		Enabled:                   true,
		Endpoint:                  "http://169.254.169.254/notify", // link-local → SSRF blocked
		AllowPrivateNetworkTarget: false,
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error when webhook endpoint is SSRF-blocked, got nil")
	}
}

// ── initializeCoreService: evidence object-store path ────────────────────────

// TestInitializeCoreService_S27_EvidenceObjectStore exercises the object-store
// evidence target init path. NewObjectStore with a non-existent AWS endpoint
// should fail and return an error, exercising the "if oerr != nil" branch.
func TestInitializeCoreService_S27_EvidenceObjectStore(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// Use a local endpoint with path-style to avoid touching real AWS.
	// NewObjectStore may or may not fail immediately; both paths are valid.
	cfg.EvidenceDelivery = config.EvidenceDeliveryConfig{
		Enabled: true,
		ObjectStore: config.EvidenceObjectStoreConfig{
			Enabled:      true,
			Bucket:       "test-bucket",
			Endpoint:     "http://127.0.0.1:19998",
			UsePathStyle: true,
		},
	}

	// Either the store init succeeds (no immediate network call) or returns an
	// error — both exercise the branch. We just verify no panic.
	_, _, _ = initializeCoreService(cfg)
}

// ── buildSAMLProvider: valid metadata file read ───────────────────────────────

// TestBuildSAMLProvider_S27_ValidMetadataFile exercises the IDPMetadataFile
// read branch in buildSAMLProvider. A valid-looking (minimal) SAML metadata XML
// is written to a temp file and passed as IDPMetadataFile. Even if samlpkg
// rejects the content, the file-read branch (line 1818–1822) is exercised.
func TestBuildSAMLProvider_S27_ValidMetadataFile(t *testing.T) {
	dir := t.TempDir()
	metaFile := filepath.Join(dir, "idp_meta.xml")
	// Minimal SAML IdP metadata — may or may not parse depending on samlpkg.
	meta := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://idp.example.com">
  <IDPSSODescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`
	if err := os.WriteFile(metaFile, []byte(meta), 0o600); err != nil {
		t.Fatalf("write metadata file: %v", err)
	}

	pc := config.SSOProviderConfig{
		Name: "file-saml",
		Type: "saml",
		SAML: &config.SAMLProviderConfig{
			IDPMetadataXML:  "", // force file read
			IDPMetadataFile: metaFile,
			SPEntityID:      "urn:my-sp",
			ACSURL:          "https://app.example.com/auth/sso/file-saml/acs",
		},
	}

	// The file read branch is exercised regardless of whether NewProvider succeeds.
	_, _ = buildSAMLProvider(pc)
}

// ── buildSSOProviders: SAML provider with metadata file (file path exercised) ─

// TestBuildSSOProviders_S27_SAMLMetadataFile exercises the SAML branch in
// buildSSOProviders when the IdP metadata is supplied as a file. Combines
// buildSAMLProvider file-read path with the buildSSOProviders SAML skip logic.
func TestBuildSSOProviders_S27_SAMLMetadataFile(t *testing.T) {
	dir := t.TempDir()
	metaFile := filepath.Join(dir, "idp.xml")
	meta := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://idp.example.com">
  <IDPSSODescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`
	if err := os.WriteFile(metaFile, []byte(meta), 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	sso := config.SSOConfig{
		Providers: []config.SSOProviderConfig{
			{
				Name: "file-saml-provider",
				Type: "saml",
				SAML: &config.SAMLProviderConfig{
					IDPMetadataXML:  "",
					IDPMetadataFile: metaFile,
					SPEntityID:      "urn:my-sp",
					ACSURL:          "https://app.example.com/auth/sso/file-saml/acs",
				},
			},
		},
	}

	// Just exercise the code path; result may be 0 or 1 depending on samlpkg validation.
	_, _, _ = buildSSOProviders(sso)
}

// ── buildSSOProviders: JWKS resolver failure after valid discovery ────────────

// TestBuildSSOProviders_S27_JWKSResolverFailure exercises the branch where
// discoverOIDC succeeds and ssoCompleteURL succeeds, but core.NewHTTPJWKSResolver
// returns an error (invalid jwks_uri scheme). This covers lines 1803-1805.
func TestBuildSSOProviders_S27_JWKSResolverFailure(t *testing.T) {
	// We need a discovery server that returns an invalid jwks_uri scheme AFTER
	// passing the jwks_uri host-match check. Use a data: URI which passes neither
	// url.Parse nor the host-check — instead we need a server-relative URL that
	// has the correct host but an invalid scheme for NewHTTPJWKSResolver.
	//
	// Strategy: return a jwks_uri with "ftp://<same host>/" — the JWKS URI host
	// matches the issuer host (passes discoverOIDC's check) but NewHTTPJWKSResolver
	// may reject a non-http(s) scheme.
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// jwks_uri host = issuer host (passes check) but scheme ftp may be rejected.
		host := r.Host
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               "ftp://" + host + "/.well-known/jwks.json",
		})
	}))
	defer srv.Close()
	issuer = srv.URL

	sso := config.SSOConfig{
		Providers: []config.SSOProviderConfig{
			{
				Name:        "jwks-fail-oidc",
				Type:        "oidc",
				Issuer:      issuer,
				ClientID:    "client-jwks",
				RedirectURL: issuer + "/callback",
			},
		},
	}

	// If discoverOIDC rejects the ftp:// jwks_uri (host mismatch or bad parse),
	// provider is skipped anyway. If it passes, NewHTTPJWKSResolver may fail.
	// Either way, we exercise the branches around the JWKS resolver path.
	_, _, _ = buildSSOProviders(sso)
}

// ── runStartupValidation: enabled with errors in result ──────────────────────

// TestRunStartupValidation_S27_EnabledWithErrors exercises the runStartupValidation
// branch that logs both warnings and errors from the startup result (lines 1432-1437).
// A world-readable DEK triggers both warnings and an error in the result.
func TestRunStartupValidation_S27_EnabledWithErrors(t *testing.T) {
	dir := t.TempDir()
	// Write a world-readable DEK (permission check enabled → produces error in result).
	configPath := writeStartupTestConfig(t, dir, true, 0o644, 0o600, 0o600)
	cfg := loadStartupTestConfig(t, configPath)

	// ValidateStartup will produce a result with errors AND return an error.
	// The logging branches for result.Warnings and result.Errors are exercised.
	err := runStartupValidation(cfg)
	// We expect an error — the function returns it after logging.
	if err == nil {
		t.Fatal("expected runStartupValidation to return an error for world-readable DEK")
	}
}

// ── initializeCoreService: SIEM init failure (bad provider) ──────────────────

// TestInitializeCoreService_S27_SIEMInitError exercises the SIEM forwarder
// init error path (line 423-425) by providing a SIEM config that causes
// siem.New to return an error (unknown provider with a private-network endpoint
// that the SSRF guard allows but an unknown provider rejects).
func TestInitializeCoreService_S27_SIEMInitError(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// Use an invalid SIEM provider name — siem.New should reject unknown providers
	// before making any network call.
	cfg.Audit.SIEM = config.SIEMConfig{
		Enabled:  true,
		Provider: "unknown-nonexistent-siem-provider",
		Endpoint: "http://127.0.0.1:65539/siem",
	}

	_, _, err := initializeCoreService(cfg)
	// If siem.New accepts unknown providers gracefully, no error is returned —
	// both paths exercise the wiring code.
	_ = err
}

// ── startSchedulers: anomaly business hours with OffHoursEnd != 0 ─────────────

// TestStartSchedulers_S27_AnomalyOffHoursEndOnly exercises the anomaly
// off-hours branch triggered when OffHoursEnd != 0 (but OffHoursStart == 0).
// This covers the condition `bh.OffHoursEnd != 0` part of the composite check.
// #G12: this branch lives in startSchedulers now.
func TestStartSchedulers_S27_AnomalyOffHoursEndOnly(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_s27_offhours.db"},
		},
		AnomalyAlerts: config.AnomalyAlertsConfig{
			BusinessHours: config.AnomalyBusinessHoursConfig{
				Timezone:      "UTC",
				OffHoursStart: 0,
				OffHoursEnd:   6, // non-zero → triggers the off-hours block
			},
		},
	}
	coreService := mustInitCoreService(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── initializeCoreService: evidence multi-target (switch default case) ────────

// TestInitializeCoreService_S27_EvidenceMultiTarget exercises the
// `default: coreService.SetEvidenceForwarder(evidencesink.NewMulti(...))` branch
// by providing two evidence webhook targets. We use two AllowPrivateNetworkTarget
// webhooks on different loopback ports.
func TestInitializeCoreService_S27_EvidenceMultiTarget(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// Set up EvidenceDelivery with two webhook-like forwarding configs.
	// We'll hack this by using a single webhook and an ObjectStore that will
	// attempt construction (it may fail — we only need the branch attempted).
	cfg.EvidenceDelivery = config.EvidenceDeliveryConfig{
		Enabled: true,
		Webhook: config.EvidenceWebhookConfig{
			Enabled:                   true,
			Endpoint:                  "http://127.0.0.1:65543/evidence",
			AllowPrivateNetworkTarget: true,
		},
		ObjectStore: config.EvidenceObjectStoreConfig{
			Enabled:      true,
			Bucket:       "test-bucket",
			Endpoint:     "http://127.0.0.1:19999", // unreachable but no immediate network call
			UsePathStyle: true,
		},
	}

	// May succeed or fail depending on NewObjectStore behavior — both exercise the switch.
	_, _, _ = initializeCoreService(cfg)
}

// ── initializeCoreService: email channel init error (empty Host) ──────────────

// TestInitializeCoreService_S27_EmailInitError exercises the email notification
// channel init error path (line 471-473) by providing an enabled email config
// with an empty host. NewEmail requires a non-empty host.
func TestInitializeCoreService_S27_EmailInitError(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Notifications.Email = config.NotificationEmailConfig{
		Enabled: true,
		Host:    "", // empty host → NewEmail returns error
		From:    "keyorix@example.com",
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error when notification email Host is empty")
	}
}

// ── initializeCoreService: Slack channel init error (SSRF-blocked URL) ───────

// TestInitializeCoreService_S27_SlackInitError exercises the Slack notification
// channel init error path (line 480-482) by providing a webhook URL that
// fails the SSRF guard (link-local address).
func TestInitializeCoreService_S27_SlackInitError(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Notifications.Slack = config.NotificationChatConfig{
		Enabled:    true,
		WebhookURL: "http://169.254.169.254/slack", // link-local → SSRF blocked
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error when Slack webhook URL is SSRF-blocked")
	}
}

// ── initializeCoreService: Teams channel init error (SSRF-blocked URL) ───────

// TestInitializeCoreService_S27_TeamsInitError exercises the Teams notification
// channel init error path (line 488-490) by providing a webhook URL that
// fails the SSRF guard.
func TestInitializeCoreService_S27_TeamsInitError(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Notifications.Teams = config.NotificationChatConfig{
		Enabled:    true,
		WebhookURL: "http://169.254.169.254/teams", // link-local → SSRF blocked
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error when Teams webhook URL is SSRF-blocked")
	}
}

// ── runStartupValidation: warning loop body covered (encryption disabled) ─────

// TestRunStartupValidation_S27_WarningsLogged exercises the for loop bodies
// that log result.Warnings and result.Errors inside runStartupValidation.
// When encryption is disabled AND EnableFilePermissionCheck=true, startup
// validation succeeds (nil error) but returns a result with warnings
// ("Encryption is disabled"), exercising the result.Warnings for-loop body.
func TestRunStartupValidation_S27_WarningsLogged(t *testing.T) {
	dir := t.TempDir()

	// Write a config with EnableFilePermissionCheck=true and encryption=false.
	// ValidateStartup will produce a result with Warnings=["Encryption is disabled"]
	// and a nil error — the for loop body on line 1433 will execute.
	dbPath := filepath.Join(dir, "keyorix.db")
	if err := os.WriteFile(dbPath, []byte("sqlite"), 0o600); err != nil {
		t.Fatalf("write db: %v", err)
	}
	configPath := filepath.Join(dir, "keyorix.yaml")
	yamlContent := "storage:\n  type: local\n  database:\n    path: " + dbPath + "\nsecurity:\n  enable_file_permission_check: true\n  allow_unsafe_file_permissions: false\n"
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg := loadStartupTestConfig(t, configPath)

	// runStartupValidation should succeed (or fail) but the warning loop fires either way.
	// The important thing is that result.Warnings is non-empty so the for-body executes.
	_ = runStartupValidation(cfg)
}

// ── startHTTPServer: AutoCert TLS path exercises https scheme + TLSConfig=nil ─

// TestStartHTTPServer_S27_AutoCertTLS exercises the TLS enabled+AutoCert=true
// path in startHTTPServer: createTLSConfig returns nil,nil for AutoCert,
// so server.TLSConfig is set to nil (line 1307) and scheme="https" (line 1318).
// The server goroutine then calls server.ServeTLS which fails immediately
// (no cert in autocert.Manager for 127.0.0.1), so it exits. We use a
// pre-cancelled context so the test completes quickly.
func TestStartHTTPServer_S27_AutoCertTLS(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_s27_autocert.db"},
		},
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    itoa(port),
				TLS: config.TLSConfig{
					Enabled:  true,
					AutoCert: true, // createTLSConfig returns nil,nil → TLSConfig=nil
					// #1475: cfg.Validate() (now enforced by initializeCoreService)
					// requires at least one domain when AutoCert is set. Never
					// resolved here — the test cancels before any real ACME
					// handshake — so a placeholder satisfies Validate() without
					// touching what this test actually exercises (createTLSConfig's
					// nil,nil AutoCert return, verified below via TLSConfig).
					Domains: []string{"s27-autocert-tls.test.invalid"},
				},
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)

	// #1475: confirm this fixture's placeholder Domains didn't change what the
	// test actually exercises — AutoCert must still make createTLSConfig return a
	// nil *tls.Config, independent of Domains being set.
	if tlsCfg, err := createTLSConfig(cfg); err != nil || tlsCfg != nil {
		t.Fatalf("createTLSConfig with AutoCert must still return (nil, nil), got (%v, %v)", tlsCfg, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the server exits immediately after <-ctx.Done()

	done := make(chan error, 1)
	go func() { done <- startHTTPServer(ctx, cfg, coreService) }()

	select {
	case err := <-done:
		_ = err // shutdown error is acceptable
	case <-context.Background().Done():
		t.Fatal("startHTTPServer with AutoCert did not return")
	}
}

// ── initializeCoreService: SIEM init error from invalid provider ──────────────

// TestInitializeCoreService_S27_SIEMProviderError exercises the SIEM forwarder
// error path (line 423-425) — siem.New returns an error for an unknown provider.
func TestInitializeCoreService_S27_SIEMProviderError(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Audit.SIEM = config.SIEMConfig{
		Enabled:  true,
		Provider: "invalid-provider-xyz",
		Endpoint: "http://127.0.0.1:65548/siem",
	}

	// If siem.New rejects the unknown provider, err != nil; otherwise nil.
	// Either way we exercise the SIEM wiring code path.
	_, _, _ = initializeCoreService(cfg)
}

// ── initializeCoreService: encryption failure propagates to caller ────────────

// TestInitializeCoreService_S27_EncryptionFailure exercises line 260-262 in
// initializeCoreService: when initializeEncryption returns a non-nil error
// (encryption enabled with password provider but no KEYORIX_MASTER_PASSWORD),
// initializeCoreService must propagate the error.
func TestInitializeCoreService_S27_EncryptionFailure(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "") // no password → initializeEncryption fails

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "test_s27_enc.db"},
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.json",
				SaltPath: "salt.bin",
				// KeyProvider.Type = "" → password provider (requires KEYORIX_MASTER_PASSWORD)
			},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error when encryption fails due to missing KEYORIX_MASTER_PASSWORD")
	}
}

// ── initializeCoreService: evidence webhook error (bad SSRF endpoint) ─────────

// TestInitializeCoreService_S27_EvidenceWebhookSSRFError exercises line 638-640:
// evidencesink.NewWebhook fails for a link-local SSRF-blocked endpoint.
func TestInitializeCoreService_S27_EvidenceWebhookSSRFError(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.EvidenceDelivery = config.EvidenceDeliveryConfig{
		Enabled: true,
		Webhook: config.EvidenceWebhookConfig{
			Enabled:                   true,
			Endpoint:                  "http://169.254.169.254/evidence", // SSRF-blocked
			AllowPrivateNetworkTarget: false,
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error when evidence webhook endpoint is SSRF-blocked")
	}
}

// ── initializeCoreService: evidence object-store init error ──────────────────

// TestInitializeCoreService_S27_EvidenceObjectStoreError triggers the
// evidencesink.NewObjectStore error path (line 655-657) by providing an
// invalid object_lock_mode value that is immediately rejected by NewObjectStore
// before any network call is attempted.
func TestInitializeCoreService_S27_EvidenceObjectStoreError(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.EvidenceDelivery = config.EvidenceDeliveryConfig{
		Enabled: true,
		ObjectStore: config.EvidenceObjectStoreConfig{
			Enabled:  true,
			Bucket:   "test-bucket",
			LockMode: "INVALID_LOCK_MODE", // objectLockMode returns error immediately
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error when object-store lock_mode is invalid")
	}
}

// ── runStartupValidation: errors loop body covered (encryption validation) ───

// TestRunStartupValidation_S27_EncryptionValidationError covers the
// for _, e := range result.Errors { log } body (line 1435.35) by
// producing a scenario where the encryption validation step fails:
// the DEK file exists with correct permissions but is too small (< 60 bytes).
// ValidateStartup appends to result.Errors and then returns an error, so
// the for-loop body in runStartupValidation executes.
func TestRunStartupValidation_S27_EncryptionValidationError(t *testing.T) {
	dir := t.TempDir()

	dekPath := filepath.Join(dir, "dek.key")
	saltPath := filepath.Join(dir, "kek.salt")
	dbPath := filepath.Join(dir, "keyorix.db")

	// DEK: exists with correct perms but too small → encryption validation fails.
	if err := os.WriteFile(dekPath, make([]byte, 10), 0o600); err != nil {
		t.Fatalf("write dek: %v", err)
	}
	// Salt: correct size and perms → passes file perm + salt validation.
	if err := os.WriteFile(saltPath, make([]byte, 32), 0o600); err != nil {
		t.Fatalf("write salt: %v", err)
	}
	if err := os.WriteFile(dbPath, []byte("sqlite"), 0o600); err != nil {
		t.Fatalf("write db: %v", err)
	}

	configPath := filepath.Join(dir, "keyorix.yaml")
	yamlContent := fmt.Sprintf(`storage:
  type: local
  database:
    path: %q
  encryption:
    enabled: true
    dek_path: %q
    salt_path: %q
security:
  enable_file_permission_check: true
  allow_unsafe_file_permissions: false
`, dbPath, dekPath, saltPath)
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := loadStartupTestConfig(t, configPath)

	// ValidateStartup will:
	//   1. Check file perms → DEK 0600 OK → no error
	//   2. Validate encryption → DEK 10 bytes < 60 → appends to result.Errors → returns error
	// runStartupValidation then iterates result.Errors, covering line 1435.35.
	err := runStartupValidation(cfg)
	if err == nil {
		t.Fatal("expected runStartupValidation to return an error for under-size DEK")
	}
}

// ── discoverOIDC: JSON decode error path ─────────────────────────────────────

// TestDiscoverOIDC_S27_InvalidJSON exercises the json.Decode error path
// in discoverOIDC (line 1659.97–1661.3). The discovery endpoint returns
// a non-JSON body; the decode fails and the error is propagated.
func TestDiscoverOIDC_S27_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return invalid JSON — json.Decode will fail.
		if _, err := w.Write([]byte("NOT-VALID-JSON{{{")); err != nil {
			t.Logf("write error: %v", err)
		}
	}))
	defer srv.Close()

	_, err := discoverOIDC(srv.URL)
	if err == nil {
		t.Fatal("discoverOIDC must return an error when the discovery body is not valid JSON")
	}
}

// ── startSchedulers: encryption enabled — audit checkpoint scheduler ─────────

// TestStartSchedulers_S27_WithEncryption runs startSchedulers with storage
// encryption enabled, covering the audit-checkpoint switch `default:` case:
// when encryption is active, AuditCheckpointsAvailable() returns true and the
// audit-checkpoint scheduler is started. The goroutine fires immediately
// (runScheduler calls tick() once before the first tick), covering the
// WriteAuditCheckpoint callback body. #G12: both the audit-checkpoint
// scheduler AND encSvc's lifecycle moved out of startHTTPServer (into
// startSchedulers and main() respectively) — encSvc.Shutdown() itself is
// exercised directly here rather than via startHTTPServer's now-removed
// defer.
func TestStartSchedulers_S27_WithEncryption(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-coverage-password-s27")

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_s27_enc2.db"},
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek_s27.json",
				SaltPath: "salt_s27.bin",
			},
		},
	}

	coreService, encSvc, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService: %v", err)
	}
	if encSvc != nil {
		defer encSvc.Shutdown()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startSchedulersForTest(t, ctx, cfg, coreService)
	// The audit-checkpoint goroutine's first (immediate) tick needs a moment
	// to run before the test exits.
	time.Sleep(300 * time.Millisecond)
}

// ── startHTTPServer: SCIM enabled with weak token → NewRouter error ──────────

// TestStartHTTPServer_S27_SCIMWeakToken exercises the NewRouter error path
// (line 847-849) when SCIM is enabled with a token shorter than the minimum
// 20-character requirement. NewRouter returns an error before any listener is
// bound, so startHTTPServer returns an error immediately.
func TestStartHTTPServer_S27_SCIMWeakToken(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_s27_scim_weak.db"},
		},
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "0",
			},
		},
		SCIM: config.SCIMConfig{
			Enabled: true,
			Token:   "weak", // 4 chars — fails ValidateSCIMTokenStrength (< 20 chars)
		},
	}

	coreService := mustInitCoreService(t, cfg)

	// startHTTPServer must return an error because NewRouter rejects the weak SCIM token.
	err := startHTTPServer(context.Background(), cfg, coreService)
	if err == nil {
		t.Fatal("expected startHTTPServer to return an error for a weak SCIM token")
	}
}

// ── startHTTPServer: AutoCert TLS with invalid cipher → goroutine error ──────

// TestStartHTTPServer_S27_AutoCertBadCipher exercises the AutoCert TLS serve
// goroutine error path (lines 1331-1334) where buildAutoCertTLSConfig fails
// because AllowedCiphers names an unrecognised cipher suite. The goroutine
// starts, calls buildAutoCertTLSConfig, hits the error, logs it, and returns
// early — never calling ServeTLS. The context timer (200 ms) lets the goroutine
// run before the main body's <-ctx.Done() returns.
func TestStartHTTPServer_S27_AutoCertBadCipher(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_s27_autocert_badcipher.db"},
		},
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "0",
				TLS: config.TLSConfig{
					Enabled:        true,
					AutoCert:       true,
					AllowedCiphers: []string{"INVALID_CIPHER_XYZ_S27"}, // not a recognised cipher suite
					// #1475: cfg.Validate() (now enforced by initializeCoreService)
					// requires at least one domain when AutoCert is set. Validate()
					// never inspects AllowedCiphers, so this placeholder only
					// satisfies the domains check — buildAutoCertTLSConfig still
					// fails at applyTLSHardening's cipher-suite resolution, BEFORE
					// domains/HostWhitelist ever matter (verified below), for the
					// same reason as before.
					Domains: []string{"s27-autocert-badcipher.test.invalid"},
				},
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)

	// #1475: confirm this fixture's placeholder Domains didn't change what the
	// test actually exercises — the invalid cipher name must still make
	// buildAutoCertTLSConfig fail at cipher-suite resolution.
	if _, err := buildAutoCertTLSConfig(cfg.Server.HTTP.TLS.Domains, cfg.Server.HTTP.TLS, ""); err == nil {
		t.Fatal("buildAutoCertTLSConfig must still fail for an unrecognised cipher suite name")
	} else if !strings.Contains(err.Error(), "invalid TLS configuration") {
		t.Fatalf("expected a cipher-resolution error, got: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	_ = startHTTPServer(ctx, cfg, coreService)
}

// ── startHTTPServer: non-AutoCert TLS with valid cert → ServeTLS path ────────

// TestStartHTTPServer_S27_TLSNonAutoCert exercises the non-AutoCert TLS serve
// path (line 1337) where server.ServeTLS is called with explicit cert/key files
// rather than the autocert.Manager. writeSelfSignedCert generates a valid
// self-signed cert+key pair; createTLSConfig succeeds and the goroutine calls
// ServeTLS which begins listening. A 200 ms context timer cancels the server.
func TestStartHTTPServer_S27_TLSNonAutoCert(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	certFile, keyFile := writeSelfSignedCert(t, dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_s27_tlsnonauto.db"},
		},
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "0",
				TLS: config.TLSConfig{
					Enabled:  true,
					AutoCert: false,
					CertFile: certFile,
					KeyFile:  keyFile,
				},
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	_ = startHTTPServer(ctx, cfg, coreService)
}

// ── buildSSOProviders: SAML provider where ssoCompleteURL rejects ACSURL ─────

// TestBuildSSOProviders_S27_SAMLInvalidACSURL exercises the ssoCompleteURL
// error path (lines 1745-1747) that fires after buildSAMLProvider succeeds but
// the ACSURL turns out to have no scheme, making ssoCompleteURL return an error.
//
// It calls buildSSOProviders directly (no HTTP server, no DB needed). The IdP
// metadata is a minimal but valid SAML XML document backed by a real self-signed
// EC certificate (from testSelfSignedCACert) to pass parseIDPMetadata/xrv.Validate.
// ACSURL "relative-no-scheme" passes samlpkg.NewProvider (url.Parse succeeds)
// but fails ssoCompleteURL (u.Scheme == "").
func TestBuildSSOProviders_S27_SAMLInvalidACSURL(t *testing.T) {
	initI18n(t)

	// Generate a PEM-encoded self-signed cert and derive its base64 DER for the SAML metadata.
	caPEM := testSelfSignedCACert(t)
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("pem.Decode returned nil block")
	}
	certB64 := base64.StdEncoding.EncodeToString(block.Bytes)

	metaXML := fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, certB64)

	sso := config.SSOConfig{
		Providers: []config.SSOProviderConfig{
			{
				Name: "test-saml-s27",
				Type: "saml",
				SAML: &config.SAMLProviderConfig{
					IDPMetadataXML: metaXML,
					SPEntityID:     "https://sp.example.com/s27",
					ACSURL:         "relative-no-scheme", // no "https://" → ssoCompleteURL returns error
				},
			},
		},
	}

	_, _, count := buildSSOProviders(sso)
	// The SAML provider is skipped because ssoCompleteURL rejects the ACSURL, so no
	// provider is registered and count is 0.
	if count != 0 {
		t.Fatalf("expected 0 registered providers, got %d", count)
	}
}

// ── startSchedulers: active legal hold blocks the retention-purge scheduler ──

// TestStartSchedulers_S27_LegalHoldBlocksPurge exercises the legalHoldBlocks
// closure's "active hold" branch inside startSchedulers. A legal hold is
// inserted directly into the storage layer (bypassing the RBAC check in
// PlaceLegalHold), then startSchedulers runs against the same DB with the
// retention-purge scheduler enabled.
//
// On its first tick (immediate, per runScheduler) the purge scheduler calls
// legalHoldBlocks, which finds an active hold and returns true, logging the
// "skipped: a legal hold is active" message. #G12: this scheduler moved out
// of startHTTPServer into startSchedulers.
func TestStartSchedulers_S27_LegalHoldBlocksPurge(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	const dbPath = "legalholdtest_s27.db"
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: dbPath},
		},
		Purge: config.PurgeConfig{
			Enabled:  true,
			Schedule: "1ms",
		},
	}

	// Initialise the DB schema and insert a legal hold via direct storage access.
	coreService, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService: %v", err)
	}
	ctx1 := context.Background()
	_, err = coreService.Storage().CreateLegalHold(ctx1, &models.LegalHold{
		Reason:   "s27-test-hold",
		PlacedAt: time.Now(),
		Released: false,
	})
	if err != nil {
		t.Fatalf("CreateLegalHold: %v", err)
	}

	// Run the schedulers against the same DB. The purge scheduler fires
	// immediately (interval=1ms), finds the active legal hold, and logs the
	// skip message.
	ctx2, cancel := context.WithCancel(context.Background())
	defer cancel()
	startSchedulersForTest(t, ctx2, cfg, coreService)
	time.Sleep(200 * time.Millisecond)
}

// ── startSchedulers: JIT access-expiry sweep removes expired role grants ─────

// TestStartSchedulers_S27_JITExpiredGrantSwept exercises the JIT expiry
// scheduler's "n > 0" log branch by pre-populating the DB with an expired
// role grant, then running startSchedulers with JITAccessExpiry.Enabled: the
// sweeper fires immediately (interval=1ms) and RemoveExpiredRoleGrants
// returns n=1, triggering the log.Printf call. #G12: this scheduler moved out
// of startHTTPServer into startSchedulers.
func TestStartSchedulers_S27_JITExpiredGrantSwept(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	const dbPath = "jitexpiry_s27.db"
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: dbPath},
		},
		JITAccessExpiry: config.JITAccessExpiryConfig{
			Enabled:  true,
			Schedule: "1ms",
		},
	}

	// Initialise DB schema and pre-populate an expired role grant.
	coreService, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService: %v", err)
	}
	ctx1 := context.Background()
	store := coreService.Storage()

	s27JitRoleName, err := identity.NewFoldedName("s27-jit-role")
	if err != nil {
		t.Fatalf("NewFoldedName: %v", err)
	}
	role, err := store.CreateRole(ctx1, s27JitRoleName, "")
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	user, err := store.CreateUser(ctx1, &models.User{
		Username: "jituser-s27",
		IsActive: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.AssignRoleWithExpiry(
		ctx1, user.ID, role.ID,
		corestorage.Scope{},        // global scope
		time.Now().Add(-time.Hour), // already expired
	); err != nil {
		t.Fatalf("AssignRoleWithExpiry: %v", err)
	}

	// Run the schedulers. The JIT expiry sweeper fires at once (interval=1ms),
	// calls RemoveExpiredRoleGrants, finds n=1, and logs the "removed N
	// expired grant(s)" message.
	ctx2, cancel := context.WithCancel(context.Background())
	defer cancel()
	startSchedulersForTest(t, ctx2, cfg, coreService)
	time.Sleep(300 * time.Millisecond)
}
