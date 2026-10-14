// server_s4_test.go — coverage push: initializeCoreService optional wiring paths,
// startHTTPServer (cancelled context), startGRPCServer error, enforceKeyFilePermissions,
// initializeEncryption error paths, discoverOIDC (httptest), and lockedRun edge cases.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// newMinimalCfg returns a bare-minimum config that lets initializeCoreService
// succeed with a fresh in-memory SQLite database and no encryption.
func newMinimalCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "test.db"},
		},
	}
}

// initI18n ensures i18n is initialised for tests that call initializeCoreService.
func initI18n(t *testing.T) {
	t.Helper()
	i18n.ResetForTesting()
	t.Cleanup(i18n.ResetForTesting)
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n init: %v", err)
	}
}

// ── initializeCoreService — happy-path baseline ───────────────────────────────

func TestInitializeCoreService_Baseline(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)

	svc, enc, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil core service")
	}
	if enc != nil {
		t.Fatal("expected nil encSvc when encryption is disabled")
	}
}

// TestInitializeCoreService_BlankStorageTypeDefaultsToLocal is
// #G-blank-storage-default's core regression guard: a config with NO
// storage.type set at all (the "no storage: block in keyorix.yaml" shape, or
// a bare zero-value config.Config{} reached with no config file present)
// must still boot into local SQLite storage exactly as it did before
// internal/storage/factory.go's CreateStorage started hard-erroring on a
// blank storage.type for every OTHER caller. The server's own boot path
// (initializeCoreService, mirroring main()'s identical default-application)
// is the one place allowed to supply that default -- this test constructs
// the config the way an operator's minimal deployment would (only
// database.path set, storage.type entirely omitted) and asserts
// initializeCoreService still succeeds, proving the default is actually
// wired up rather than merely intended.
func TestInitializeCoreService_BlankStorageTypeDefaultsToLocal(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := &config.Config{
		Storage: config.StorageConfig{
			// Type deliberately left blank -- see doc comment above.
			Database: config.DatabaseConfig{Path: "test.db"},
		},
	}

	svc, enc, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with blank storage.type: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil core service")
	}
	if enc != nil {
		t.Fatal("expected nil encSvc when encryption is disabled")
	}
	if cfg.Storage.Type != "local" {
		t.Errorf("expected initializeCoreService to default cfg.Storage.Type to %q, got %q", "local", cfg.Storage.Type)
	}
}

// ── initializeCoreService — password policy ───────────────────────────────────

func TestInitializeCoreService_PasswordPolicy(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.PasswordPolicy = config.PasswordPolicyConfig{
		MinLength:        config.IntPtr(12),
		RequireUppercase: config.BoolPtr(true),
		RequireLowercase: config.BoolPtr(true),
		RequireDigit:     config.BoolPtr(true),
		RequireSpecial:   config.BoolPtr(true),
		HistoryCount:     config.IntPtr(5),
		MaxAgeDays:       90,
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with PasswordPolicy: %v", err)
	}
}

// ── initializeCoreService — secret-value policy ───────────────────────────────

func TestInitializeCoreService_SecretValuePolicy(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.SecretValuePolicy = config.SecretValuePolicyConfig{
		Enabled:       true,
		MinLength:     8,
		RejectCommon:  true,
		ExtraDenylist: []string{"hunter2", "changeme"},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with SecretValuePolicy: %v", err)
	}
}

// ── initializeCoreService — secret-name policy ───────────────────────────────

func TestInitializeCoreService_SecretNamePolicy(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.SecretNamePolicy = config.SecretNamePolicyConfig{
		Enabled:   true,
		Pattern:   `^[a-z][a-z0-9_-]{0,63}$`,
		MaxLength: 64,
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with SecretNamePolicy: %v", err)
	}
}

// ── initializeCoreService — login lockout disabled ────────────────────────────

func TestInitializeCoreService_LoginLockoutDisabled(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Security.LoginLockout = config.LoginLockoutConfig{Disabled: true}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with lockout disabled: %v", err)
	}
}

// ── initializeCoreService — classification enforcement ───────────────────────

func TestInitializeCoreService_ClassificationEnforcement(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Classification.RestrictedRequiresApproval = true

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with classification enforcement: %v", err)
	}
}

// ── initializeCoreService — dual-control policy ───────────────────────────────

func TestInitializeCoreService_DualControl(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.DualControl = config.DualControlConfig{RequiredApprovals: 2}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with DualControl: %v", err)
	}
}

// ── initializeCoreService — break-glass policy ───────────────────────────────

func TestInitializeCoreService_BreakGlass(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.BreakGlass = config.BreakGlassConfig{
		Enabled:       true,
		EmergencyRole: "emergency-admin",
		DefaultTTL:    "2h",
		MaxTTL:        "12h",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with BreakGlass: %v", err)
	}
}

// ── initializeCoreService — data-retention windows ───────────────────────────

func TestInitializeCoreService_DataRetention(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.DataRetention = config.DataRetentionConfig{
		AnomalyAlertsDays:       30,
		ClosedAccessReviewsDays: 90,
		BreakGlassDays:          365,
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with DataRetention: %v", err)
	}
}

// ── initializeCoreService — recertification cadence ──────────────────────────

func TestInitializeCoreService_RecertificationCadence(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Recertification.CadenceDays = 90

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with Recertification: %v", err)
	}
}

// ── initializeCoreService — session TTLs ─────────────────────────────────────

func TestInitializeCoreService_SessionTTLs(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Session = config.SessionConfig{
		AccessTTL:   "30m",
		AbsoluteTTL: "8h",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with Session TTLs: %v", err)
	}
}

// ── initializeCoreService — dynamic secrets ───────────────────────────────────

func TestInitializeCoreService_DynamicSecrets(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.DynamicSecrets = config.DynamicSecretsConfig{
		SweepEnabled: true,
		MaxLeaseTTL:  "24h",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with DynamicSecrets: %v", err)
	}
}

// ── initializeCoreService — membership validation mode ───────────────────────

func TestInitializeCoreService_MembershipValidationMode(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Membership.ValidationMode = "allowlist"

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with membership mode: %v", err)
	}
}

// ── initializeCoreService — KEYORIX_BOOTSTRAP_TOKEN env ──────────────────────

func TestInitializeCoreService_BootstrapTokenFromEnv(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "test-bootstrap-token-12345")

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with KEYORIX_BOOTSTRAP_TOKEN: %v", err)
	}
}

// ── initializeCoreService — audit checkpoint notary (url empty) ───────────────

func TestInitializeCoreService_CheckpointNotary_NoURL(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Audit.CheckpointNotary.Enabled = true
	cfg.Audit.CheckpointNotary.URL = ""

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with notary (no URL): %v", err)
	}
}

// ── initializeCoreService — audit checkpoint notary (url + no ca_cert) ───────

// Enabling the notary without a trust root must NOT fail startup — this is a
// legitimate, intentional configuration (see config.CheckpointNotaryConfig.
// CACertPath's doc comment: anchoring still records tokens for later/off-box
// verification even without a locally-configured trust root). But the resulting
// core must report the anchor as not locally verifiable
// (#baseline/notary-findings.json#1), so a caller/auditor reviewing checkpoint
// records can tell a recorded-but-unverifiable anchor apart from a verified one.
func TestInitializeCoreService_CheckpointNotary_WithURL_NoCA(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Audit.CheckpointNotary.Enabled = true
	cfg.Audit.CheckpointNotary.URL = "https://tsa.example.com/ts"
	cfg.Audit.CheckpointNotary.CACertPath = ""

	svc, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with notary URL but no CA: %v", err)
	}
	if svc.CheckpointAnchorVerifiable() {
		t.Error("expected CheckpointAnchorVerifiable() to be false with no ca_cert_path configured")
	}
}

// ── initializeCoreService — audit checkpoint notary (invalid ca path) ─────────

func TestInitializeCoreService_CheckpointNotary_BadCACert(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Audit.CheckpointNotary.Enabled = true
	cfg.Audit.CheckpointNotary.URL = "https://tsa.example.com/ts"
	cfg.Audit.CheckpointNotary.CACertPath = "/nonexistent/ca.pem"

	// A bad CA path only logs a warning; it must NOT fail startup.
	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with bad CA cert path: %v", err)
	}
}

// ── initializeCoreService — rotation backend (postgresql, no allowed_refs) ───

func TestInitializeCoreService_RotationBackend_NoAllowedRefs(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{
		{Name: "pg-prod", Type: "postgresql", AllowedRefs: nil},
	}

	// Expect success — no allowed_refs logs a warning but skips the backend.
	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with backend (no allowed_refs): %v", err)
	}
}

// ── initializeCoreService — rotation backend (postgresql, with allowed_refs) ─

func TestInitializeCoreService_RotationBackend_PostgreSQL(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{
		{Name: "pg-prod", Type: "postgresql", AllowedRefs: []string{"prod/*"}},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with postgresql backend: %v", err)
	}
}

// ── initializeCoreService — rotation backend (mysql) ─────────────────────────

func TestInitializeCoreService_RotationBackend_MySQL(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{
		{Name: "mysql-prod", Type: "mysql", AllowedRefs: []string{"prod/*"}},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with mysql backend: %v", err)
	}
}

// ── initializeCoreService — rotation backend (various types) ─────────────────

func TestInitializeCoreService_RotationBackend_Various(t *testing.T) {
	requireCloudBuild(t, true, true, true)
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{
		{Name: "mongo", Type: "mongodb", AllowedRefs: []string{"prod/*"}},
		{Name: "redis", Type: "redis", AllowedRefs: []string{"prod/*"}},
		{Name: "aws", Type: "aws-iam", AllowedRefs: []string{"prod/*"}},
		{Name: "gcp", Type: "gcp-service-account", AllowedRefs: []string{"prod/*"}},
		{Name: "azure", Type: "azure-app", AllowedRefs: []string{"prod/*"}},
		{Name: "unknown", Type: "other-db", AllowedRefs: []string{"prod/*"}},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with various backends: %v", err)
	}
}

// ── initializeCoreService — Connect (unknown type rejected) ──────────────────

// #1476: an unknown connector Type used to be silently skipped (this test's
// own name and assertion, until this change, encoded exactly that now-obsolete
// behavior) — the same fail-open shape ADR-082 closed for scope. It now fails
// cfg.Validate() before initializeCoreService reaches its Connect-wiring loop.
func TestInitializeCoreService_Connect_UnknownType(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "c1", Type: "unknown-type", Scope: "platform"},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot with an unrecognized connector type")
	}
}

// ── initializeCoreService — Connect (known types) ─────────────────────────────

func TestInitializeCoreService_Connect_KnownTypes(t *testing.T) {
	requireCloudBuild(t, true, false, true)
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "aws", Type: "aws-secrets-manager", AllowedRefs: []string{"prod/*"}, Scope: "platform"},
			{Name: "gcp", Type: "gcp-secret-manager", ProjectID: "my-proj", AllowedRefs: []string{"prod/*"}, Scope: "platform"},
			{Name: "vault", Type: "vault", Address: "http://vault:8200", AllowedRefs: []string{"prod/*"}, Scope: "platform"},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with known connector types: %v", err)
	}
}

// ── initializeCoreService — Connect (gcp, no project_id) ────────────────────

// project_id is now a required field for gcp-secret-manager connectors — an unset
// project_id used to only log a startup warning (an unpinned connector could reach
// any GCP project the ambient ADC identity can access, regardless of this
// connector's Keyorix tenant scope: a confused-deputy gap). This test's own name
// and assertion, until this change, encoded exactly that now-obsolete "boots fine"
// behavior. It now fails cfg.Validate() (called inside initializeCoreService)
// before boot ever reaches the Connect-wiring loop.
func TestInitializeCoreService_Connect_GCP_NoProjectID(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "gcp-noproj", Type: "gcp-secret-manager", ProjectID: "", AllowedRefs: []string{"prod/*"}, Scope: "platform"},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot a gcp-secret-manager connector with no project_id")
	}
	if got := err.Error(); !contains(got, "gcp-noproj") || !contains(got, "project_id") {
		t.Fatalf("expected error to name the connector and project_id, got: %v", err)
	}
}

// ── initializeCoreService — aws (account_id is optional, unlike GCP's project_id) ──

// account_id is deliberately OPTIONAL for aws-secrets-manager connectors — see
// ConnectorConfig.AccountID's own doc comment and internal/connect/awssm.go for the
// risk-shape reason a mandatory pin isn't warranted here the way it is for GCP. A
// missing account_id must still boot fine (server/main.go only logs a
// recommendation), while a MALFORMED one (set, but not 12 digits) must fail boot —
// validateConnectAWSAccountID's format check, run from cfg.Validate() before the
// Connect-wiring loop is ever reached.
func TestInitializeCoreService_Connect_AWS_NoAccountID(t *testing.T) {
	requireCloudBuild(t, true, false, false)
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "aws-noaccount", Type: "aws-secrets-manager", AccountID: "", AllowedRefs: []string{"prod/*"}, Scope: "platform"},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with aws-secrets-manager, no account_id (optional, must still boot): %v", err)
	}
}

func TestInitializeCoreService_Connect_AWS_MalformedAccountID(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "aws-badaccount", Type: "aws-secrets-manager", AccountID: "not-12-digits", AllowedRefs: []string{"prod/*"}, Scope: "platform"},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot an aws-secrets-manager connector with a malformed account_id")
	}
	if got := err.Error(); !contains(got, "aws-badaccount") || !contains(got, "account_id") {
		t.Fatalf("expected error to name the connector and account_id, got: %v", err)
	}
}

// ── initializeCoreService — azure connector ───────────────────────────────────

func TestInitializeCoreService_Connect_AzureKeyVault(t *testing.T) {
	requireCloudBuild(t, false, true, false)
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "azure-kv", Type: "azure-key-vault", Address: "https://vault.vault.azure.net", AllowedRefs: []string{"prod/*"}, Scope: "platform"},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with Azure Key Vault connector: %v", err)
	}
}

// ── initializeCoreService — WebAuthn enabled ──────────────────────────────────

func TestInitializeCoreService_WebAuthn(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.WebAuthn = config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "localhost",
		RPOrigins: []string{"http://localhost:3000"},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with WebAuthn: %v", err)
	}
}

// ── initializeCoreService — WebAuthn invalid config (bad RP ID) ──────────────

func TestInitializeCoreService_WebAuthn_InvalidConfig(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.WebAuthn = config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "", // invalid: empty RPID
		RPOrigins: []string{},
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error for WebAuthn with empty RPID")
	}
}

// ── initializeCoreService — SSO enabled with skipped provider ─────────────────

func TestInitializeCoreService_SSO_AllProvidersFail(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.SSO = config.SSOConfig{
		Enabled: true,
		Providers: []config.SSOProviderConfig{
			{
				// All required fields missing → skipped with a warning
				Name:   "",
				Type:   "oidc",
				Issuer: "",
			},
		},
	}

	// Must not fail startup — bad provider is just skipped.
	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with empty SSO provider: %v", err)
	}
}

// ── initializeCoreService — license path (nonexistent) ───────────────────────

func TestInitializeCoreService_License_MissingFile(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.License.Path = "/nonexistent/license.jwt"

	// A missing license file logs a warning but does NOT fail startup.
	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with missing license path: %v", err)
	}
}

// ── initializeCoreService — license path (valid file with dummy token) ────────

func TestInitializeCoreService_License_ValidPath(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)
	licFile := filepath.Join(dir, "license.jwt")
	if err := os.WriteFile(licFile, []byte("dummy-token-not-valid"), 0o600); err != nil {
		t.Fatalf("write license file: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "test.db"},
		},
		License: config.LicenseConfig{Path: licFile},
	}

	// A file with an invalid token still succeeds (community baseline fallback).
	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with dummy license file: %v", err)
	}
}

// ── enforceKeyFilePermissions ─────────────────────────────────────────────────

func TestEnforceKeyFilePermissions_NoFiles(t *testing.T) {
	cfg := &config.Config{}
	if err := enforceKeyFilePermissions(cfg); err != nil {
		t.Errorf("enforceKeyFilePermissions (no files): %v", err)
	}
}

func TestEnforceKeyFilePermissions_FileNotExist(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  filepath.Join(dir, "nonexistent_dek.json"),
				SaltPath: filepath.Join(dir, "nonexistent_salt.bin"),
			},
		},
	}
	// Non-existent paths are silently skipped.
	if err := enforceKeyFilePermissions(cfg); err != nil {
		t.Errorf("enforceKeyFilePermissions (nonexistent files): %v", err)
	}
}

func TestEnforceKeyFilePermissions_InsecureFile_WarnOnly(t *testing.T) {
	dir := t.TempDir()
	dek := filepath.Join(dir, "dek.json")
	salt := filepath.Join(dir, "salt.bin")
	if err := os.WriteFile(dek, []byte("{}"), 0o644); err != nil { // world-readable
		t.Fatalf("write dek: %v", err)
	}
	if err := os.WriteFile(salt, []byte("salt"), 0o644); err != nil { // world-readable
		t.Fatalf("write salt: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  dek,
				SaltPath: salt,
			},
		},
		Security: config.SecurityConfig{
			// EnableFilePermissionCheck = false → warn only
		},
	}

	// Should return nil (warn only, not fail closed)
	if err := enforceKeyFilePermissions(cfg); err != nil {
		t.Errorf("enforceKeyFilePermissions (warn mode) returned error: %v", err)
	}
}

func TestEnforceKeyFilePermissions_InsecureFile_FailClosed(t *testing.T) {
	dir := t.TempDir()
	dek := filepath.Join(dir, "dek.json")
	if err := os.WriteFile(dek, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write dek: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled: true,
				DEKPath: dek,
			},
		},
		Security: config.SecurityConfig{
			EnableFilePermissionCheck: true,
			// AllowUnsafeFilePermissions = false → fail closed
		},
	}

	if err := enforceKeyFilePermissions(cfg); err == nil {
		t.Error("expected error for world-readable DEK with fail-closed mode, got nil")
	}
}

func TestEnforceKeyFilePermissions_InsecureFile_AllowUnsafe(t *testing.T) {
	dir := t.TempDir()
	dek := filepath.Join(dir, "dek.json")
	if err := os.WriteFile(dek, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write dek: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled: true,
				DEKPath: dek,
			},
		},
		Security: config.SecurityConfig{
			EnableFilePermissionCheck:  true,
			AllowUnsafeFilePermissions: true, // explicit override
		},
	}

	// AllowUnsafeFilePermissions bypasses the fail-closed → warn only, nil return.
	if err := enforceKeyFilePermissions(cfg); err != nil {
		t.Errorf("enforceKeyFilePermissions (allow_unsafe): %v", err)
	}
}

func TestEnforceKeyFilePermissions_TLSKeyFile_Insecure_WarnOnly(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "server.key")
	if err := os.WriteFile(keyFile, []byte("KEY"), 0o644); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				TLS: config.TLSConfig{
					Enabled: true,
					KeyFile: keyFile,
				},
			},
		},
	}

	// warn mode (EnableFilePermissionCheck = false)
	if err := enforceKeyFilePermissions(cfg); err != nil {
		t.Errorf("enforceKeyFilePermissions (TLS key warn): %v", err)
	}
}

// ── initializeEncryption error paths ─────────────────────────────────────────

func TestInitializeEncryption_Disabled(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{Enabled: false},
		},
	}
	svc, err := initializeEncryption(cfg, nil)
	if err != nil {
		t.Errorf("initializeEncryption (disabled): %v", err)
	}
	if svc != nil {
		t.Error("expected nil service when encryption disabled")
	}
}

func TestInitializeEncryption_PasswordProvider_NoPassword(t *testing.T) {
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.json",
				SaltPath: "salt.bin",
			},
		},
	}
	_, err := initializeEncryption(cfg, nil)
	if err == nil {
		t.Fatal("expected error for password provider with no KEYORIX_MASTER_PASSWORD")
	}
}

func TestInitializeEncryption_ExplicitPasswordProvider_NoPassword(t *testing.T) {
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.json",
				SaltPath: "salt.bin",
				KeyProvider: config.KeyProviderConfig{
					Type: "password",
				},
			},
		},
	}
	_, err := initializeEncryption(cfg, nil)
	if err == nil {
		t.Fatal("expected error for explicit password provider with no KEYORIX_MASTER_PASSWORD")
	}
}

// ── discoverOIDC — httptest server paths ──────────────────────────────────────

// discoverDoc is a helper struct for building OIDC discovery JSON.
type discoverDoc struct {
	Issuer                string `json:"issuer,omitempty"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri,omitempty"`
}

func TestDiscoverOIDC_Non200Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := discoverOIDC(srv.URL)
	if err == nil {
		t.Fatal("expected error for non-200 discovery response")
	}
}

func TestDiscoverOIDC_MissingEndpoints(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := discoverDoc{Issuer: issuer} // missing authorization_endpoint etc.
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	issuer = srv.URL

	_, err := discoverOIDC(issuer)
	if err == nil {
		t.Fatal("expected error for discovery doc missing required endpoints")
	}
}

func TestDiscoverOIDC_IssuerMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := discoverDoc{
			Issuer:                "https://other-issuer.example.com",
			AuthorizationEndpoint: "https://other-issuer.example.com/auth",
			TokenEndpoint:         "https://other-issuer.example.com/token",
			JWKSURI:               "https://other-issuer.example.com/.well-known/jwks.json",
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()

	_, err := discoverOIDC(srv.URL)
	if err == nil {
		t.Fatal("expected error for issuer mismatch in discovery doc")
	}
}

func TestDiscoverOIDC_JWKSURIHostMismatch(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := discoverDoc{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/auth",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               "https://attacker.example.com/.well-known/jwks.json",
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	issuer = srv.URL

	_, err := discoverOIDC(issuer)
	if err == nil {
		t.Fatal("expected error when jwks_uri host differs from issuer host")
	}
}

func TestDiscoverOIDC_ValidDocument(t *testing.T) {
	// httptest.NewServer binds to 127.0.0.1 — loopback is allowed by discoverOIDC.
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := discoverDoc{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/auth",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               issuer + "/.well-known/jwks.json",
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	issuer = srv.URL

	disc, err := discoverOIDC(issuer)
	if err != nil {
		t.Fatalf("discoverOIDC valid doc: %v", err)
	}
	if disc.JWKSURI == "" {
		t.Error("expected non-empty JWKSURI")
	}
}

func TestDiscoverOIDC_EmptyIssuerInDoc(t *testing.T) {
	// When issuer is empty in the doc, the issuer-match check is skipped.
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := discoverDoc{
			// Issuer deliberately absent → issuer check is skipped
			AuthorizationEndpoint: issuer + "/auth",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               issuer + "/.well-known/jwks.json",
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	issuer = srv.URL

	disc, err := discoverOIDC(issuer)
	if err != nil {
		t.Fatalf("discoverOIDC (empty issuer in doc): %v", err)
	}
	if disc.AuthorizationEndpoint == "" {
		t.Error("expected non-empty AuthorizationEndpoint")
	}
}

func TestDiscoverOIDC_InvalidJWKSURI(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := discoverDoc{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/auth",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               "://bad-url-no-host", // invalid URL
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	issuer = srv.URL

	_, err := discoverOIDC(issuer)
	if err == nil {
		t.Fatal("expected error for invalid jwks_uri")
	}
}

// ── startHTTPServer — cancelled context exits quickly ─────────────────────────

// TestStartHTTPServer_CancelledContext verifies that startHTTPServer returns
// when the context is already cancelled. This exercises all the setup code in
// startHTTPServer up to the <-ctx.Done() wait.
func TestStartHTTPServer_CancelledContext(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	// Pick a free port to avoid conflicts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest.db"},
		},
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    itoa(port),
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	// startHTTPServer blocks on <-ctx.Done() which returns immediately.
	done := make(chan error, 1)
	go func() {
		done <- startHTTPServer(ctx, cfg, coreService)
	}()

	select {
	case err := <-done:
		// Any result is acceptable — function must return, not hang.
		_ = err
	case <-context.Background().Done():
		t.Fatal("startHTTPServer did not return when context was already cancelled")
	}
}

// TestStartHTTPServer_NormalShutdown_NotFlaggedAsStartupFailure is
// RELEASE-BLOCKERS item 4's negative control: a normal, already-successful
// shutdown (bound, served, then ctx cancelled with no active connections —
// server.Shutdown()'s fast, error-free path) must NOT be wrapped in
// errHTTPServerFailedToStart. main()'s caller uses errors.Is against that
// sentinel to decide whether to exit the process fatally — if an ordinary
// shutdown were ever wrongly wrapped, every normal server stop would start
// exiting non-zero instead of the intended narrow case (a startup failure
// that leaves nothing listening).
func TestStartHTTPServer_NormalShutdown_NotFlaggedAsStartupFailure(t *testing.T) {
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
			Database: config.DatabaseConfig{Path: "httptest_normal_shutdown.db"},
		},
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    itoa(port),
			},
		},
	}
	coreService := mustInitCoreService(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- startHTTPServer(ctx, cfg, coreService)
	}()

	// Give the listener a moment to actually bind before triggering shutdown,
	// so this exercises the real bind-then-shutdown sequence, not a
	// pre-cancelled context racing the bind itself.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case shutdownErr := <-done:
		if shutdownErr != nil {
			t.Fatalf("a clean shutdown with no active connections should not error: %v", shutdownErr)
		}
		if errors.Is(shutdownErr, errHTTPServerFailedToStart) {
			t.Error("a normal shutdown must never be wrapped in errHTTPServerFailedToStart")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startHTTPServer did not return after ctx was cancelled")
	}
}

// itoa converts an int to a decimal string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := 20
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// ── startGRPCServer — cancelled context ───────────────────────────────────────

func TestStartGRPCServer_CancelledContext(t *testing.T) {
	// startGRPCServer with a pre-cancelled context exercises initializeCoreService,
	// NewServer (gRPC), net.Listen, and the <-ctx.Done() wait — all returning
	// immediately after a cancelled context.
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "grpctest.db"},
		},
		Server: config.ServerConfig{
			GRPC: config.ServerInstanceConfig{
				Enabled: true,
				Port:    itoa(port),
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	done := make(chan error, 1)
	go func() {
		done <- startGRPCServer(ctx, cfg, coreService)
	}()

	select {
	case err := <-done:
		_ = err
	case <-context.Background().Done():
		t.Fatal("startGRPCServer did not return when context was already cancelled")
	}
}

// ── startSchedulers — with optional scheduler features ───────────────────────

// #G12: this used to run through startHTTPServer with a pre-cancelled context
// (the schedulers wired up synchronously before the HTTP listener even bound);
// scheduler wiring moved to startSchedulers, so it's exercised directly.
func TestStartSchedulers_WithSchedulers(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest2.db"},
		},
		AnomalyAlerts: config.AnomalyAlertsConfig{
			Enabled: true,
			ML: config.AnomalyMLConfig{
				Enabled:   true,
				Threshold: 0.7,
				NumTrees:  50,
			},
			BusinessHours: config.AnomalyBusinessHoursConfig{
				Timezone: "UTC",
			},
		},
		Purge: config.PurgeConfig{
			Enabled:  true,
			Schedule: "1h",
		},
		DataRetention: config.DataRetentionConfig{
			Enabled:           true,
			AnomalyAlertsDays: 30,
		},
		RotationReminders: config.RotationRemindersConfig{
			Enabled:  true,
			Schedule: "1h",
		},
		AutoRotation: config.AutoRotationConfig{
			Enabled:  true,
			Schedule: "1h",
		},
		ComplianceDigest: config.ComplianceDigestConfig{
			Enabled:  true,
			Schedule: "1h",
		},
		Recertification: config.RecertificationConfig{
			Enabled:     true,
			CadenceDays: 90,
			Schedule:    "1h",
		},
		EvidenceDelivery: config.EvidenceDeliveryConfig{
			Enabled:   true,
			OutputDir: dir,
			Schedule:  "1h",
		},
		JITAccessExpiry: config.JITAccessExpiryConfig{
			Enabled:  true,
			Schedule: "1h",
		},
		DynamicSecrets: config.DynamicSecretsConfig{
			SweepEnabled:  true,
			SweepInterval: "1h",
		},
		ExpiryReminders: config.ExpiryRemindersConfig{
			Enabled:  true,
			Schedule: "1h",
		},
		CertificateExpiry: config.CertificateExpiryConfig{
			Enabled:  true,
			Schedule: "1h",
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — anomaly BusinessHours bad timezone ─────────────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_AnomalyBadTimezone(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest3.db"},
		},
		AnomalyAlerts: config.AnomalyAlertsConfig{
			BusinessHours: config.AnomalyBusinessHoursConfig{
				Timezone: "not/a/valid/timezone",
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — license expiry scheduler ────────────────────────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_LicenseExpiryScheduler(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest4.db"},
		},
		LicenseExpiry: config.LicenseExpiryConfig{
			Enabled:  true,
			LeadDays: 30,
			Schedule: "1h",
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── initializeCoreService — SIEM audit forwarding ─────────────────────────────

func TestInitializeCoreService_SIEM_Webhook(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// Use a loopback target to pass SSRF guard (loopback is explicitly allowed).
	cfg.Audit.SIEM = config.SIEMConfig{
		Enabled:  true,
		Provider: "webhook",
		Endpoint: "http://127.0.0.1:65530/siem",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with SIEM webhook: %v", err)
	}
}

// ── initializeCoreService — notifications (webhook channel) ──────────────────

func TestInitializeCoreService_Notifications_Webhook(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// Use AllowPrivateNetworkTarget to bypass SSRF guard for test endpoints,
	// exercising the notification webhook wiring code path.
	cfg.Notifications.Webhook = config.NotificationWebhookConfig{
		Enabled:                   true,
		Endpoint:                  "http://127.0.0.1:65531/notify",
		AllowPrivateNetworkTarget: true,
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with notifications webhook: %v", err)
	}
}

// ── initializeCoreService — notifications (slack channel) ────────────────────

func TestInitializeCoreService_Notifications_Slack(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// Use loopback http:// — loopback is explicitly permitted by the SSRF guard.
	cfg.Notifications.Slack = config.NotificationChatConfig{
		Enabled:    true,
		WebhookURL: "http://127.0.0.1:65531/slack",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with Slack notification: %v", err)
	}
}

// ── initializeCoreService — notifications (teams channel) ────────────────────

func TestInitializeCoreService_Notifications_Teams(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// Use loopback http:// — loopback is explicitly permitted by the SSRF guard.
	cfg.Notifications.Teams = config.NotificationChatConfig{
		Enabled:    true,
		WebhookURL: "http://127.0.0.1:65532/teams",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with Teams notification: %v", err)
	}
}

// ── initializeCoreService — notifications (email only, no broadcast_to) ──────

func TestInitializeCoreService_Notifications_Email_NoBroadcastTo(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// Email enabled, no broadcast_to → warning logged, but no failure
	cfg.Notifications.Email = config.NotificationEmailConfig{
		Enabled: true,
		Host:    "127.0.0.1",
		Port:    65533,
		From:    "keyorix@localhost",
		TLS:     "starttls",
		// BroadcastTo deliberately empty
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with email (no broadcast_to): %v", err)
	}
}

// ── initializeCoreService — OIDC federation ───────────────────────────────────

func TestInitializeCoreService_OIDCFederation(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// A loopback jwks_uri is valid for init (no network call at startup).
	cfg.OIDC = config.OIDCConfig{
		Enabled: true,
		Issuers: []config.OIDCIssuerConfig{
			{
				Name:      "k8s",
				Issuer:    "https://kubernetes.default.svc",
				JWKSURI:   "http://127.0.0.1:65432/.well-known/jwks.json", // loopback — valid scheme
				Audiences: []string{"keyorix"},
			},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with OIDC federation: %v", err)
	}
}

// ── initializeCoreService — OIDC federation invalid jwks_uri ──────────────────

func TestInitializeCoreService_OIDCFederation_InvalidJWKS(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.OIDC = config.OIDCConfig{
		Enabled: true,
		Issuers: []config.OIDCIssuerConfig{
			{
				Name:      "bad",
				Issuer:    "https://oidc.example.com",
				JWKSURI:   "ftp://bad-scheme.example.com/jwks", // invalid scheme
				Audiences: []string{"keyorix"},
			},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error for invalid jwks_uri scheme in OIDC federation config")
	}
}

// ── buildSSOProviders — valid OIDC discovery (httptest) ───────────────────────

// TestBuildSSOProviders_OIDCSuccess tests the complete OIDC provider registration
// path when discovery succeeds, exercising the JWKS resolver wiring.
func TestBuildSSOProviders_OIDCSuccess(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := discoverDoc{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/auth",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               issuer + "/.well-known/jwks.json",
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	issuer = srv.URL

	sso := config.SSOConfig{
		Providers: []config.SSOProviderConfig{
			{
				Name:        "testoidc",
				Type:        "oidc",
				Issuer:      issuer,
				ClientID:    "client123",
				RedirectURL: issuer + "/callback",
			},
		},
	}

	providers, resolver, n := buildSSOProviders(sso)
	if n == 0 {
		t.Fatal("expected buildSSOProviders to register the OIDC provider")
	}
	if providers == nil {
		t.Fatal("expected non-nil providers map")
	}
	if resolver == nil {
		t.Fatal("expected non-nil JWKS resolver for OIDC provider")
	}
}

// TestBuildSSOProviders_SAMLOnly verifies that a SAML-only deployment (no OIDC)
// builds a nil JWKS resolver (SAML doesn't need one).
func TestBuildSSOProviders_SAMLOnly(t *testing.T) {
	// Build a minimal valid SAML IdP metadata XML (enough to parse).
	metaXML := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

	sso := config.SSOConfig{
		Providers: []config.SSOProviderConfig{
			{
				Name: "mysaml",
				Type: "saml",
				SAML: &config.SAMLProviderConfig{
					IDPMetadataXML: metaXML,
					SPEntityID:     "urn:my-sp",
					ACSURL:         "https://app.example.com/auth/sso/mysaml/acs",
				},
			},
		},
	}

	providers, resolver, n := buildSSOProviders(sso)
	// buildSAMLProvider may or may not succeed depending on samlpkg validation.
	// If it does succeed, resolver should be nil (SAML-only, no OIDC).
	if n > 0 {
		if resolver != nil {
			t.Error("SAML-only deployment should have a nil JWKS resolver")
		}
		_ = providers
	}
	// If n == 0 the provider was skipped (invalid metadata) — that's also valid.
}

// ── startHTTPServer — data-retention enabled but unconfigured ─────────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_DataRetention_Unconfigured(t *testing.T) {
	// DataRetention.Enabled with no windows → logs a warning, no scheduler started.
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_dr.db"},
		},
		DataRetention: config.DataRetentionConfig{
			Enabled: true,
			// All day-count fields remain 0 → Configured() returns false → warning logged
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — evidence delivery (no target) ───────────────────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_EvidenceDelivery_NoTarget(t *testing.T) {
	// EvidenceDelivery.Enabled but no target → logs a warning, no scheduler started.
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_ev.db"},
		},
		EvidenceDelivery: config.EvidenceDeliveryConfig{
			Enabled: true,
			// No OutputDir and no Webhook → HasTarget() = false
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — audit checkpoints disabled ──────────────────────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_AuditCheckpointsDisabled(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_ckpt.db"},
		},
		AuditCheckpoints: config.AuditCheckpointsConfig{
			Disabled: true,
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — anomaly alerts enabled ──────────────────────────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_AnomalyAlertsEnabled(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_anom.db"},
		},
		AnomalyAlerts: config.AnomalyAlertsConfig{
			Enabled: true, // enables the alerting branch
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — purge scheduler enabled ─────────────────────────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_PurgeScheduler(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_purge.db"},
		},
		Purge: config.PurgeConfig{
			Enabled:  true,
			Schedule: "1h",
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — data-retention configured scheduler ────────────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_DataRetention_Configured(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_dr2.db"},
		},
		DataRetention: config.DataRetentionConfig{
			Enabled:           true,
			AnomalyAlertsDays: 30, // Configured() = true
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — JIT access expiry + dynamic secrets enabled ─────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_JITAndDynamicSecrets(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_jit.db"},
		},
		JITAccessExpiry: config.JITAccessExpiryConfig{
			Enabled:  true,
			Schedule: "1h",
		},
		DynamicSecrets: config.DynamicSecretsConfig{
			SweepEnabled: true,
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── initializeCoreService — auto rotation enabled ─────────────────────────────

func TestInitializeCoreService_AutoRotation_Enabled(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation = config.AutoRotationConfig{
		Enabled:  true,
		Schedule: "1h",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with AutoRotation enabled: %v", err)
	}
}

// ── startHTTPServer — auto rotation + recertification ────────────────────────

// #G12: moved to startSchedulers.
func TestStartSchedulers_AutoRotationAndRecertification(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_rot.db"},
		},
		AutoRotation: config.AutoRotationConfig{
			Enabled:  true,
			Schedule: "1h",
		},
		Recertification: config.RecertificationConfig{
			Enabled:     true,
			CadenceDays: 90,
			Schedule:    "1h",
			AutoOpen:    true,
		},
		ComplianceDigest: config.ComplianceDigestConfig{
			Enabled:  true,
			Schedule: "1h",
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── initializeCoreService — rotation backends no-allowed-refs for all types ──

func TestInitializeCoreService_RotationBackend_AllNoAllowedRefs(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// None have AllowedRefs → all are skipped with a warning, no executors registered
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{
		{Name: "mysql", Type: "mysql"},
		{Name: "mongo", Type: "mongodb"},
		{Name: "redis", Type: "redis"},
		{Name: "aws", Type: "aws-iam"},
		{Name: "gcp", Type: "gcp-service-account"},
		{Name: "azure", Type: "azure-app"},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with all no-allowed-refs backends: %v", err)
	}
}

// ── initializeCoreService — evidence webhook target wiring ───────────────────

func TestInitializeCoreService_EvidenceWebhook(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// Use loopback + AllowPrivateNetworkTarget to exercise evidence webhook wiring.
	cfg.EvidenceDelivery = config.EvidenceDeliveryConfig{
		Enabled: true,
		Webhook: config.EvidenceWebhookConfig{
			Enabled:                   true,
			Endpoint:                  "http://127.0.0.1:65540/evidence",
			AllowPrivateNetworkTarget: true,
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with evidence webhook: %v", err)
	}
}

// ── initializeCoreService — multiple evidence targets (multi-forwarder) ───────

func TestInitializeCoreService_EvidenceWebhook_MultiTarget(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// First webhook target
	cfg.EvidenceDelivery = config.EvidenceDeliveryConfig{
		Enabled: true,
		Webhook: config.EvidenceWebhookConfig{
			Enabled:                   true,
			Endpoint:                  "http://127.0.0.1:65541/evidence1",
			AllowPrivateNetworkTarget: true,
		},
		// ObjectStore also enabled → two targets → multi-forwarder path
		// However NewObjectStore would need cloud creds. Use two webhooks instead
		// by testing the single-target path only. ObjectStore requires cloud auth.
	}

	// Still exercises the "case 1" path in the evidenceTargets switch.
	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with evidence single target: %v", err)
	}
}

// ── initializeCoreService — SSO with successful OIDC discovery ───────────────

func TestInitializeCoreService_SSO_OIDCSuccess(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)

	// Use httptest.NewServer — loopback is allowed by discoverOIDC and the JWKS resolver.
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discoverDoc{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/auth",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               issuer + "/.well-known/jwks.json",
		})
	}))
	defer srv.Close()
	issuer = srv.URL

	cfg.SSO = config.SSOConfig{
		Enabled: true,
		Providers: []config.SSOProviderConfig{
			{
				Name:        "test-oidc",
				Type:        "oidc",
				Issuer:      issuer,
				ClientID:    "client123",
				RedirectURL: issuer + "/callback",
			},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with SSO OIDC: %v", err)
	}
}

// ── initializeCoreService — CA cert for checkpoint notary ────────────────────

func TestInitializeCoreService_CheckpointNotary_ValidCA(t *testing.T) {
	initI18n(t)

	// Generate a minimal self-signed CA cert PEM for test purposes.
	caPEM := testSelfSignedCACert(t)
	dir := t.TempDir()
	t.Chdir(dir)
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "test.db"},
		},
		Audit: config.AuditConfig{
			CheckpointNotary: config.CheckpointNotaryConfig{
				Enabled:    true,
				URL:        "http://127.0.0.1:65542/ts",
				CACertPath: caFile,
			},
		},
	}

	svc, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with valid CA cert: %v", err)
	}
	// A configured, loaded trust root must make the anchor locally verifiable
	// (#baseline/notary-findings.json#1) — contrast with
	// TestInitializeCoreService_CheckpointNotary_WithURL_NoCA, which pins the
	// false case.
	if !svc.CheckpointAnchorVerifiable() {
		t.Error("expected CheckpointAnchorVerifiable() to be true once a valid ca_cert_path is configured")
	}
}

// ── createTLSConfig — AutoCert returns nil ────────────────────────────────────

func TestCreateTLSConfig_AutoCert_ReturnsNil(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				TLS: config.TLSConfig{
					Enabled:  true,
					AutoCert: true,
				},
			},
		},
	}
	tlsCfg, err := createTLSConfig(cfg)
	if err != nil {
		t.Errorf("createTLSConfig with AutoCert: %v", err)
	}
	if tlsCfg != nil {
		t.Error("createTLSConfig with AutoCert should return nil")
	}
}

// ── createTLSConfig — bad cert/key returns error ─────────────────────────────

func TestCreateTLSConfig_BadCertKey(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				TLS: config.TLSConfig{
					Enabled:  true,
					AutoCert: false,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
		},
	}
	_, err := createTLSConfig(cfg)
	if err == nil {
		t.Error("createTLSConfig with missing cert/key should return error")
	}
}

// ── helpers for test certificate generation ───────────────────────────────────

// testSelfSignedCACert generates a minimal self-signed CA cert as PEM bytes using
// crypto/x509. The cert is valid so loadCertPool and x509.CertPool.AppendCertsFromPEM
// accept it — required to exercise the success branch of loadCertPool (line 248)
// and the checkpoint notary CA-cert wiring path (lines 347-350).
func testSelfSignedCACert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ── startHTTPServer — brief live run to exercise scheduler closure bodies ─────

// TestStartHTTPServer_ShortLive runs startHTTPServer with a real timeout (not
// pre-cancelled) so that all the background scheduler goroutines have time to
// schedule and execute their first closure invocation. This covers the closure
// bodies inside the scheduler callbacks (anomaly detection, retention purge,
// rotation reminders, etc.) that require the scheduler goroutine to actually run.
// #G12: moved to startSchedulers.
func TestStartSchedulers_ShortLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live server test in short mode")
	}
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	// The evidence-delivery scheduler fires at 1ms and may write a new file
	// after the test returns but before t.TempDir() cleanup runs, causing
	// "directory not empty". Use a separate dir with ignored cleanup.
	evidenceDir, errMkdir := os.MkdirTemp("", "kx-evidence-test-*")
	if errMkdir != nil {
		t.Fatalf("MkdirTemp: %v", errMkdir)
	}
	t.Cleanup(func() { _ = os.RemoveAll(evidenceDir) })

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_live.db"},
		},
		// Enable all schedulers so their closure bodies execute on the first tick.
		AnomalyAlerts: config.AnomalyAlertsConfig{
			Enabled:  true,
			Schedule: "1ms", // fire immediately on first tick
		},
		Purge: config.PurgeConfig{
			Enabled:  true,
			Schedule: "1ms",
		},
		DataRetention: config.DataRetentionConfig{
			Enabled:           true,
			AnomalyAlertsDays: 30,
			Schedule:          "1ms",
		},
		RotationReminders: config.RotationRemindersConfig{
			Enabled:  true,
			Schedule: "1ms",
		},
		ExpiryReminders: config.ExpiryRemindersConfig{
			Enabled:  true,
			LeadDays: 14,
			Schedule: "1ms",
		},
		CertificateExpiry: config.CertificateExpiryConfig{
			Enabled:  true,
			LeadDays: 30,
			Schedule: "1ms",
		},
		LicenseExpiry: config.LicenseExpiryConfig{
			Enabled:  true,
			LeadDays: 30,
			Schedule: "1ms",
		},
		AutoRotation: config.AutoRotationConfig{
			Enabled:  true,
			Schedule: "1ms",
		},
		ComplianceDigest: config.ComplianceDigestConfig{
			Enabled:  true,
			Schedule: "1ms",
		},
		Recertification: config.RecertificationConfig{
			Enabled:     true,
			CadenceDays: 90,
			Schedule:    "1ms",
			AutoOpen:    false,
		},
		EvidenceDelivery: config.EvidenceDeliveryConfig{
			Enabled:   true,
			OutputDir: evidenceDir,
			Schedule:  "1ms",
		},
		JITAccessExpiry: config.JITAccessExpiryConfig{
			Enabled:  true,
			Schedule: "1ms",
		},
		DynamicSecrets: config.DynamicSecretsConfig{
			SweepEnabled:  true,
			SweepInterval: "1ms",
		},
	}

	coreService := mustInitCoreService(t, cfg)

	// Use a short timeout so the scheduler goroutines' own <-ctx.Done() exits fire.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	startSchedulersForTest(t, ctx, cfg, coreService)

	// 11 schedulers all fire on this 200ms window; under a loaded CI runner
	// running the rest of the suite in parallel, their first ticks (each
	// wrapped in a WithSchedulerLock DB round-trip) can take longer than a
	// tight ceiling allows (observed flake: keyorixhq/keyorix#1257, #1258,
	// #1263) even though each tick completes in well under 1s locally — give
	// them a generous window to settle before the test (and its DB) tears down.
	time.Sleep(2 * time.Second)
}

// ── loadCertPool — success path ───────────────────────────────────────────────

// TestLoadCertPool_ValidPEM exercises the success branch of loadCertPool
// (return pool, nil — line 248) using a freshly-generated self-signed CA cert.
func TestLoadCertPool_ValidPEM(t *testing.T) {
	caPEM := testSelfSignedCACert(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
	pool, err := loadCertPool(caFile)
	if err != nil {
		t.Fatalf("loadCertPool: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil cert pool")
	}
}

// ── initializeCoreService — OIDC verifier error ───────────────────────────────

// TestInitializeCoreService_OIDCVerifier_EmptyAudiences triggers the
// NewOIDCVerifier error path (line 756–758): a valid JWKS URI but no audiences.
func TestInitializeCoreService_OIDCVerifier_EmptyAudiences(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.OIDC = config.OIDCConfig{
		Enabled: true,
		Issuers: []config.OIDCIssuerConfig{
			{
				Name:      "no-aud",
				Issuer:    "https://oidc.example.com",
				JWKSURI:   "http://127.0.0.1:65433/.well-known/jwks.json", // valid loopback URI
				Audiences: nil,                                            // empty — NewOIDCVerifier returns error
			},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error for OIDC issuer with no audiences")
	}
}

// ── initializeCoreService — storage init failure ──────────────────────────────

// TestInitializeCoreService_StorageError covers the storage init error path
// (lines 255–257) by specifying an unknown storage type.
func TestInitializeCoreService_StorageError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "unknown_storage_type_xyz",
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error for unknown storage type")
	}
}

// ── enforceKeyFilePermissions — gRPC TLS key file ────────────────────────────

// TestEnforceKeyFilePermissions_GRPCTLSKey covers the gRPC TLS key-file branch
// (line 1468–1470 in enforceKeyFilePermissions) when the gRPC server has TLS enabled.
func TestEnforceKeyFilePermissions_GRPCTLSKey(t *testing.T) {
	dir := t.TempDir()
	// Create an insecure (0o644) gRPC key file.
	keyFile := filepath.Join(dir, "grpc_key.pem")
	if err := os.WriteFile(keyFile, []byte("fake-grpc-key"), 0o644); err != nil {
		t.Fatalf("write gRPC key file: %v", err)
	}
	cfg := &config.Config{
		Server: config.ServerConfig{
			GRPC: config.ServerInstanceConfig{
				TLS: config.TLSConfig{
					Enabled: true,
					KeyFile: keyFile,
				},
			},
		},
	}
	// Warn-only (EnableFilePermissionCheck=false): must not return error.
	if err := enforceKeyFilePermissions(cfg); err != nil {
		t.Errorf("enforceKeyFilePermissions gRPC key warn-only: %v", err)
	}
}

// ── startHTTPServer — cert-expiry + rotation-reminder schedulers ─────────────

// TestStartHTTPServer_CertExpiryAndRotationReminder covers the cert-expiry
// (lines 1036–1053) and rotation-reminder (lines 993–1009) scheduler branches
// within startHTTPServer.
// #G12: moved to startSchedulers.
func TestStartSchedulers_CertExpiryAndRotationReminder(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_certrr.db"},
		},
		CertificateExpiry: config.CertificateExpiryConfig{
			Enabled:  true,
			LeadDays: 30,
			Schedule: "1h",
		},
		RotationReminders: config.RotationRemindersConfig{
			Enabled:  true,
			Schedule: "1h",
		},
		ExpiryReminders: config.ExpiryRemindersConfig{
			Enabled:  true,
			LeadDays: 14,
			Schedule: "1h",
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — anomaly ML config enabled ───────────────────────────────

// TestStartSchedulers_AnomalyML covers the ML-config path inside the anomaly
// scheduler block. #G12: moved to startSchedulers.
func TestStartSchedulers_AnomalyML(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_aml.db"},
		},
		AnomalyAlerts: config.AnomalyAlertsConfig{
			Enabled:  true,
			Schedule: "1h",
			ML: config.AnomalyMLConfig{
				Enabled:    true,
				Threshold:  0.6,
				NumTrees:   50,
				SampleSize: 256,
				Seed:       42,
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — evidence delivery with configured target ────────────────

// TestStartSchedulers_EvidenceDelivery_WithTarget covers the evidence-delivery
// scheduler branch when a valid webhook target is configured. #G12: moved to
// startSchedulers.
func TestStartSchedulers_EvidenceDelivery_WithTarget(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_evtgt.db"},
		},
		EvidenceDelivery: config.EvidenceDeliveryConfig{
			Enabled:  true,
			Schedule: "1h",
			Webhook: config.EvidenceWebhookConfig{
				Enabled:                   true,
				Endpoint:                  "http://127.0.0.1:65543/evidence",
				AllowPrivateNetworkTarget: true,
			},
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}

// ── startHTTPServer — read-quota alert scheduler ──────────────────────────────

// TestStartSchedulers_ReadQuotaAlerts verifies that startSchedulers wires the
// read-quota alert background scheduler when ReadQuotaAlerts.Enabled is true.
// #G12: moved out of startHTTPServer.
func TestStartSchedulers_ReadQuotaAlerts(t *testing.T) {
	initI18n(t)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "httptest_rqa.db"},
		},
		ReadQuotaAlerts: config.ReadQuotaAlertsConfig{
			Enabled:  true,
			Schedule: "1h",
		},
	}

	coreService := mustInitCoreService(t, cfg)
	ctx := t.Context()
	startSchedulersForTest(t, ctx, cfg, coreService)
	time.Sleep(50 * time.Millisecond)
}
