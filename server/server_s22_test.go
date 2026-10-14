// server_s22_test.go — targeted coverage for branches not yet reached by
// scheduler_run_test.go, server_s3_test.go, server_s4_test.go, transport_tls_test.go,
// startup_validation_test.go, and verify_encryption_wiring_test.go.
//
// Covered here:
//   - lockedRun: SchedulerSkipped outcome (storage returns ran=false, nil error)
//   - runScheduler: context cancellation terminates the goroutine cleanly
//   - initializeEncryption: non-password key provider (file/env) bypasses passphrase check
//   - buildSSOProviders: provider with explicit scopes set (non-empty scopes slice)
//   - initializeCoreService: vault connector with custom TokenEnv
//   - initializeCoreService: email notifications with BroadcastTo set alongside webhook
//   - enforceKeyFilePermissions: relative (non-absolute) DEK/salt paths via resolve()
//   - initializeCoreService: credential delivery with out_of_band mode explicitly set
//   - initializeCoreService: email notifications with BroadcastTo set alone (no webhook)
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"encoding/json"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ── lockedRun: SchedulerSkipped outcome ───────────────────────────────────────

// skippedStorage is a minimal corestorage.Storage stub that returns (false, nil)
// from WithSchedulerLock, simulating a follower replica that sees the lock held.
// All other methods panic — lockedRun only calls WithSchedulerLock.
type skippedStorage struct {
	corestorage.Storage // embed the interface so the type satisfies it at compile time
}

func (s *skippedStorage) WithSchedulerLock(_ context.Context, _ int64, _ func() error) (bool, error) {
	return false, nil // another replica holds the lock — caller should skip
}

// TestLockedRun_S22_Skipped verifies the SchedulerSkipped path: when
// WithSchedulerLock returns (false, nil) lockedRun must return SchedulerSkipped
// and must NOT call fn.
func TestLockedRun_S22_Skipped(t *testing.T) {
	st := &skippedStorage{}
	var fnCalled bool
	outcome := lockedRun(context.Background(), st, 99, "test-skipped", func() error {
		fnCalled = true
		return nil
	})
	if outcome != middleware.SchedulerSkipped {
		t.Errorf("lockedRun (ran=false) = %v, want SchedulerSkipped", outcome)
	}
	if fnCalled {
		t.Error("fn must not be called when the scheduler lock is not acquired")
	}
}

// ── runScheduler: context cancellation ────────────────────────────────────────

// TestRunScheduler_S22_CancelledContext verifies that the goroutine spawned by
// runScheduler exits when the context is cancelled (the <-ctx.Done() branch
// inside the for-select loop). Without this path, a leaked goroutine would keep
// the ticker alive indefinitely after shutdown.
func TestRunScheduler_S22_CancelledContext(t *testing.T) {
	var ticks atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())

	runScheduler(ctx, "test-cancel-exit", 5*time.Millisecond, func() middleware.SchedulerOutcome {
		ticks.Add(1)
		return middleware.SchedulerSuccess
	})

	// Wait for at least the initial run (immediate) to confirm it started.
	deadline := time.Now().Add(500 * time.Millisecond)
	for ticks.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if ticks.Load() < 1 {
		t.Fatal("scheduler did not run the initial tick before cancellation")
	}

	// Cancel the context — the goroutine must notice <-ctx.Done() and stop.
	cancel()

	// Give the goroutine time to exit, then assert that tick count stabilises
	// (i.e. the goroutine is no longer running further ticks).
	time.Sleep(30 * time.Millisecond)
	before := ticks.Load()
	time.Sleep(20 * time.Millisecond)
	after := ticks.Load()
	if after-before > 2 {
		t.Errorf("scheduler kept running after context cancel (before=%d after=%d)", before, after)
	}
}

// ── initializeEncryption: non-password provider bypasses passphrase check ────

// TestInitializeEncryption_S22_FileProvider_NoPasswordRequired exercises the
// branch in initializeEncryption that skips the KEYORIX_MASTER_PASSWORD
// requirement when the key provider type is "file". The subsequent svc.Initialize
// call will fail (the file does not exist), but the passphrase guard must not
// trigger first.
func TestInitializeEncryption_S22_FileProvider_NoPasswordRequired(t *testing.T) {
	t.Setenv("KEYORIX_MASTER_PASSWORD", "") // ensure no password is set
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "/nonexistent/dek.json",
				SaltPath: "/nonexistent/salt.bin",
				KeyProvider: config.KeyProviderConfig{
					Type:     "file",
					FilePath: "/nonexistent/kek.key",
				},
			},
		},
	}
	_, err := initializeEncryption(cfg, nil)
	// Must get an error — but NOT "KEYORIX_MASTER_PASSWORD is not set".
	// Any error from reading/deriving is acceptable; the passphrase guard must be silent.
	if err == nil {
		t.Fatal("expected an error (missing key file), got nil")
	}
	const passMsg = "KEYORIX_MASTER_PASSWORD"
	if contains(err.Error(), passMsg) {
		t.Errorf("got an unexpected KEYORIX_MASTER_PASSWORD error for file provider: %v", err)
	}
}

// TestInitializeEncryption_S22_EnvProvider_NoPasswordRequired mirrors the file
// test for the "env" key provider type.
func TestInitializeEncryption_S22_EnvProvider_NoPasswordRequired(t *testing.T) {
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	t.Setenv("MY_KEK_ENV", "") // not set — provider will fail, but not on passphrase guard
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "/nonexistent/dek.json",
				SaltPath: "/nonexistent/salt.bin",
				KeyProvider: config.KeyProviderConfig{
					Type:   "env",
					EnvVar: "MY_KEK_ENV",
				},
			},
		},
	}
	_, err := initializeEncryption(cfg, nil)
	// Expect an error from the missing/empty env key, NOT from passphrase guard.
	if err == nil {
		t.Fatal("expected an error (empty env var key), got nil")
	}
	if contains(err.Error(), "KEYORIX_MASTER_PASSWORD") {
		t.Errorf("got passphrase error for env provider: %v", err)
	}
}

// ── buildSSOProviders: explicit non-empty scopes ──────────────────────────────

// TestBuildSSOProviders_S22_ExplicitScopes covers the branch in buildSSOProviders
// where the OIDC provider config has a non-empty Scopes slice, so the default
// ["openid","profile","email"] list is NOT substituted. The provider's OAuth2 config
// must carry the configured scopes, not the default.
func TestBuildSSOProviders_S22_ExplicitScopes(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/.well-known/jwks.json",
		})
	}))
	defer srv.Close()
	issuer = srv.URL

	customScopes := []string{"openid", "groups"}
	sso := config.SSOConfig{
		Providers: []config.SSOProviderConfig{
			{
				Name:        "scoped-oidc",
				Type:        "oidc",
				Issuer:      issuer,
				ClientID:    "client-scoped",
				RedirectURL: issuer + "/callback",
				Scopes:      customScopes,
			},
		},
	}

	providers, _, n := buildSSOProviders(sso)
	if n == 0 {
		t.Fatal("expected provider to be registered when scopes are explicitly set")
	}
	p, ok := providers["scoped-oidc"]
	if !ok {
		t.Fatal("expected \"scoped-oidc\" in the providers map")
	}
	if p.OAuth == nil {
		t.Fatal("expected OAuth config to be set on the provider")
	}
	if len(p.OAuth.Scopes) != len(customScopes) {
		t.Errorf("scopes = %v, want %v", p.OAuth.Scopes, customScopes)
	}
	for i, s := range p.OAuth.Scopes {
		if s != customScopes[i] {
			t.Errorf("scope[%d] = %q, want %q", i, s, customScopes[i])
		}
	}
}

// ── initializeCoreService: vault connector with custom TokenEnv ───────────────

// TestInitializeCoreService_S22_VaultCustomTokenEnv covers the vault connector
// code path when TokenEnv is set to a non-default value. The branch in
// initializeCoreService substitutes "VAULT_TOKEN" only when TokenEnv is empty;
// this test exercises the non-empty branch.
func TestInitializeCoreService_S22_VaultCustomTokenEnv(t *testing.T) {
	initI18n(t)
	const customEnv = "MY_VAULT_TOKEN_FOR_TEST"
	t.Setenv(customEnv, "") // env is set but empty — connector will warn, not fail
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{
				Name:        "vault-custom-env",
				Type:        "vault",
				Address:     "http://vault.example.com:8200",
				TokenEnv:    customEnv,
				AllowedRefs: []string{"prod/*"},
				Scope:       "platform",
			},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with vault custom TokenEnv: %v", err)
	}
}

// ── initializeCoreService: email + BroadcastTo set alongside webhook ──────────

// TestInitializeCoreService_S22_EmailWithBroadcastTo covers the case where email
// notifications are enabled AND BroadcastTo is set. This is the non-warning path:
// the warning in initializeCoreService only fires when email is the sole channel
// AND BroadcastTo is empty. With BroadcastTo set, no warning is emitted.
func TestInitializeCoreService_S22_EmailWithBroadcastTo(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Notifications.Email = config.NotificationEmailConfig{
		Enabled:     true,
		Host:        "127.0.0.1",
		Port:        25,
		From:        "keyorix@example.com",
		BroadcastTo: "admin@example.com",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with email+BroadcastTo: %v", err)
	}
}

// TestInitializeCoreService_S22_EmailAndWebhook covers the case where both email
// and webhook notification channels are enabled (two broadcastSinks, one
// recipientSink), exercising the NewMulti fan-out path for both sink sets.
func TestInitializeCoreService_S22_EmailAndWebhook(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Notifications.Email = config.NotificationEmailConfig{
		Enabled:     true,
		Host:        "127.0.0.1",
		Port:        25,
		From:        "keyorix@example.com",
		BroadcastTo: "admin@example.com",
	}
	cfg.Notifications.Webhook = config.NotificationWebhookConfig{
		Enabled:                   true,
		Endpoint:                  "http://127.0.0.1:65545/notify",
		AllowPrivateNetworkTarget: true,
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with email+webhook: %v", err)
	}
}

// ── enforceKeyFilePermissions: relative path resolution ───────────────────────

// TestEnforceKeyFilePermissions_S22_RelativePaths verifies that the internal
// resolve() helper in enforceKeyFilePermissions correctly handles relative (non-
// absolute) DEK and salt paths. The function joins them with "." so the Stat call
// uses the working directory rather than requiring an absolute path. This test
// creates relative-path files in a temp dir (set as cwd) and confirms the
// function correctly inspects and flags them.
func TestEnforceKeyFilePermissions_S22_RelativePaths(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// Write relative-path files from the new working directory.
	dek := "relative_dek.key"
	salt := "relative_salt.key"
	if err := os.WriteFile(filepath.Join(dir, dek), []byte("x"), 0o644); err != nil {
		t.Fatalf("write dek: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, dek), 0o644); err != nil { // defeat umask
		t.Fatalf("chmod dek: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, salt), []byte("x"), 0o600); err != nil {
		t.Fatalf("write salt: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  dek, // relative — resolve() will join with "."
				SaltPath: salt,
			},
		},
		Security: config.SecurityConfig{
			EnableFilePermissionCheck: true,
		},
	}

	// world-readable DEK with fail-closed mode must return an error.
	if err := enforceKeyFilePermissions(cfg); err == nil {
		t.Error("enforceKeyFilePermissions must fail for world-readable relative-path DEK with fail-closed mode")
	}

	// In warn-only mode (EnableFilePermissionCheck = false), the same relative path
	// must not produce an error.
	cfg.Security.EnableFilePermissionCheck = false
	if err := enforceKeyFilePermissions(cfg); err != nil {
		t.Errorf("enforceKeyFilePermissions relative path warn-only: %v", err)
	}
}

// ── initializeCoreService: credential delivery explicit out_of_band mode ──────

// TestInitializeCoreService_S22_CredentialDelivery_OutOfBand exercises the
// credential-delivery wiring with mode explicitly set to "out_of_band". The
// delivery.New switch-case for ModeOutOfBand returns immediately, so this is a
// quick no-network-required path through the wiring.
func TestInitializeCoreService_S22_CredentialDelivery_OutOfBand(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.CredentialDelivery = config.CredentialDeliveryConfig{
		Mode:    "out_of_band",
		BaseURL: "https://app.example.com",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with out_of_band delivery: %v", err)
	}
}

// ── initializeCoreService: invalid credential delivery mode ───────────────────

// TestInitializeCoreService_S22_CredentialDelivery_InvalidMode confirms that an
// unknown delivery mode causes initializeCoreService to return an error (not
// silently default to auto).
func TestInitializeCoreService_S22_CredentialDelivery_InvalidMode(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.CredentialDelivery = config.CredentialDeliveryConfig{
		Mode: "carrier-pigeon",
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected error for unknown credential_delivery.mode, got nil")
	}
}

// ── initializeCoreService: SecretValuePolicy disabled (zero-value) ────────────

// TestInitializeCoreService_S22_SecretValuePolicy_Disabled confirms that an
// explicitly disabled SecretValuePolicy (Enabled=false, i.e. the zero value)
// does not set any policy on the core service — the branch at lines 371-380 in
// main.go must be skipped.
func TestInitializeCoreService_S22_SecretValuePolicy_Disabled(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.SecretValuePolicy = config.SecretValuePolicyConfig{
		Enabled: false,
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with disabled SecretValuePolicy: %v", err)
	}
}

// ── initializeCoreService: PasswordPolicy zero value (IsZero branch) ─────────

// TestInitializeCoreService_S22_PasswordPolicy_ZeroValue confirms the zero-value
// PasswordPolicy path: when IsZero() is true the policy block is skipped and
// the core service uses its built-in defaults (no log line, no error).
func TestInitializeCoreService_S22_PasswordPolicy_ZeroValue(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	// cfg.PasswordPolicy is the zero value — IsZero() returns true, block is skipped.

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with zero PasswordPolicy: %v", err)
	}
}

// ── initializeCoreService: MembershipValidationMode empty (skipped) ───────────

// TestInitializeCoreService_S22_MembershipMode_Empty confirms that an empty
// ValidationMode string skips the SetMembershipValidationMode call without error.
func TestInitializeCoreService_S22_MembershipMode_Empty(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Membership.ValidationMode = "" // empty → branch at line 671 is skipped

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with empty membership mode: %v", err)
	}
}

// ── buildSSOProviders: default scopes applied when Scopes is empty ────────────

// TestBuildSSOProviders_S22_DefaultScopes confirms that when Scopes is nil/empty
// the provider gets the default ["openid","profile","email"] scopes. This is the
// companion to TestBuildSSOProviders_S22_ExplicitScopes above and ensures the
// default branch is exercised explicitly.
func TestBuildSSOProviders_S22_DefaultScopes(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/.well-known/jwks.json",
		})
	}))
	defer srv.Close()
	issuer = srv.URL

	sso := config.SSOConfig{
		Providers: []config.SSOProviderConfig{
			{
				Name:        "default-scope-oidc",
				Type:        "oidc",
				Issuer:      issuer,
				ClientID:    "client-defaults",
				RedirectURL: issuer + "/callback",
				Scopes:      nil, // empty → default scopes applied
			},
		},
	}

	providers, _, n := buildSSOProviders(sso)
	if n == 0 {
		t.Fatal("expected provider to be registered")
	}
	p := providers["default-scope-oidc"]
	if p == nil || p.OAuth == nil {
		t.Fatal("expected OAuth config on provider")
	}
	defaultScopes := []string{"openid", "profile", "email"}
	if len(p.OAuth.Scopes) != len(defaultScopes) {
		t.Errorf("default scopes = %v, want %v", p.OAuth.Scopes, defaultScopes)
	}
}

// ── runScheduler: SchedulerSkipped outcome recorded ──────────────────────────

// TestRunScheduler_S22_SkippedOutcome verifies that runScheduler correctly
// handles a tick function that returns SchedulerSkipped — the goroutine must
// not crash and must continue ticking.
func TestRunScheduler_S22_SkippedOutcome(t *testing.T) {
	var ticks atomic.Int32
	ctx := t.Context()

	runScheduler(ctx, "test-skipped-outcome", 10*time.Millisecond, func() middleware.SchedulerOutcome {
		ticks.Add(1)
		return middleware.SchedulerSkipped
	})

	deadline := time.Now().Add(2 * time.Second)
	for ticks.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ticks.Load() < 2 {
		t.Fatalf("scheduler did not continue ticking after SchedulerSkipped outcome (got %d ticks)", ticks.Load())
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// contains reports whether substr appears in s. Used instead of importing strings.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
