// server_s23_test.go — targeted coverage for branches not yet reached by
// scheduler_run_test.go, server_s3_test.go, server_s4_test.go,
// server_s22_test.go, transport_tls_test.go, startup_validation_test.go,
// and verify_encryption_wiring_test.go.
//
// Covered here:
//   - lockedRun: storage.WithSchedulerLock itself returns an error (lock acquisition failure)
//   - runScheduler: SchedulerFailure outcome recorded without crashing the scheduler
//   - buildSSOProviders: OIDC provider with bad redirect_url after successful discovery (skipped)
//   - initializeCoreService: credential delivery mode "smtp" with a host set
//   - initializeCoreService: credential delivery mode "auto" (zero/default path)
//   - initializeCoreService: email-only notification with Slack also enabled (warning bypassed)
//   - initializeCoreService: Teams + email with broadcast_to (multi-sink fan-out)
//   - initializeCoreService: Connect vault connector with default VAULT_TOKEN env (empty, warns)
//   - initializeCoreService: rotation backend with DSNEnv set but env unset (logs, does not fail)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ── lockedRun: storage.WithSchedulerLock itself returns an error ──────────────

// lockErrorStorage is a stub that returns (false, err) from WithSchedulerLock,
// simulating a storage-level failure acquiring the advisory lock (e.g. a
// PostgreSQL advisory-lock timeout, lost DB connection, etc.).
type lockErrorStorage struct {
	corestorage.Storage
	err error
}

func (s *lockErrorStorage) WithSchedulerLock(_ context.Context, _ int64, _ func() error) (bool, error) {
	return false, s.err
}

// TestLockedRun_S23_LockAcquisitionError verifies that when
// storage.WithSchedulerLock itself returns a non-nil error (not fn's error),
// lockedRun returns SchedulerFailure and does NOT call fn.
func TestLockedRun_S23_LockAcquisitionError(t *testing.T) {
	st := &lockErrorStorage{err: errors.New("advisory lock unavailable")}
	var fnCalled bool
	outcome := lockedRun(context.Background(), st, 77, "lock-error-test", func() error {
		fnCalled = true
		return nil
	})
	if outcome != middleware.SchedulerFailure {
		t.Errorf("lockedRun (lock error) = %v, want SchedulerFailure", outcome)
	}
	if fnCalled {
		t.Error("fn must not be called when the lock acquisition fails")
	}
}

// ── runScheduler: SchedulerFailure outcome is recorded without crash ──────────

// TestRunScheduler_S23_FailureOutcome verifies that runScheduler continues
// running across ticks when the tick function returns SchedulerFailure —
// a failure must be recorded (Prometheus counter) but the goroutine must not
// exit or panic.
func TestRunScheduler_S23_FailureOutcome(t *testing.T) {
	var ticks atomic.Int32
	ctx := t.Context()

	runScheduler(ctx, "test-failure-outcome", 10*time.Millisecond, func() middleware.SchedulerOutcome {
		ticks.Add(1)
		return middleware.SchedulerFailure
	})

	deadline := time.Now().Add(2 * time.Second)
	for ticks.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ticks.Load() < 2 {
		t.Fatalf("scheduler stopped after SchedulerFailure outcome (got %d ticks, want >= 2)", ticks.Load())
	}
}

// ── buildSSOProviders: OIDC with bad redirect_url after successful discovery ──

// TestBuildSSOProviders_S23_OIDCBadRedirectURL exercises the branch in
// buildSSOProviders where discoverOIDC succeeds but ssoCompleteURL fails
// because the provider's redirect_url has no scheme+host. The provider must
// be skipped (n == 0) without panicking.
func TestBuildSSOProviders_S23_OIDCBadRedirectURL(t *testing.T) {
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
				Name:        "bad-redirect-oidc",
				Type:        "oidc",
				Issuer:      issuer,
				ClientID:    "client-bad",
				RedirectURL: "not-a-valid-url", // no scheme/host → ssoCompleteURL fails
			},
		},
	}

	_, _, n := buildSSOProviders(sso)
	if n != 0 {
		t.Errorf("OIDC provider with bad redirect_url must be skipped, got %d registered", n)
	}
}

// ── initializeCoreService: credential delivery mode "smtp" ───────────────────

// TestInitializeCoreService_S23_CredentialDelivery_SMTP exercises the delivery.New
// branch for mode "smtp" with a host set. The SMTP relay is unreachable at test
// time but construction must succeed (no network call at New time).
func TestInitializeCoreService_S23_CredentialDelivery_SMTP(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.CredentialDelivery = config.CredentialDeliveryConfig{
		Mode:    "smtp",
		BaseURL: "https://app.example.com",
		SMTP: config.CredentialSMTPConfig{
			Host: "127.0.0.1",
			Port: 587,
			From: "keyorix@example.com",
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with smtp delivery: %v", err)
	}
}

// ── initializeCoreService: credential delivery mode "auto" ───────────────────

// TestInitializeCoreService_S23_CredentialDelivery_Auto exercises delivery.New
// for the "auto" mode (empty string falls through to ModeAuto). With no SMTP
// host configured, auto selects out-of-band, so construction must succeed.
func TestInitializeCoreService_S23_CredentialDelivery_Auto(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.CredentialDelivery = config.CredentialDeliveryConfig{
		Mode:    "auto",
		BaseURL: "https://app.example.com",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with auto delivery: %v", err)
	}
}

// ── initializeCoreService: email + Slack enabled (warning suppressed) ─────────

// TestInitializeCoreService_S23_EmailAndSlack covers the notification-channel
// warning predicate (line ~499): the warning fires only when email is the ONLY
// channel AND broadcast_to is empty. With Slack also enabled the condition is
// false → no warning, no error.
func TestInitializeCoreService_S23_EmailAndSlack(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Notifications.Email = config.NotificationEmailConfig{
		Enabled: true,
		Host:    "127.0.0.1",
		Port:    25,
		From:    "keyorix@example.com",
		// BroadcastTo deliberately empty — would warn if email were the only channel.
	}
	cfg.Notifications.Slack = config.NotificationChatConfig{
		Enabled:    true,
		WebhookURL: "http://127.0.0.1:65534/slack",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with email+slack (no broadcast_to): %v", err)
	}
}

// ── initializeCoreService: Teams + email with broadcast_to (multi-broadcast sink) ─

// TestInitializeCoreService_S23_TeamsAndEmailBroadcast exercises the case where
// both Teams (broadcast-only) and email (broadcast+recipient, with BroadcastTo
// set) channels are enabled. This builds len(broadcastSinks)==2 and drives the
// notifychan.NewMulti fan-out path for both sink sets.
func TestInitializeCoreService_S23_TeamsAndEmailBroadcast(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Notifications.Email = config.NotificationEmailConfig{
		Enabled:     true,
		Host:        "127.0.0.1",
		Port:        25,
		From:        "keyorix@example.com",
		BroadcastTo: "ops@example.com",
	}
	cfg.Notifications.Teams = config.NotificationChatConfig{
		Enabled:    true,
		WebhookURL: "http://127.0.0.1:65535/teams",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with Teams+email broadcast: %v", err)
	}
}

// ── initializeCoreService: vault connector with default VAULT_TOKEN (empty) ───

// TestInitializeCoreService_S23_VaultDefaultTokenEnv covers the branch in
// initializeCoreService where the vault connector's TokenEnv is empty, so the
// code substitutes the default "VAULT_TOKEN". The env var is unset (empty) so a
// warning is logged, but no error is returned.
func TestInitializeCoreService_S23_VaultDefaultTokenEnv(t *testing.T) {
	initI18n(t)
	t.Setenv("VAULT_TOKEN", "") // ensure default env is unset — triggers the warning log
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{
				Name:        "vault-default-env",
				Type:        "vault",
				Address:     "http://vault.example.com:8200",
				TokenEnv:    "", // empty → code substitutes "VAULT_TOKEN"
				AllowedRefs: []string{"prod/*"},
				Scope:       "platform",
			},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService vault default VAULT_TOKEN: %v", err)
	}
}

// ── initializeCoreService: rotation backend with DSNEnv set but env unset ────

// TestInitializeCoreService_S23_RotationBackend_EmptyDSN covers the branch in
// initializeCoreService where a rotation backend has AllowedRefs set (so it is
// registered) but its DSN env var is unset, causing GetDSN() to return an empty
// string. This logs a warning but must not return an error.
func TestInitializeCoreService_S23_RotationBackend_EmptyDSN(t *testing.T) {
	initI18n(t)
	const dsnEnv = "MY_PG_DSN_FOR_TEST"
	t.Setenv(dsnEnv, "") // env is set but empty → GetDSN returns ""
	cfg := newMinimalCfg(t)
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{
		{
			Name:        "pg-empty-dsn",
			Type:        "postgresql",
			DSNEnv:      dsnEnv,
			AllowedRefs: []string{"prod/*"},
		},
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with empty DSN backend: %v", err)
	}
}
