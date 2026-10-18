// scim_token_strength_test.go -- #3397: the SCIM bearer token is checked at boot
// for being obviously not random, under the ADR-112 upgrade grace (warn on an
// upgraded deployment until it boots with a good token once, refuse otherwise).
package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

const goodSCIMToken = "q3Vx9cJr0mZ2bT8yLk4wNfHs7uPe1aGd6oRi5tYn" // #nosec G101 -- test fixture

func scimConfig(t *testing.T, token string) *config.Config {
	t.Helper()
	cfg := adr112GraceConfig(t)
	cfg.Security.EnableFilePermissionCheck = false
	cfg.SCIM = config.SCIMConfig{Enabled: true, Token: token}
	t.Setenv("KEYORIX_SCIM_TOKEN", "")
	if err := os.Unsetenv("KEYORIX_SCIM_TOKEN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adr112SCIMTokenSoftened.Store(false) })
	return cfg
}

func captureSCIMLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestEnforceSCIMTokenStrength(t *testing.T) {
	const weak = "changeme-changeme-ch"

	t.Run("fresh install refuses a placeholder token", func(t *testing.T) {
		cfg := scimConfig(t, weak)
		err := enforceSCIMTokenStrength(cfg)
		if err == nil || !strings.Contains(err.Error(), "SCIM token is too weak") || !strings.Contains(err.Error(), "openssl rand -base64 32") {
			t.Fatalf("want the weak-token refusal, got %v", err)
		}
	})
	t.Run("upgraded deployment in the grace period warns and boots", func(t *testing.T) {
		cfg := scimConfig(t, weak)
		migrateADR112DB(t, cfg, 1)
		logs := captureSCIMLog(t)
		if err := enforceSCIMTokenStrength(cfg); err != nil {
			t.Fatalf("grace period must only warn, got %v", err)
		}
		if !strings.Contains(logs.String(), "SCIM token is too weak") || !strings.Contains(logs.String(), "grace") {
			t.Fatalf("grace boot must log the problem and the grace period: %q", logs.String())
		}
		if !adr112SCIMTokenSoftened.Load() {
			t.Fatal("a softened boot must be recorded so it does not end the grace period")
		}
		recordADR112Markers(cfg)
		adr112SCIMTokenSoftened.Store(false)
		if err := enforceSCIMTokenStrength(cfg); err != nil {
			t.Fatalf("a softened boot must not end the grace period: %v", err)
		}
	})
	t.Run("grace ends after one boot with a good token", func(t *testing.T) {
		cfg := scimConfig(t, goodSCIMToken)
		migrateADR112DB(t, cfg, 1)
		if err := enforceSCIMTokenStrength(cfg); err != nil {
			t.Fatalf("good token: %v", err)
		}
		recordADR112Markers(cfg)
		cfg.SCIM.Token = weak
		if err := enforceSCIMTokenStrength(cfg); err == nil {
			t.Fatal("after a clean boot the deployment is enforced: a weak token must be refused")
		}
	})
	t.Run("the length floor is never softened", func(t *testing.T) {
		cfg := scimConfig(t, "short")
		migrateADR112DB(t, cfg, 1)
		if err := enforceSCIMTokenStrength(cfg); err == nil || !strings.Contains(err.Error(), "too short") {
			t.Fatalf("want the length refusal even in the grace period, got %v", err)
		}
	})
	t.Run("token equal to another configured secret", func(t *testing.T) {
		cfg := scimConfig(t, goodSCIMToken)
		cfg.Storage.Database.Password = goodSCIMToken
		err := enforceSCIMTokenStrength(cfg)
		if err == nil || !strings.Contains(err.Error(), "KEYORIX_DB_PASSWORD") {
			t.Fatalf("want the reuse refusal naming the other secret, got %v", err)
		}
	})
	t.Run("SCIM disabled or token unset is not checked", func(t *testing.T) {
		cfg := scimConfig(t, weak)
		cfg.SCIM.Enabled = false
		if err := enforceSCIMTokenStrength(cfg); err != nil {
			t.Fatal(err)
		}
		cfg = scimConfig(t, "")
		if err := enforceSCIMTokenStrength(cfg); err != nil {
			t.Fatal(err)
		}
	})
}
