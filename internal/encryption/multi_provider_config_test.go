package encryption_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyProviderFromConfig_Fallback(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type:     "file",
			FilePath: filepath.Join(dir, "nonexistent.key"),
			Fallbacks: []config.KeyProviderConfig{
				{Type: "password"},
			},
		},
	}
	p, err := encryption.NewKeyProviderFromConfig(cfg, dir, "test-passphrase")
	require.NoError(t, err)
	assert.Contains(t, p.Name(), "multi(")
	key, err := p.KEK()
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestNewKeyProviderFromConfig_NoFallback(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:     true,
		DEKPath:     "dek.key",
		SaltPath:    "salt",
		KeyProvider: config.KeyProviderConfig{Type: "password"},
	}
	p, err := encryption.NewKeyProviderFromConfig(cfg, dir, "pass")
	require.NoError(t, err)
	assert.NotContains(t, p.Name(), "multi(")
}

func TestNewKeyProviderFromConfig_BadFallbackType(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type:      "password",
			Fallbacks: []config.KeyProviderConfig{{Type: "invalid-type"}},
		},
	}
	_, err := encryption.NewKeyProviderFromConfig(cfg, dir, "pass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

// TestNewKeyProviderFromConfig_EnvProvider verifies the env case is constructed
// without error even when the env var is absent (validation deferred to KEK()).
func TestNewKeyProviderFromConfig_EnvProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:     true,
		DEKPath:     "dek.key",
		SaltPath:    "salt",
		KeyProvider: config.KeyProviderConfig{Type: "env", EnvVar: "_KEYORIX_TEST_KEK_ABSENT"},
	}
	p, err := encryption.NewKeyProviderFromConfig(cfg, dir, "")
	require.NoError(t, err)
	assert.Equal(t, "env", p.Name())
}

// TestNewKeyProviderFromConfig_ExecProvider verifies the exec case is constructed
// without error (command execution is deferred to KEK()).
func TestNewKeyProviderFromConfig_ExecProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:     true,
		DEKPath:     "dek.key",
		SaltPath:    "salt",
		KeyProvider: config.KeyProviderConfig{Type: "exec", ExecCommand: []string{"/bin/true"}},
	}
	p, err := encryption.NewKeyProviderFromConfig(cfg, dir, "")
	require.NoError(t, err)
	assert.Contains(t, p.Name(), "exec")
}

// TestNewKeyProviderFromConfig_AzureKMSContextError covers the azure-kms branch
// when KMSEncryptionContext is set (unsupported for RSA-OAEP wrap).
func TestNewKeyProviderFromConfig_AzureKMSContextError(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type:                 "azure-kms",
			KMSKeyID:             "https://vault.azure.net/keys/mykey",
			KMSEncryptionContext: map[string]string{"bound": "true"},
		},
	}
	_, err := encryption.NewKeyProviderFromConfig(cfg, dir, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure-kms")
}

// ── Weak-fallback gate (allow_weaker_fallback) ───────────────────────────────
//
// The "tpm" primary below never touches a real TPM device: with WrappedKeyPath
// left empty, TPMKeyProvider.KEK() fails immediately and deterministically
// ("wrapped_key_path is required") before any device access is attempted — see
// crypto.TPMKeyProvider.KEK. That's exactly what's needed here: the config-shape
// downgrade check (keyed by Type/Name(), both "tpm") doesn't care whether the
// provider can actually reach hardware, and the runtime fallback test below
// needs the primary to reliably fail without depending on test-host hardware.

// TestNewKeyProviderFromConfig_WeakFallback_RejectedWithoutOptIn is the negative
// case: a TPM (hardware-tier) primary with a password (software-tier) fallback,
// without allow_weaker_fallback, must be refused at config/startup time — the
// whole point of the fail-closed gate.
func TestNewKeyProviderFromConfig_WeakFallback_RejectedWithoutOptIn(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type: "tpm",
			Fallbacks: []config.KeyProviderConfig{
				{Type: "password"},
			},
		},
	}
	_, err := encryption.NewKeyProviderFromConfig(cfg, dir, "test-passphrase")
	require.Error(t, err)
	// The refusal names the CURRENT key (the deprecated old one still works as an
	// alias, but an operator must be told the name to put in new config).
	assert.Contains(t, err.Error(), "insecure_allow_weaker_kek_fallback")
	assert.NotContains(t, err.Error(), "key_provider.allow_weaker_fallback")
	assert.Contains(t, err.Error(), "password")
}

// TestNewKeyProviderFromConfig_WeakFallback_AcceptedWithOptIn is the positive
// case: the SAME downgrading chain, with AllowWeakerFallback set, must be
// accepted and build a working MultiKeyProvider that actually falls through to
// the (now permitted) weaker password provider at KEK() time.
func TestNewKeyProviderFromConfig_WeakFallback_AcceptedWithOptIn(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type: "tpm",
			Fallbacks: []config.KeyProviderConfig{
				{Type: "password"},
			},
			AllowWeakerFallback: true,
		},
	}
	p, err := encryption.NewKeyProviderFromConfig(cfg, dir, "test-passphrase")
	require.NoError(t, err)
	assert.Contains(t, p.Name(), "multi(")
	key, err := p.KEK()
	require.NoError(t, err, "tpm primary must fail closed (no wrapped_key_path) and fall through to the accepted password fallback")
	assert.Len(t, key, 32)
}

// TestNewKeyProviderFromConfig_WeakFallback_RuntimeAuditEvent asserts the
// runtime-firing signal (item 3 of the fix): when the fallback in an
// opted-in-downgrading chain actually fires at KEK() time, it must be recorded
// as more than a log line. buildKeyProvider wires Service.auditKeyProviderDowngrade
// as the crypto.MultiKeyProvider downgrade hook; this test exercises that wiring
// end-to-end through Service.Initialize with a fake audit sink standing in for
// storage.Storage.LogAuditEvent.
func TestNewKeyProviderFromConfig_WeakFallback_RuntimeAuditEvent(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type: "tpm",
			Fallbacks: []config.KeyProviderConfig{
				{Type: "password"},
			},
			AllowWeakerFallback: true,
		},
	}
	svc := encryption.NewService(cfg, dir)

	var got *models.AuditEvent
	svc.SetAuditSink(func(ctx context.Context, event *models.AuditEvent) error {
		got = event
		return nil
	})

	require.NoError(t, svc.Initialize("test-passphrase"))
	require.NotNil(t, got, "a security-relevant audit event must be recorded when the fallback actually fires at KEK() time, not just a log line")
	assert.Equal(t, encryption.EventKeyProviderFallbackDowngrade, got.EventType)
	assert.Equal(t, "system", got.ActorType)
	require.NotNil(t, got.Success)
	assert.False(t, *got.Success, "a silent strength downgrade is a security-negative event, not a routine success")
	assert.Contains(t, got.Description, "password")
}

// TestNewKeyProviderFromConfig_SameTierFallback_NoRuntimeAuditEvent is the
// control for the runtime signal: a same-tier fallback firing must NOT be
// reported as a downgrade event.
func TestNewKeyProviderFromConfig_SameTierFallback_NoRuntimeAuditEvent(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type:     "file",
			FilePath: filepath.Join(dir, "nonexistent-primary.key"),
			Fallbacks: []config.KeyProviderConfig{
				{Type: "env", EnvVar: "_KEYORIX_TEST_KEK_ABSENT_SAME_TIER_2"},
			},
		},
	}
	svc := encryption.NewService(cfg, dir)

	called := false
	svc.SetAuditSink(func(ctx context.Context, event *models.AuditEvent) error {
		called = true
		return nil
	})

	// Both file and env fail here (nonexistent path / unset env var), so
	// Initialize returns an error — the point is only that no downgrade event
	// fires along the way, since file→env is a same-tier chain.
	_ = svc.Initialize("test-passphrase")
	assert.False(t, called, "a same-tier fallback must never be reported as a downgrade, even when both providers ultimately fail")
}

// TestNewKeyProviderFromConfig_SameTierFallback_NoOptInRequired is the
// non-downgrading control case: a same-tier fallback chain (aws-kms primary,
// gcp-kms fallback — both TierHardware) must keep working with NO opt-in, so the
// gate never breaks the legitimate multi-provider use case.
func TestNewKeyProviderFromConfig_SameTierFallback_NoOptInRequired(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type:     "file",
			FilePath: filepath.Join(dir, "nonexistent-primary.key"),
			Fallbacks: []config.KeyProviderConfig{
				{Type: "env", EnvVar: "_KEYORIX_TEST_KEK_ABSENT_SAME_TIER"},
			},
			// no AllowWeakerFallback — file and env are both TierSoftware, so this
			// must be accepted without it.
		},
	}
	p, err := encryption.NewKeyProviderFromConfig(cfg, dir, "test-passphrase")
	require.NoError(t, err)
	assert.Contains(t, p.Name(), "multi(")
}
