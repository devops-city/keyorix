package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

func serverSecretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestResolveBootstrapToken_Env(t *testing.T) {
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "  tok-from-env \n")
	got, err := resolveBootstrapToken()
	require.NoError(t, err)
	assert.Equal(t, "tok-from-env", got)
}

func TestResolveBootstrapToken_File(t *testing.T) {
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN_FILE", serverSecretFile(t, "tok-from-file\n"))
	got, err := resolveBootstrapToken()
	require.NoError(t, err)
	assert.Equal(t, "tok-from-file", got)
}

func TestResolveBootstrapToken_Unset(t *testing.T) {
	got, err := resolveBootstrapToken()
	require.NoError(t, err)
	assert.Empty(t, got, "unset means: the caller generates a one-time token")
}

func TestResolveBootstrapToken_BothSetRefuses(t *testing.T) {
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "tok-env")
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN_FILE", serverSecretFile(t, "tok-file\n"))
	got, err := resolveBootstrapToken()
	require.Error(t, err)
	assert.Empty(t, got)
	assert.NotContains(t, err.Error(), "tok-env")
	assert.NotContains(t, err.Error(), "tok-file")
}

func TestResolveBootstrapToken_UnreadableFileRefuses(t *testing.T) {
	// Must NOT fall through to "generate a token": an operator who pointed at a
	// file wants THAT token, and a generated one would silently differ.
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
	got, err := resolveBootstrapToken()
	require.Error(t, err)
	assert.Empty(t, got)
}

func TestResolveVaultToken(t *testing.T) {
	t.Setenv("KX_VAULT_TOK_FILE", serverSecretFile(t, "hvs.abc\n"))
	got, err := resolveVaultToken("KX_VAULT_TOK")
	require.NoError(t, err)
	assert.Equal(t, "hvs.abc", got)

	t.Setenv("KX_VAULT_TOK", "hvs.def")
	_, err = resolveVaultToken("KX_VAULT_TOK")
	require.Error(t, err, "both set")
}

func TestResolveVaultToken_DefaultName(t *testing.T) {
	t.Setenv("VAULT_TOKEN_FILE", serverSecretFile(t, "hvs.zzz\n"))
	got, err := resolveVaultToken("")
	require.NoError(t, err)
	assert.Equal(t, "hvs.zzz", got)
}

func TestVaultTokenUnset_IsNotAnError(t *testing.T) {
	got, err := resolveVaultToken("KX_VAULT_TOK_UNSET")
	require.NoError(t, err)
	assert.Empty(t, got, "pre-existing behaviour: log 'reads will fail', keep booting")
}

func secretFileMode(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := serverSecretFile(t, "value\n")
	require.NoError(t, os.Chmod(p, mode))
	return p
}

func TestEnforceSecretFilePermissions(t *testing.T) {
	strict := func() *config.Config {
		return &config.Config{Security: config.SecurityConfig{EnableFilePermissionCheck: true}}
	}
	t.Run("no secret files is a no-op", func(t *testing.T) {
		require.NoError(t, enforceSecretFilePermissions(strict()))
	})
	t.Run("0600 and 0400 pass", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o600, 0o400} {
			t.Setenv("KEYORIX_DB_PASSWORD_FILE", secretFileMode(t, mode))
			require.NoError(t, enforceSecretFilePermissions(strict()), mode.String())
		}
	})
	t.Run("group-readable file owned by the running user refuses", func(t *testing.T) {
		// The orchestrator-mount exception (root-owned 0440 in a held group) is covered
		// in internal/secretenv; a file the test creates is owned by the test's uid.
		for _, mode := range []os.FileMode{0o440, 0o640} {
			t.Setenv("KEYORIX_DB_PASSWORD_FILE", secretFileMode(t, mode))
			require.Error(t, enforceSecretFilePermissions(strict()), mode.String())
		}
	})
	t.Run("world-readable refuses when the check is on", func(t *testing.T) {
		p := secretFileMode(t, 0o644)
		t.Setenv("KEYORIX_DB_PASSWORD_FILE", p)
		err := enforceSecretFilePermissions(strict())
		require.Error(t, err)
		assert.Contains(t, err.Error(), p)
		assert.NotContains(t, err.Error(), "value")
	})
	t.Run("covers master password and bootstrap token files", func(t *testing.T) {
		t.Setenv("KEYORIX_MASTER_PASSWORD_FILE", secretFileMode(t, 0o666))
		require.Error(t, enforceSecretFilePermissions(strict()))
	})
	t.Run("only warns when the check is off", func(t *testing.T) {
		t.Setenv("KEYORIX_DB_PASSWORD_FILE", secretFileMode(t, 0o644))
		require.NoError(t, enforceSecretFilePermissions(&config.Config{}))
	})
	t.Run("allow_unsafe_file_permissions downgrades to a warning", func(t *testing.T) {
		t.Setenv("KEYORIX_DB_PASSWORD_FILE", secretFileMode(t, 0o644))
		cfg := strict()
		cfg.Security.AllowUnsafeFilePermissions = true
		require.NoError(t, enforceSecretFilePermissions(cfg))
	})
	t.Run("group-writable refuses", func(t *testing.T) {
		t.Setenv("KEYORIX_SCIM_TOKEN_FILE", secretFileMode(t, 0o660))
		require.Error(t, enforceSecretFilePermissions(strict()))
	})
}

// ADR-112 (#2446) integration: a secret file is STRICT on the
// implicit default too (unlike an orchestrator-mounted config/TLS file), but an
// upgraded deployment inside the grace period gets a warning instead of a refusal and
// the grace is recorded as softened (so the "enforced" marker is not written).
func TestEnforceSecretFilePermissions_ADR112(t *testing.T) {
	t.Cleanup(func() { adr112GraceSoftened.Store(false) })
	bad := func(t *testing.T) { t.Setenv("KEYORIX_DB_PASSWORD_FILE", secretFileMode(t, 0o644)) }

	t.Run("fresh install, implicit default: refuses", func(t *testing.T) {
		bad(t)
		cfg := &config.Config{Security: config.SecurityConfig{
			EnableFilePermissionCheck: true, EnableFilePermissionCheckImplicitDefault: true}}
		require.Error(t, enforceSecretFilePermissions(cfg))
	})
	t.Run("explicit true: refuses", func(t *testing.T) {
		bad(t)
		require.Error(t, enforceSecretFilePermissions(&config.Config{Security: config.SecurityConfig{EnableFilePermissionCheck: true}}))
	})
	t.Run("upgrade grace: warns, and records the softening", func(t *testing.T) {
		adr112GraceSoftened.Store(false)
		bad(t)
		cfg := &config.Config{Security: config.SecurityConfig{
			EnableFilePermissionCheck: true, EnableFilePermissionCheckImplicitDefault: true,
			EnableFilePermissionCheckUpgradeGrace: true}}
		require.NoError(t, enforceSecretFilePermissions(cfg))
		assert.True(t, adr112GraceSoftened.Load(), "a softened boot must not ratchet the grace period closed")
	})
	t.Run("grace does not hide a compliant file", func(t *testing.T) {
		adr112GraceSoftened.Store(false)
		// 0400, not main's 0440: a 0440 file owned by the running user is refused by
		// the stricter secretenv.CheckPermissions (group-read is only for an
		// orchestrator-owned file), so 0400 is the compliant mode for a test-owned file.
		t.Setenv("KEYORIX_DB_PASSWORD_FILE", secretFileMode(t, 0o400))
		cfg := &config.Config{Security: config.SecurityConfig{
			EnableFilePermissionCheck: true, EnableFilePermissionCheckImplicitDefault: true,
			EnableFilePermissionCheckUpgradeGrace: true}}
		require.NoError(t, enforceSecretFilePermissions(cfg))
		assert.False(t, adr112GraceSoftened.Load())
	})
}
