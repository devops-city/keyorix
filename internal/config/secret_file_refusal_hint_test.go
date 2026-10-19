package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BOOT-REFUSALS-1 "Misleading messages" item 4: the secret-file refusal offered
// security.insecure_allow_unsafe_file_permissions for every file, but a
// key-material file (KEYORIX_MASTER_PASSWORD_FILE, the env KEK, Shamir shares) is
// refused again with no override where it is read, so the hint was untrue for
// it. It also said "refusing" twice.

func looseSecretFile(t *testing.T) string {
	t.Helper()
	p := writeSecretFile(t, "x\n")
	require.NoError(t, os.Chmod(p, 0o644))
	return p
}

func strictCheck(c *Config) *Config {
	c.Security.EnableFilePermissionCheck = true
	return c
}

func TestEnforceSecretFilePermissions_KeyMaterialHintHasNoOverride(t *testing.T) {
	mp := looseSecretFile(t)
	t.Setenv("KEYORIX_MASTER_PASSWORD_FILE", mp)
	_, err := strictCheck(validLocalConfig()).EnforceSecretFilePermissions()
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "KEYORIX_MASTER_PASSWORD_FILE")
	assert.Contains(t, msg, mp)
	assert.Contains(t, msg, "does not apply to it")
	assert.NotContains(t, msg, "turns this into a warning", "the override is never offered for key material")
	assert.Equal(t, 1, strings.Count(msg, "refusing"), "one 'refusing', not two: %q", msg)
}

func TestEnforceSecretFilePermissions_OtherSecretHintOffersOverride(t *testing.T) {
	db := looseSecretFile(t)
	t.Setenv("KEYORIX_DB_PASSWORD_FILE", db)
	_, err := strictCheck(validLocalConfig()).EnforceSecretFilePermissions()
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, db)
	assert.Contains(t, msg, "security.insecure_allow_unsafe_file_permissions: true turns this into a warning")
	assert.NotContains(t, msg, "does not apply to it")
	assert.Equal(t, 1, strings.Count(msg, "refusing"), "one 'refusing', not two: %q", msg)

	// ...and the override really does turn it into a warning for this kind of file.
	c := strictCheck(validLocalConfig())
	c.Security.AllowUnsafeFilePermissions = true
	_, err = c.EnforceSecretFilePermissions()
	require.NoError(t, err)
}

// The env KEK provider's variable and Shamir share variables are key material too.
func TestEnforceSecretFilePermissions_KeyProviderVarsAreKeyMaterial(t *testing.T) {
	c := strictCheck(validLocalConfig())
	c.Storage.Encryption.KeyProvider.EnvVar = "KX_TEST_KEK"
	c.Storage.Encryption.KeyProvider.ShamirShareEnv = []string{"KX_TEST_SHARE"}
	t.Setenv("KX_TEST_KEK_FILE", looseSecretFile(t))
	t.Setenv("KX_TEST_SHARE_FILE", looseSecretFile(t))
	_, err := c.EnforceSecretFilePermissions()
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "KX_TEST_KEK_FILE")
	assert.Contains(t, msg, "KX_TEST_SHARE_FILE")
	assert.NotContains(t, msg, "turns this into a warning")
}
