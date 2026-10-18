package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// #3410: enforceKeyFilePermissions judged the mode only, so a 0600 DEK, salt or
// TLS private key owned by another unprivileged account passed, although that
// account can replace it. The owner rule is secretenv's (#3393): the running
// user or root. A foreign owner follows the same warn-or-refuse matrix as a bad
// mode. The test cannot chown to a third uid, so every file reports owner
// fileUID through secretenv's ownership hook and the server "runs" as uid 1001.

type keyOwnerPosture struct {
	name                     string
	implicit, grace, off, ok bool // none set = an explicit true; ok = insecure_allow_unsafe_file_permissions
}

func (p keyOwnerPosture) apply(cfg *config.Config) {
	cfg.Security.EnableFilePermissionCheck = !p.off
	cfg.Security.EnableFilePermissionCheckImplicitDefault = p.implicit || p.grace
	cfg.Security.EnableFilePermissionCheckUpgradeGrace = p.grace
	cfg.Security.AllowUnsafeFilePermissions = p.ok
}

// keyOwnerConfig writes a 0600 DEK, salt and TLS key and returns a config naming them.
func keyOwnerConfig(t *testing.T) (*config.Config, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	paths := map[string]string{
		"dek":  filepath.Join(dir, "dek.enc"),
		"salt": filepath.Join(dir, "salt.bin"),
		"tls":  filepath.Join(dir, "server.key"),
	}
	for _, p := range paths {
		require.NoError(t, os.WriteFile(p, []byte("k"), 0o600))
	}
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.DEKPath = paths["dek"]
	cfg.Storage.Encryption.SaltPath = paths["salt"]
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.HTTP.TLS.KeyFile = paths["tls"]
	return cfg, paths
}

func captureKeyOwnerLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

func TestEnforceKeyFilePermissions_ForeignOwner(t *testing.T) {
	t.Cleanup(func() { adr112GraceSoftened.Store(false) })
	cases := []struct {
		posture    keyOwnerPosture
		wantRefuse bool
	}{
		{keyOwnerPosture{name: "explicit true"}, true},
		{keyOwnerPosture{name: "implicit default (fresh install)", implicit: true}, true},
		{keyOwnerPosture{name: "upgrade grace", grace: true}, false},
		{keyOwnerPosture{name: "check off", off: true}, false},
		{keyOwnerPosture{name: "insecure_allow_unsafe_file_permissions", ok: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.posture.name, func(t *testing.T) {
			adr112GraceSoftened.Store(false)
			cfg, paths := keyOwnerConfig(t)
			tc.posture.apply(cfg)
			logs := captureKeyOwnerLog(t)
			t.Cleanup(secretenv.OverrideOwnershipForTest(1000, 1001))

			err := enforceKeyFilePermissions(cfg)
			out := logs.String()
			if tc.wantRefuse {
				require.Error(t, err, "a 0600 DEK owned by uid 1000 (not the server, not root) must be refused")
				out = err.Error()
			} else {
				require.NoError(t, err)
				require.Contains(t, out, "WARNING", "a foreign owner is never silent")
			}
			assert.Contains(t, out, paths["dek"], "names the file")
			assert.Contains(t, out, paths["salt"])
			assert.Contains(t, out, "uid 1000", "names the owner")
			assert.Contains(t, out, "uid 1001", "names the server's uid")
			assert.Equal(t, tc.posture.grace, adr112GraceSoftened.Load(), "only the grace period records a softened boot")
		})
	}
}

// The TLS private key is an orchestrator-mounted input: on the implicit default
// a foreign owner warns (as a bad mode does), an explicit true refuses.
func TestEnforceKeyFilePermissions_ForeignOwnedTLSKey(t *testing.T) {
	for _, explicit := range []bool{true, false} {
		cfg, paths := keyOwnerConfig(t)
		cfg.Storage.Encryption.Enabled = false
		keyOwnerPosture{implicit: !explicit}.apply(cfg)
		logs := captureKeyOwnerLog(t)
		restore := secretenv.OverrideOwnershipForTest(1000, 1001)
		err := enforceKeyFilePermissions(cfg)
		restore()
		if explicit {
			require.Error(t, err)
			assert.Contains(t, err.Error(), paths["tls"])
			assert.Contains(t, err.Error(), "uid 1000")
			continue
		}
		require.NoError(t, err)
		assert.Contains(t, logs.String(), paths["tls"])
		assert.Contains(t, logs.String(), "uid 1000")
	}
}

// Own-uid and root-owned key files keep passing in the strictest posture.
func TestEnforceKeyFilePermissions_TrustedOwnersPass(t *testing.T) {
	for _, owner := range []int{1001, 0} {
		cfg, _ := keyOwnerConfig(t)
		keyOwnerPosture{}.apply(cfg)
		logs := captureKeyOwnerLog(t)
		restore := secretenv.OverrideOwnershipForTest(owner, 1001)
		err := enforceKeyFilePermissions(cfg)
		restore()
		require.NoError(t, err, "owner uid %d", owner)
		assert.Empty(t, logs.String(), "owner uid %d: nothing to warn about", owner)
	}
}
