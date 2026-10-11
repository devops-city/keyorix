//go:build e2e

// upgrade_test.go is I3: the "table missing on upgraded installs" class
// PR #2258 also warned about -- a fresh SQLite/Postgres database ISN'T the
// only "first time this code path runs" case. An install that was created
// by an OLDER release binary and then upgraded in place (new binary,
// existing database) exercises the migration path's "already-migrated,
// converge the diff" branches instead of its "create from nothing" ones --
// a structurally different code path (see internal/storage/factory.go's own
// tableExists-guarded blocks, most of which have separate fresh-vs-existing
// arms) that a fresh-database-only smoke run (upgrade_test.go's own sibling,
// api_smoke_test.go) never touches.
package e2e

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// upgradeFromReleaseTag is the release this test upgrades FROM. Deliberately
// the immediately-prior release (not an arbitrarily old one): the point is
// to catch "the last release's schema, migrated by HEAD," which is what a
// real operator upgrading one version at a time actually does. Override via
// KEYORIX_E2E_UPGRADE_FROM_TAG for a manual run against a different release.
const defaultUpgradeFromReleaseTag = "v0.95.1"

// downloadReleaseBinary fetches the keyorix-server release binary for tag
// from GitHub's public release-asset URL (no auth needed for a public repo)
// and returns its local path, executable. Skips (not fails) the test on any
// download problem -- network unavailable, this GOOS/GOARCH combination has
// no published asset (e.g. Windows), or a bad tag -- since this test's whole
// premise depends on an external resource this driver does not control, the
// same "skip is not a failure" contract KEYORIX_TEST_PG_DSN-gated tests use
// elsewhere in this repo (see docs/security-closures.tsv's "pg-gated"
// verification column).
func downloadReleaseBinary(t *testing.T, tag string) string {
	t.Helper()
	url := fmt.Sprintf("https://github.com/keyorixhq/keyorix/releases/download/%s/keyorix-server_%s_%s",
		tag, runtime.GOOS, runtime.GOARCH)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url) // #nosec G107 -- fixed, versioned, publicly-documented release URL
	if err != nil {
		t.Skipf("could not reach %s (network unavailable?): %v", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Skipf("no release asset at %s (status %d) -- this GOOS/GOARCH combination may not be published for %s",
			url, resp.StatusCode, tag)
	}

	dir := t.TempDir() // under $TMPDIR, removed when the test ends
	binPath := filepath.Join(dir, "keyorix-server-old")
	out, err := os.Create(binPath) // #nosec G304 -- fixed tmpdir path this function itself created
	if err != nil {
		t.Fatalf("create %s: %v", binPath, err)
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		t.Fatalf("download %s: %v", url, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", binPath, err)
	}
	if err := os.Chmod(binPath, 0o755); err != nil { // #nosec G302 -- must be executable
		t.Fatalf("chmod %s: %v", binPath, err)
	}
	return binPath
}

// TestAPISmoke_UpgradePath boots the OLD release binary, runs its own
// admin init/encryption init/migrate/boot/bootstrap sequence (creating a
// real admin, project, and secret under the OLD schema -- an upgraded
// install always has real pre-existing data, not just an empty schema),
// stops it, then runs `admin migrate` and boots the NEW (HEAD, built from
// this checkout) binary against that SAME on-disk database -- an in-place
// upgrade, exactly like a real operator's `systemctl stop keyorix &&
// <new binary> admin migrate && systemctl start keyorix`. The full
// create/read/list/update/delete sweep then runs against the upgraded
// server, logged in as the SAME admin account the OLD binary created --
// catching "table missing on an upgraded install" even for a table whose
// AutoMigrate guard only runs correctly on a fresh database (the exact
// shape of gap PR #2264 -- this session's own I2 finding -- specifically
// checked was NOT the case: see that PR's UpgradedInstall regression test).
func TestAPISmoke_UpgradePath(t *testing.T) {
	fromTag := os.Getenv("KEYORIX_E2E_UPGRADE_FROM_TAG")
	if fromTag == "" {
		fromTag = defaultUpgradeFromReleaseTag
	}
	oldBinary := downloadReleaseBinary(t, fromTag)
	newBinary, cliBin := harness.BuildBinaries(t)

	backend := harness.DBBackend{Name: "sqlite-upgrade-from-" + fromTag}
	dir := t.TempDir()
	env := append(harness.BaseServerEnv(dir),
		"KEYORIX_MASTER_PASSWORD=e2e-upgrade-master-password")
	configPath := "./keyorix.yaml"

	runAdmin := func(binary string, args ...string) {
		t.Helper()
		out, err := harness.RunAdminCmd(binary, dir, env, args...)
		if err != nil {
			t.Fatalf("%s admin %v: %v\n%s", filepath.Base(binary), args, err, out)
		}
	}

	t.Logf("provisioning with OLD binary (%s, %s)", fromTag, oldBinary)
	runAdmin(oldBinary, "init", "--config", configPath)
	runAdmin(oldBinary, "encryption", "init", "--config", configPath)
	runAdmin(oldBinary, "migrate", "--config", configPath)

	port := harness.FreeTCPPort(t)
	harness.RewritePort(t, dir, port)

	const bootstrapToken = "e2e-upgrade-bootstrap-token-0123456789"
	// The previous release predates /health's instance_nonce echo, so
	// WaitHealthy must confirm it via the old binary's access log (#2596).
	oldSrv := harness.BootAndBootstrap(t, oldBinary, dir, env, configPath, port, bootstrapToken,
		"upgradeadmin", "upgradeadmin@example.invalid", upgradeAdminPassword, harness.WithPreNonceBinary())

	// Real pre-existing data under the OLD schema: an operator's install
	// always has data by the time it's upgraded, not just an empty schema.
	oldClient := newClient(t, oldSrv.BaseURL)
	oldClient.login("upgradeadmin", upgradeAdminPassword)
	oldClient.callExpect("POST", "POST /api/v1/projects", "/api/v1/projects",
		map[string]string{"name": "e2e-upgrade-project"}, 200, 201)

	t.Log("stopping OLD binary")
	oldSrv.Close()
	// Give the OS a moment to release the SQLite file lock before the new
	// binary's subprocess admin commands touch the same DB file (same
	// precedent as server/admin_recover_admin_integration_test.go's
	// bootstrapAdminViaHTTP).
	time.Sleep(200 * time.Millisecond)

	t.Logf("upgrading with NEW (HEAD) binary")
	runAdmin(newBinary, "migrate", "--config", configPath)

	newPort := harness.FreeTCPPort(t)
	harness.RewritePort(t, dir, newPort)

	serverEnv := append(append([]string{}, env...),
		"KEYORIX_BOOTSTRAP_TOKEN="+bootstrapToken, // unused post-bootstrap, harmless to still set
		"KEYORIX_CONFIG_PATH="+configPath,
	)
	newSrv := &harness.Server{
		T: t, Dir: dir, ConfigPath: configPath, BaseURL: "http://127.0.0.1:" + newPort,
		Binary: newBinary, Env: serverEnv, LogPath: filepath.Join(dir, "e2e-upgrade-server.log"),
		Backend: backend,
	}
	harness.StartBackgroundProcess(t, newSrv, serverEnv)
	t.Cleanup(newSrv.Close)
	harness.WaitHealthy(t, newSrv)

	// ADR-112: the old release's config never set security.require_mfa, and its
	// database already has users, so HEAD must boot it in the require_mfa grace
	// period (warning, not enforced) rather than confine the existing admin to MFA
	// enrolment -- the sweep below logs in as that admin without MFA.
	if logBytes, err := os.ReadFile(newSrv.LogPath); err != nil {
		t.Fatalf("read upgraded server log: %v", err)
	} else if !strings.Contains(string(logBytes), "ADR-112 grace period: security.require_mfa") {
		t.Fatalf("expected the ADR-112 require_mfa grace-period warning after upgrade; server log:\n%s", logBytes)
	}

	// The full happy-path sweep, logged in as the admin the OLD binary
	// created -- proves every route this driver covers works against a
	// database that started life under the previous release's schema, not
	// just a brand-new one.
	runAPISmokeAgainstServer(t, newSrv, cliBin, backend, "upgradeadmin", upgradeAdminPassword)
}

// upgradeAdminPassword shares no substring with "upgradeadmin"/its email/
// display name -- see harness.BootstrapAdminPassword for why that
// matters (internal/core/rules.DefaultPasswordPolicy).
const upgradeAdminPassword = "Meridian-Cobalt-19-Ferrous!"
