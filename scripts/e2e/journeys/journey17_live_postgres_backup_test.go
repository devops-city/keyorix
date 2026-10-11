//go:build e2e

package journeys

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_LivePostgresBackup is DEMO-1's Postgres disaster-recovery
// drill, in the Docker image's shape (keyorix.docker.yaml: field-by-field
// database config, ABSOLUTE key paths in a separately mounted keys volume):
//
//   - #2602: `keyorix-server admin backup` runs against a LIVE server, as
//     docs/SELF_HOSTING.md §5 documents (`docker compose exec backend`),
//     which promises a REPEATABLE READ snapshot "without taking the database
//     offline". Before the fix it refused immediately: it took the EXCLUSIVE
//     dek.lock flock, which a live server holds for its whole lifetime.
//   - #2604: after a full wipe (`docker compose down -v`: the keys volume
//     comes back EMPTY, Postgres comes back with a fresh database), `admin
//     restore` must succeed and the restored server must serve the same
//     secret value. Before the fix, restore's KEK-unwrap "staging" step
//     wrote the archive's key files straight into an absolute-path target,
//     and its own concurrent-creation guard then refused them.
//
// pg-gated (KEYORIX_TEST_PG_DSN): skips without a Postgres DSN, like every
// other Postgres journey/test in this repo.
func TestJourney_LivePostgresBackup(t *testing.T) {
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- skipping the live Postgres backup journey")
	}
	serverBin, cliBin := harness.BuildBinaries(t)

	srcDSN := isolatedPGDatabase(t, base, "j17_live_backup")
	keysVolume := t.TempDir() // stands in for the keyorix_keys volume (absolute paths, as in the image)
	src := harness.StartServer(t, serverBin, j17PostgresBackend(t, srcDSN, keysVolume))
	t.Cleanup(src.Close)
	// Shipped security.require_mfa default (ADR-112): prove it, then enrol TOTP through
	// the real API. The factor is kept: the restored server carries the same MFA state,
	// so the operator logs in there with the same authenticator.
	requireMFAEnrolmentPremise(t, src, "smoketestadmin", harness.BootstrapAdminPassword)
	srcToken, factor := enrolTOTPFactor(t, src, "smoketestadmin", harness.BootstrapAdminPassword)
	seeded := appGetsSecretAs(t, src, cliBin, srcToken)
	wantValue, _ := secretValueAndCount(t, src, srcToken, seeded.SecretID)

	// ── Backup WHILE the server is live (the documented flow) ────────────
	backupPath := filepath.Join(t.TempDir(), "j17-live-backup.tar.gz")
	out, err := harness.RunAdminCmd(serverBin, src.Dir, src.Env,
		"backup", "--config", "./keyorix.yaml", "--output", backupPath)
	if err != nil {
		t.Fatalf("admin backup against a LIVE Postgres server: %v\n%s", err, out)
	}
	if !strings.Contains(out, "live") {
		t.Errorf("admin backup against a live server should say it took the live (snapshot) path, got:\n%s", out)
	}

	// The server is still serving after the backup -- nothing was taken
	// offline.
	restExpect(t, src, srcToken, http.MethodGet, "/api/v1/projects", nil, http.StatusOK)

	// --exclusive is the documented maintenance-window mode: it needs the
	// database to itself, so against a live server it must refuse loudly,
	// never silently degrade to the snapshot path.
	exclPath := filepath.Join(t.TempDir(), "j17-exclusive.tar.gz")
	if out, err := harness.RunAdminCmd(serverBin, src.Dir, src.Env,
		"backup", "--config", "./keyorix.yaml", "--output", exclPath, "--exclusive"); err == nil {
		t.Fatalf("admin backup --exclusive against a live server unexpectedly succeeded:\n%s", out)
	}
	if _, statErr := os.Stat(exclPath); statErr == nil {
		t.Fatalf("a refused --exclusive backup left an archive behind at %s", exclPath)
	}

	// ── `docker compose down -v`: server gone, keys volume back EMPTY,
	// Postgres back with a fresh database. Restore from the off-site archive.
	src.Close()
	entries, err := os.ReadDir(keysVolume)
	if err != nil {
		t.Fatalf("read keys volume: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("precondition: the source server wrote no key files into the keys volume %s", keysVolume)
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(keysVolume, e.Name())); err != nil {
			t.Fatalf("wipe keys volume: %v", err)
		}
	}
	dstDSN := isolatedPGDatabase(t, base, "j17_live_backup")
	targetDir := t.TempDir()
	srcCfg, err := os.ReadFile(filepath.Join(src.Dir, "keyorix.yaml")) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatalf("read source config: %v", err)
	}
	dstCfg := strings.Replace(string(srcCfg), "name: "+parsePGDSN(t, srcDSN).DBName, "name: "+parsePGDSN(t, dstDSN).DBName, 1)
	if dstCfg == string(srcCfg) {
		t.Fatalf("could not retarget the config at the fresh database (no %q line)", "name: "+parsePGDSN(t, srcDSN).DBName)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "keyorix.yaml"), []byte(dstCfg), 0o600); err != nil {
		t.Fatalf("write target config: %v", err)
	}
	targetPort := harness.FreeTCPPort(t)
	harness.RewritePort(t, targetDir, targetPort)
	targetEnv := replaceHome(src.Env, targetDir)

	rout, rerr := harness.RunAdminCmd(serverBin, targetDir, targetEnv,
		"restore", "--config", "./keyorix.yaml", "--input", backupPath)
	if rerr != nil {
		t.Fatalf("admin restore of the live backup: %v\n%s", rerr, rout)
	}
	restored := bootRestoredServer(t, serverBin, targetDir, targetEnv, targetPort)
	t.Cleanup(restored.Close)
	restoredToken := loginWithTOTP(t, restored, "smoketestadmin", harness.BootstrapAdminPassword, factor)
	gotValue, _ := secretValueAndCount(t, restored, restoredToken, seeded.SecretID)
	if gotValue != wantValue {
		t.Fatalf("restored secret value mismatch (redacted; want-len=%d got-len=%d)", len(wantValue), len(gotValue))
	}
}

// j17PostgresBackend is harness.DBBackend for a Postgres database at dsn,
// in the same field-by-field shape scripts/e2e's own Postgres smoke leg
// uses (password via KEYORIX_DB_PASSWORD, never in the config file), and
// key files at ABSOLUTE paths in keysDir, as keyorix.docker.yaml does.
func j17PostgresBackend(t *testing.T, dsn, keysDir string) harness.DBBackend {
	t.Helper()
	pg := parsePGDSN(t, dsn)
	return harness.DBBackend{
		Name: "postgres",
		ConfigExtra: "storage:\n  type: postgres\n  database:\n" + pg.yaml() + fmt.Sprintf("  encryption:\n    enabled: true\n    dek_path: %q\n    salt_path: %q\n",
			filepath.Join(keysDir, "data.key"), filepath.Join(keysDir, "kek.salt")),
		ExtraEnv: []string{"KEYORIX_DB_PASSWORD=" + pg.Password},
	}
}
