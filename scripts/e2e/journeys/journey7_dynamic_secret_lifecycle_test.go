//go:build e2e && e2e_containers

// Package journeys, journey 7: dynamic-secret full lifecycle against a real
// Postgres target (R4 spec #1, J12). Containers, nightly tier -- gated on
// BOTH build tags (e2e && e2e_containers), same convention as journey4/5:
// `make e2e-journeys` (`-tags e2e`) never builds or runs this file. Fresh
// install -> register a Postgres target config -> issue a credential ->
// assert it REALLY authenticates against the target DB (a live pgx
// connection, not a Keyorix-side assertion) -> `dynamic-secret leases` shows
// it -> revoke -> assert the credential REALLY fails to authenticate anymore
// -> separately, a short-TTL lease left unrevoked fails on its own once
// Postgres's native VALID UNTIL lapses (PostgresEngine.SupportsNativeExpiry).
package journeys

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

const (
	n7ContainersOptInEnvVar = "KEYORIX_E2E_CONTAINERS"
	n7PGImage               = "postgres:16" // matches .github/workflows/ci.yml's pg-gated job
	n7PGUser                = "keyorix"
	n7PGPassword            = "keyorix123"
	n7PGDB                  = "keyorix"
	n7ProjectName           = "n7-dynamic-secrets"
	n7ConfigName            = "n7-pg-target"
)

func TestJourney_DynamicSecretLifecycle(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		if os.Getenv(n7ContainersOptInEnvVar) != "" {
			t.Fatalf("docker not available, but %s is set -- the container journey job opted in and must not silently skip", n7ContainersOptInEnvVar)
		}
		t.Skip("docker not available -- skipping container-based journey (see make e2e-journeys-containers)")
	}

	pgAddr, cleanup := startPostgresContainer(t)
	t.Cleanup(cleanup)
	adminDSN := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", n7PGUser, n7PGPassword, pgAddr, n7PGDB)
	waitForPostgresReady(t, adminDSN)

	serverBin, cliBin := harness.BuildBinaries(t)
	s := startServerWithDynamicSecrets(t, serverBin)
	t.Cleanup(s.Close)

	// Boots with the shipped config (security.require_mfa on, ADR-112): prove that,
	// then enrol TOTP through the real API and work from the MFA-backed session.
	requireMFAEnrolmentPremise(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	adminToken := enrolTOTPAndLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", n7ProjectName)
	projID := projectID(t, s, adminToken, n7ProjectName)
	envID := environmentID(t, s, adminToken, projID, "development")

	configEnv := append(append([]string{}, aEnv...), "KEYORIX_DYNAMIC_ADMIN_DSN="+adminDSN)
	createOut := runCLI(t, cliBin, configEnv, "dynamic-secret", "create",
		"--name", n7ConfigName, "--project-id", fmt.Sprintf("%d", projID), "--environment-id", fmt.Sprintf("%d", envID),
		"--backend", "postgres",
		"--creation-template", "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};")
	configID := parseDynConfigID(t, createOut)

	// ── Issue, and assert the credential REALLY authenticates ──────────────
	issueOut := runCLI(t, cliBin, aEnv, "dynamic-secret", "issue", configID, "--ttl", "3600")
	username, password, leaseID := parseDynLease(t, issueOut)
	assertPostgresLogin(t, pgAddr, username, password, true)

	// ── `dynamic-secret leases` shows it ─────────────────────────────────────
	leasesOut := runCLI(t, cliBin, aEnv, "dynamic-secret", "leases", configID)
	if !strings.Contains(leasesOut, leaseID) {
		t.Fatalf("`dynamic-secret leases` does not show lease %s:\n%s", leaseID, leasesOut)
	}
	if !strings.Contains(leasesOut, "active") {
		t.Fatalf("`dynamic-secret leases` does not show the lease as active:\n%s", leasesOut)
	}

	// ── Revoke, and assert the credential REALLY stops authenticating
	// (the "assert the effect, not the return value" lesson -- not just that
	// the CLI call exits 0). ────────────────────────────────────────────────
	runCLI(t, cliBin, aEnv, "dynamic-secret", "revoke", leaseID)
	assertPostgresLogin(t, pgAddr, username, password, false)

	// ── Separately: a short-TTL lease left unrevoked fails on its own once
	// Postgres's native VALID UNTIL lapses -- PostgresEngine.SupportsNativeExpiry,
	// no Keyorix-side sweeper involved. ─────────────────────────────────────
	shortIssueOut := runCLI(t, cliBin, aEnv, "dynamic-secret", "issue", configID, "--ttl", "2")
	shortUser, shortPass, _ := parseDynLease(t, shortIssueOut)
	assertPostgresLogin(t, pgAddr, shortUser, shortPass, true)
	time.Sleep(3 * time.Second)
	assertPostgresLogin(t, pgAddr, shortUser, shortPass, false)
}

// startPostgresContainer runs a Postgres dev container via `docker run`,
// waits for the port to be published, and returns its "host:port" address
// plus a cleanup func. Readiness (accepting real connections, not just the
// port being open) is confirmed separately by waitForPostgresReady.
func startPostgresContainer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("n7-postgres-%d", time.Now().UnixNano())
	args := []string{"run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_USER=" + n7PGUser,
		"-e", "POSTGRES_PASSWORD=" + n7PGPassword,
		"-e", "POSTGRES_DB=" + n7PGDB,
		"-p", "127.0.0.1:0:5432",
		n7PGImage,
	}
	cmd := exec.Command("docker", args...) // #nosec G204 -- n7PGImage is this file's own fixed constant; no external input reaches it
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker run postgres: %v\n%s", err, out)
	}
	cleanup = func() {
		_ = exec.Command("docker", "stop", "-t", "5", name).Run() // #nosec G204 -- name is this test's own generated container name
	}

	portOut, err := exec.Command("docker", "port", name, "5432/tcp").CombinedOutput() // #nosec G204 -- name is this test's own generated container name
	if err != nil {
		cleanup()
		t.Fatalf("docker port %s: %v\n%s", name, err, portOut)
	}
	return parseDockerPortOutput(t, string(portOut)), cleanup
}

// waitForPostgresReady polls adminDSN with a real pgx connection until it
// succeeds or 30s elapses -- unlike a TCP-open check, this proves Postgres
// has actually finished its init scripts and is accepting authenticated
// connections.
func waitForPostgresReady(t *testing.T, adminDSN string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := pgx.Connect(ctx, adminDSN)
		cancel()
		if err == nil {
			_ = conn.Close(context.Background())
			return
		}
		lastErr = err
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("postgres container never became ready at %s: %v", adminDSN, lastErr)
}

// assertPostgresLogin attempts a real pgx connection as username/password
// against the Postgres container and asserts it succeeds or fails exactly as
// wantSuccess says -- this is the journey's real "the credential actually
// works / actually stopped working" proof, independent of Keyorix's own
// bookkeeping.
func assertPostgresLogin(t *testing.T, pgAddr, username, password string, wantSuccess bool) {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", username, password, pgAddr, n7PGDB)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err == nil {
		defer func() { _ = conn.Close(context.Background()) }()
		var one int
		err = conn.QueryRow(ctx, "SELECT 1").Scan(&one)
	}
	if wantSuccess && err != nil {
		t.Fatalf("expected credential %q to authenticate successfully against postgres, got error: %v", username, err)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("expected credential %q to be REJECTED by postgres, but it authenticated successfully", username)
	}
}

// startServerWithDynamicSecrets is harness.StartServer's own sequence, with
// one extra step: appending a `dynamic_secrets:` block enabling
// allow_private_network_targets (the Postgres container listens on
// 127.0.0.1, which the SSRF guard on admin_dsn otherwise refuses -- see
// internal/config.DynamicSecretsConfig's own doc comment). Mirrors
// journey9's startServerWithBreakGlass / journey5's startServerWithSSO.
func startServerWithDynamicSecrets(t *testing.T, binary string) *harness.Server {
	t.Helper()
	dir := t.TempDir()
	env := append(harness.BaseServerEnv(dir),
		"KEYORIX_MASTER_PASSWORD=e2e-smoke-master-password-dynsecrets")
	configPath := "./keyorix.yaml"

	run := func(args ...string) {
		t.Helper()
		out, err := harness.RunAdminCmd(binary, dir, env, args...)
		if err != nil {
			t.Fatalf("keyorix-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "--config", configPath)

	dynBlock := "\ndynamic_secrets:\n  allow_private_network_targets: true\n"
	cfgFile := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfgFile) // #nosec G304 -- cfgFile is this test's own t.TempDir()-derived path
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if err := os.WriteFile(cfgFile, append(raw, []byte(dynBlock)...), 0o600); err != nil {
		t.Fatalf("append dynamic_secrets: block to config: %v", err)
	}

	run("encryption", "init", "--config", configPath)
	run("migrate", "--config", configPath)

	port := harness.FreeTCPPort(t)
	harness.RewritePort(t, dir, port)

	const bootstrapToken = "e2e-smoke-bootstrap-token-dyn-0123456789"
	s := harness.BootAndBootstrap(t, binary, dir, env, configPath, port, bootstrapToken,
		"smoketestadmin", "smoketestadmin@example.invalid", harness.BootstrapAdminPassword)
	s.Backend = harness.DBBackend{Name: "sqlite-dynamicsecrets"}
	return s
}

var dynConfigIDRe = regexp.MustCompile(`config #(\d+)`)

// parseDynConfigID extracts the config ID from `dynamic-secret create`'s
// stdout ("Created dynamic-secret config #%d (%s, %s).").
func parseDynConfigID(t *testing.T, out string) string {
	t.Helper()
	m := dynConfigIDRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find config id in `dynamic-secret create` output:\n%s", out)
	}
	return m[1]
}

var (
	dynLeaseIDRe = regexp.MustCompile(`(?m)^\s*lease:\s+(\S+)$`)
	dynUserRe    = regexp.MustCompile(`(?m)^\s*username:\s+(\S+)$`)
	dynPassRe    = regexp.MustCompile(`(?m)^\s*password:\s+(\S+)$`)
)

// parseDynLease extracts the username, password, and lease ID from
// `dynamic-secret issue`'s stdout.
func parseDynLease(t *testing.T, out string) (username, password, leaseID string) {
	t.Helper()
	lm := dynLeaseIDRe.FindStringSubmatch(out)
	um := dynUserRe.FindStringSubmatch(out)
	pm := dynPassRe.FindStringSubmatch(out)
	if lm == nil || um == nil || pm == nil {
		t.Fatalf("could not parse lease/username/password from `dynamic-secret issue` output:\n%s", out)
	}
	return um[1], pm[1], lm[1]
}
