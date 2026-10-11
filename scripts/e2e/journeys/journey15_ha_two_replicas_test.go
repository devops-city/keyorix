//go:build e2e

package journeys

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_HATwoReplicas is J22: two real keyorix-server processes behind
// no load balancer, sharing one Postgres database (ADR-039's documented HA
// shape -- stateless replicas, no leader election, no unseal ceremony).
// Postgres only; skipped without KEYORIX_TEST_PG_DSN. Runs locally (two
// server processes against one Postgres container on this machine), not on
// pve01 (reserved for Session PERF per this session's brief).
//
// Three properties, each against the REAL running binaries:
//  1. Write on replica A, read on replica B (shared storage, not per-process state).
//  2. Revoke a token on A; B denies it within the documented auth-cache window
//     (server/middleware/auth.go's validTokenTTL, 30s) -- not instantly necessarily
//     (B may have a stale positive cache entry), but never past the window.
//  3. The single-writer advisory-lock scheduler (ADR-039): while something else
//     holds the "anomaly_detection" job's lock key, BOTH real server processes'
//     own ticks are skipped, not run concurrently -- and the job resumes once
//     the lock is released. (The lock MECHANISM itself -- exactly one of N
//     contending holders wins -- is already proven directly against Postgres by
//     internal/storage/store/concurrency_scheduler_lock_postgres_test.go's
//     TestConcurrency_WithSchedulerLock_MultiInstancePostgres_ExactlyOneRunsAtOnce;
//     this journey demonstrates the user-visible consequence through two real
//     server binaries, not a second proof of the mechanism.)
//
// Tenancy/RLS (J28) is NOT exercised here: ADR-103 ("PostgreSQL Row-Level
// Security as a second, independent tenancy layer") is Accepted as a design
// but not implemented -- confirmed by grep, zero `CREATE POLICY` / `ENABLE ROW
// LEVEL SECURITY` anywhere in this checkout. A cross-tenant RLS read attempt
// has nothing to exercise yet. Left open, reported as such (not silently
// dropped) per this repo's own "no silent caps" convention.
func TestJourney_HATwoReplicas(t *testing.T) {
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- skipping the HA two-replica journey (Postgres only)")
	}

	serverBin, cliBin := harness.BuildBinaries(t)

	// Own database per run: the admin enrols TOTP below, and that must not survive
	// into the next run against the same server.
	dsn := isolatedPGDatabase(t, base, "j15_ha")
	pg := parsePGDSN(t, dsn)
	dbPassword := os.Getenv("KEYORIX_TEST_PG_PASSWORD")
	if dbPassword == "" {
		dbPassword = pg.Password
	}
	if dbPassword == "" {
		dbPassword = "keyorix-e2e-smoke"
	}
	// anomaly_alerts.schedule: "2s" so the scheduler-singleton check below
	// doesn't need to wait out the real 1h default interval to observe a tick.
	configExtra := fmt.Sprintf("storage:\n  type: postgres\n  database:\n%s  encryption:\n    enabled: true\n    dek_path: keys/dek.key\n    salt_path: keys/kek.salt\nanomaly_alerts:\n  schedule: \"2s\"\n",
		pg.yaml())
	backend := harness.DBBackend{
		Name:        "postgres",
		ConfigExtra: configExtra,
		ExtraEnv:    []string{"KEYORIX_DB_PASSWORD=" + dbPassword},
	}

	// ── Replica A: the normal fresh-install boot sequence (admin init ->
	// encryption init -> migrate -> start -> bootstrap). This is also what
	// creates the shared encryption keys (keys/dek.key, keys/kek.salt) replica
	// B must reuse -- envelope encryption (ADR-004/038) wraps the DEK with a
	// KEK derived from KEYORIX_MASTER_PASSWORD + an on-disk salt; two replicas
	// that each generated their OWN DEK could not read each other's ciphertext
	// at all, let alone agree on one secret's value. ──────────────────────────

	sA := harness.StartServer(t, serverBin, backend)
	t.Cleanup(sA.Close)

	// ── Replica B: same Postgres DB, but must NOT re-run `admin encryption
	// init` (would mint a SECOND, different DEK) and must NOT re-bootstrap
	// (the admin account already exists in the shared DB) -- copy A's key
	// material instead, then just start and wait healthy. ──────────────────

	sB := startHAReplica(t, serverBin, backend, sA.Dir)
	t.Cleanup(sB.Close)

	// Both replicas run the shipped config (security.require_mfa on): prove that on
	// each, then enrol TOTP through replica A's API and work from the MFA-backed
	// session (replica B reads the same shared MFA state from the database).
	requireMFAEnrolmentPremise(t, sA, "smoketestadmin", harness.BootstrapAdminPassword)
	requireMFAEnrolmentPremise(t, sB, "smoketestadmin", harness.BootstrapAdminPassword)
	adminToken := enrolTOTPAndLogin(t, sA, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnvA := adminEnv(sA, adminToken)

	const (
		projName    = "j15-ha-two-replicas"
		envName     = "development"
		secretName  = "ha-shared-secret"
		secretValue = "ha-value-replicated-9d2f"
		machineName = "j15-ha-reader"
	)

	// ── 1. Write on A, read on B ──────────────────────────────────────────────

	runCLI(t, cliBin, aEnvA, "project", "create", "--name", projName)
	projID := projectID(t, sA, adminToken, projName)
	envID := environmentID(t, sA, adminToken, projID, envName)
	runCLI(t, cliBin, aEnvA, "secret", "create", "--name", secretName,
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--value", secretValue)
	secID := secretID(t, sA, adminToken, projID, envID, secretName)

	readFromB := restExpect(t, sB, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil, http.StatusOK)
	var readBack struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(readFromB.Data, &readBack); err != nil {
		t.Fatalf("decode replica B's readback: %v\nraw: %s", err, readFromB.Data)
	}
	if readBack.Value != secretValue {
		t.Fatalf("replica B read: want %q, got %q -- secret written on A is not visible on B (shared storage broken)", secretValue, readBack.Value)
	}

	// ── 2. Revoke a token on A; B denies it within the documented cache window ──

	runCLI(t, cliBin, aEnvA, "machine", "create", "--project", projName, "--name", machineName, "--type", "service")
	runCLI(t, cliBin, aEnvA, "machine", "grant-role", machineName, "--project", projName, "--role", "project_viewer")
	issueOut := runCLI(t, cliBin, aEnvA, "machine", "token", "issue", machineName, "--project", projName, "--name", "j15-ha-token")
	machToken, machTokenID := parseIssuedToken(t, issueOut)

	ref := fmt.Sprintf("%s/%s/%s", projName, envName, secretName)
	readValueViaReplica := func(s *harness.Server) int {
		env := restCall(t, s, machToken, http.MethodGet, "/api/v1/secrets/value?ref="+url.QueryEscape(ref), nil)
		return env.StatusCode
	}

	// Read via B BEFORE revoking, both to confirm the token works cross-replica
	// at all, and so B has a chance to positively cache it -- the scenario the
	// cache-window bound below actually needs to be meaningful for.
	if status := readValueViaReplica(sB); status != http.StatusOK {
		t.Fatalf("machine token read via replica B before revocation: want HTTP 200, got %d", status)
	}

	runCLI(t, cliBin, aEnvA, "machine", "token", "revoke", machineName, strconv.Itoa(machTokenID), "--project", projName, "--force")

	deadline := time.Now().Add(35 * time.Second) // validTokenTTL (30s) + margin
	start := time.Now()
	denied := false
	for time.Now().Before(deadline) {
		if status := readValueViaReplica(sB); status == http.StatusUnauthorized {
			denied = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	if !denied {
		t.Fatalf("revoked token still accepted by replica B after %s -- exceeds the documented %s auth-cache window", time.Since(start), 30*time.Second)
	}
	t.Logf("replica B denied the revoked token %s after revocation (documented window: 30s)", time.Since(start))

	// ── 3. Single-writer scheduler: both real replicas' ticks are skipped
	// while something else holds the job's lock, and resume once it's freed ──

	testHoldsSchedulerLockOnBothReplicas(t, dsn, sA, sB)
}

// schedLockAnomaly mirrors server/main.go's own constant exactly (the
// "anomaly_detection" scheduler's advisory-lock key, 0x4B455953414E4F4D /
// "KEYSANOM") -- this journey must contend on the SAME key the real
// schedulers use, not a stand-in.
const schedLockAnomaly int64 = 0x4B455953414E4F4D

// testHoldsSchedulerLockOnBothReplicas holds the real anomaly_detection
// advisory lock from a connection OUTSIDE either server process (standing in
// for "some other replica is mid-tick"), and confirms both real server
// processes record a SKIPPED tick -- never a concurrent success -- while it's
// held, then releases it and confirms the job resumes on at least one replica.
func testHoldsSchedulerLockOnBothReplicas(t *testing.T, dsn string, sA, sB *harness.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to hold the scheduler advisory lock externally: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck

	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", schedLockAnomaly).Scan(&locked); err != nil {
		t.Fatalf("pg_try_advisory_lock: %v", err)
	}
	if !locked {
		t.Fatalf("could not acquire the anomaly_detection advisory lock externally -- is a real replica already stuck holding it?")
	}

	// anomaly_alerts.schedule is "2s" on both replicas (see TestJourney_HATwoReplicas's
	// ConfigExtra), but each replica's FIRST pass is deferred by a jittered 1-5 minutes
	// after startup (server/scheduler_run.go's anomalyFirstPassDelay, #2632) and there is
	// no knob to shorten it. So poll, rather than sleep a fixed time, until both replicas
	// have recorded a skipped tick; the lock stays held throughout, so a tick that is
	// not skipped would show up as a success.
	waitDeadline := time.Now().Add(6 * time.Minute)
	var skippedA, skippedB int
	for time.Now().Before(waitDeadline) {
		skippedA = schedulerOutcomeCount(t, sA, "anomaly_detection", "skipped")
		skippedB = schedulerOutcomeCount(t, sB, "anomaly_detection", "skipped")
		if skippedA > 0 && skippedB > 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if skippedA == 0 {
		t.Errorf("replica A recorded 0 skipped anomaly_detection ticks while the lock was externally held -- expected at least one")
	}
	if skippedB == 0 {
		t.Errorf("replica B recorded 0 skipped anomaly_detection ticks while the lock was externally held -- expected at least one")
	}
	successDuringHold := schedulerOutcomeCount(t, sA, "anomaly_detection", "success") + schedulerOutcomeCount(t, sB, "anomaly_detection", "success")

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", schedLockAnomaly); err != nil {
		t.Fatalf("pg_advisory_unlock: %v", err)
	}

	time.Sleep(4 * time.Second) // one more 2s tick interval, with margin

	successAfter := schedulerOutcomeCount(t, sA, "anomaly_detection", "success") + schedulerOutcomeCount(t, sB, "anomaly_detection", "success")
	if successAfter <= successDuringHold {
		t.Fatalf("no replica recorded a new successful anomaly_detection tick after the external lock was released "+
			"(success count stayed at %d) -- the job looks permanently wedged, not just correctly deferred", successDuringHold)
	}
}

// schedulerOutcomeCount scrapes s's unauthenticated /metrics endpoint
// (server/middleware/scheduler_metrics.go) and returns the current counter
// value for one scheduler+outcome pair, or 0 if the series hasn't been
// recorded yet (a counter with zero observations is simply absent from the
// exposition, not printed as 0 -- Prometheus client behavior, not a bug).
// schedulerMetricLineRe matches one keyorix_scheduler_runs_total sample line
// and captures its full label set plus its value, WITHOUT assuming a label
// order -- the Prometheus client library serializes labels alphabetically
// (outcome before scheduler), not in declaration order, so a regex anchored
// to `scheduler="..."` before `outcome="..."` silently matches nothing.
var schedulerMetricLineRe = regexp.MustCompile(`keyorix_scheduler_runs_total\{([^}]*)\}\s+([0-9.]+)`)

func schedulerOutcomeCount(t *testing.T, s *harness.Server, scheduler, outcome string) int {
	t.Helper()
	resp, err := http.Get(s.BaseURL + "/metrics") // #nosec G107 -- fixed test harness URL
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}
	wantScheduler := fmt.Sprintf(`scheduler="%s"`, scheduler)
	wantOutcome := fmt.Sprintf(`outcome="%s"`, outcome)
	for _, m := range schedulerMetricLineRe.FindAllStringSubmatch(string(raw), -1) {
		labels := m[1]
		if !strings.Contains(labels, wantScheduler) || !strings.Contains(labels, wantOutcome) {
			continue
		}
		val, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			t.Fatalf("parse metric value %q: %v", m[2], err)
		}
		return int(val)
	}
	return 0
}

// startHAReplica boots a SECOND real keyorix-server process against the same
// Postgres database as an already-bootstrapped replica (sourceDir): admin
// init + the same ConfigExtra + admin migrate (idempotent against an
// already-migrated DB), but deliberately skips `admin encryption init` (would
// mint a second DEK) and the /system/init bootstrap call (the admin account
// already exists) -- it copies the FIRST replica's encryption key material
// instead, then just starts the process and waits for it to become healthy.
func startHAReplica(t *testing.T, serverBin string, backend harness.DBBackend, sourceDir string) *harness.Server {
	t.Helper()
	dir := t.TempDir()
	env := append(harness.BaseServerEnv(dir),
		// Same derivation as harness.StartServer's own (backend.Name is "postgres"
		// for both replicas, so this string is identical on both sides) -- the KEK
		// is PBKDF2(master password, on-disk salt); replica B must derive the SAME
		// KEK as replica A to unwrap the DEK it's about to copy.
		"KEYORIX_MASTER_PASSWORD=e2e-smoke-master-password-"+backend.Name)
	env = append(env, backend.ExtraEnv...)

	configPath := "./keyorix.yaml"
	run := func(args ...string) {
		t.Helper()
		out, err := harness.RunAdminCmd(serverBin, dir, env, args...)
		if err != nil {
			t.Fatalf("keyorix-server admin %s (replica B): %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "--config", configPath)
	applyConfigExtraJ15(t, dir, backend.ConfigExtra)
	// No `admin migrate` here: the shared database is already migrated by
	// replica A's own boot sequence, and `admin migrate` takes serverguard's
	// EXCLUSIVE lock -- which correctly conflicts with replica A's already-running
	// server (holding the SHARED multi-replica lock, internal/serverguard's own
	// documented design) and fails fast rather than racing it.

	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatalf("create replica B keys dir: %v", err)
	}
	for _, name := range []string{"dek.key", "kek.salt"} {
		src := filepath.Join(sourceDir, "keys", name)
		raw, err := os.ReadFile(src) // #nosec G304 -- fixed test-tmpdir path from harness.StartServer's own replica A
		if err != nil {
			t.Fatalf("read replica A's %s to share with replica B: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "keys", name), raw, 0o600); err != nil {
			t.Fatalf("write replica B's %s: %v", name, err)
		}
	}

	port := harness.FreeTCPPort(t)
	harness.RewritePort(t, dir, port)

	s := &harness.Server{
		T: t, Dir: dir, ConfigPath: configPath, BaseURL: "http://127.0.0.1:" + port,
		Binary: serverBin, Env: env, LogPath: filepath.Join(dir, "e2e-server-replica-b.log"),
		Backend: backend,
	}
	serverEnv := append(append([]string{}, env...), "KEYORIX_CONFIG_PATH="+configPath)
	harness.StartBackgroundProcess(t, s, serverEnv)
	harness.WaitHealthy(t, s)
	return s
}

// applyConfigExtraJ15 replaces admin-init's generated storage: block with
// configExtra -- the same splice harness.StartServer performs internally, but
// exported nowhere, so replicated here for replica B's own manual boot
// sequence (this file doesn't touch the shared scripts/e2e/journeys/helpers.go,
// per this session's coordination-via-inbox rule for that file).
func applyConfigExtraJ15(t *testing.T, dir, configExtra string) {
	t.Helper()
	if configExtra == "" {
		return
	}
	path := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "storage:")
	if start < 0 {
		t.Fatalf("generated config has no storage: block:\n%s", text)
	}
	rest := text[start:]
	end := strings.Index(rest, "\nsecrets:")
	if end < 0 {
		t.Fatalf("generated config's storage: block has no following secrets: key:\n%s", text)
	}
	newText := text[:start] + configExtra + rest[end+1:]
	if err := os.WriteFile(path, []byte(newText), 0o600); err != nil { // #nosec G703 -- dir is always t.TempDir()
		t.Fatalf("rewrite config: %v", err)
	}
}
