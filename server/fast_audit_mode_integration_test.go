package main

// fast_audit_mode_integration_test.go — ADR-112 Amendment 1 / FASTAUDIT-1
// (docs/specs/fast-audit-mode.md) driven the way an operator drives it: the
// real built binary, a real config file edit, real `admin` commands.
//
// Reuses this package's existing harness (buildServerBinary/runAdmin/baseEnv
// from admin_integration_test.go, bootstrapAdminViaHTTP from
// admin_recover_admin_integration_test.go) and deliberately mirrors
// TestAdminRecoverAdmin_KeylessMode_SQLite's structure: this is the same
// category of setting (a config-file-only security opt-out that must be loud
// and surfaced), so it earns the same end-to-end treatment.
//
// WHAT IS AND IS NOT COVERED HERE, after Andrei's 2026-10-05 decision that the
// mode is PostgreSQL-only. This harness's `admin init` generates a SQLite
// config, so what it can exercise end-to-end against the real binary is:
//
//   - the SQLite REFUSAL — now the user-visible behaviour on this backend, and
//     the single most important thing to prove with the real binary, because
//     "no silent ignore" is the whole point of the decision;
//   - the default install staying silent and durable.
//
// It does NOT cover the in-effect Postgres boot end-to-end: that needs a real
// Postgres cluster, which this package's harness has no fixture for. That path
// is covered instead by internal/storage/store's pg-gated tests (the SET LOCAL
// mechanism, its non-leakage, and a real postmaster-crash tail-loss test) and
// by internal/startup's posture test. Stated rather than left implicit, per
// this repo's rule about naming what a mechanism does not check.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const fastAuditStartupEventType = "admin.audit_durable_sync_skipped_at_startup"

// enableFastAuditModeInConfig edits the generated config's storage.database
// block to set insecure_audit_skip_durable_sync: true. Editing the YAML file
// is the ONLY legitimate way to set this field — see
// internal/config/insecure_audit_skip_durable_sync_reachability_test.go for
// the guard that keeps it that way — so the test has to do it the same way an
// operator would, rather than reaching into a config struct.
func enableFastAuditModeInConfig(t *testing.T, cfgPath string) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath) //nolint:gosec // test-generated path under t.TempDir()
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	// `admin init` writes storage.database.path; anchor on it so the new key
	// lands inside the same mapping rather than guessing at indentation.
	lines := strings.Split(string(raw), "\n")
	var out []string
	injected := false
	for _, line := range lines {
		out = append(out, line)
		trimmed := strings.TrimSpace(line)
		if !injected && strings.HasPrefix(trimmed, "path:") && strings.HasPrefix(line, "    ") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
			out = append(out, indent+"insecure_audit_skip_durable_sync: true")
			injected = true
		}
	}
	if !injected {
		t.Fatalf("failed to inject insecure_audit_skip_durable_sync into the generated config "+
			"(no storage.database.path anchor line found). Config was:\n%s", raw)
	}
	if err := os.WriteFile(cfgPath, []byte(strings.Join(out, "\n")), 0600); err != nil {
		t.Fatalf("write edited config: %v", err)
	}
}

func fastAuditStartupEventCount(t *testing.T, dbPath string) int {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open db for verification: %v", err)
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	var events []models.AuditEvent
	if err := db.Where("event_type = ?", fastAuditStartupEventType).Find(&events).Error; err != nil {
		t.Fatalf("query startup audit events: %v", err)
	}
	return len(events)
}

// TestFastAuditMode_SQLiteRefusesToStartEndToEnd is Andrei's "no silent
// ignore" requirement, proven against the real binary rather than against
// config.Validate in isolation: a SQLite install that sets the setting must
// FAIL, with the named error, on every command that loads config — not start
// quietly while the operator believes their durability is relaxed and their
// reads are fast, when on SQLite neither would be true.
//
// Checks more than one command on purpose. The refusal lives in
// config.Validate, so it has to bite wherever config is loaded; a refusal that
// only fired on `admin validate` would let the server itself boot.
func TestFastAuditMode_SQLiteRefusesToStartEndToEnd(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-fast-audit-sqlite-refusal")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	cfgPath := filepath.Join(dir, "keyorix.yaml")

	// Positive control: the SAME config, before the one-line edit, works. So
	// the failures below are attributable to the setting and not to a broken
	// fixture.
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("control: admin migrate must succeed BEFORE the setting is added: %v\n%s", err, out)
	}

	enableFastAuditModeInConfig(t, cfgPath)

	const wantErr = "insecure_audit_skip_durable_sync is only supported with PostgreSQL"

	// THE SERVER ITSELF. This is the contract Andrei's decision is about:
	// server/main.go calls cfg.Validate() on its boot path, so the process
	// must die rather than serve reads while the operator believes their
	// durability is relaxed.
	serverOut := runServerExpectingExit(t, bin, dir, env)
	if !strings.Contains(serverOut, wantErr) {
		t.Errorf("the SERVER did not refuse to boot with the named refusal (%q) on a SQLite config that sets "+
			"insecure_audit_skip_durable_sync. This is the whole point of the Postgres-only decision -- the "+
			"process must not come up. Server output:\n%s", wantErr, serverOut)
	}
	if !strings.Contains(serverOut, "remove it or switch storage to postgres") {
		t.Errorf("the refusal must tell the operator what to DO, not just that it is wrong. Output:\n%s", serverOut)
	}

	// `admin validate` and `admin diagnose` both load AND validate config
	// (server/admin/validate.go via internal/startup.ValidateStartup;
	// server/admin/diagnose.go calls cfg.Validate directly), so both refuse too.
	//
	// `admin migrate` is deliberately NOT in this list: it does not call
	// cfg.Validate at all, so it applies schema migrations regardless of this
	// setting -- pre-existing behaviour for every other config error, not
	// something this change introduced or should silently paper over. Harmless
	// here (migrate neither serves secrets nor writes audit). Filed as #2854;
	// when that is decided, add "migrate" to this list if it starts
	// validating.
	for _, cmd := range []string{"validate", "diagnose"} {
		out, err := runAdmin(t, bin, dir, env, cmd, "--config", "./keyorix.yaml")
		if err == nil {
			t.Errorf("`admin %s` SUCCEEDED on a SQLite config with insecure_audit_skip_durable_sync set; "+
				"it must refuse. Output:\n%s", cmd, out)
			continue
		}
		if !strings.Contains(out, wantErr) {
			t.Errorf("`admin %s` failed, but not with the named refusal (%q). An unrelated failure would "+
				"make this test pass for the wrong reason. Output:\n%s", cmd, wantErr, out)
		}
	}
}

// runServerExpectingExit starts the built binary as a real server and expects
// it to EXIT on its own rather than serve. Returns its combined output.
//
// Fails if the process is still alive after the grace period: a server that
// keeps running is precisely the "silent ignore" outcome this test exists to
// rule out, so a hang must be a failure rather than a timeout nobody reads.
func runServerExpectingExit(t *testing.T, bin, dir string, env []string) string {
	t.Helper()
	cmd := exec.Command(bin) //nolint:gosec // bin is this suite's own freshly built binary
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("the server exited with status 0 on a config it must REFUSE. A clean exit is not a "+
				"refusal -- an operator's supervisor would read it as success. Output:\n%s", buf.String())
		}
		return buf.String()
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("the server was STILL RUNNING 20s after being started with a config it must refuse. That is "+
			"the silent-ignore outcome the Postgres-only decision rules out. Output:\n%s", buf.String())
		return buf.String()
	}
}

// TestFastAuditMode_DefaultBootIsSilentAndDurable is the off case: a default
// install must print no fast-audit warning, write no such audit event, and
// report no such posture deviation.
//
// This is the half that stops the other tests from passing for the wrong
// reason. Without it, a change that emitted the warning unconditionally — or
// that reported every install as deviant — would leave them green while making
// the posture report useless, which is the "a check that always fails is as
// useless as one that always passes" failure.
func TestFastAuditMode_DefaultBootIsSilentAndDurable(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-fast-audit-default")

	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	// Deliberately NO config edit: this is what `admin init` generates.
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	bootstrapAdminViaHTTP(t, bin, dir, env, "8080", "defaultadmin", "fast-audit-default@example.com", "InitialPassw0rd!")

	// After the boot: the encryption key files are created on first server
	// start, not by `admin init`, so a pre-boot `validate` fails its own
	// key-file permission check for reasons unrelated to this setting.
	validateOut, err := runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin validate failed: %v\n%s", err, validateOut)
	}
	if strings.Contains(validateOut, "insecure_audit_skip_durable_sync") {
		t.Errorf("a DEFAULT install reported the fast audit mode in its posture output. ADR-112 §4's gate "+
			"is that the posture report shows zero deviations on the default configuration. Output:\n%s", validateOut)
	}

	serverLog, err := os.ReadFile(filepath.Join(dir, "bootstrap-server.log")) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatalf("read server log: %v", err)
	}
	if strings.Contains(string(serverLog), "insecure_audit_skip_durable_sync") {
		t.Errorf("a default boot mentioned insecure_audit_skip_durable_sync in its log. The default must be "+
			"durable AND silent about a setting nobody enabled. Server log was:\n%s", serverLog)
	}

	if n := fastAuditStartupEventCount(t, filepath.Join(dir, "keyorix.db")); n != 0 {
		t.Fatalf("a default boot wrote %d %s audit event(s); expected 0", n, fastAuditStartupEventType)
	}

	// The default install's chain must still verify — the baseline this whole
	// feature is an opt-out from.
	verifyOut, err := runAdmin(t, bin, dir, env, "verify-audit", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("`admin verify-audit` failed on a default install: %v\n%s", err, verifyOut)
	}
	if !strings.Contains(verifyOut, "VALID") {
		t.Errorf("expected a VALID verdict from verify-audit on a default install, got:\n%s", verifyOut)
	}
}
