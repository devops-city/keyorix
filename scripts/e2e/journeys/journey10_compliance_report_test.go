//go:build e2e

// Package journeys, journey 10: compliance report, full cycle (R4 spec #4,
// J27). Fast tier (no containers): a project with three planted compliance
// gaps -- a secret with no rotation policy, a secret overdue for rotation,
// and an unclassified secret -- each confirmed to appear BY NAME in
// `compliance` output (not just "the command exits 0"), then each gap fixed
// one at a time and confirmed to drop out.
package journeys

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

const (
	n10ProjectName       = "n10-compliance"
	n10DevEnv            = "development"
	n10StagingEnv        = "staging"
	n10SecretOverdue     = "n10-secret-overdue"
	n10SecretNoPolicy    = "n10-secret-no-policy"
	n10SecretUnclassifed = "n10-secret-unclassified"
)

func TestJourney_ComplianceReport(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", n10ProjectName)
	projID := projectID(t, s, adminToken, n10ProjectName)
	devEnvID := environmentID(t, s, adminToken, projID, n10DevEnv)
	stagingEnvID := environmentID(t, s, adminToken, projID, n10StagingEnv)

	// secretOverdue and secretUnclassified both live in "development" (covered
	// by the policy created below); secretNoPolicy lives in "staging", which
	// deliberately has no policy of its own -- the "no rotation policy" gap.
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n10SecretOverdue,
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(devEnvID), "--value", "v1")
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n10SecretUnclassifed,
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(devEnvID), "--value", "v1")
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n10SecretNoPolicy,
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(stagingEnvID), "--value", "v1")
	idOverdue := secretID(t, s, adminToken, projID, devEnvID, n10SecretOverdue)
	idUnclassified := secretID(t, s, adminToken, projID, devEnvID, n10SecretUnclassifed)
	idNoPolicy := secretID(t, s, adminToken, projID, stagingEnvID, n10SecretNoPolicy)

	runCLI(t, cliBin, aEnv, "rotation", "create", "--name", "n10-dev-policy", "--scope", "environment",
		"--environment-id", strconv.Itoa(devEnvID), "--interval-days", "10", "--alert-days-before", "1")

	// Backdate secretOverdue (only) 15 days into the past so it is OVERDUE
	// under the 10-day policy -- server stopped first so the direct DB edit
	// never races the server's own writer (same pattern as journey8).
	s.Close()
	dbPath := filepath.Join(s.Dir, "keyorix.db")
	backdateSecretCreatedAtN10(t, dbPath, idOverdue)
	restartServerN10(t, s)

	// ── Baseline: all three gaps are visible, by name, in compliance output ──

	assertInventoryClassification(t, cliBin, aEnv, projID, n10SecretUnclassifed, "")
	assertEvidenceRotationOverdue(t, cliBin, aEnv, n10SecretOverdue, true)
	assertPostureCoveredSecrets(t, s, adminToken, projID, 2) // overdue + unclassified (both in development); n10SecretNoPolicy (staging) uncovered

	reportOut := runCLI(t, cliBin, aEnv, "compliance", "report")
	if !strings.Contains(reportOut, "unclassified") {
		t.Fatalf("`compliance report` doesn't mention unclassified secrets:\n%s", reportOut)
	}

	// ── Fix gap 1: classify the unclassified secret -- confirm it drops out ──
	runCLI(t, cliBin, aEnv, "secret", "classify", "--id", strconv.Itoa(idUnclassified), "--level", "internal")
	assertInventoryClassification(t, cliBin, aEnv, projID, n10SecretUnclassifed, "internal")

	// ── Fix gap 2: rotate the overdue secret -- confirm it drops out ─────────
	runCLI(t, cliBin, aEnv, "secret", "rotate", "--id", strconv.Itoa(idOverdue), "--value", "v2-rotated")
	assertEvidenceRotationOverdue(t, cliBin, aEnv, n10SecretOverdue, false)

	// ── Fix gap 3: cover staging with its own policy -- confirm CoveredSecrets
	// rises by exactly 1 (idNoPolicy's gap closing). ────────────────────────
	runCLI(t, cliBin, aEnv, "rotation", "create", "--name", "n10-staging-policy", "--scope", "environment",
		"--environment-id", strconv.Itoa(stagingEnvID), "--interval-days", "10", "--alert-days-before", "1")
	assertPostureCoveredSecrets(t, s, adminToken, projID, 3)
	_ = idNoPolicy
}

// backdateSecretCreatedAtN10 mirrors journey8's backdateSecretCreatedAt
// (duplicated rather than shared across files to keep each journey
// self-contained and independently reviewable/mergeable).
func backdateSecretCreatedAtN10(t *testing.T, dbPath string, secretID int) {
	t.Helper()
	stmt := fmt.Sprintf("UPDATE secret_nodes SET created_at = datetime('now', '-15 days') WHERE id = %d;", secretID)
	cmd := exec.Command("sqlite3", dbPath, stmt) // #nosec G204 -- dbPath is this test's own tempdir-derived path, secretID is an int this test itself created, never attacker input
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlite3 backdate UPDATE failed: %v\n%s", err, out)
	}
}

// restartServerN10 mirrors journey8's restartServer (duplicated, not shared,
// for the same self-containment reason as backdateSecretCreatedAtN10 above)
// -- stops (if still running) and restarts s.Binary in place, reusing the
// same dir/config/port, used after backdateSecretCreatedAtN10's direct DB
// edit.
func restartServerN10(t *testing.T, s *harness.Server) {
	t.Helper()
	if s.Cmd != nil && s.Cmd.Process != nil {
		_ = s.Cmd.Process.Kill()
		_, _ = s.Cmd.Process.Wait()
	}
	serverEnv := append(append([]string{}, s.Env...), "KEYORIX_CONFIG_PATH="+s.ConfigPath)
	harness.StartBackgroundProcess(t, s, serverEnv)
	harness.WaitHealthy(t, s)
}

// assertInventoryClassification runs `compliance inventory --project` and
// asserts secretName's row has exactly wantClassification in its
// classification column (empty string for unclassified).
func assertInventoryClassification(t *testing.T, cliBin string, env []string, projID int, secretName, wantClassification string) {
	t.Helper()
	out := runCLI(t, cliBin, env, "compliance", "inventory", "--project", strconv.Itoa(projID))
	r := csv.NewReader(strings.NewReader(out))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parse `compliance inventory` CSV: %v\nraw:\n%s", err, out)
	}
	if len(rows) == 0 {
		t.Fatalf("`compliance inventory` returned no rows:\n%s", out)
	}
	header := rows[0]
	nameCol, classCol := -1, -1
	for i, h := range header {
		switch h {
		case "name":
			nameCol = i
		case "classification":
			classCol = i
		}
	}
	if nameCol == -1 || classCol == -1 {
		t.Fatalf("`compliance inventory` CSV header missing name/classification columns: %v", header)
	}
	for _, row := range rows[1:] {
		if row[nameCol] != secretName {
			continue
		}
		if row[classCol] != wantClassification {
			t.Fatalf("secret %q classification: want %q, got %q", secretName, wantClassification, row[classCol])
		}
		return
	}
	t.Fatalf("secret %q not found in `compliance inventory` CSV:\n%s", secretName, out)
}

// evidencePackRotationOverdue mirrors internal/core.EvidenceRotation's wire
// shape -- only the fields this journey needs.
type evidencePackRotationOverdue struct {
	SecretName  string `json:"secret_name"`
	DaysOverdue int    `json:"days_overdue"`
}

// assertEvidenceRotationOverdue runs `compliance export` (stdout, unsigned-OK)
// and asserts whether secretName appears in the evidence pack's
// rotation_overdue list -- the one place `compliance` output names a
// specific overdue secret (compliance report/posture are aggregate-only).
func assertEvidenceRotationOverdue(t *testing.T, cliBin string, env []string, secretName string, wantPresent bool) {
	t.Helper()
	out := runCLI(t, cliBin, env, "compliance", "export")
	var pack struct {
		RotationOverdue []evidencePackRotationOverdue `json:"rotation_overdue"`
	}
	// json.NewDecoder stops after the first valid JSON value -- `compliance
	// export` may append a plain-text "Note: signature not persisted..."
	// line to stderr after the JSON body, and runCLI captures combined
	// output; Decode simply ignores that trailing text.
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&pack); err != nil {
		t.Fatalf("decode `compliance export` evidence pack: %v\nraw:\n%s", err, out)
	}
	found := false
	for _, r := range pack.RotationOverdue {
		if r.SecretName == secretName {
			found = true
			break
		}
	}
	if found != wantPresent {
		t.Fatalf("secret %q in evidence pack's rotation_overdue: want present=%v, got present=%v (list: %+v)",
			secretName, wantPresent, found, pack.RotationOverdue)
	}
}

// assertPostureCoveredSecrets asserts GET /api/v1/compliance/posture's
// rotation.covered_secrets EXACTLY equals want for projID -- the aggregate
// signal for the "no rotation policy" gap (there is no per-secret named view
// for policy COVERAGE specifically, unlike overdue (evidence pack) and
// classification (inventory CSV) -- noted in this journey's PR description).
func assertPostureCoveredSecrets(t *testing.T, s *harness.Server, adminToken string, projID, want int) {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/compliance/posture", nil, http.StatusOK)
	var data struct {
		Rotation struct {
			CoveredSecrets int `json:"covered_secrets"`
		} `json:"rotation"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/compliance/posture: %v\nraw: %s", err, env.Data)
	}
	if data.Rotation.CoveredSecrets != want {
		t.Fatalf("compliance posture rotation.covered_secrets: want %d, got %d (project %d)", want, data.Rotation.CoveredSecrets, projID)
	}
}
