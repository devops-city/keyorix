//go:build e2e

// Package journeys, journey 8: rotation plan + dependency-safe waves (R4 spec
// #2, J13/J34). Fast tier (no containers): three secrets A -> B -> C
// (secret deps, ADR-052), a project-scoped rotation policy covering all
// three, a rotation plan whose wave order is actually driven by the
// dependency graph (red-proofed by reversing the graph and confirming the
// plan's order follows it, not a hardcoded guess), rotation-simulate as a
// genuine dry-run (no write), then a real rotate leaving `rotation status`
// clean.
package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

const (
	n8ProjectName = "n8-rotation-waves"
	n8EnvName     = "development"
	n8SecretA     = "n8-secret-a"
	n8SecretB     = "n8-secret-b"
	n8SecretC     = "n8-secret-c"
	n8ValueA      = "n8-value-a-v1"
	n8ValueB      = "n8-value-b-v1"
	n8ValueC      = "n8-value-c-v1"
)

func TestJourney_RotationDependencyWaves(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", n8ProjectName)
	projID := projectID(t, s, adminToken, n8ProjectName)
	envID := environmentID(t, s, adminToken, projID, n8EnvName)

	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n8SecretA, "--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--value", n8ValueA)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n8SecretB, "--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--value", n8ValueB)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n8SecretC, "--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--value", n8ValueC)
	idA := secretID(t, s, adminToken, projID, envID, n8SecretA)
	idB := secretID(t, s, adminToken, projID, envID, n8SecretB)
	idC := secretID(t, s, adminToken, projID, envID, n8SecretC)

	// B depends on A, C depends on B -- chain A -> B -> C.
	edgeBA := parseDepEdgeID(t, runCLI(t, cliBin, aEnv, "secret", "deps", "add", strconv.Itoa(idB), strconv.Itoa(idA)))
	edgeCB := parseDepEdgeID(t, runCLI(t, cliBin, aEnv, "secret", "deps", "add", strconv.Itoa(idC), strconv.Itoa(idB)))

	runCLI(t, cliBin, aEnv, "rotation", "create", "--name", "n8-policy", "--scope", "project",
		"--project-id", strconv.Itoa(projID), "--interval-days", "10", "--alert-days-before", "1")

	// All three secrets must be OVERDUE for the plan to have any waves at all
	// (GenerateRotationPlan only includes overdue/due-soon secrets) --
	// backdate created_at directly via sqlite3 (same fixture-setup pattern
	// journey3 uses for its tamper matrix), server stopped first so the edit
	// never races the server's own writer.
	s.Close()
	dbPath := filepath.Join(s.Dir, "keyorix.db")
	backdateSecretCreatedAt(t, dbPath, idA)
	backdateSecretCreatedAt(t, dbPath, idB)
	backdateSecretCreatedAt(t, dbPath, idC)
	restartServer(t, s)

	// ── Plan order follows the dependency graph: A, then B, then C ─────────
	planOut := runCLI(t, cliBin, aEnv, "rotation", "plan", strconv.Itoa(projID))
	assertWaveOrder(t, planOut, n8SecretA, n8SecretB, n8SecretC)

	// ── Red-proof: reverse the dependency graph and confirm the plan's
	// order actually follows it -- not a hardcoded A-B-C guess. Remove the
	// A->B->C chain, add the reverse (A depends on C, B depends on A --
	// chain C -> A -> B), and assert the plan's order flips accordingly. ───
	removeDepEdge(t, cliBin, aEnv, idB, edgeBA)
	removeDepEdge(t, cliBin, aEnv, idC, edgeCB)
	edgeAC := parseDepEdgeID(t, runCLI(t, cliBin, aEnv, "secret", "deps", "add", strconv.Itoa(idA), strconv.Itoa(idC)))
	edgeBA2 := parseDepEdgeID(t, runCLI(t, cliBin, aEnv, "secret", "deps", "add", strconv.Itoa(idB), strconv.Itoa(idA)))

	reversedPlanOut := runCLI(t, cliBin, aEnv, "rotation", "plan", strconv.Itoa(projID))
	assertWaveOrder(t, reversedPlanOut, n8SecretC, n8SecretA, n8SecretB)

	// Restore the original graph (A -> B -> C) for the rest of this journey.
	removeDepEdge(t, cliBin, aEnv, idA, edgeAC)
	removeDepEdge(t, cliBin, aEnv, idB, edgeBA2)
	runCLI(t, cliBin, aEnv, "secret", "deps", "add", strconv.Itoa(idB), strconv.Itoa(idA))
	runCLI(t, cliBin, aEnv, "secret", "deps", "add", strconv.Itoa(idC), strconv.Itoa(idB))

	restoredPlanOut := runCLI(t, cliBin, aEnv, "rotation", "plan", strconv.Itoa(projID))
	assertWaveOrder(t, restoredPlanOut, n8SecretA, n8SecretB, n8SecretC)

	// ── rotation-simulate is a genuine dry-run: no value/version change ────
	beforeVerA := secretVersionCount(t, s, adminToken, idA)
	simOut := runCLI(t, cliBin, aEnv, "secret", "rotation-simulate", "--id", strconv.Itoa(idA))
	if !strings.Contains(simOut, "policy_exists") {
		t.Fatalf("rotation-simulate output missing the policy_exists check:\n%s", simOut)
	}
	afterVerA := secretVersionCount(t, s, adminToken, idA)
	if afterVerA != beforeVerA {
		t.Fatalf("rotation-simulate (dry-run) changed secret %d's version count: was %d, now %d", idA, beforeVerA, afterVerA)
	}
	afterSimValue := readSecretValueAsAdmin(t, s, adminToken, idA)
	if afterSimValue != n8ValueA {
		t.Fatalf("rotation-simulate (dry-run) changed secret %d's value: want %q, got %q", idA, n8ValueA, afterSimValue)
	}

	// ── Actually rotate all three, in wave order ────────────────────────────
	runCLI(t, cliBin, aEnv, "secret", "rotate", "--id", strconv.Itoa(idA), "--value", n8ValueA+"-rotated")
	runCLI(t, cliBin, aEnv, "secret", "rotate", "--id", strconv.Itoa(idB), "--value", n8ValueB+"-rotated")
	runCLI(t, cliBin, aEnv, "secret", "rotate", "--id", strconv.Itoa(idC), "--value", n8ValueC+"-rotated")

	// ── rotation status is now clean ────────────────────────────────────────
	statusOut := runCLI(t, cliBin, aEnv, "rotation", "status")
	if !strings.Contains(statusOut, "within their rotation window") {
		t.Fatalf("expected `rotation status` to report a clean posture after rotating, got:\n%s", statusOut)
	}
}

var depEdgeAddRe = regexp.MustCompile(`\(edge (\d+)\)`)

// parseDepEdgeID extracts the edge ID from `secret deps add`'s stdout
// ("Added: secret %d now depends on secret %d (edge %d).").
func parseDepEdgeID(t *testing.T, out string) int {
	t.Helper()
	m := depEdgeAddRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find edge id in `secret deps add` output:\n%s", out)
	}
	id, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse edge id %q: %v", m[1], err)
	}
	return id
}

// removeDepEdge removes a known edge ID from secretID's dependency list.
func removeDepEdge(t *testing.T, cliBin string, env []string, secretID, edgeID int) {
	t.Helper()
	runCLI(t, cliBin, env, "secret", "deps", "rm", strconv.Itoa(secretID), strconv.Itoa(edgeID))
}

var waveSecretLineRe = regexp.MustCompile(`^\s+([a-zA-Z0-9._-]+)\s+`)

// assertWaveOrder asserts planOut's secrets appear in exactly the given
// order, one per wave (this journey's fixture never puts two secrets in the
// same wave), by scanning for the secret-name lines `rotation plan` prints
// under each "Wave N" header.
func assertWaveOrder(t *testing.T, planOut string, wantOrder ...string) {
	t.Helper()
	var got []string
	for _, line := range strings.Split(planOut, "\n") {
		if strings.Contains(line, "Wave ") {
			continue
		}
		m := waveSecretLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, want := range wantOrder {
			if m[1] == want {
				got = append(got, m[1])
				break
			}
		}
	}
	if len(got) != len(wantOrder) {
		t.Fatalf("expected %d secrets in wave order %v, found %v in plan output:\n%s", len(wantOrder), wantOrder, got, planOut)
	}
	for i, want := range wantOrder {
		if got[i] != want {
			t.Fatalf("wave order mismatch at position %d: want %q, got %q (full order %v) in plan output:\n%s", i, want, got[i], got, planOut)
		}
	}
}

// backdateSecretCreatedAt sets secret_nodes.created_at 15 days into the past
// via the sqlite3 CLI, so a 10-day-interval rotation policy considers it
// overdue (internal/core/rotation_policies.go's appendSecretRotationEntries:
// lastRotated falls back to CreatedAt when LastRotatedAt is nil). Requires
// sqlite3 on the runner's PATH, same assumption journey3's tamper matrix
// makes; the server MUST be stopped first (caller's responsibility) so this
// write never races the server's own.
func backdateSecretCreatedAt(t *testing.T, dbPath string, secretID int) {
	t.Helper()
	stmt := fmt.Sprintf("UPDATE secret_nodes SET created_at = datetime('now', '-15 days') WHERE id = %d;", secretID)
	cmd := exec.Command("sqlite3", dbPath, stmt) // #nosec G204 -- dbPath is this test's own tempdir-derived path, secretID is an int this test itself created, never attacker input
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlite3 backdate UPDATE failed: %v\n%s", err, out)
	}
}

// restartServer stops (if still running) and restarts s.Binary in place,
// reusing the same dir/config/port -- used after backdateSecretCreatedAt's
// direct DB edit, which requires the server to be stopped while it happens.
func restartServer(t *testing.T, s *harness.Server) {
	t.Helper()
	if s.Cmd != nil && s.Cmd.Process != nil {
		_ = s.Cmd.Process.Kill()
		_, _ = s.Cmd.Process.Wait()
	}
	serverEnv := append(append([]string{}, s.Env...), "KEYORIX_CONFIG_PATH="+s.ConfigPath)
	harness.StartBackgroundProcess(t, s, serverEnv)
	harness.WaitHealthy(t, s)
}

// readSecretValueAsAdmin reads secID's current value via the admin session.
func readSecretValueAsAdmin(t *testing.T, s *harness.Server, adminToken string, secID int) string {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil, http.StatusOK)
	var data struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode secret readback: %v\nraw: %s", err, env.Data)
	}
	return data.Value
}
