//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_VersioningRollback is J18: an admin creates a secret, updates it
// twice (three versions total), diffs two versions, then rolls back to the
// original value. The rollback must land as a NEW version (append-only
// history, never a rewrite of an old one), the read must return the restored
// value, and the audit trail must show the rollback event.
//
// journey1 (N1, appGetsSecret) already exercises one update + one rollback as
// a side check of its own revocation story; this journey is the dedicated
// J18 spec: three real versions (not two), `secret diff` between two of them,
// and an explicit audit-trail assertion the N1 check never makes.
func TestJourney_VersioningRollback(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projectName = "j11-versioning"
		envName     = "development"
		secretName  = "api-key"
		valueV1     = "api-key-v1-7f3a9c"
		valueV2     = "api-key-v2-rotated-01de"
		valueV3     = "api-key-v3-rotated-8b2c"
	)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	// ── set → update twice: three versions ──────────────────────────────────

	runCLI(t, cliBin, aEnv, "project", "create", "--name", projectName)
	projID := projectID(t, s, adminToken, projectName)
	envID := environmentID(t, s, adminToken, projID, envName)

	runCLI(t, cliBin, aEnv, "secret", "create",
		"--name", secretName, "--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID),
		"--value", valueV1)
	secID := secretID(t, s, adminToken, projID, envID, secretName)

	runCLI(t, cliBin, aEnv, "secret", "update", "--id", strconv.Itoa(secID), "--value", valueV2)
	runCLI(t, cliBin, aEnv, "secret", "update", "--id", strconv.Itoa(secID), "--value", valueV3)

	// ── `secret versions` lists 3 ────────────────────────────────────────────

	versionsOut := runCLI(t, cliBin, aEnv, "secret", "versions", "--id", strconv.Itoa(secID))
	if !strings.Contains(versionsOut, "Total Versions: 3") {
		t.Fatalf("expected 3 versions after create + 2 updates, got:\n%s", versionsOut)
	}
	if got := secretVersionCount(t, s, adminToken, secID); got != 3 {
		t.Fatalf("expected 3 versions via REST, got %d", got)
	}

	// ── `secret diff` between v1 and v3 ──────────────────────────────────────
	// Values (ciphertext) are never compared by this command -- it diffs
	// metadata only (secret_versions.go's own doc comment) -- so the real
	// assertion here is that the command resolves both version numbers and
	// returns a well-formed response naming the secret and the two versions
	// asked for, not that it reports a value change it was never designed to see.

	diffOut := runCLI(t, cliBin, aEnv, "secret", "diff", secretName, "1", "3",
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID))
	if !strings.Contains(diffOut, secretName) || !strings.Contains(diffOut, "v1 -> v3") {
		t.Fatalf("expected `secret diff` output to name the secret and v1 -> v3, got:\n%s", diffOut)
	}

	// ── `secret rollback` to v1: lands as a NEW version, read returns the old value ──

	runCLI(t, cliBin, aEnv, "secret", "rollback", "--id", strconv.Itoa(secID), "--version", "1")

	if got := secretVersionCount(t, s, adminToken, secID); got != 4 {
		t.Fatalf("rollback must append a new version (history stays append-only): want 4 versions, got %d", got)
	}

	readback := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil, http.StatusOK)
	var result struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(readback.Data, &result); err != nil {
		t.Fatalf("decode readback after rollback: %v\nraw: %s", err, readback.Data)
	}
	if result.Value != valueV1 {
		t.Fatalf("rollback to v1: want %q, got %q -- version history did not retain the original value", valueV1, result.Value)
	}

	// ── audit shows the rollback ─────────────────────────────────────────────
	// EventSecretRolledBack ("secret.rolled_back", internal/core/versions.go)
	// is written by RollbackSecret itself -- this is the one assertion in this
	// journey that `secret rollback`'s own "it printed success" isn't enough
	// for (the "assert the effect, not the return value" lesson): a rollback
	// that silently skipped the audit write would still pass every assertion
	// above.

	auditOut := runCLI(t, cliBin, aEnv, "audit", "search",
		"--action", "secret.rolled_back", "--resource-id", strconv.Itoa(secID))
	if !strings.Contains(auditOut, "rolled back") {
		t.Fatalf("expected `audit search --action secret.rolled_back` to show the rollback event, got:\n%s", auditOut)
	}
}
