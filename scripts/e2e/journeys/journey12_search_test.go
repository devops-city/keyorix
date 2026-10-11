//go:build e2e

package journeys

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_Search is J19: secrets scattered across two projects, found by
// `secret list --search` without knowing the exact path -- and, the security
// assertion this journey exists for, a caller with access to only one of the
// two projects gets nothing back from the project they can't see, even
// though their search has no --project filter at all (server/http/handlers/
// secrets_list.go's own documented behaviour: a caller with no global grant
// gets the UNION of every scope they hold secrets.read in, never a scope
// they don't).
func TestJourney_Search(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projA       = "j12-search-a"
		projB       = "j12-search-b"
		envName     = "development"
		searcherU   = "j12-searcher"
		searcherEml = "j12-searcher@example.invalid"
		searcherPwd = "Opal-Thicket-61-Grove!"
		needle      = "needle"
	)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	// ── Setup: two projects, a mix of matching and non-matching secrets, one
	// human user granted a role in project A only ───────────────────────────

	runCLI(t, cliBin, aEnv, "project", "create", "--name", projA)
	runCLI(t, cliBin, aEnv, "project", "create", "--name", projB)
	projAID := projectID(t, s, adminToken, projA)
	projBID := projectID(t, s, adminToken, projB)
	envAID := environmentID(t, s, adminToken, projAID, envName)
	envBID := environmentID(t, s, adminToken, projBID, envName)

	createSecret := func(projID, envID int, name string) {
		runCLI(t, cliBin, aEnv, "secret", "create", "--name", name,
			"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--value", "v-"+name)
	}
	createSecret(projAID, envAID, "needle-alpha-1")
	createSecret(projAID, envAID, "needle-alpha-2")
	createSecret(projAID, envAID, "other-a")
	createSecret(projBID, envBID, "needle-beta-1")
	createSecret(projBID, envBID, "other-b")

	runCLI(t, cliBin, aEnv, "user", "create", "--username", searcherU, "--email", searcherEml, "--password", searcherPwd)
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", searcherEml, "--role", "project_viewer", "--project", projA)
	// No grant on projB at all -- the caller under test can see project A only.

	// ── Sanity: the admin's own search (global access) finds all 3 matches,
	// proving `--search` itself works before testing the scoped case ────────

	adminHits := searchSecretNames(t, cliBin, aEnv, needle)
	if len(adminHits) != 3 {
		t.Fatalf("admin search for %q: want 3 matches (needle-alpha-1, needle-alpha-2, needle-beta-1), got %d: %v", needle, len(adminHits), adminHits)
	}

	// ── The scoped caller's search: sees project A's matches, nothing from B ──

	searcherToken := mfaPersonaLogin(t, s, searcherU, searcherPwd)
	searcherEnv := tokenEnv(s, searcherToken)

	hits := searchSecretNames(t, cliBin, searcherEnv, needle)
	wantA := map[string]bool{"needle-alpha-1": true, "needle-alpha-2": true}
	if len(hits) != len(wantA) {
		t.Fatalf("scoped searcher: want exactly %d matches (project A's needles), got %d: %v", len(wantA), len(hits), hits)
	}
	for _, name := range hits {
		if !wantA[name] {
			t.Fatalf("scoped searcher: got a match %q outside project A's scope -- enumeration leak from project B", name)
		}
		if name == "needle-beta-1" {
			t.Fatalf("scoped searcher: saw project B's secret %q -- no-access caller must get nothing from B", name)
		}
	}

	// ── Same guarantee over REST directly (no CLI name-resolution in the way) ──

	restEnv := restExpect(t, s, searcherToken, http.MethodGet,
		"/api/v1/secrets?search="+needle, nil, http.StatusOK)
	var restData struct {
		Secrets []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(restEnv.Data, &restData); err != nil {
		t.Fatalf("decode REST search response: %v\nraw: %s", err, restEnv.Data)
	}
	if len(restData.Secrets) != len(wantA) {
		t.Fatalf("REST scoped search: want exactly %d matches, got %d", len(wantA), len(restData.Secrets))
	}
	for _, sec := range restData.Secrets {
		if sec.Name == "needle-beta-1" {
			t.Fatalf("REST scoped search: saw project B's secret %q -- enumeration leak", sec.Name)
		}
	}
}

// searchSecretNames runs `secret list --search <query> --format json` as env
// and returns the matched secret names.
func searchSecretNames(t *testing.T, cliBin string, env []string, query string) []string {
	t.Helper()
	out := runCLI(t, cliBin, env, "secret", "list", "--search", query, "--format", "json", "--limit", "100")
	var data struct {
		Secrets []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("decode `secret list --search %s --format json`: %v\nraw: %s", query, err, out)
	}
	names := make([]string, 0, len(data.Secrets))
	for _, sec := range data.Secrets {
		names = append(names, sec.Name)
	}
	return names
}
