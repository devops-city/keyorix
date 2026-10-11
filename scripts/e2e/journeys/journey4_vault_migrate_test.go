//go:build e2e && e2e_containers

// Package journeys, journey 4: migrate from Vault/OpenBao. Containers,
// nightly tier (per the SESSION-N brief: journeys 1-3 are merge-queue
// candidates, 4-6 use containers and run nightly) -- gated on BOTH build tags (e2e && e2e_containers) so the fast/merge-queue
// tier (`go test -tags e2e ./scripts/e2e/journeys/...`) never builds or
// runs this file, while the container tier builds it together with the
// shared e2e helpers: run it with `-tags e2e,e2e_containers`
// (`make e2e-journeys-containers`, wired in N7).
package journeys

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// n4ContainersOptInEnvVar is the signal this journey's dedicated nightly CI
// job sets to opt into running it. When set, "docker not available" is a
// hard test FAILURE, not a skip -- a job that deliberately opted into the
// container tier must not report green having tested nothing. When unset
// (e.g. a local `-tags e2e_containers` run without Docker installed), it's
// a clean skip.
const n4ContainersOptInEnvVar = "KEYORIX_E2E_CONTAINERS"

// n4VaultSeed describes the fixture this journey writes into Vault before
// running the health scan and import: a KV v2 tree with a nested path, two
// versions of one secret, and one ACL policy -- matching the brief's "KV v2
// with nested paths, a few versions, a policy or two."
var n4VaultSeed = struct {
	mount      string
	dbPassword struct {
		path     string
		versionA string
		versionB string
	}
	nestedAPIKey struct {
		path  string
		value string
	}
	policyName string
	policyHCL  string
}{
	mount: "secret",
}

func init() {
	n4VaultSeed.dbPassword.path = "n4-team/db-password"
	n4VaultSeed.dbPassword.versionA = "n4-db-pw-v1-4f2a"
	n4VaultSeed.dbPassword.versionB = "n4-db-pw-v2-9c31"
	n4VaultSeed.nestedAPIKey.path = "n4-team/nested/api-key"
	n4VaultSeed.nestedAPIKey.value = "n4-api-key-7e58"
	n4VaultSeed.policyName = "n4-readonly"
	n4VaultSeed.policyHCL = `path "secret/data/n4-team/*" { capabilities = ["read", "list"] }`
}

// n4Backend parametrizes this journey over both Vault and OpenBao -- the
// brief: "Repeat against OpenBao (the ci.yml migrate job already tests
// both) if it is cheap." Same code path, same fixture, only the pinned
// image and container env var names differ (dev-mode root-token env var is
// named differently between the two -- VAULT_DEV_ROOT_TOKEN_ID vs
// BAO_DEV_ROOT_TOKEN_ID -- ci.yml's migrate job sets both unconditionally
// for the same reason: one services: block covering both legs).
type n4Backend struct {
	name          string
	image         string // pinned by digest, matching .github/workflows/ci.yml's migrate job matrix
	rootTokenVars []string
	listenVars    []string
}

var n4Backends = []n4Backend{
	{
		name:          "vault",
		image:         "hashicorp/vault@sha256:0450896c43b13879b19442b204ce29dd19b5a10fce43d5cf38af17da20f56f4d", // 1.15, pinned digest from ci.yml's migrate job
		rootTokenVars: []string{"VAULT_DEV_ROOT_TOKEN_ID=root-token"},
		listenVars:    []string{"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200"},
	},
	{
		name:          "openbao",
		image:         "openbao/openbao@sha256:05d777d6b47d0d0985b87317914632de31d98994b58e490ebabde3c389b09f8f", // 2.0, pinned digest from ci.yml's migrate job
		rootTokenVars: []string{"BAO_DEV_ROOT_TOKEN_ID=root-token"},
		listenVars:    []string{"BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200"},
	},
}

const n4RootToken = "root-token"

// n4ImportedDBPasswordName/n4ImportedAPIKeyName are the Keyorix secret names
// keyorix-migrate's importer assigns to n4VaultSeed.dbPassword.path/
// n4VaultSeed.nestedAPIKey.path: the full source path relative to
// --vault-path, slashes replaced with hyphens -- confirmed live, not the
// leaf path component alone.
const (
	n4ImportedDBPasswordName = "n4-team-db-password"
	n4ImportedAPIKeyName     = "n4-team-nested-api-key"
)

func TestJourney_VaultMigrate(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		if os.Getenv(n4ContainersOptInEnvVar) != "" {
			t.Fatalf("docker not available, but %s is set -- the container journey job opted in and must not silently skip", n4ContainersOptInEnvVar)
		}
		t.Skip("docker not available -- skipping container-based journey (see make e2e-journeys-containers)")
	}
	migrateBin := buildMigrateBinary(t)

	for _, backend := range n4Backends {
		t.Run(backend.name, func(t *testing.T) {
			vaultAddr, cleanup := startVaultContainer(t, backend)
			t.Cleanup(cleanup)

			seedVault(t, vaultAddr)
			assertVaultPolicyExists(t, vaultAddr, n4VaultSeed.policyName, n4VaultSeed.policyHCL)

			// ── Read-only health scan, before any Keyorix involvement ──────
			//
			// The brief originally called for "the health-scan report's
			// findings match what was seeded" -- this was NOT achievable
			// when this journey was first written (the check registry was
			// empty, G1-scaffolding-only: a real scan returned
			// `{"findings":null,...}` unconditionally). Re-verified live
			// while rebasing this branch: G2/G3 have since landed (schema
			// bumped to 2, 20 checks now registered, migrate/internal/
			// healthscan/report.go's own SchemaVersion doc comment confirms
			// "Bumped to 2 in G3"). assertScanReportSchema below now DOES
			// assert real content -- the structured migration_readiness
			// field's kv_v2_mounts/kv_top_level_secrets_approx counts
			// directly reflect this journey's own seeded fixture (1 KV v2
			// mount, 1 top-level path under it), the original brief's ask,
			// achieved via the field least likely to drift on unrelated
			// healthscan prose changes (a structured count, not a Finding's
			// free-text Evidence string).
			scanPrefix := filepath.Join(t.TempDir(), "n4-scan")
			runMigrateBin(t, migrateBin, nil, "vault", "scan",
				"--addr", vaultAddr, "--token", n4RootToken, "--output", scanPrefix)
			scanReport := readScanReportJSON(t, scanPrefix+".json")
			assertScanReportSchema(t, scanReport, vaultAddr)

			// ── Import into a fresh Keyorix install ─────────────────────────
			serverBin, cliBin := harness.BuildBinaries(t)
			s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
			t.Cleanup(s.Close)
			adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
			aEnv := adminEnv(s, adminToken)

			projectName := "n4-" + backend.name + "-import"
			runCLI(t, cliBin, aEnv, "project", "create", "--name", projectName)
			projID := projectID(t, s, adminToken, projectName)
			envID := environmentID(t, s, adminToken, projID, "development")

			keyorixPAT := createAdminPAT(t, cliBin, aEnv, "n4-"+backend.name+"-migrate-pat")

			// Dry run first: assert the printed plan mentions both seeded paths,
			// nothing written yet, and -- since this output could plausibly end
			// up in a CI log -- that it leaks NONE of the actual secret values.
			dryRunOut := runMigrateBin(t, migrateBin, nil, "vault",
				"--vault-addr", vaultAddr, "--vault-token", n4RootToken, "--vault-mount", n4VaultSeed.mount,
				"--vault-path", "n4-team",
				"--server", s.BaseURL, "--token", keyorixPAT,
				"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID))
			assertContains(t, dryRunOut, n4VaultSeed.dbPassword.path)
			assertContains(t, dryRunOut, n4VaultSeed.nestedAPIKey.path)
			assertNoSecretValueLeaked(t, dryRunOut, n4VaultSeed.dbPassword.versionA, n4VaultSeed.dbPassword.versionB, n4VaultSeed.nestedAPIKey.value)
			assertNoSecretNamed(t, s, adminToken, projID, envID, n4ImportedDBPasswordName)
			assertNoSecretNamed(t, s, adminToken, projID, envID, n4ImportedAPIKeyName)

			applyOut := runMigrateBin(t, migrateBin, nil, "vault",
				"--vault-addr", vaultAddr, "--vault-token", n4RootToken, "--vault-mount", n4VaultSeed.mount,
				"--vault-path", "n4-team",
				"--server", s.BaseURL, "--token", keyorixPAT,
				"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID),
				"--apply")
			assertNoSecretValueLeaked(t, applyOut, n4VaultSeed.dbPassword.versionA, n4VaultSeed.dbPassword.versionB, n4VaultSeed.nestedAPIKey.value)

			// ── Every seeded secret is readable in Keyorix with the same value ──
			// keyorix-migrate names an imported secret after its full source path
			// relative to --vault-path, slashes replaced with hyphens (confirmed
			// live: "n4-team/db-password" -> "n4-team-db-password",
			// "n4-team/nested/api-key" -> "n4-team-nested-api-key") -- not just
			// the leaf component.
			dbPwID := secretID(t, s, adminToken, projID, envID, n4ImportedDBPasswordName)
			assertSecretUnchanged(t, s, adminToken, dbPwID, n4VaultSeed.dbPassword.versionB) // latest KV v2 version
			// Only the latest KV v2 version is imported -- NOT the full version
			// history (versionA never reaches Keyorix at all) -- confirmed live,
			// asserted here rather than left as a comment: exactly 1 Keyorix
			// version exists for this secret post-import.
			if got := secretVersionCount(t, s, adminToken, dbPwID); got != 1 {
				t.Errorf("imported secret version count: want 1 (latest-KV-version-only import, no history replay), got %d", got)
			}
			apiKeyID := secretID(t, s, adminToken, projID, envID, n4ImportedAPIKeyName)
			assertSecretUnchanged(t, s, adminToken, apiKeyID, n4VaultSeed.nestedAPIKey.value)

			// ── An "app" using a machine token reads the imported secret,
			// reusing N1's reader pattern (REST + CLI). ────────────────────
			runCLI(t, cliBin, aEnv, "machine", "create", "--project", projectName, "--name", "n4-reader", "--type", "service")
			runCLI(t, cliBin, aEnv, "machine", "grant-role", "n4-reader", "--project", projectName, "--role", "project_viewer")
			issueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", "n4-reader", "--project", projectName, "--name", "n4-reader-token")
			machToken, _ := parseIssuedToken(t, issueOut)
			ref := fmt.Sprintf("%s/development/%s", projectName, n4ImportedDBPasswordName)
			restEnv := restExpect(t, s, machToken, http.MethodGet,
				"/api/v1/secrets/value?ref="+url.QueryEscape(ref), nil, http.StatusOK)
			var got struct {
				Value string `json:"value"`
			}
			if err := json.Unmarshal(restEnv.Data, &got); err != nil {
				t.Fatalf("decode machine-token read: %v", err)
			}
			if got.Value != n4VaultSeed.dbPassword.versionB {
				t.Fatalf("machine-token read of imported secret: want %q, got %q", n4VaultSeed.dbPassword.versionB, got.Value)
			}
		})
	}
}

// buildMigrateBinary compiles keyorix-migrate from this checkout's migrate/
// module (its own go.mod, like cli/) exactly once per test binary run.
func buildMigrateBinary(t *testing.T) string {
	t.Helper()
	root := harness.RepoRoot(t)
	dir := t.TempDir()
	binPath := filepath.Join(dir, "keyorix-migrate")
	cmd := exec.Command("go", "build", "-o", binPath, ".") // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built, with the harness's own fixed arguments; no external input reaches it
	cmd.Dir = filepath.Join(root, "migrate")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build keyorix-migrate: %v\n%s", err, out)
	}
	return binPath
}

// runMigrateBin runs the built keyorix-migrate binary and returns combined
// output, failing the test on a non-zero exit.
func runMigrateBin(t *testing.T, bin string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...) // #nosec G204 -- bin is this test's own built binary, args are the test's own fixed arguments nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e journey itself built, with the journey's own fixed arguments; no external input reaches it
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keyorix-migrate %v: %v\n%s", redactSensitiveArgs(args), err, out)
	}
	return string(out)
}

// redactSensitiveArgs returns a copy of args with the value following any
// --token/--vault-token flag replaced -- runMigrateBin's own fatal message
// above would otherwise print the raw Keyorix PAT / Vault root token
// straight into this test's (and CI's) output on any migrate failure.
func redactSensitiveArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i, a := range out {
		if (a == "--token" || a == "--vault-token") && i+1 < len(out) {
			out[i+1] = "[REDACTED]"
		}
	}
	return out
}

// startVaultContainer runs the backend's pinned dev-mode image via `docker
// run`, waits for it to answer /v1/sys/health, and returns its address plus
// a cleanup func that stops and removes the container.
func startVaultContainer(t *testing.T, backend n4Backend) (addr string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("n4-%s-%d", backend.name, time.Now().UnixNano())
	args := []string{"run", "-d", "--rm", "--name", name, "--cap-add=IPC_LOCK", "-p", "127.0.0.1:0:8200"}
	for _, v := range backend.rootTokenVars {
		args = append(args, "-e", v)
	}
	for _, v := range backend.listenVars {
		args = append(args, "-e", v)
	}
	args = append(args, backend.image)
	cmd := exec.Command("docker", args...) // #nosec G204 -- backend.image is one of two fixed, pinned-by-digest constants declared in this file; no external input reaches it
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", backend.name, err, out)
	}
	cleanup = func() {
		_ = exec.Command("docker", "stop", "-t", "5", name).Run() // #nosec G204 -- name is this test's own generated container name
	}

	portOut, err := exec.Command("docker", "port", name, "8200/tcp").CombinedOutput() // #nosec G204 -- name is this test's own generated container name
	if err != nil {
		cleanup()
		t.Fatalf("docker port %s: %v\n%s", name, err, portOut)
	}
	hostPort := parseDockerPortOutput(t, string(portOut))
	addr = "http://" + hostPort

	deadline := time.Now().Add(30 * time.Second)
	healthy := false
	for time.Now().Before(deadline) {
		resp, herr := http.Get(addr + "/v1/sys/health") // #nosec G107 -- fixed localhost test URL, port from docker's own output
		if herr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !healthy {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput() // #nosec G204 -- name is this test's own generated container name
		cleanup()
		t.Fatalf("%s dev-mode container never became healthy at %s\nlogs:\n%s", backend.name, addr, logs)
	}
	return addr, cleanup
}

// parseDockerPortOutput extracts "host:port" from `docker port <name> 8200/tcp`'s
// output, e.g. "0.0.0.0:54321\n127.0.0.1:54321\n" -- prefers the 127.0.0.1 line.
func parseDockerPortOutput(t *testing.T, out string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "127.0.0.1:") {
			return line
		}
	}
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("docker port: unexpected empty output")
	}
	return lines[0]
}

// seedVault writes n4VaultSeed's fixture directly via Vault's/OpenBao's HTTP
// KV v2 API (both are wire-compatible) -- two versions of one secret, one
// nested-path secret, and one ACL policy.
func seedVault(t *testing.T, addr string) {
	t.Helper()
	vaultKVPut(t, addr, n4VaultSeed.dbPassword.path, map[string]string{"value": n4VaultSeed.dbPassword.versionA})
	vaultKVPut(t, addr, n4VaultSeed.dbPassword.path, map[string]string{"value": n4VaultSeed.dbPassword.versionB})
	vaultKVPut(t, addr, n4VaultSeed.nestedAPIKey.path, map[string]string{"value": n4VaultSeed.nestedAPIKey.value})
	vaultPutPolicy(t, addr, n4VaultSeed.policyName, n4VaultSeed.policyHCL)
}

func vaultKVPut(t *testing.T, addr, path string, data map[string]string) {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"data": data})
	url := fmt.Sprintf("%s/v1/%s/data/%s", addr, n4VaultSeed.mount, path)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build vault kv put request: %v", err)
	}
	req.Header.Set("X-Vault-Token", n4RootToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("vault kv put %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("vault kv put %s: HTTP %d: %s", path, resp.StatusCode, raw)
	}
}

func vaultPutPolicy(t *testing.T, addr, name, hcl string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"policy": hcl})
	url := fmt.Sprintf("%s/v1/sys/policies/acl/%s", addr, name)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build vault policy put request: %v", err)
	}
	req.Header.Set("X-Vault-Token", n4RootToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("vault put policy %s: %v", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("vault put policy %s: HTTP %d: %s", name, resp.StatusCode, raw)
	}
}

// assertVaultPolicyExists reads the seeded ACL policy back via Vault's own
// API (GET /v1/sys/policies/acl/<name>) and confirms it matches the HCL
// seedVault wrote -- keyorix-migrate never touches ACL policies (import is
// about secret VALUES, not Vault authorization config), so this is a sanity
// check on the fixture itself: confirms the policy this journey's own
// n4VaultSeed claims to have seeded was actually written, not a check on
// any Keyorix behavior.
func assertVaultPolicyExists(t *testing.T, addr, name, wantHCL string) {
	t.Helper()
	reqURL := fmt.Sprintf("%s/v1/sys/policies/acl/%s", addr, name)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		t.Fatalf("build vault policy get request: %v", err)
	}
	req.Header.Set("X-Vault-Token", n4RootToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("vault get policy %s: %v", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read vault get policy %s response: %v", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vault get policy %s: HTTP %d: %s", name, resp.StatusCode, raw)
	}
	var data struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode vault get policy %s response: %v\nraw: %s", name, err, raw)
	}
	if strings.TrimSpace(data.Data.Policy) != strings.TrimSpace(wantHCL) {
		t.Errorf("seeded vault policy %s: want %q, got %q", name, wantHCL, data.Data.Policy)
	}
}

// assertNoSecretValueLeaked fails if haystack (migrate CLI output) contains
// any of the given secret values as a bare substring -- called on both
// dry-run and --apply output, since either could plausibly end up in a CI
// log.
func assertNoSecretValueLeaked(t *testing.T, haystack string, values ...string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(haystack, v) {
			t.Errorf("migrate output leaks a secret value %q:\n%s", v, haystack)
		}
	}
}

// readScanReportJSON reads and decodes keyorix-migrate vault scan's JSON
// report -- only the fields this journey's assertions need.
func readScanReportJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- path is this test's own t.TempDir()-derived path
	if err != nil {
		t.Fatalf("read scan report %s: %v", path, err)
	}
	var report map[string]interface{}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode scan report %s: %v\nraw: %s", path, err, raw)
	}
	return report
}

// assertScanReportSchema asserts the scan report's schema-level fields
// (schema_version, vault_addr, generated_by) PLUS the structured
// migration_readiness field's KV counts against this journey's own seeded
// fixture -- see this function's call site doc comment for why the counts
// (not a Finding's free-text Evidence) are what's asserted.
func assertScanReportSchema(t *testing.T, report map[string]interface{}, vaultAddr string) {
	t.Helper()
	if v, _ := report["schema_version"].(float64); v != 3 {
		t.Errorf("scan report schema_version: want 3 (healthscan.SchemaVersion), got %v", report["schema_version"])
	}
	if got, _ := report["vault_addr"].(string); got != vaultAddr {
		t.Errorf("scan report vault_addr: want %q, got %q", vaultAddr, got)
	}
	if _, ok := report["generated_by"].(string); !ok {
		t.Errorf("scan report generated_by: expected a string, got %v", report["generated_by"])
	}
	mr, ok := report["migration_readiness"].(map[string]interface{})
	if !ok {
		t.Fatalf("scan report migration_readiness: expected an object, got %v", report["migration_readiness"])
	}
	if got, _ := mr["kv_v2_mounts"].(float64); got != 1 {
		t.Errorf("scan report migration_readiness.kv_v2_mounts: want 1 (this journey's own seeded %q mount), got %v", n4VaultSeed.mount, mr["kv_v2_mounts"])
	}
	if got, _ := mr["kv_top_level_secrets_approx"].(float64); got != 1 {
		t.Errorf("scan report migration_readiness.kv_top_level_secrets_approx: want 1 (this journey seeds everything under one top-level %q path), got %v", "n4-team", mr["kv_top_level_secrets_approx"])
	}
	// findings/not_checked are both populated now (G2/G3 landed, 20 checks
	// registered) -- deliberately not pinned here beyond migration_readiness
	// above: their exact content is healthscan's own scan-content ownership,
	// not this journey's, and pinning severity/evidence text would make
	// this journey brittle to any healthscan prose or scoring change.
}

func assertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected output to contain %q, got:\n%s", needle, haystack)
	}
}

// patTokenRe matches a raw PAT (`pat create`'s own bare-line output,
// cli/cmd/pat.go's `fmt.Printf("  %s\n", derefStr(data.Token))` -- no
// "Token:" label, just the value, prefixed kx_pat_ per
// server/middleware/auth.go's patTokenPrefix). Declared here, not
// helpers.go, since createAdminPAT below is its only consumer and this
// journey is the only one that creates a PAT -- keeping it here avoids an
// "unused var" lint failure under a plain `-tags e2e` build (this file only
// compiles under e2e_containers).
var patTokenRe = regexp.MustCompile(`kx_pat_\S+`)

// createAdminPAT creates a Personal Access Token for the admin session env
// carries and returns the raw token -- keyorix-migrate's --token flag
// documents itself as expecting a PAT specifically, not a session token.
func createAdminPAT(t *testing.T, cliBin string, env []string, name string) string {
	t.Helper()
	out := runCLI(t, cliBin, env, "pat", "create", "--name", name)
	m := patTokenRe.FindString(out)
	if m == "" {
		t.Fatalf("could not find a kx_pat_ token in `pat create` output:\n%s", out)
	}
	return m
}
