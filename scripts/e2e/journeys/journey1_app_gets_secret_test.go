//go:build e2e

package journeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	keyorix "github.com/keyorixhq/keyorix-sdks/go"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_AppGetsSecret is N1: an admin provisions a project, an
// environment's secret, and a machine identity token scoped to read it; an
// "application" then reads the secret three independent ways (REST, the
// keyorix-sdks/go SDK, the CLI) and all three must agree -- through a
// rotation (all three see the new value, version history holds both) and a
// token revocation (all three are denied, and the secret itself is
// unchanged). It also proves two SDK-specific properties that have no REST/
// CLI equivalent in this journey: a token scoped to a DIFFERENT project is
// denied with a typed *keyorix.ForbiddenError (and the value never leaks
// into that error), and ListSecretsScoped returns every secret in a scope
// larger than the server's single-page default instead of silently
// truncating.
//
// Every step below is exported as appGetsSecret so N3 (the audit-trail
// journey) can call it directly against its own shared install instead of
// re-running the CLI a second time (SESSION-N brief, N3: "call their step
// functions directly, to avoid double-provisioning").
func TestJourney_AppGetsSecret(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	appGetsSecretAs(t, s, cliBin, mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword))
}

// appGetsSecretResult is what the journey provisioned, returned so a caller
// (N3) can reference the same project/secret/machine without re-resolving
// IDs.
type appGetsSecretResult struct {
	ProjectID  int
	EnvID      int
	SecretID   int
	MachineID  int
	ProjectRef string // "project/environment/name", for --ref reads
}

const (
	n1ProjectName = "n1-app-gets-secret"
	n1EnvName     = "development" // admin init's own default seed (harness.StartServer)
	n1SecretName  = "db-password"
	n1MachineName = "n1-reader"
	n1ValueV1     = "hunter2-v1-fbeacd3c"
	n1ValueV2     = "hunter2-v2-rotated-9a71"

	// A second project + machine token, scoped to nothing in n1ProjectName,
	// for the cross-project SDK denial check.
	n1ForeignProjectName = "n1-app-gets-secret-foreign"
	n1ForeignMachineName = "n1-foreign-reader"

	// n1BulkSecretCount additional secrets (on top of n1SecretName itself)
	// put the scope over the server's page_size=20 default -- the exact
	// truncation keyorix-sdks/go v0.2.x's ListSecretsScoped-equivalent query
	// silently hit (see assertListSecretsScopedReturnsEverything).
	n1BulkSecretCount = 24
)

// appGetsSecretAs runs the journey as a caller that already holds the admin session
// token (an MFA-backed one from mfaLogin / enrolTOTPAndLogin: the shipped config
// confines a not-yet-enrolled session to enrolment).
func appGetsSecretAs(t *testing.T, s *harness.Server, cliBin, adminToken string) appGetsSecretResult {
	t.Helper()
	ctx := context.Background()
	aEnv := adminEnv(s, adminToken)

	// ── Admin (CLI): project, secret, machine identity + scoped token ──────

	runCLI(t, cliBin, aEnv, "project", "create", "--name", n1ProjectName)
	projID := projectID(t, s, adminToken, n1ProjectName)
	envID := environmentID(t, s, adminToken, projID, n1EnvName)

	runCLI(t, cliBin, aEnv, "secret", "create",
		"--name", n1SecretName,
		"--project", strconv.Itoa(projID),
		"--environment", strconv.Itoa(envID),
		"--value", n1ValueV1,
	)
	secID := secretID(t, s, adminToken, projID, envID, n1SecretName)

	runCLI(t, cliBin, aEnv, "machine", "create",
		"--project", n1ProjectName, "--name", n1MachineName, "--type", "service")
	machID := machineIdentityID(t, s, adminToken, projID, n1MachineName)

	// project_viewer: read-only at project scope (ADR-021 two-tier roles) --
	// this machine identity only ever reads in this journey.
	runCLI(t, cliBin, aEnv, "machine", "grant-role", n1MachineName,
		"--project", n1ProjectName, "--role", "project_viewer")

	issueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", n1MachineName,
		"--project", n1ProjectName, "--name", "n1-reader-token")
	machToken, machTokenID := parseIssuedToken(t, issueOut)

	ref := fmt.Sprintf("%s/%s/%s", n1ProjectName, n1EnvName, n1SecretName)

	// ── Three readers agree on the initial value ────────────────────────────

	assertThreeReadersAgree(t, s, cliBin, machToken, ref, n1SecretName, n1ValueV1)

	// ── SDK-only properties: cross-project denial, and ListSecretsScoped
	// doesn't truncate a scope bigger than one page. Both are exercised once
	// here, against the stable v1 value/scope, rather than repeated on every
	// assertThreeReadersAgree call. ──────────────────────────────────────────

	assertForeignTokenForbidden(t, s, cliBin, adminToken, n1ProjectName, n1EnvName, n1SecretName, n1ValueV1)
	assertListSecretsScopedReturnsEverything(t, s, adminToken, machToken, projID, envID, n1SecretName)

	// ── Rotate (admin CLI `secret update`) -- version-bump, not the
	// backend-rotation-policy-flavored `secret rotate` (secret_rotation.go is
	// for auto-rotation against an external backend; a plain new value is a
	// version-bumping update, confirmed by secret_crud.go's runSecretUpdate
	// printing "New encrypted version created"). ──────────────────────────

	runCLI(t, cliBin, aEnv, "secret", "update", "--id", strconv.Itoa(secID), "--value", n1ValueV2)

	assertThreeReadersAgree(t, s, cliBin, machToken, ref, n1SecretName, n1ValueV2)

	// Version history holds both versions. GetSecretVersions returns metadata
	// ONLY -- internal/storage/models.SecretVersion.EncryptedValue is
	// `json:"-"` (values are ciphertext-at-rest, never serialized here on
	// purpose) -- so "both present" is checked by count (2: the create + the
	// rotate) here, and by an actual value readback via `secret rollback`
	// (the one mechanism that decrypts a historical version) at the very end
	// of this test, after every other assertion that depends on the current
	// value being n1ValueV2 has already run.
	versionCount := secretVersionCount(t, s, adminToken, secID)
	if versionCount != 2 {
		t.Fatalf("expected exactly 2 versions (create + rotate), got %d", versionCount)
	}

	// ── Revoke the machine token ─────────────────────────────────────────

	runCLI(t, cliBin, aEnv, "machine", "token", "revoke", n1MachineName,
		strconv.Itoa(machTokenID), "--project", n1ProjectName, "--force")

	// All three readers are now denied with the documented status, and the
	// secret itself is unchanged (still v2, still 2 versions) -- read back
	// via the still-valid ADMIN session, not the now-revoked machine token.
	assertReadersDenied(t, s, cliBin, machToken, ref)

	adminReadback := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil, http.StatusOK)
	var afterRevoke struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(adminReadback.Data, &afterRevoke); err != nil {
		t.Fatalf("decode admin readback after revoke: %v\nraw: %s", err, adminReadback.Data)
	}
	if afterRevoke.Value != n1ValueV2 {
		t.Fatalf("secret value changed after a denied read: want %q, got %q", n1ValueV2, afterRevoke.Value)
	}
	if got := secretVersionCount(t, s, adminToken, secID); got != versionCount {
		t.Fatalf("version count changed after a denied read: was %d, now %d", versionCount, got)
	}

	// ── Version history recoverability: prove v1's actual VALUE (not just
	// version-count) is still held, via `secret rollback` -- the only
	// mechanism that decrypts a historical version. Done last, after every
	// assertion above that depends on the current value being n1ValueV2. ──

	runCLI(t, cliBin, aEnv, "secret", "rollback", "--id", strconv.Itoa(secID), "--version", "1")
	rolledBack := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil, http.StatusOK)
	var rolledBackResult struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(rolledBack.Data, &rolledBackResult); err != nil {
		t.Fatalf("decode readback after rollback: %v\nraw: %s", err, rolledBack.Data)
	}
	if rolledBackResult.Value != n1ValueV1 {
		t.Fatalf("rollback to version 1: want %q, got %q -- version history did not retain the original value", n1ValueV1, rolledBackResult.Value)
	}
	if got := secretVersionCount(t, s, adminToken, secID); got != versionCount+1 {
		t.Fatalf("rollback should append a new version (append-only history): want %d, got %d", versionCount+1, got)
	}

	_ = ctx
	return appGetsSecretResult{ProjectID: projID, EnvID: envID, SecretID: secID, MachineID: machID, ProjectRef: ref}
}

// secretVersionCount returns how many versions secretID currently has.
func secretVersionCount(t *testing.T, s *harness.Server, adminToken string, secID int) int {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d/versions", secID), nil, http.StatusOK)
	var data struct {
		Versions []struct{} `json:"versions"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/secrets/%d/versions: %v\nraw: %s", secID, err, env.Data)
	}
	return len(data.Versions)
}

// assertThreeReadersAgree reads secretName by ref via REST, the CLI, and the
// keyorix-sdks/go SDK (both GetSecretIn and GetSecretByRef), and asserts all
// four reads return byte-identical values.
func assertThreeReadersAgree(t *testing.T, s *harness.Server, cliBin, machToken, ref, secretName, want string) {
	t.Helper()

	restEnv := restExpect(t, s, machToken, http.MethodGet,
		"/api/v1/secrets/value?ref="+url.QueryEscape(ref), nil, http.StatusOK)
	var restResult struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(restEnv.Data, &restResult); err != nil {
		t.Fatalf("decode REST secret-by-ref response: %v\nraw: %s", err, restEnv.Data)
	}
	if restResult.Value != want {
		t.Fatalf("REST reader: want %q, got %q", want, restResult.Value)
	}

	cliOut := runCLI(t, cliBin, machineEnv(s, machToken), "secret", "get", "--ref", ref)
	cliValue := parseDecryptedValue(t, cliOut)
	if cliValue != want {
		t.Fatalf("CLI reader: want %q, got %q", want, cliValue)
	}

	assertSDKReaderAgrees(t, s, machToken, ref, secretName, want)
}

// assertSDKReaderAgrees is the SDK leg of assertThreeReadersAgree: a
// project-scoped machine token calls both GetSecretIn (project/environment/
// name) and GetSecretByRef (the same, pre-joined as a "project/environment/
// name" ref) and both must return want. keyorix-sdks/go v0.3.0 fixed the bug
// that made this unconditionally fail for a machine token (see keyorix-sdks
// #49 / this repo's PR body for the red/green proof) -- prior to that fix
// this journey could only assert the SDK leg failed with a specific error
// (assertSDKBlockedByMachineTokenBug, now removed); it is a real reader now.
func assertSDKReaderAgrees(t *testing.T, s *harness.Server, machToken, ref, secretName, want string) {
	t.Helper()
	ctx := context.Background()
	sdkClient, err := keyorix.New(s.BaseURL, machToken)
	if err != nil {
		t.Fatalf("keyorix.New: %v", err)
	}

	projectName, envName, name, ok := splitRef(ref)
	if !ok {
		t.Fatalf("splitRef(%q): malformed ref", ref)
	}
	if name != secretName {
		t.Fatalf("splitRef(%q): name = %q, want %q", ref, name, secretName)
	}

	gotIn, err := sdkClient.GetSecretIn(ctx, projectName, envName, name)
	if err != nil {
		t.Fatalf("SDK reader GetSecretIn(%q, %q, %q): %v", projectName, envName, name, err)
	}
	if gotIn != want {
		t.Fatalf("SDK reader GetSecretIn: want %q, got %q", want, gotIn)
	}

	gotByRef, err := sdkClient.GetSecretByRef(ctx, ref)
	if err != nil {
		t.Fatalf("SDK reader GetSecretByRef(%q): %v", ref, err)
	}
	if gotByRef != want {
		t.Fatalf("SDK reader GetSecretByRef: want %q, got %q", want, gotByRef)
	}
}

// splitRef splits a "project/environment/name" ref into its three parts, the
// same way the server itself does (only the first two "/"-separated segments
// are taken as project/environment; the rest is the name).
func splitRef(ref string) (project, environment, name string, ok bool) {
	parts := strings.SplitN(ref, "/", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// assertForeignTokenForbidden provisions a second project and a machine
// token scoped ONLY to it, then has that token try to read n1's secret via
// the SDK's two single-round-trip readers. Both must fail with a typed
// *keyorix.ForbiddenError (not a generic error, not success), and the
// secret's actual value must never appear anywhere in the error -- a
// forbidden response is not supposed to carry the thing it's refusing to
// disclose.
func assertForeignTokenForbidden(t *testing.T, s *harness.Server, cliBin, adminToken, project1Name, env1Name, secretName, secretValue string) {
	t.Helper()
	ctx := context.Background()
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", n1ForeignProjectName)
	foreignProjID := projectID(t, s, adminToken, n1ForeignProjectName)

	runCLI(t, cliBin, aEnv, "machine", "create",
		"--project", n1ForeignProjectName, "--name", n1ForeignMachineName, "--type", "service")
	_ = machineIdentityID(t, s, adminToken, foreignProjID, n1ForeignMachineName)

	runCLI(t, cliBin, aEnv, "machine", "grant-role", n1ForeignMachineName,
		"--project", n1ForeignProjectName, "--role", "project_viewer")

	issueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", n1ForeignMachineName,
		"--project", n1ForeignProjectName, "--name", "n1-foreign-token")
	foreignToken, _ := parseIssuedToken(t, issueOut)

	sdkClient, err := keyorix.New(s.BaseURL, foreignToken)
	if err != nil {
		t.Fatalf("keyorix.New: %v", err)
	}

	ref := fmt.Sprintf("%s/%s/%s", project1Name, env1Name, secretName)

	_, err = sdkClient.GetSecretIn(ctx, project1Name, env1Name, secretName)
	assertTypedForbiddenNoValueLeak(t, "GetSecretIn", err, secretValue)

	_, err = sdkClient.GetSecretByRef(ctx, ref)
	assertTypedForbiddenNoValueLeak(t, "GetSecretByRef", err, secretValue)
}

// assertTypedForbiddenNoValueLeak asserts err is a *keyorix.ForbiddenError
// (not merely non-nil, not some other typed error) and that its message
// never contains secretValue.
func assertTypedForbiddenNoValueLeak(t *testing.T, callLabel string, err error, secretValue string) {
	t.Helper()
	if err == nil {
		t.Fatalf("SDK reader %s: a foreign-project token unexpectedly succeeded", callLabel)
	}
	var forbidden *keyorix.ForbiddenError
	if !errors.As(err, &forbidden) {
		t.Fatalf("SDK reader %s: want *keyorix.ForbiddenError, got %T: %v", callLabel, err, err)
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("SDK reader %s: forbidden error leaked the secret value: %v", callLabel, err)
	}
}

// assertListSecretsScopedReturnsEverything seeds n1BulkSecretCount additional
// secrets into project+environment (on top of the one already there),
// putting the scope over the server's page_size=20 default, then asserts
// ListSecretsScoped returns every one of them by name -- the pagination fix
// (keyorix-sdks#49 / CHANGELOG "ListSecretsScoped silently truncated at the
// server's default page size (20)"). The admin token does the seeding (CLI
// would also work but is far slower for two dozen creates); the
// project-scoped machine token does the listing, exactly as an application
// would.
func assertListSecretsScopedReturnsEverything(t *testing.T, s *harness.Server, adminToken, machToken string, projID, envID int, existingSecretName string) {
	t.Helper()
	ctx := context.Background()

	want := map[string]bool{existingSecretName: true}
	for i := 0; i < n1BulkSecretCount; i++ {
		name := fmt.Sprintf("n1-bulk-%02d", i)
		restExpect(t, s, adminToken, http.MethodPost, "/api/v1/secrets", map[string]interface{}{
			"name":           name,
			"value":          "n1-bulk-value",
			"project_id":     projID,
			"environment_id": envID,
			"type":           "generic",
		}, http.StatusCreated)
		want[name] = true
	}

	sdkClient, err := keyorix.New(s.BaseURL, machToken)
	if err != nil {
		t.Fatalf("keyorix.New: %v", err)
	}
	secrets, err := sdkClient.ListSecretsScoped(ctx, keyorix.ProjectByID(uint(projID)), keyorix.EnvironmentByID(uint(envID))) //nolint:gosec // projID/envID come from this test's own int-typed REST decode, never negative
	if err != nil {
		t.Fatalf("ListSecretsScoped: %v", err)
	}

	got := make(map[string]bool, len(secrets))
	for _, sec := range secrets {
		got[sec.Name] = true
	}
	if len(got) != len(want) {
		t.Fatalf("ListSecretsScoped: got %d distinct secrets, want %d (scope has %d total, over the server's page_size=20 default): got=%v",
			len(got), len(want), len(want), namesOf(secrets))
	}
	for name := range want {
		if !got[name] {
			t.Fatalf("ListSecretsScoped: missing secret %q -- truncated at the server's page_size=20 default? got=%v", name, namesOf(secrets))
		}
	}
}

func namesOf(secrets []keyorix.Secret) []string {
	names := make([]string, len(secrets))
	for i, sec := range secrets {
		names[i] = sec.Name
	}
	return names
}

// assertReadersDenied re-attempts the REST and CLI reads with the
// now-revoked machine token and asserts both are denied (the SDK leg is not
// re-checked here -- it fails identically before and after revocation, for
// an unrelated reason: the token itself is revoked, which assertSDKReaderAgrees
// already proved the SDK legs depend on just like REST/CLI do).
func assertReadersDenied(t *testing.T, s *harness.Server, cliBin, machToken, ref string) {
	t.Helper()

	restEnv := restCall(t, s, machToken, http.MethodGet, "/api/v1/secrets/value?ref="+url.QueryEscape(ref), nil)
	if restEnv.StatusCode != http.StatusUnauthorized {
		t.Errorf("REST reader after revoke: want HTTP %d, got %d: %s",
			http.StatusUnauthorized, restEnv.StatusCode, string(restEnv.Raw))
	}

	runCLIExpectErr(t, cliBin, machineEnv(s, machToken), "secret", "get", "--ref", ref)
}
