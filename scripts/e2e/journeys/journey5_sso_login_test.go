//go:build e2e && e2e_containers

// Package journeys, journey 5: SSO login via a real Keycloak (OIDC only).
// Containers, nightly tier -- gated on e2e && e2e_containers, same as
// journey4 -- see that file's own build-tag doc comment for why.
package journeys

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

const (
	n5KeycloakImage = "quay.io/keycloak/keycloak@sha256:09a381c715ab0b111835b70f2905955274843a219c6f27efb348e4d9f4086858" // 26.0, pinned digest (no prior Keycloak reference existed anywhere in this repo -- sourced fresh, same way ci.yml's vault/openbao digests were: pin whatever tag is current on first use)
	n5KCAdminUser   = "n5admin"
	n5KCAdminPass   = "n5-kc-admin-pw-do-not-use-in-prod"

	n5Realm         = "n5-realm"
	n5ClientID      = "keyorix"
	n5ClientSecret  = "n5-client-secret-fixed-do-not-use-in-prod" // #nosec G101 -- test-fixture-only, a throwaway Keycloak dev-mode client secret, never a real credential
	n5ProviderName  = "keycloak"                                  // Keyorix-side SSO provider name (also the URL slug)
	n5GroupAuditors = "n5-auditors"
	n5GroupEditors  = "n5-editors"
	// n5GroupBaseline: every user also joins this UNMAPPED group, so a
	// removal test (leaving n5GroupAuditors/n5GroupEditors) still asserts a
	// NON-empty "groups" claim -- internal/core/sso.go's reconciliation is
	// deliberately skipped outright when the claim is empty ("an IdP that
	// omits the groups attribute must not strip a user's memberships/roles"
	// -- confirmed live, see this journey's own doc comment at the removal
	// assertion below for what this means for a user who leaves ALL their
	// mapped groups). Testing partial removal (still in *a* group, just not
	// the mapped one) is what actually exercises reconcileSSORoles's remove
	// path instead of silently hitting that empty-claim skip.
	n5GroupBaseline = "n5-baseline"
	n5RoleForGroupA = "system_auditor" // GroupRoleMap target for n5GroupAuditors
	// n5RoleForGroupB is deliberately NOT "system_viewer": that's this
	// journey's own default_role (the JIT-provisioning baseline every new
	// user gets, config.go's DefaultRole) -- confirmed live that mapping a
	// SECOND group to the same name as default_role makes every login for a
	// user outside that group immediately strip their own baseline role
	// (reconcileSSORoles treats every GroupRoleMap-managed role name as
	// authoritative, including one that happens to collide with
	// default_role), which is a confusing self-inflicted interaction, not a
	// real illustration of "second group, second role." "editor" avoids the
	// collision and isn't blocked by the IdP-auto-grant escalation guard
	// (idpAutoGrantOfRoleIsEscalation only blocks admin-tier roles).
	n5RoleForGroupB = "editor"

	n5User1     = "n5user1"
	n5User1Pass = "N5-User-Pw-1!" // #nosec G101 -- test-fixture-only Keycloak user password
	n5User2     = "n5user2"
	n5User2Pass = "N5-User-Pw-2!" // #nosec G101 -- test-fixture-only Keycloak user password
)

func TestJourney_SSOLogin(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		if os.Getenv(n4ContainersOptInEnvVar) != "" {
			t.Fatalf("docker not available, but %s is set -- the container journey job opted in and must not silently skip", n4ContainersOptInEnvVar)
		}
		t.Skip("docker not available -- skipping container-based journey (see make e2e-journeys-containers)")
	}

	kcAddr, kcCleanup := startKeycloakContainer(t)
	t.Cleanup(kcCleanup)

	kcToken := keycloakAdminToken(t, kcAddr)
	kcCreateRealm(t, kcAddr, kcToken)

	// The CLI leg doesn't apply to this journey: SSO login is inherently a
	// browser/OIDC flow, not something a CLI ever drives -- only the server
	// binary is needed here.
	serverBin, _ := harness.BuildBinaries(t)
	serverPort := harness.FreeTCPPort(t)
	redirectURL := fmt.Sprintf("http://127.0.0.1:%s/auth/sso/%s/callback", serverPort, n5ProviderName)

	clientUUID := kcCreateClient(t, kcAddr, kcToken, redirectURL)
	kcAddGroupsMapper(t, kcAddr, kcToken, clientUUID)
	groupAuditorsID := kcCreateGroup(t, kcAddr, kcToken, n5GroupAuditors)
	groupEditorsID := kcCreateGroup(t, kcAddr, kcToken, n5GroupEditors)
	groupBaselineID := kcCreateGroup(t, kcAddr, kcToken, n5GroupBaseline)
	user1ID := kcCreateUser(t, kcAddr, kcToken, n5User1, n5User1Pass, groupAuditorsID, groupBaselineID)
	kcCreateUser(t, kcAddr, kcToken, n5User2, n5User2Pass, groupEditorsID, groupBaselineID)

	issuer := fmt.Sprintf("%s/realms/%s", kcAddr, n5Realm)
	s := startServerWithSSO(t, serverBin, serverPort, issuer, redirectURL)
	t.Cleanup(s.Close)
	// Boots with the shipped config (security.require_mfa on, ADR-112): prove that,
	// then enrol TOTP through the real API and work from the MFA-backed session.
	requireMFAEnrolmentPremise(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	adminToken := enrolTOTPAndLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)

	// ── First login (JIT-provisioned), mapped role from its group ───────────

	jar1, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("new cookie jar: %v", err)
	}
	completeSSOLogin(t, s, jar1, kcAddr, n5User1, n5User1Pass)
	assertUserHasRole(t, s, adminToken, n5User1, n5RoleForGroupA)

	// ── Second user, second group -> second role ─────────────────────────────

	jar2, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("new cookie jar: %v", err)
	}
	completeSSOLogin(t, s, jar2, kcAddr, n5User2, n5User2Pass)
	assertUserHasRole(t, s, adminToken, n5User2, n5RoleForGroupB)
	assertUserLacksRole(t, s, adminToken, n5User2, n5RoleForGroupA)

	// ── Remove user1 from their Keycloak group, log in again: assert against
	// actual behavior (GroupRoleMap's own doc comment: "roles outside the map
	// are left alone -- the IdP drives THESE role assignments"), not assumed. ──

	kcRemoveUserFromGroup(t, kcAddr, kcToken, user1ID, groupAuditorsID)
	jar1b, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("new cookie jar: %v", err)
	}
	completeSSOLogin(t, s, jar1b, kcAddr, n5User1, n5User1Pass)
	assertRoleRemovalWasSynced(t, s, adminToken)
	assertUserLacksRole(t, s, adminToken, n5User1, n5RoleForGroupA)

	// ── Negative OIDC cases: each must be rejected with NO session cookie
	// set. nonce/audience/expiry/signature validation is already covered by
	// unit-level fuzzing (internal/core/sso_claims_fuzz_test.go's
	// FuzzVerifyIDTokenClaims, which signs every token with the trusted key
	// so mutation pours into claim semantics rather than dying at the
	// signature check -- issuer/audience/nonce/expiry are all asserted
	// fail-closed there) and internal/core/sso_fuzz_test.go's signature-
	// bypass fuzzing -- not re-implemented at this E2E layer. These three
	// cases are specifically about the CALLBACK's own code/state handling,
	// which only a real IdP round trip can exercise. ──────────────────────

	t.Run("negative: tampered state is rejected, no session set", func(t *testing.T) {
		jar, jerr := cookiejar.New(nil)
		if jerr != nil {
			t.Fatalf("new cookie jar: %v", jerr)
		}
		callbackURL := obtainSSOCallbackURL(t, s, jar, kcAddr, n5User1, n5User1Pass)
		tampered := tamperQueryParam(t, callbackURL, "state", "n5-tampered-state-value")
		assertCallbackRejectedNoSession(t, s, jar, tampered)
	})

	t.Run("negative: replayed code+state is rejected on second use", func(t *testing.T) {
		jar, jerr := cookiejar.New(nil)
		if jerr != nil {
			t.Fatalf("new cookie jar: %v", jerr)
		}
		callbackURL := obtainSSOCallbackURL(t, s, jar, kcAddr, n5User1, n5User1Pass)
		client := ssoClient(jar)
		firstResp, ferr := client.Get(callbackURL) // #nosec G107 -- callbackURL is this journey's own real, freshly-obtained value
		if ferr != nil {
			t.Fatalf("first (legitimate) callback completion: %s", redactCode(ferr.Error()))
		}
		_ = firstResp.Body.Close()
		if firstResp.StatusCode != http.StatusFound {
			t.Fatalf("first (legitimate) callback completion: want 302, got %d", firstResp.StatusCode)
		}
		// Second use of the SAME code+state, a FRESH jar so the first
		// call's own successful session can't leak into this assertion.
		jar2, jerr2 := cookiejar.New(nil)
		if jerr2 != nil {
			t.Fatalf("new cookie jar: %v", jerr2)
		}
		assertCallbackRejectedNoSession(t, s, jar2, callbackURL)
	})

	t.Run("negative: unknown state (never issued by a real BeginSSO) is rejected", func(t *testing.T) {
		// There is no "state cookie" to omit -- state is tracked SERVER-SIDE,
		// not in a browser cookie (confirmed by reading server/http/handlers/
		// sso.go's own error strings: "invalid or expired login state",
		// "login state does not match the callback provider" are core-layer
		// lookup failures, not a missing-cookie check). The closest real
		// analog to "a callback with no state to validate against" is a
		// state value the server never recorded in the first place.
		jar, jerr := cookiejar.New(nil)
		if jerr != nil {
			t.Fatalf("new cookie jar: %v", jerr)
		}
		fabricated := fmt.Sprintf("%s?code=n5-fabricated-code-never-issued&state=n5-fabricated-state-never-issued", redirectURL)
		assertCallbackRejectedNoSession(t, s, jar, fabricated)
	})

	// ── Logout invalidates the session; logging out an already-invalidated
	// session must not 500 (Session I's finding, this journey's to fix if
	// still open). ──────────────────────────────────────────────────────────

	t.Run("logout invalidates session, repeat logout does not 500", func(t *testing.T) {
		// Capture the raw kx_session cookie value BEFORE logging out: the
		// first logout's response clears the cookie (an expired Set-Cookie),
		// which a standard cookiejar correctly drops on the next request --
		// so a naive "call logout twice through the same jar" second call
		// would present NO cookie at all (400 "missing token"), not an
		// ALREADY-INVALIDATED one, silently missing the exact scenario
		// Session I's finding is about. Re-attach the stale value manually
		// for the second call instead, matching a real double-logout-click
		// or race where the client still holds the old value.
		staleSessionValue, staleCSRFValue := sessionAndCSRFCookieValues(t, s, jar1b)

		// Positive control: the SAME session, while still valid, must get
		// something other than 401 on the exact endpoint the post-logout
		// checks below use -- without this, an exact-401 assertion could
		// just as easily mean the test's own auth wiring (cookie name,
		// CSRF header) is broken, not that the session was specifically
		// invalidated by logout.
		if controlStatus := getWithStaleSession(t, s, staleSessionValue, "/api/v1/users"); controlStatus == http.StatusUnauthorized {
			t.Fatal("positive control: the session is already unauthorized BEFORE logout -- the 401 checks below would prove nothing")
		}

		status1 := ssoPost(t, s, jar1b, "/auth/logout", nil)
		if status1 < 200 || status1 >= 300 {
			t.Fatalf("first logout: want 2xx, got %d", status1)
		}
		// Exact 401, not "any 4xx" -- a CSRF mismatch or a malformed-request
		// 400 would also satisfy a loose 4xx check while proving nothing
		// about the specific bug (an already-invalidated session must map to
		// Unauthorized, not merely "not a 500"). internal/core/auth.go's
		// ErrSessionNotFound -> server/http/handlers/auth.go's errors.Is
		// mapping (fixed in #2337) is what this pins.
		status2 := ssoPostWithStaleSession(t, s, staleSessionValue, staleCSRFValue, "/auth/logout")
		if status2 == http.StatusInternalServerError {
			t.Fatalf("second logout (already-invalidated session): got 500 -- Session I's finding is still open")
		}
		if status2 != http.StatusUnauthorized {
			t.Errorf("second logout (already-invalidated session): want exactly %d, got %d", http.StatusUnauthorized, status2)
		}

		// The stale session is genuinely dead, not just rejected by the
		// logout ROUTE specifically -- an authenticated GET with the same
		// stale cookie must also be refused.
		getStatus := getWithStaleSession(t, s, staleSessionValue, "/api/v1/users")
		if getStatus != http.StatusUnauthorized {
			t.Errorf("authenticated GET with the stale (already-invalidated) session: want %d, got %d", http.StatusUnauthorized, getStatus)
		}
	})
}

// ── Keycloak container lifecycle ────────────────────────────────────────────

func startKeycloakContainer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("n5-keycloak-%d", time.Now().UnixNano())
	cmd := exec.Command("docker", "run", "-d", "--rm", "--name", name, //nolint:gosec // #nosec G204 -- n5KeycloakImage is a fixed, pinned-by-digest constant; no external input reaches this
		"-p", "127.0.0.1:0:8080",
		"-e", "KC_BOOTSTRAP_ADMIN_USERNAME="+n5KCAdminUser,
		"-e", "KC_BOOTSTRAP_ADMIN_PASSWORD="+n5KCAdminPass,
		n5KeycloakImage, "start-dev")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker run keycloak: %v\n%s", err, out)
	}
	cleanup = func() {
		_ = exec.Command("docker", "stop", "-t", "5", name).Run() // #nosec G204 -- name is this test's own generated container name
	}

	portOut, err := exec.Command("docker", "port", name, "8080/tcp").CombinedOutput() // #nosec G204 -- name is this test's own generated container name
	if err != nil {
		cleanup()
		t.Fatalf("docker port %s: %v\n%s", name, err, portOut)
	}
	hostPort := parseDockerPortOutput(t, string(portOut))
	addr = "http://" + hostPort

	deadline := time.Now().Add(60 * time.Second) // Keycloak's own startup is slower than Vault's
	healthy := false
	for time.Now().Before(deadline) {
		resp, herr := http.Get(addr + "/realms/master") // #nosec G107 -- fixed localhost test URL, port from docker's own output
		if herr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !healthy {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput() // #nosec G204 -- name is this test's own generated container name
		cleanup()
		t.Fatalf("keycloak dev-mode container never became healthy at %s\nlogs:\n%s", addr, logs)
	}
	return addr, cleanup
}

// ── Keycloak admin API setup ────────────────────────────────────────────────

func keycloakAdminToken(t *testing.T, addr string) string {
	t.Helper()
	form := url.Values{
		"client_id":  {"admin-cli"},
		"username":   {n5KCAdminUser},
		"password":   {n5KCAdminPass},
		"grant_type": {"password"},
	}
	resp, err := http.PostForm(addr+"/realms/master/protocol/openid-connect/token", form) // #nosec G107 -- fixed localhost test URL
	if err != nil {
		t.Fatalf("keycloak admin token: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		raw, _ := readAllBody(resp)
		t.Fatalf("keycloak admin token: HTTP %d: %s", resp.StatusCode, raw)
	}
	var data struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode keycloak admin token response: %v", err)
	}
	return data.AccessToken
}

func kcAdminCall(t *testing.T, method, addr, kcToken, path string, body interface{}) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal keycloak admin request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, addr+path, reader)
	if err != nil {
		t.Fatalf("build keycloak admin request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+kcToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func kcExpect(t *testing.T, method, addr, kcToken, path string, body interface{}, want int) *http.Response {
	t.Helper()
	resp := kcAdminCall(t, method, addr, kcToken, path, body)
	if resp.StatusCode != want {
		raw, _ := readAllBody(resp)
		_ = resp.Body.Close()
		t.Fatalf("%s %s: want HTTP %d, got %d: %s", method, path, want, resp.StatusCode, raw)
	}
	return resp
}

func kcCreateRealm(t *testing.T, addr, kcToken string) {
	t.Helper()
	resp := kcExpect(t, http.MethodPost, addr, kcToken, "/admin/realms", map[string]interface{}{
		"realm": n5Realm, "enabled": true,
	}, http.StatusCreated)
	_ = resp.Body.Close()
}

func kcCreateClient(t *testing.T, addr, kcToken, redirectURL string) (clientUUID string) {
	t.Helper()
	resp := kcExpect(t, http.MethodPost, addr, kcToken, "/admin/realms/"+n5Realm+"/clients", map[string]interface{}{
		"clientId":                  n5ClientID,
		"enabled":                   true,
		"publicClient":              false,
		"secret":                    n5ClientSecret,
		"redirectUris":              []string{redirectURL},
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": true,
		"protocol":                  "openid-connect",
	}, http.StatusCreated)
	_ = resp.Body.Close()

	listResp := kcExpect(t, http.MethodGet, addr, kcToken, "/admin/realms/"+n5Realm+"/clients?clientId="+n5ClientID, nil, http.StatusOK)
	defer listResp.Body.Close() //nolint:errcheck
	var clients []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&clients); err != nil || len(clients) == 0 {
		t.Fatalf("resolve keycloak client uuid: decode error=%v, len=%d", err, len(clients))
	}
	return clients[0].ID
}

// kcAddGroupsMapper adds a "groups" protocol mapper to the client -- Keycloak
// does not include group membership in the ID token by default; Keyorix's
// GroupRoleMap needs a "groups" claim (config.go's GroupsClaim default) to
// reconcile against.
func kcAddGroupsMapper(t *testing.T, addr, kcToken, clientUUID string) {
	t.Helper()
	resp := kcExpect(t, http.MethodPost, addr, kcToken, "/admin/realms/"+n5Realm+"/clients/"+clientUUID+"/protocol-mappers/models",
		map[string]interface{}{
			"name":           "groups",
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-group-membership-mapper",
			"config": map[string]string{
				"full.path":            "false",
				"id.token.claim":       "true",
				"access.token.claim":   "true",
				"userinfo.token.claim": "true",
				"claim.name":           "groups",
			},
		}, http.StatusCreated)
	_ = resp.Body.Close()
}

func kcCreateGroup(t *testing.T, addr, kcToken, name string) (groupID string) {
	t.Helper()
	resp := kcExpect(t, http.MethodPost, addr, kcToken, "/admin/realms/"+n5Realm+"/groups", map[string]string{"name": name}, http.StatusCreated)
	_ = resp.Body.Close()

	listResp := kcExpect(t, http.MethodGet, addr, kcToken, "/admin/realms/"+n5Realm+"/groups?search="+name, nil, http.StatusOK)
	defer listResp.Body.Close() //nolint:errcheck
	var groups []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&groups); err != nil || len(groups) == 0 {
		t.Fatalf("resolve keycloak group id %q: decode error=%v, len=%d", name, err, len(groups))
	}
	return groups[0].ID
}

// kcCreateUser creates a user with firstName/lastName and an explicitly
// empty requiredActions list -- without both, Keycloak 26's default
// VERIFY_PROFILE required action interrupts the login flow with a profile
// form this journey does not drive (confirmed live: omitting either field
// redirects the code flow to a login-actions/required-action page instead
// of completing with a code).
func kcCreateUser(t *testing.T, addr, kcToken, username, password string, groupIDs ...string) (userID string) {
	t.Helper()
	resp := kcExpect(t, http.MethodPost, addr, kcToken, "/admin/realms/"+n5Realm+"/users", map[string]interface{}{
		"username":        username,
		"email":           username + "@example.invalid",
		"emailVerified":   true,
		"enabled":         true,
		"firstName":       "N5",
		"lastName":        username,
		"requiredActions": []string{},
		"credentials": []map[string]interface{}{
			{"type": "password", "value": password, "temporary": false},
		},
	}, http.StatusCreated)
	_ = resp.Body.Close()

	listResp := kcExpect(t, http.MethodGet, addr, kcToken, "/admin/realms/"+n5Realm+"/users?username="+username, nil, http.StatusOK)
	defer listResp.Body.Close() //nolint:errcheck
	var users []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&users); err != nil || len(users) == 0 {
		t.Fatalf("resolve keycloak user id %q: decode error=%v, len=%d", username, err, len(users))
	}
	userID = users[0].ID

	for _, groupID := range groupIDs {
		joinResp := kcExpect(t, http.MethodPut, addr, kcToken, "/admin/realms/"+n5Realm+"/users/"+userID+"/groups/"+groupID, nil, http.StatusNoContent)
		_ = joinResp.Body.Close()
	}
	return userID
}

func kcRemoveUserFromGroup(t *testing.T, addr, kcToken, userID, groupID string) {
	t.Helper()
	resp := kcExpect(t, http.MethodDelete, addr, kcToken, "/admin/realms/"+n5Realm+"/users/"+userID+"/groups/"+groupID, nil, http.StatusNoContent)
	_ = resp.Body.Close()
}

func readAllBody(resp *http.Response) (string, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	return buf.String(), err
}

// redactCodeRe matches an OIDC authorization code query parameter --
// short-lived (single-use, expires quickly) but still a credential, and
// this journey's own dev-mode Keycloak fixture is not a reason to print one
// into test/CI output regardless.
var redactCodeRe = regexp.MustCompile(`code=[^&]+`)

// oneRemovalRe matches exactly "-1" in a "+N/-M" sync description, not
// "-10" or "-12".
var oneRemovalRe = regexp.MustCompile(`(^|[^0-9])-1([^0-9]|$)`)

// redactCode replaces a URL's code= query parameter value with a fixed
// placeholder -- used wherever a callback/authorization URL is printed in a
// failure message.
func redactCode(u string) string {
	return redactCodeRe.ReplaceAllString(u, "code=[REDACTED]")
}

// tamperQueryParam returns rawURL with key's query value replaced by value.
func tamperQueryParam(t *testing.T, rawURL, key, value string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL to tamper: %v", err)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// assertCallbackRejectedNoSession GETs callbackURL (a tampered, replayed, or
// fabricated code/state pair) through a fresh client sharing jar, and
// asserts: a 302 (CompleteSSO's redirectFragment always 302s, success or
// error -- never a raw error page), the fragment carries an "error" key
// (not a success), and -- the actual point of this check -- NO kx_session
// cookie was set in jar as a result.
func assertCallbackRejectedNoSession(t *testing.T, s *harness.Server, jar *cookiejar.Jar, callbackURL string) {
	t.Helper()
	client := ssoClient(jar)
	resp, err := client.Get(callbackURL) // #nosec G107 -- callbackURL is derived from this journey's own real/fabricated fixed test values
	if err != nil {
		t.Fatalf("GET tampered/replayed/fabricated callback: %s", redactCode(err.Error()))
	}
	location := resp.Header.Get("Location")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want a 302 redirect (redirectFragment always 302s, success or error), got %d", resp.StatusCode)
	}
	if !strings.Contains(location, "error=") {
		t.Fatalf("expected the redirect fragment to carry an error, got: %q", redactCode(location))
	}
	base, berr := url.Parse(s.BaseURL)
	if berr != nil {
		t.Fatalf("parse base URL: %v", berr)
	}
	for _, c := range jar.Cookies(base) {
		if c.Name == "kx_session" && c.Value != "" {
			t.Fatal("a kx_session cookie was set despite a rejected callback")
		}
	}
}

// ── Keyorix boot with SSO configured ────────────────────────────────────────

// startServerWithSSO is harness.StartServer's own sequence (admin init ->
// encryption init -> migrate -> rewrite port -> boot+bootstrap), with one
// extra step: appending an `sso:` block to the generated config before
// boot. Not a harness.go change (SSO config injection is N5-only, unlike
// storage backend selection which both this session's own N1-N4 and
// Session I's smoke suite need) -- reimplemented locally using harness's
// already-exported primitives instead.
func startServerWithSSO(t *testing.T, binary, port, issuer, redirectURL string) *harness.Server {
	t.Helper()
	dir := t.TempDir()
	env := append(harness.BaseServerEnv(dir),
		"KEYORIX_MASTER_PASSWORD=e2e-smoke-master-password-sso")
	configPath := "./keyorix.yaml"

	run := func(args ...string) {
		t.Helper()
		out, err := harness.RunAdminCmd(binary, dir, env, args...)
		if err != nil {
			t.Fatalf("keyorix-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "--config", configPath)

	ssoBlock := fmt.Sprintf(`
sso:
  enabled: true
  providers:
    - name: %s
      type: oidc
      issuer: %s
      client_id: %s
      client_secret: %s
      redirect_url: %s
      scopes: [openid, profile, email]
      auto_provision: true
      default_role: system_viewer
      group_sync: true
      groups_claim: groups
      group_role_map:
        %s: %s
        %s: %s
`, n5ProviderName, issuer, n5ClientID, n5ClientSecret, redirectURL,
		n5GroupAuditors, n5RoleForGroupA, n5GroupEditors, n5RoleForGroupB)

	cfgFile := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfgFile) // #nosec G304 -- cfgFile is this test's own t.TempDir()-derived path
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if err := os.WriteFile(cfgFile, append(raw, []byte(ssoBlock)...), 0o600); err != nil {
		t.Fatalf("append sso: block to config: %v", err)
	}

	run("encryption", "init", "--config", configPath)
	run("migrate", "--config", configPath)
	harness.RewritePort(t, dir, port)

	const bootstrapToken = "e2e-smoke-bootstrap-token-sso-0123456789"
	s := harness.BootAndBootstrap(t, binary, dir, env, configPath, port, bootstrapToken,
		"smoketestadmin", "smoketestadmin@example.invalid", harness.BootstrapAdminPassword)
	s.Backend = harness.DBBackend{Name: "sqlite-sso"}
	return s
}

// ── Driving the OIDC code flow with a plain HTTP client (no browser) ───────

var kcLoginFormActionRe = regexp.MustCompile(`action="([^"]*)"`)

// ssoClient returns a plain http.Client using jar with redirects disabled
// (so each hop's Location can be inspected/rewritten) -- shared by
// obtainSSOCallbackURL/completeSSOLogin and the negative-case tests below.
func ssoClient(jar *cookiejar.Jar) *http.Client {
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// obtainSSOCallbackURL drives Keyorix's BeginSSO -> Keycloak's login form ->
// Keycloak's redirect-with-code, and returns the REAL, valid (code, state)
// callback URL Keycloak produced -- WITHOUT calling Keyorix's own callback.
// completeSSOLogin (below) is this plus that final call; the negative-case
// tests need to tamper with or replay a genuine pair rather than a
// fabricated one, so they call this directly instead.
func obtainSSOCallbackURL(t *testing.T, s *harness.Server, jar *cookiejar.Jar, kcAddr, username, password string) string {
	t.Helper()
	client := ssoClient(jar)

	beginResp, err := client.Get(s.BaseURL + "/auth/sso/" + n5ProviderName + "/login") // #nosec G107 -- fixed test harness URL
	if err != nil {
		t.Fatalf("GET /auth/sso/%s/login: %v", n5ProviderName, err)
	}
	kcAuthURL := beginResp.Header.Get("Location")
	_ = beginResp.Body.Close()
	if kcAuthURL == "" {
		t.Fatalf("BeginSSO: expected a redirect Location, got status %d", beginResp.StatusCode)
	}

	loginPageResp, err := client.Get(kcAuthURL) // #nosec G107 -- URL from Keyorix's own BeginSSO redirect, a fixed test-container address
	if err != nil {
		t.Fatalf("GET keycloak auth endpoint: %v", err)
	}
	pageBytes, _ := readAllBody(loginPageResp)
	_ = loginPageResp.Body.Close()
	if loginPageResp.StatusCode != http.StatusOK {
		t.Fatalf("GET keycloak auth endpoint: want 200, got %d:\n%s", loginPageResp.StatusCode, pageBytes)
	}

	m := kcLoginFormActionRe.FindStringSubmatch(pageBytes)
	if m == nil {
		t.Fatalf("could not find login form action in keycloak's login page:\n%s", pageBytes)
	}
	actionURL := strings.ReplaceAll(m[1], "&amp;", "&")

	form := url.Values{"username": {username}, "password": {password}}
	loginResp, err := client.PostForm(actionURL, form) // #nosec G107 -- actionURL parsed from Keycloak's own login page, a fixed test-container address
	if err != nil {
		t.Fatalf("POST keycloak login form: %v", err)
	}
	callbackURL := loginResp.Header.Get("Location")
	loginBody, _ := readAllBody(loginResp)
	_ = loginResp.Body.Close()
	if callbackURL == "" || !strings.Contains(callbackURL, "code=") {
		t.Fatalf("keycloak login: expected a redirect to Keyorix's callback with a code, got status %d location=%q\n%s",
			loginResp.StatusCode, redactCode(callbackURL), loginBody)
	}
	return callbackURL
}

// completeSSOLogin drives Keyorix's BeginSSO -> Keycloak's login form ->
// Keycloak's redirect-with-code -> Keyorix's CompleteSSO, storing the
// resulting session cookie in jar. A plain http.Client with a cookie jar
// and redirects disabled (so each hop's Location can be inspected/rewritten)
// suffices -- Keycloak's browser-based login form posts back to a plain HTML
// form action, no JS required, confirmed live.
func completeSSOLogin(t *testing.T, s *harness.Server, jar *cookiejar.Jar, kcAddr, username, password string) {
	t.Helper()
	callbackURL := obtainSSOCallbackURL(t, s, jar, kcAddr, username, password)
	client := ssoClient(jar)

	callbackResp, err := client.Get(callbackURL) // #nosec G107 -- callbackURL is Keyorix's own registered redirect_url plus Keycloak's code, both fixed test values
	if err != nil {
		t.Fatalf("GET keyorix callback: %s", redactCode(err.Error()))
	}
	successLocation := callbackResp.Header.Get("Location")
	_ = callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusFound {
		t.Fatalf("keyorix CompleteSSO: want a 302 redirect, got %d", callbackResp.StatusCode)
	}
	// A 302 alone doesn't prove SUCCESS -- server/http/handlers/sso.go's
	// CompleteSSO redirects to the SAME completeURL base on both success and
	// failure (redirectFragment), differing only in the URL FRAGMENT
	// (`#error=...` on failure; expires_at/absolute_expires_at/return_to are
	// each individually conditional on success, so "no error key" plus the
	// session-cookie check below -- not any specific success-only fragment
	// key -- is what actually distinguishes success here) -- confirmed by
	// reading the handler directly, not guessed.
	if strings.Contains(successLocation, "error=") {
		t.Fatalf("keyorix CompleteSSO: redirect Location's fragment carries an error, not success: %q", successLocation)
	}
	// The session cookie must actually be set -- a redirect alone doesn't
	// prove a session was created; a caller with a bug that redirects
	// success-shaped but forgets to set the cookie would still pass a
	// Location-only check.
	base, berr := url.Parse(s.BaseURL)
	if berr != nil {
		t.Fatalf("parse base URL: %v", berr)
	}
	found := false
	for _, c := range jar.Cookies(base) {
		if c.Name == "kx_session" && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("keyorix CompleteSSO: 302 redirect but no kx_session cookie was set in the jar")
	}
}

// sessionAndCSRFCookieValues returns the raw kx_session/csrf_token cookie
// values jar currently holds for s -- see the "logout invalidates session"
// test's own comment for why both must be captured before the first logout
// clears them.
func sessionAndCSRFCookieValues(t *testing.T, s *harness.Server, jar *cookiejar.Jar) (session, csrf string) {
	t.Helper()
	base, err := url.Parse(s.BaseURL)
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	for _, c := range jar.Cookies(base) {
		switch c.Name {
		case "kx_session":
			session = c.Value
		case "csrf_token":
			csrf = c.Value
		}
	}
	if session == "" || csrf == "" {
		t.Fatalf("missing kx_session/csrf_token cookie(s) in jar for %s (session=%q csrf=%q)", s.BaseURL, session, csrf)
	}
	return session, csrf
}

// ssoPostWithStaleSession POSTs with explicit, manually-attached
// kx_session/X-CSRF-Token values -- bypassing the cookiejar's own (correct)
// clear-on-expiry behavior, so a caller can present values the server has
// already invalidated, as a real client racing/double-clicking logout
// would.
func ssoPostWithStaleSession(t *testing.T, s *harness.Server, sessionValue, csrfValue, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.BaseURL+path, bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("build request %s: %v", path, err)
	}
	req.AddCookie(&http.Cookie{Name: "kx_session", Value: sessionValue})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfValue})
	req.Header.Set("X-CSRF-Token", csrfValue)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	return resp.StatusCode
}

// getWithStaleSession issues a GET carrying only the (possibly already-
// invalidated) kx_session cookie -- no CSRF header needed, GET is not
// state-changing -- to prove a stale session is refused generally, not
// just by the logout route specifically.
func getWithStaleSession(t *testing.T, s *harness.Server, sessionValue, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, s.BaseURL+path, nil)
	if err != nil {
		t.Fatalf("build request %s: %v", path, err)
	}
	req.AddCookie(&http.Cookie{Name: "kx_session", Value: sessionValue})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	return resp.StatusCode
}

// ssoPost issues an authenticated (cookie-based) POST against s and returns
// the status code -- for the logout assertions, which need the real session
// cookie completeSSOLogin's flow produced, not a bearer token.
func ssoPost(t *testing.T, s *harness.Server, jar *cookiejar.Jar, path string, body interface{}) int {
	t.Helper()
	client := &http.Client{Jar: jar}
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body for %s: %v", path, err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(http.MethodPost, s.BaseURL+path, reader)
	if err != nil {
		t.Fatalf("build request %s: %v", path, err)
	}
	// A cookie-authenticated (session, not bearer) state-changing request
	// needs the double-submit CSRF header: server/middleware/csrf.go requires
	// X-CSRF-Token to echo the csrf_token cookie's value whenever a session
	// cookie is present -- confirmed live (a 403 without it).
	base, perr := url.Parse(s.BaseURL)
	if perr != nil {
		t.Fatalf("parse base URL: %v", perr)
	}
	for _, c := range jar.Cookies(base) {
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
			break
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	return resp.StatusCode
}

// ── JIT-provisioned user role assertions (admin inspection) ────────────────

// assertRoleRemovalWasSynced asserts a real audit trail signal exists for
// the role removal this journey's own group-removal step should have
// triggered -- at least one auth.sso_roles_synced event whose description
// reports a removal ("-1", matching reconcileSSORoles's own "+N/-M mapped
// role grants" description shape), not just "some sync event exists"
// (which the previous, log-only version of this check would have passed
// even on a sync that changed nothing). Checks ANY event, not assuming a
// particular array order from the search API.
func assertRoleRemovalWasSynced(t *testing.T, s *harness.Server, adminToken string) {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/audit/search?action=auth.sso_roles_synced", nil, http.StatusOK)
	var data struct {
		Events []struct {
			Description string `json:"description"`
			Timestamp   string `json:"timestamp"`
		} `json:"events"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode sso sync events: %v\nraw: %s", err, env.Data)
	}
	if len(data.Events) == 0 {
		t.Fatal("expected at least one auth.sso_roles_synced event after the group-removal re-login, found none")
	}
	for _, e := range data.Events {
		if oneRemovalRe.MatchString(e.Description) {
			return
		}
	}
	descriptions := make([]string, len(data.Events))
	for i, e := range data.Events {
		descriptions[i] = e.Description
	}
	t.Errorf("no sso_roles_synced event reports a removal (\"-1\"): %v", descriptions)
}

func findJITUserID(t *testing.T, s *harness.Server, adminToken, username string) int {
	t.Helper()
	// ?username= (exact match), not ?search= (fuzzy): the latter hits the
	// pre-existing #2265 SQLite ILIKE bug (500 on SQLite, already filed --
	// see N1's report entry, confirmed independently live here too) that has
	// nothing to do with this journey.
	env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/users?username="+username, nil, http.StatusOK)
	var data struct {
		Users []struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		} `json:"users"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/users?username=%s: %v\nraw: %s", username, err, env.Data)
	}
	for _, u := range data.Users {
		if u.Username == username {
			return u.ID
		}
	}
	t.Fatalf("JIT-provisioned user %q not found via GET /api/v1/users?username=%s: %s", username, username, env.Data)
	return 0
}

func userRoleNames(t *testing.T, s *harness.Server, adminToken string, userID int) []string {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/users/%d/roles", userID), nil, http.StatusOK)
	var data struct {
		Roles []struct {
			Name string `json:"name"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/users/%d/roles: %v\nraw: %s", userID, err, env.Data)
	}
	names := make([]string, 0, len(data.Roles))
	for _, r := range data.Roles {
		names = append(names, r.Name)
	}
	return names
}

func assertUserHasRole(t *testing.T, s *harness.Server, adminToken, username, role string) {
	t.Helper()
	userID := findJITUserID(t, s, adminToken, username)
	for _, r := range userRoleNames(t, s, adminToken, userID) {
		if r == role {
			return
		}
	}
	t.Fatalf("user %q: expected role %q, roles are %v", username, role, userRoleNames(t, s, adminToken, userID))
}

func assertUserLacksRole(t *testing.T, s *harness.Server, adminToken, username, role string) {
	t.Helper()
	userID := findJITUserID(t, s, adminToken, username)
	names := userRoleNames(t, s, adminToken, userID)
	hasBaseline := false
	for _, r := range names {
		if r == role {
			t.Fatalf("user %q: expected role %q to be absent, roles are %v", username, role, names)
		}
		if r == "system_viewer" {
			hasBaseline = true
		}
	}
	// An EMPTY roles list would also satisfy "role is absent" -- but that
	// would mean the user lost EVERYTHING, not specifically the role this
	// call is checking for, which is a much bigger (and different) problem
	// this check would otherwise silently pass. Assert the universal
	// auto-granted baseline (internal/core/auth_bootstrap.go's
	// defaultRoles) is still present, so a vacuously-empty list can't pass.
	if !hasBaseline {
		t.Fatalf("user %q: expected role %q absent AND system_viewer (the baseline) present, but roles are %v (baseline missing -- an empty/near-empty roles list is a different bug than this check is for)", username, role, names)
	}
}
