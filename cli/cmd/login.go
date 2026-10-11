package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
	"github.com/keyorixhq/keyorix/cli/internal/credstore"
	"github.com/keyorixhq/keyorix/cli/internal/migrate"
)

var (
	loginServerURL string
	loginUsername  string
	loginPassword  string
	loginMFACode   string
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate to a Keyorix server and store the resulting token",
	Long: `login exchanges a username and password for a session token via POST /auth/login,
verifies it against GET /api/v1/auth/profile, and stores it (with the server URL) at the
one credential-file location this CLI uses (see "keyorix status --help").

When the account has TOTP multi-factor authentication enabled, /auth/login answers with a
second-factor challenge instead of a token; login then asks for an authenticator code (or
an unused recovery code) and completes the challenge via POST /auth/mfa/verify. Pass
--mfa-code to supply it non-interactively. The code is used for that one request only: it
is never echoed, never logged, and never written to the credential file.`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginServerURL, "server", "", "Server base URL (or set KEYORIX_SERVER)")
	loginCmd.Flags().StringVar(&loginUsername, "username", "", "Username")
	loginCmd.Flags().StringVar(&loginPassword, "password", "", "Password (omit to be prompted)")
	loginCmd.Flags().StringVar(&loginMFACode, "mfa-code", "", "Authenticator (TOTP) code or an unused recovery code, for an MFA-enabled account (omit to be prompted)")
}

func runLogin(cmd *cobra.Command, args []string) error {
	serverURL, err := resolveLoginServerURL()
	if err != nil {
		return err
	}

	username := loginUsername
	if username == "" {
		u, err := promptLine("Username: ")
		if err != nil {
			return fmt.Errorf("read username: %w", err)
		}
		username = u
	}

	password, err := resolveLoginPassword(cmd)
	if err != nil {
		return err
	}

	ctx := context.Background()
	client, err := newAPIClient(serverURL, "")
	if err != nil {
		return fmt.Errorf("build client for %s: %w", serverURL, err)
	}

	loginResp, err := client.AuthLoginWithResponse(ctx, apiclient.AuthLoginJSONRequestBody{
		Username: username,
		Password: password,
	})
	if err != nil {
		return fmt.Errorf("contact %s: %w", serverURL, err)
	}
	token, err := resolveSessionToken(ctx, cmd, client, loginResp.StatusCode(), loginResp.Body)
	if err != nil {
		return err
	}

	// Verify the token before persisting anything -- a bad/mistyped server URL that
	// happens to accept the login POST but isn't really Keyorix should be caught here,
	// not discovered on the next command.
	verifyClient, err := newAPIClient(serverURL, token)
	if err != nil {
		return fmt.Errorf("build verification client: %w", err)
	}
	profileResp, err := verifyClient.GetAuthProfileWithResponse(ctx)
	if err != nil {
		return fmt.Errorf("verify token against %s: %w", serverURL, err)
	}
	if profileResp.StatusCode() != http.StatusOK {
		return httpStatusError("login succeeded but token verification failed", profileResp.StatusCode(), profileResp.Body)
	}

	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	if err := store.Save(credstore.Credentials{ServerURL: serverURL, Token: token}); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	if skewResult, err := checkVersionSkew(ctx, verifyClient); err == nil && skewResult.Warning != "" {
		fmt.Fprintln(os.Stderr, "Warning:", skewResult.Warning)
	}

	fmt.Printf("Logged in to %s as %s.\n", serverURL, username)
	return nil
}

// ── /auth/login's two 200 response shapes (#2737) ─────────────────────────────

// loginShape names one of the shapes openapi.yaml documents under authLogin's 200
// `data` oneOf. Both are HTTP 200 and they are disambiguated by `mfa_required`, never
// by status code (see the schema comment above LoginSuccessData in
// server/http/handlers/openapi.yaml).
type loginShape int

const (
	// loginShapeUnrecognized is a 200 `data` that matches neither documented shape —
	// a server newer than this CLI, or a URL that is not really Keyorix.
	loginShapeUnrecognized loginShape = iota
	// loginShapeSession is LoginSuccessData: the session token is in hand.
	loginShapeSession
	// loginShapeMFAChallenge is MFAChallengeData: the password was accepted but a
	// second factor is required before any session exists.
	loginShapeMFAChallenge
)

// loginShapeForSchema maps each component schema named in authLogin's 200 `data`
// oneOf to the shape resolveSessionToken handles it as.
//
// TestLoginHandlesEveryDocumentedLoginResponseShape derives the oneOf branch list from
// server/http/handlers/openapi.yaml itself and fails when this map's key set and the
// spec's branch set diverge — so a THIRD shape added to the contract cannot land with
// this command silently dead-ending on it, which is exactly how #2737 happened (the
// MFAChallengeData branch was added to the spec; `login` only ever looked for a token
// and reported the success status code back as a failure).
//
// What that guard does NOT check: that each shape is handled *correctly*. The
// behavioural tests in login_test.go do that, one per branch.
var loginShapeForSchema = map[string]loginShape{
	"LoginSuccessData": loginShapeSession,
	"MFAChallengeData": loginShapeMFAChallenge,
}

// loginEnvelope decodes the sendSuccess envelope /auth/login and /auth/mfa/verify both
// return, flattened across both documented `data` shapes.
//
// Decoded from the raw response body rather than the generated client's JSON200 field
// on purpose: oapi-codegen v2.4.1 renders this inline `oneOf` as an opaque
// `AuthLogin_200_Data struct{ union json.RawMessage }` with no exported field and no
// accessor methods, so the generated type cannot yield either branch's contents.
// TestGeneratedAuthLoginDataIsAnOpaqueUnion pins that premise — when a generator
// upgrade starts emitting real As<Branch>() accessors, it fails and this decoder
// should be replaced by them.
type loginEnvelope struct {
	Message string `json:"message"`
	Data    struct {
		Token             *string `json:"token"`
		MFARequired       bool    `json:"mfa_required"`
		MFAChallenge      string  `json:"mfa_challenge"`
		TOTPAvailable     bool    `json:"totp_available"`
		WebAuthnAvailable bool    `json:"webauthn_available"`
	} `json:"data"`
}

// classify reports which documented shape this decoded 200 body is. A token wins over
// mfa_required: a body carrying a usable session token is a completed login regardless
// of what else it says, and treating it otherwise would re-prompt for a factor the
// server has already accepted.
func (e loginEnvelope) classify() loginShape {
	if e.Data.Token != nil && *e.Data.Token != "" {
		return loginShapeSession
	}
	if e.Data.MFARequired && e.Data.MFAChallenge != "" {
		return loginShapeMFAChallenge
	}
	return loginShapeUnrecognized
}

// resolveSessionToken turns a /auth/login response into a session token, completing the
// second-factor step when the server asked for one.
//
// Before #2737 this was a single condition that required `data.token` to be present and
// reported "login failed: HTTP %d" otherwise — which, on the MFA branch, printed the
// SUCCESS status code back as an error ("login failed: HTTP 200") and left no indication
// that a second factor was wanted.
func resolveSessionToken(ctx context.Context, cmd *cobra.Command, client *apiclient.ClientWithResponses, status int, body []byte) (string, error) {
	if status != http.StatusOK {
		return "", apiError("login", status, body)
	}
	var env loginEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("login failed: the server answered HTTP 200 with a body this CLI could not parse as a login response: %w", err)
	}
	switch env.classify() {
	case loginShapeSession:
		return *env.Data.Token, nil
	case loginShapeMFAChallenge:
		return completeMFAChallenge(ctx, cmd, client, env)
	default:
		return "", unrecognizedLoginResponseError(env, body)
	}
}

// completeMFAChallenge finishes a two-step login: it obtains an authenticator or recovery
// code (--mfa-code, else an interactive no-echo prompt) and exchanges it, together with
// the challenge the server just issued, for a session via POST /auth/mfa/verify.
//
// The code is passed straight to that one request. It is never echoed back, never printed
// in an error, and never reaches the credential file — only the session token the server
// returns is persisted (by the caller). No new server endpoint is involved and nothing
// about lockout counting changes: a rejected code is the same failed /auth/mfa/verify a
// browser produces, counted by the same per-account and per-IP throttles.
func completeMFAChallenge(ctx context.Context, cmd *cobra.Command, client *apiclient.ClientWithResponses, env loginEnvelope) (string, error) {
	if !env.Data.TOTPAvailable {
		if env.Data.WebAuthnAvailable {
			return "", fmt.Errorf("this account's only second factor is a WebAuthn passkey, which this CLI cannot complete: " +
				"sign in with the web UI instead, or create a personal access token there (\"keyorix pat list\" shows them) " +
				"and set KEYORIX_TOKEN for CLI use")
		}
		return "", fmt.Errorf("the server requires a second factor for this account but reports no factor this CLI can complete " +
			"(neither an authenticator code nor a passkey): sign in with the web UI to check the account's security settings")
	}

	code, err := resolveMFACode(cmd)
	if err != nil {
		return "", err
	}

	verifyResp, err := client.VerifyMFALoginWithResponse(ctx, apiclient.VerifyMFALoginJSONRequestBody{
		MfaChallenge: env.Data.MFAChallenge,
		Code:         code,
	})
	if err != nil {
		return "", fmt.Errorf("complete second factor: %w", err)
	}
	if verifyResp.StatusCode() != http.StatusOK {
		// The server deliberately answers a wrong code and a dead challenge
		// identically ("Invalid or expired code") — pass its message through rather
		// than guessing which it was, and add the one piece of context it cannot
		// know: a challenge is short-lived, so a slow prompt is a real cause.
		return "", fmt.Errorf("%w (an authenticator code is valid for about a minute, and the login challenge expires too — re-run \"keyorix login\" to get a fresh one)",
			apiError("second-factor verification", verifyResp.StatusCode(), verifyResp.Body))
	}
	var verified loginEnvelope
	if err := json.Unmarshal(verifyResp.Body, &verified); err != nil {
		return "", fmt.Errorf("second-factor verification: the server answered HTTP 200 with a body this CLI could not parse: %w", err)
	}
	if verified.classify() != loginShapeSession {
		return "", fmt.Errorf("second-factor verification: %w", unrecognizedLoginResponseError(verified, verifyResp.Body))
	}
	return *verified.Data.Token, nil
}

// resolveMFACode resolves the second-factor code: the (insecure, warned) --mfa-code flag,
// or else an interactive no-echo prompt. With neither — no flag and no terminal to prompt
// on — it names the flag instead of blocking on a pipe that will never carry one.
func resolveMFACode(cmd *cobra.Command) (string, error) {
	if loginMFACode != "" {
		warnInsecureFlag(cmd, "mfa-code", "omit it to be prompted instead.")
		return loginMFACode, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("this account requires a second factor and there is no terminal to prompt on: pass --mfa-code <authenticator or recovery code>") // docs-secrets:allow -- single-use code; the only non-interactive path when there is no TTY
	}
	code, err := promptPassword("Authenticator code (or an unused recovery code): ")
	if err != nil {
		return "", fmt.Errorf("read second-factor code: %w", err)
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "", fmt.Errorf("no second-factor code given")
	}
	return code, nil
}

// unrecognizedLoginResponseError describes a 200 that is neither documented shape, naming
// the server's own message and the field NAMES present under `data` — never their values,
// which on this route are credential material. "login failed: HTTP 200" (what #2737
// reported) is exactly what this replaces.
func unrecognizedLoginResponseError(env loginEnvelope, body []byte) error {
	detail := fmt.Sprintf("fields in `data`: %s", strings.Join(loginDataFieldNames(body), ", "))
	if env.Message != "" {
		detail = fmt.Sprintf("the server said %q; %s", cliout.SanitizeForTerminal(env.Message), detail)
	}
	return fmt.Errorf("login failed: the server answered HTTP 200 with neither a session token nor a second-factor challenge (%s)", detail)
}

// loginDataFieldNames lists the keys present under the response envelope's `data`
// object, sorted, for the diagnostic above. Returns a placeholder rather than an error
// for any body shape that has no `data` object at all.
func loginDataFieldNames(body []byte) []string {
	var raw struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || raw.Data == nil {
		return []string{"(none — the response had no `data` object)"}
	}
	if len(raw.Data) == 0 {
		return []string{"(none — `data` was empty)"}
	}
	names := make([]string, 0, len(raw.Data))
	for k := range raw.Data {
		names = append(names, cliout.SanitizeForTerminal(k))
	}
	sort.Strings(names)
	return names
}

// resolveLoginServerURL resolves the target server URL (flag > KEYORIX_SERVER > old-CLI
// migration prompt) and warns to stderr if it is not HTTPS/loopback before this command's
// username and password are sent to it. CLI-LOGIN-001: prior to this fix, login was the
// one credential-transmitting command in this module that never called
// warnIfInsecureEndpoint -- systeminit.go's `system init --server` does (see its own
// warnIfInsecureEndpoint doc comment), and the old CLI called the equivalent
// common.WarnIfInsecureEndpoint from every credential-persisting/transmitting call site,
// explicitly including "auth login" (#G74) -- this closes the gap this rewrite silently
// reopened for the single most commonly used auth command.
func resolveLoginServerURL() (string, error) {
	serverURL := loginServerURL
	if serverURL == "" {
		serverURL = os.Getenv("KEYORIX_SERVER")
	}
	if serverURL == "" {
		serverURL = offerOldServerURLMigration()
	}
	if serverURL == "" {
		return "", fmt.Errorf("no server given: pass --server or set KEYORIX_SERVER")
	}
	warnIfInsecureEndpoint(serverURL)
	return serverURL, nil
}

// resolveLoginPassword resolves the password: the (insecure, warned) --password flag, or
// else an interactive no-echo prompt. CLI-LOGIN-001: --password previously carried no
// warnInsecureFlag call, unlike every sibling command with a password-bearing flag
// (systeminit.go's --admin-password, user.go's --password).
func resolveLoginPassword(cmd *cobra.Command) (string, error) {
	if loginPassword != "" {
		warnInsecureFlag(cmd, "password", "omit it to be prompted instead.")
		return loginPassword, nil
	}
	p, err := promptPassword("Password: ")
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return p, nil
}

// offerOldServerURLMigration looks for a server URL left behind by the old,
// pre-ADR-108 CLI and, if one is found, asks the operator whether to reuse it --
// it never imports a credential, only a URL (see internal/migrate's doc comment).
// Returns "" if none is found or the operator declines, in which case runLogin
// falls through to its existing "no server given" error exactly as before.
func offerOldServerURLMigration() string {
	c, ok := migrate.DetectOldServerURL()
	if !ok {
		return ""
	}
	answer, err := promptLine(fmt.Sprintf("Found a server URL from an older keyorix CLI config (%s): %s\nUse it? [Y/n]: ", c.Source, c.ServerURL))
	if err != nil {
		return ""
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer == "" || answer == "y" || answer == "yes" {
		return c.ServerURL
	}
	return ""
}

func promptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return promptLine("")
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
