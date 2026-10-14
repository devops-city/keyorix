package cmd

// #2737: the MFA branch of /auth/login.
//
// Before the fix, runLogin required `data.token` and reported "login failed: HTTP %d"
// for anything else -- so an MFA-enabled account got "login failed: HTTP 200", the
// SUCCESS status code printed back as a failure, with no hint that a second factor was
// wanted. Every test here fails on main: resolveSessionToken, completeMFAChallenge,
// resolveMFACode and loginShapeForSchema do not exist there.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// loginBody renders the sendSuccess envelope the server writes, with data as given.
func loginBody(t *testing.T, message string, data map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"success": true, "message": message, "data": data})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	return raw
}

// verifyServer stands in for POST /auth/mfa/verify, recording what the CLI sent and
// answering with status/respBody. Nothing else is routed: a test whose CLI path should
// never reach the verify endpoint asserts calls == 0, and any other request fails the
// test outright (the fix must complete the challenge through the server's EXISTING
// endpoint, not a new one).
type verifyServer struct {
	srv      *httptest.Server
	calls    int
	gotBody  map[string]string
	status   int
	respBody []byte
}

func newVerifyServer(t *testing.T, status int, respBody []byte) *verifyServer {
	t.Helper()
	vs := &verifyServer{status: status, respBody: respBody, gotBody: map[string]string{}}
	vs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/mfa/verify" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s -- login must complete the challenge via the existing POST /auth/mfa/verify and nothing else", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		vs.calls++
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode verify request body: %v", err)
		}
		vs.gotBody = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(vs.status)
		_, _ = w.Write(vs.respBody)
	}))
	t.Cleanup(vs.srv.Close)
	return vs
}

func (vs *verifyServer) client(t *testing.T) *apiclient.ClientWithResponses {
	t.Helper()
	c, err := newAPIClient(vs.srv.URL, "")
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	return c
}

// withMFACodeFlag sets --mfa-code the way cobra would (Set, so Changed is true, which is
// what warnInsecureFlag keys off) and restores it afterwards.
func withMFACodeFlag(t *testing.T, code string) {
	t.Helper()
	if err := loginCmd.Flags().Set("mfa-code", code); err != nil {
		t.Fatalf("set --mfa-code: %v", err)
	}
	t.Cleanup(func() {
		loginMFACode = ""
		loginCmd.Flags().Lookup("mfa-code").Changed = false
	})
}

// mfaChallengeResponse is the exact /auth/login 200 body an MFA-enrolled account gets
// (server/http/handlers/auth.go's ErrMFARequired branch).
func mfaChallengeResponse(t *testing.T, challenge string, totp, webauthn bool) []byte {
	t.Helper()
	return loginBody(t, "MFA required", map[string]any{
		"mfa_required":       true,
		"mfa_challenge":      challenge,
		"totp_available":     totp,
		"webauthn_available": webauthn,
	})
}

func TestResolveSessionToken_SessionShapeReturnsTheToken(t *testing.T) {
	body := loginBody(t, "Login successful", map[string]any{"token": "sess-abc", "username": "admin"})
	got, err := resolveSessionToken(t.Context(), loginCmd, nil, http.StatusOK, body)
	if err != nil {
		t.Fatalf("resolveSessionToken: %v", err)
	}
	if got != "sess-abc" {
		t.Fatalf("token: got %q, want %q", got, "sess-abc")
	}
}

// TestResolveSessionToken_MFAChallengeCompletesViaVerifyEndpoint is the unit-level red
// test for #2737: this is the exact response an MFA-enabled account gets from
// /auth/login.
func TestResolveSessionToken_MFAChallengeCompletesViaVerifyEndpoint(t *testing.T) {
	const (
		challenge = "challenge-token-xyz"
		code      = "123456"
	)
	vs := newVerifyServer(t, http.StatusOK, loginBody(t, "Login successful", map[string]any{"token": "sess-after-mfa"}))
	withMFACodeFlag(t, code)

	var token string
	stderr := captureStderr(t, func() {
		var err error
		token, err = resolveSessionToken(t.Context(), loginCmd, vs.client(t), http.StatusOK, mfaChallengeResponse(t, challenge, true, false))
		if err != nil {
			t.Errorf("resolveSessionToken on the MFA branch: %v", err)
		}
	})

	if token != "sess-after-mfa" {
		t.Fatalf("token after the second factor: got %q, want %q", token, "sess-after-mfa")
	}
	if vs.calls != 1 {
		t.Fatalf("POST /auth/mfa/verify calls: got %d, want exactly 1", vs.calls)
	}
	if vs.gotBody["mfa_challenge"] != challenge {
		t.Fatalf("verify request carried mfa_challenge %q, want the challenge /auth/login issued (%q)", vs.gotBody["mfa_challenge"], challenge)
	}
	if vs.gotBody["code"] != code {
		t.Fatalf("verify request carried code %q, want %q", vs.gotBody["code"], code)
	}
	// The code must never be echoed. --mfa-code warns that passing a credential on the
	// command line is insecure; that warning names the flag and never its value.
	if strings.Contains(stderr, code) {
		t.Fatalf("the second-factor code leaked to stderr: %q", stderr)
	}
	if !strings.Contains(strings.ToLower(stderr), "insecure") || !strings.Contains(stderr, "mfa-code") {
		t.Fatalf("expected an insecure-flag warning naming --mfa-code, got: %q", stderr)
	}
}

// A recovery code goes to the same endpoint in the same field -- the server accepts
// either there (internal/core.VerifyMFACredentials tries the TOTP step, then
// ConsumeMFARecoveryCode), so the CLI must not pre-validate the code's shape.
func TestResolveSessionToken_MFAChallengeAcceptsARecoveryCode(t *testing.T) {
	const recovery = "A1B2-C3D4-E5F6"
	vs := newVerifyServer(t, http.StatusOK, loginBody(t, "Login successful", map[string]any{"token": "sess-recovery"}))
	withMFACodeFlag(t, recovery)

	var token string
	_ = captureStderr(t, func() {
		var err error
		token, err = resolveSessionToken(t.Context(), loginCmd, vs.client(t), http.StatusOK, mfaChallengeResponse(t, "ch", true, false))
		if err != nil {
			t.Errorf("resolveSessionToken with a recovery code: %v", err)
		}
	})
	if token != "sess-recovery" {
		t.Fatalf("token: got %q, want %q", token, "sess-recovery")
	}
	if vs.gotBody["code"] != recovery {
		t.Fatalf("verify request carried code %q, want the recovery code verbatim (%q)", vs.gotBody["code"], recovery)
	}
}

func TestResolveSessionToken_RejectedCodeSurfacesTheServersReason(t *testing.T) {
	const code = "000000"
	errBody, err := json.Marshal(map[string]any{
		"success": false, "error": "Unauthorized", "message": "Invalid or expired code", "code": 401,
	})
	if err != nil {
		t.Fatalf("marshal error body: %v", err)
	}
	vs := newVerifyServer(t, http.StatusUnauthorized, errBody)
	withMFACodeFlag(t, code)

	var gotErr error
	stderr := captureStderr(t, func() {
		_, gotErr = resolveSessionToken(t.Context(), loginCmd, vs.client(t), http.StatusOK, mfaChallengeResponse(t, "ch", true, false))
	})
	if gotErr == nil {
		t.Fatal("expected a rejected second factor to fail")
	}
	msg := gotErr.Error()
	if !strings.Contains(msg, "Invalid or expired code") {
		t.Fatalf("expected the server's own reason in the error, got: %v", gotErr)
	}
	if !strings.Contains(msg, "401") {
		t.Fatalf("expected the real status code (401) in the error, got: %v", gotErr)
	}
	if strings.Contains(msg, "HTTP 200") {
		t.Fatalf("a rejected code must not be reported as the login POST's success status, got: %v", gotErr)
	}
	if strings.Contains(msg, code) || strings.Contains(stderr, code) {
		t.Fatalf("the submitted code leaked into output: err=%q stderr=%q", msg, stderr)
	}
}

func TestResolveSessionToken_WebAuthnOnlyAccountGetsAnActionableError(t *testing.T) {
	// No TOTP factor to complete: the CLI must say so, and must not call the verify
	// endpoint at all (a WebAuthn ceremony is not what that endpoint does).
	vs := newVerifyServer(t, http.StatusOK, loginBody(t, "", map[string]any{"token": "never"}))
	_, err := resolveSessionToken(t.Context(), loginCmd, vs.client(t), http.StatusOK, mfaChallengeResponse(t, "ch", false, true))
	if err == nil {
		t.Fatal("expected a WebAuthn-only account to fail with a specific error")
	}
	lower := strings.ToLower(err.Error())
	for _, want := range []string{"passkey", "web ui"} {
		if !strings.Contains(lower, want) {
			t.Fatalf("expected the error to mention %q, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "HTTP 200") {
		t.Fatalf("a WebAuthn-only account must not be reported as \"HTTP 200\", got: %v", err)
	}
	if vs.calls != 0 {
		t.Fatalf("POST /auth/mfa/verify was called %d times for a WebAuthn-only account; want 0", vs.calls)
	}
}

func TestResolveSessionToken_200WithoutTokenOrChallengeNamesWhatCameBack(t *testing.T) {
	body := loginBody(t, "Something else entirely", map[string]any{
		"password_change_required": true, "account_state": "restricted",
	})
	_, err := resolveSessionToken(t.Context(), loginCmd, nil, http.StatusOK, body)
	if err == nil {
		t.Fatal("expected an unrecognized 200 shape to fail")
	}
	msg := err.Error()
	// The old behaviour, verbatim, is what this must never be again.
	if msg == "login failed: HTTP 200" {
		t.Fatalf("regression: the misleading #2737 error is back: %v", err)
	}
	for _, want := range []string{"Something else entirely", "account_state", "password_change_required"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("expected the error to name %q (what actually came back), got: %v", want, err)
		}
	}
}

func TestResolveSessionToken_NonOKSurfacesTheServersMessage(t *testing.T) {
	errBody, err := json.Marshal(map[string]any{
		"success": false, "error": "Unauthorized", "message": "Invalid credentials", "code": 401,
	})
	if err != nil {
		t.Fatalf("marshal error body: %v", err)
	}
	_, gotErr := resolveSessionToken(t.Context(), loginCmd, nil, http.StatusUnauthorized, errBody)
	if gotErr == nil {
		t.Fatal("expected a 401 to fail")
	}
	if !strings.Contains(gotErr.Error(), "Invalid credentials") || !strings.Contains(gotErr.Error(), "401") {
		t.Fatalf("expected the server's message and status in the error, got: %v", gotErr)
	}
}

// resolveMFACode must not block on a pipe that will never carry a code: with no
// --mfa-code, no KEYORIX_MFA_CODE and no terminal (how `go test`, CI, and scripts run the
// CLI) it names the env var instead of hanging on stdin.
func TestResolveMFACode_NoFlagNoTerminalNamesTheEnvVar(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal here, so the interactive prompt path would be taken; this test covers the non-TTY path only")
	}
	t.Setenv("KEYORIX_MFA_CODE", "")
	t.Setenv("KEYORIX_MFA_CODE_FILE", "")
	_, err := resolveMFACode(loginCmd)
	if err == nil {
		t.Fatal("expected an error when no code can be obtained")
	}
	if !strings.Contains(err.Error(), "KEYORIX_MFA_CODE") {
		t.Fatalf("expected the error to name KEYORIX_MFA_CODE, got: %v", err)
	}
}

// TestLoginHandlesEveryDocumentedLoginResponseShape derives authLogin's 200 `data`
// oneOf branch list from the canonical spec and requires loginShapeForSchema to cover
// exactly it. This is the guard for the CLASS #2737 belongs to -- "a 200 response shape
// the contract documents that this command silently cannot handle" -- not for the single
// MFA instance of it: a third branch added to the spec fails this test until login.go
// classifies it.
//
// What it does NOT check: that each branch is handled CORRECTLY. The behavioural tests
// above do that, one per branch.
func TestLoginHandlesEveryDocumentedLoginResponseShape(t *testing.T) {
	const specPath = "../../server/http/handlers/openapi.yaml"
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read %s (the canonical API definition this client is generated from): %v", specPath, err)
	}
	type schemaRef struct {
		Ref string `yaml:"$ref"`
	}
	var spec struct {
		Paths map[string]struct {
			Post struct {
				OperationID string `yaml:"operationId"`
				Responses   map[string]struct {
					Content map[string]struct {
						Schema struct {
							Properties struct {
								Data struct {
									OneOf []schemaRef `yaml:"oneOf"`
									Ref   string      `yaml:"$ref"`
								} `yaml:"data"`
							} `yaml:"properties"`
						} `yaml:"schema"`
					} `yaml:"content"`
				} `yaml:"responses"`
			} `yaml:"post"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	login, ok := spec.Paths["/auth/login"]
	if !ok {
		t.Fatalf("%s has no /auth/login path -- this guard's premise is gone; re-derive it rather than deleting it", specPath)
	}
	if login.Post.OperationID != "authLogin" {
		t.Fatalf("/auth/login post operationId: got %q, want authLogin", login.Post.OperationID)
	}
	data := login.Post.Responses["200"].Content["application/json"].Schema.Properties.Data
	refs := data.OneOf
	if data.Ref != "" {
		refs = append(refs, schemaRef{Ref: data.Ref})
	}
	if len(refs) == 0 {
		t.Fatalf("found no schema reference under authLogin's 200 `data` in %s -- the spec's shape changed and this guard no longer reads it", specPath)
	}
	documented := map[string]bool{}
	for _, r := range refs {
		documented[r.Ref[strings.LastIndex(r.Ref, "/")+1:]] = true
	}
	for name := range documented {
		if _, handled := loginShapeForSchema[name]; !handled {
			t.Errorf("authLogin's 200 `data` documents schema %q, which login.go does not classify: add it to loginShapeForSchema and handle it in resolveSessionToken (an unhandled branch is exactly how #2737 produced \"login failed: HTTP 200\")", name)
		}
	}
	for name := range loginShapeForSchema {
		if !documented[name] {
			t.Errorf("loginShapeForSchema classifies %q, which authLogin's 200 `data` no longer documents: remove it", name)
		}
	}
}

// TestGeneratedAuthLoginDataIsAnOpaqueUnion pins the premise loginEnvelope's
// hand-written decoder rests on: oapi-codegen renders this inline oneOf as a struct with
// no exported field and no As<Branch>() accessor, so the generated type cannot yield
// either branch's contents. When a generator upgrade changes that, this fails -- and the
// decoder should then be replaced by the generated accessors.
func TestGeneratedAuthLoginDataIsAnOpaqueUnion(t *testing.T) {
	typ := reflect.TypeFor[apiclient.AuthLogin_200_Data]()
	for field := range typ.Fields() {
		if field.IsExported() {
			t.Errorf("apiclient.AuthLogin_200_Data now has an exported field %q -- the generated type may be usable directly; re-check loginEnvelope", field.Name)
		}
	}
	for _, m := range []string{"AsLoginSuccessData", "AsMFAChallengeData"} {
		if _, ok := typ.MethodByName(m); ok {
			t.Errorf("apiclient.AuthLogin_200_Data now has %s() -- use the generated accessors instead of loginEnvelope's hand-written decode", m)
		}
		if _, ok := reflect.PointerTo(typ).MethodByName(m); ok {
			t.Errorf("apiclient.AuthLogin_200_Data now has (*T).%s() -- use the generated accessors instead of loginEnvelope's hand-written decode", m)
		}
	}
}
