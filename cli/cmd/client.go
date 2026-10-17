package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
	"github.com/keyorixhq/keyorix/cli/internal/cliversion"
	"github.com/keyorixhq/keyorix/cli/internal/credstore"
	"github.com/keyorixhq/keyorix/cli/internal/skew"
)

// resolveCredStore returns the one credential store this CLI uses (ADR-108 PR 0 decision --
// see internal/credstore's package doc comment).
func resolveCredStore() (*credstore.FileStore, error) {
	path, err := credstore.DefaultPath()
	if err != nil {
		return nil, err
	}
	return credstore.NewFileStore(path), nil
}

// resolveServerAndToken applies the precedence flag > env var > stored credentials file. A
// server URL is required; a token is optional (e.g. `login` itself has none yet).
func resolveServerAndToken(store *credstore.FileStore) (serverURL, token string, err error) {
	serverURL = os.Getenv("KEYORIX_SERVER")
	token = os.Getenv("KEYORIX_TOKEN")

	if serverURL != "" && token != "" {
		return serverURL, token, nil
	}

	creds, loadErr := store.Load()
	if serverURL == "" {
		serverURL = creds.ServerURL
	}
	if token == "" {
		token = creds.Token
	}
	if serverURL == "" {
		// A missing credentials file is the ordinary "never logged in" case: say so
		// plainly. Any other failure (wrong permissions, a symlink, bad YAML) is a
		// problem with the file, and its message says how to fix it.
		if loadErr != nil && !errors.Is(loadErr, fs.ErrNotExist) {
			return "", "", withExitCode(exitAuth, fmt.Errorf("not logged in: %w. Next step: fix the credentials file, "+
				"or run `keyorix login --server <url>` (or set KEYORIX_SERVER and KEYORIX_TOKEN)", loadErr))
		}
		return "", "", withExitCode(exitAuth, errors.New("not logged in: no server is configured. "+
			"Next step: run `keyorix login --server <url>` (or set KEYORIX_SERVER and KEYORIX_TOKEN)"))
	}
	return serverURL, token, nil
}

// caFileFlag is the global --ca-file flag (root.go).
var caFileFlag string

// caFileEnv names the environment variable form of --ca-file.
const caFileEnv = "KEYORIX_CA_FILE"

// resolveCAFile applies the precedence --ca-file > KEYORIX_CA_FILE > ca_file in the
// credentials file, and names where the value came from (for error messages and for
// `config get`). An unreadable credentials file yields no stored value here: every command
// that needs credentials reports that refusal itself, and without a CA file a self-signed
// server simply fails TLS verification (fails closed).
func resolveCAFile() (path, source string) {
	if caFileFlag != "" {
		return caFileFlag, "--ca-file"
	}
	if v := os.Getenv(caFileEnv); v != "" {
		return v, caFileEnv
	}
	store, err := resolveCredStore()
	if err != nil {
		return "", ""
	}
	if creds, err := store.Load(); err == nil && creds.CAFile != "" {
		return creds.CAFile, "ca_file in " + store.Path()
	}
	return "", ""
}

// newAPIClient builds a generated client against serverURL, attaching an Authorization
// header when token is non-empty. Always uses apiclient.NewHardenedHTTPClient (request
// timeout, response-size cap, redirect refusal) instead of the generated client's bare
// &http.Client{} default -- see hardened_client.go's doc comment for why.
//
// When a CA file is configured (resolveCAFile), the client trusts exactly that file's
// certificates for TLS instead of the system roots.
func newAPIClient(serverURL, token string) (*apiclient.ClientWithResponses, error) {
	httpClient := apiclient.NewHardenedHTTPClient()
	if caFile, source := resolveCAFile(); caFile != "" {
		c, err := apiclient.NewHardenedHTTPClientWithCAFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("CA file from %s: %w", source, err)
		}
		httpClient = c
	}
	opts := []apiclient.ClientOption{apiclient.WithHTTPClient(httpClient)}
	if token != "" {
		opts = append(opts, apiclient.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+token)
			return nil
		}))
	}
	return apiclient.NewClientWithResponses(serverURL, opts...)
}

// checkVersionSkew calls GET /api/v1/version and classifies the result via internal/skew.
// A 404 means the server predates this endpoint entirely (an "old server," not merely an
// old api_version) -- distinguished here rather than inside internal/skew, which only ever
// sees a successfully-parsed response.
func checkVersionSkew(ctx context.Context, client *apiclient.ClientWithResponses) (skew.Result, error) {
	resp, err := client.GetVersionWithResponse(ctx)
	if err != nil {
		return skew.Result{}, fmt.Errorf("contact server: %w", err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		return skew.Result{
			Warning: "server predates the version-skew endpoint (GET /api/v1/version) -- it is likely a much older release; some commands may not be supported",
		}, nil
	}
	if resp.JSON200 == nil {
		return skew.Result{}, fmt.Errorf("unexpected response from GET /api/v1/version: HTTP %d", resp.StatusCode())
	}

	apiVersion := 0
	if resp.JSON200.ApiVersion != nil {
		apiVersion = *resp.JSON200.ApiVersion
	}
	minCLI := ""
	if resp.JSON200.MinimumCliVersion != nil {
		minCLI = *resp.JSON200.MinimumCliVersion
	}
	return skew.Check(cliversion.Version, cliversion.TargetAPIVersion, apiVersion, minCLI), nil
}

// apiClientWithSkewCheck resolves credentials, builds a client, and checks version skew
// against the server (docs/cli-split-inventory.md §7, PR 6's "skew check on every request"
// method, carried forward into PR 7/8/10) before returning -- unlike PR 1/2's per-command
// clients, which only checked skew from `login`/`status`. A Refuse result blocks the
// command outright; a Warning is printed to stderr (so it never pollutes stdout output a
// script might parse) and the command proceeds.
func apiClientWithSkewCheck(ctx context.Context) (*apiclient.ClientWithResponses, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, err
	}
	client, err := newAPIClient(serverURL, token)
	if err != nil {
		return nil, err
	}
	skewResult, err := checkVersionSkew(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("version-skew check: %w", err)
	}
	if skewResult.Refuse {
		return nil, fmt.Errorf("incompatible with this server: %s", skewResult.Reason)
	}
	if skewResult.Warning != "" {
		fmt.Fprintln(os.Stderr, "Warning:", skewResult.Warning)
	}
	return client, nil
}

// apiEnvelope decodes the `{"success", "data", "message"}` envelope every handler
// (sendSuccess, server/http/handlers/helpers.go) wraps a 2xx response body in. T is the
// shape of the "data" field.
type apiEnvelope[T any] struct {
	Data T `json:"data"`
}

// decodeData unmarshals a 2xx response body's "data" field into T. Used for the routes
// this package calls whose generated response type has no typed JSON2xx field (no response
// schema was added to openapi.yaml for them -- see server/http/handlers/openapi.yaml's PR
// 6/7/8/10 additions and their doc comments for why a full typed schema wasn't worth it for
// a one-PR-only caller): the generated client always exposes the raw Body, decoding it here
// is the documented fallback (docs/cli-split-inventory.md §7).
func decodeData[T any](body []byte) (T, error) {
	var env apiEnvelope[T]
	if err := json.Unmarshal(body, &env); err != nil {
		var zero T
		return zero, fmt.Errorf("decode response: %w", err)
	}
	return env.Data, nil
}

// apiErrorBody mirrors the `{"error", "message"}` fields sendError
// (server/http/handlers/helpers.go) writes on a non-2xx response -- enough to surface a
// readable reason instead of a bare status code. Task requirement (PR 6 method, carried
// forward into PR 7/8/10, docs/cli-split-inventory.md §7): "surface ... refusals readably."
type apiErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// apiError builds a readable error for a non-2xx response: action describes what was being
// attempted (e.g. "update user"), statusCode and body come straight from the generated
// response. Falls back to a bare status code if body isn't the expected error shape (e.g.
// an empty body, or a transport-layer failure that never reached a handler).
//
// eb.Message is server-controlled text -- the server may be compromised, misconfigured, or
// (absent a validated TLS chain) MITM'd -- and this error's .Error() text reaches the
// operator's terminal raw via main.go's fmt.Fprintln(os.Stderr, "Error:", err). Route it
// through cliout.SanitizeForTerminal, the same defense every other piece of free text
// printed by this CLI goes through, so a crafted message can't inject a terminal escape
// sequence (found by FuzzApiError, CLI-FUZZ target 2).
func apiError(action string, statusCode int, body []byte) error {
	var eb apiErrorBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Message != "" {
		return withExitCode(statusExitCode(statusCode), fmt.Errorf("%s failed: %s (HTTP %d)%s",
			action, cliout.SanitizeForTerminal(eb.Message), statusCode, hintFor(action, statusCode, eb)))
	}
	return withExitCode(statusExitCode(statusCode), fmt.Errorf("%s failed: HTTP %d%s",
		action, statusCode, statusHint(action, statusCode)))
}

// hintFor picks the " Next step: ..." suffix for a failed call: the server's own error
// code first (one fixed remedy), then the remedy for the HTTP status.
func hintFor(action string, statusCode int, eb apiErrorBody) string {
	if h := nextStepHint(eb); h != "" {
		return h
	}
	return statusHint(action, statusCode)
}

// errCodeMFAEnrollmentRequired is the "error" code the server's auth middleware
// returns (403) on every authenticated route when security.require_mfa is on and
// the caller has no MFA enrolled (server/middleware/auth.go).
const errCodeMFAEnrollmentRequired = "MFAEnrollmentRequired"

// Codes the server sends when a secret's own state refuses a value read
// (ERRMAP-1, server/http/handlers/openapi.yaml's SecretReadRefused): 403 for the
// schedule, 409 for the others.
const (
	errCodeSecretOutsideSchedule   = "SecretAccessOutsideSchedule"
	errCodeSecretExpired           = "SecretExpired"
	errCodeSecretSuspended         = "SecretSuspended"
	errCodeSecretMaxReadsExhausted = "SecretMaxReadsExhausted"
)

// nextStepHint returns a " Next step: ..." suffix for server error codes that
// have one fixed remedy, or "". MFA enrolment: without it a fresh admin logs in
// successfully and then every command fails (#2937). The secret read refusals:
// each names the command that lifts it (run by someone allowed to).
func nextStepHint(eb apiErrorBody) string {
	switch eb.Error {
	case errCodeMFAEnrollmentRequired:
		return " Next step: this server requires multi-factor authentication. " +
			"Enrol MFA with `keyorix mfa enroll`, then `keyorix mfa activate`, " +
			"then log in again with `keyorix login` (it prompts for the code)."
	case errCodeSecretOutsideSchedule:
		return " Next step: read it inside its access window " +
			"(`keyorix secret get-schedule <secret-id>` shows it)."
	case errCodeSecretExpired:
		return " Next step: someone with secrets.write can extend the expiration " +
			"(`keyorix secret update --id <secret-id> --expires <RFC3339>` or `--clear-expiration`)."
	case errCodeSecretSuspended:
		return " Next step: someone with secrets.write can resume it " +
			"(`keyorix secret resume --id <secret-id>`)."
	case errCodeSecretMaxReadsExhausted:
		return " Next step: someone with secrets.write can raise the limit " +
			"(`keyorix secret update --id <secret-id> --max-reads <n>`, n above the reads already made)."
	}
	return ""
}

// httpStatusError is the failure path for a non-2xx response where the caller
// has its own wording: "<what>: <server message> (HTTP <code>)", falling back to
// "<what>: HTTP <code>" when the body carries no message. Every CLI command uses
// this (or apiError) so a 403/409 always says why (#2937, #2938). what is a
// phrase such as "failed to create secret".
func httpStatusError(what string, statusCode int, body []byte) error {
	var eb apiErrorBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Message != "" {
		return withExitCode(statusExitCode(statusCode), fmt.Errorf("%s: %s (HTTP %d)%s",
			what, cliout.SanitizeForTerminal(eb.Message), statusCode, hintFor(what, statusCode, eb)))
	}
	return withExitCode(statusExitCode(statusCode), fmt.Errorf("%s: HTTP %d%s", what, statusCode, statusHint(what, statusCode)))
}
