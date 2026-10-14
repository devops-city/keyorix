// Package keyorix is a tiny HTTP client for the Keyorix by-reference value endpoint
// (GET /api/v1/secrets/value?ref=project/environment/name, ADR-059). It is deliberately
// dependency-free and reads one value at a time; the operator never logs values.
package keyorix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBodyBytes caps how much of FetchValue's HTTP response body is ever
// decoded (#428 follow-up). Without a cap, json.NewDecoder(resp.Body) buffers an
// arbitrarily large (or gzip-bomb-expanded, since Go's transport auto-decompresses)
// response fully into memory — and this operator runs as a single cluster-wide
// singleton reconciler (see maxConcurrentReconciles in the controller package), so an
// OOM here doesn't just fail one reconcile, it halts secret sync for every
// KeyorixSecret in the cluster. Mirrors the same constant/idiom already used by
// internal/mcp/keyorix.go's getJSON for the identical by-reference value endpoint.
const maxResponseBodyBytes = 10 << 20 // 10 MiB

// ErrSecretGone is wrapped into the error FetchValue returns when the Keyorix server
// AFFIRMATIVELY reports the referenced secret no longer exists or is no longer
// accessible (HTTP 404 Not Found — the server's ref resolution already collapses
// "never existed" and "soft-deleted" into 404 — or HTTP 403 Forbidden, meaning the
// caller's own scope was denied for that specific reference, e.g. a revoked
// machine-identity role). Callers use errors.Is(err, ErrSecretGone) to distinguish
// this confirmed case from a transient failure (network error, timeout, 5xx) where
// taking a destructive action on a previously synced target would cause an unnecessary
// outage for workloads that depend on it.
//
// A 401 is deliberately NOT folded into ErrSecretGone: unlike 403, it says the bearer
// token itself is invalid/expired, not that the referenced secret's own existence or
// grant was checked and denied. It gets its own sentinel, ErrUnauthorized, below.
var ErrSecretGone = errors.New("secret reference no longer exists or is not accessible")

// ErrUnauthorized is wrapped into the error FetchValue returns on HTTP 401, classified
// from the response status alone (never from message text). A 401 says the operator's OWN
// bearer token is invalid, expired or rotated; it says nothing about the referenced
// secret or this workload's grant on it (that is a 403/404, see ErrSecretGone). The
// controller therefore never wipes a target Secret on a 401: it keeps it, reports
// KeyorixAuthFailed and retries with backoff until the credential is fixed.
var ErrUnauthorized = errors.New("bearer token rejected (unauthorized)")

// ErrSecretUnavailable is wrapped into the error FetchValue returns when the server
// answers that the referenced secret exists and this token may read it, but the
// secret's own state refuses the read right now: outside its access schedule (403
// SecretAccessOutsideSchedule) or its max-reads budget is spent (409
// SecretMaxReadsExhausted). Neither says access was cut, so it is NOT ErrSecretGone
// and a previously synced target Secret is left in place: a schedule window that closes
// every night must not become a nightly outage, and a max-reads budget limits
// disclosures (the operator's own refreshes spend it), it does not withdraw the value
// already materialized.
var ErrSecretUnavailable = errors.New("secret is temporarily unavailable for reading")

// ErrSecretSuspended is wrapped into the error FetchValue returns on 409
// SecretSuspended: an operator has switched value reads off for the secret. It is NOT
// ErrSecretGone (the secret exists and the grant stands, and resuming restores it), so
// nothing here removes a target Secret. The controller decides what the target holds
// meanwhile from spec.onSuspend (Retain by default, or Clear) and reports it.
var ErrSecretSuspended = errors.New("secret is suspended")

// ErrClearSyncedCopies is wrapped (together with ErrSecretSuspended) into the error
// FetchValue returns when the suspension asked for the synced Kubernetes copies to be
// cleared: the 409 SecretSuspended envelope carries details.clear_synced_copies=true. The
// controller then treats that reference as onSuspend=Clear whatever spec.onSuspend says,
// with exactly the Clear semantics (empty only the keys it manages, never delete a Secret
// or touch one it does not own). It is set only on a suspended refusal.
var ErrClearSyncedCopies = errors.New("suspension requests clearing the synced copies")

// ErrSecretExpired is wrapped into the error FetchValue returns on 409 SecretExpired.
// The target Secret keeps its last value (Retain); the controller flags the state with
// a condition, a Warning Event and a metric, as it does ahead of the expiry.
var ErrSecretExpired = errors.New("secret has expired")

// ErrUnreachable, ErrTimeout and ErrServerError are wrapped into the error FetchValue
// returns when Keyorix could not answer the read at all: the request failed before a
// response arrived (connection refused, DNS, TLS, reset), it timed out, or the server
// answered 5xx. They are classified from the transport error and the status code alone
// (never from message text). None of them says anything about the secret or the grant,
// so the controller keeps the target Secret, reports KeyorixUnreachable (one Warning
// Event on entry, keyorix_operator_fetch_errors_total) and retries with backoff.
var (
	ErrUnreachable = errors.New("keyorix server unreachable")
	ErrTimeout     = errors.New("keyorix request timed out")
	ErrServerError = errors.New("keyorix server error (5xx)")
)

// Error codes the server puts in the error envelope's "error" field when a
// secret's own state refuses a value read (server/http/handlers/openapi.yaml,
// SecretReadRefused; ERRMAP-1).
const (
	codeOutsideSchedule   = "SecretAccessOutsideSchedule"
	codeExpired           = "SecretExpired"
	codeSuspended         = "SecretSuspended"
	codeMaxReadsExhausted = "SecretMaxReadsExhausted"
)

// errorEnvelope reads the "error" code from an error response's envelope, plus whether
// its details say the suspension asks for the synced copies to be cleared. It returns
// "" when the body is not that shape. It reads at most maxResponseBodyBytes.
func errorEnvelope(resp *http.Response) (code string, clearSyncedCopies bool) {
	var env struct {
		Error   string          `json:"error"`
		Details json.RawMessage `json:"details"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&env); err != nil {
		return "", false
	}
	// details is decoded on its own so a shape this client does not know drops only the
	// request marker (the safe direction: the resource's own onSuspend decides), never the
	// error code.
	var details struct {
		ClearSyncedCopies bool `json:"clear_synced_copies"`
	}
	if len(env.Details) > 0 {
		_ = json.Unmarshal(env.Details, &details)
	}
	return env.Error, details.ClearSyncedCopies
}

// Client reads secret values from a Keyorix server with a bearer (machine-identity)
// token. The token is sent on every request and never logged.
type Client struct {
	baseURL string
	token   string
	hc      *http.Client
}

// New builds a client for the given Keyorix base URL and bearer token.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc:      &http.Client{Timeout: 30 * time.Second, CheckRedirect: refuseRedirect},
	}
}

// refuseRedirect blocks the http.Client from following ANY redirect. Go's default
// redirect behavior only strips the Authorization header when the redirect target's
// Host differs from the original — it never checks scheme. A same-host redirect from
// https:// to http:// (a misconfigured reverse proxy in front of the Keyorix server, or
// a compromised server) would otherwise keep this client's bearer token attached and
// send it — and the plaintext secret value in the response — over cleartext. This
// client only ever talks to a single, fixed, operator-validated base URL (see
// validateServer in the controller package, which also requires https) and has no
// legitimate reason to follow a redirect at all, so refusing every redirect outright is
// the simplest and safest fix.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("keyorix: refusing to follow redirect to %q", req.URL)
}

// drainAndClose discards any unread response body before closing it, so the
// underlying connection can be returned to net/http's keep-alive pool instead
// of being torn down. FetchValue used to defer a bare resp.Body.Close() and
// return without reading the body on every one of its five error branches
// (404/403/401/400/>=400) — this operator is a single cluster-wide singleton
// reconciler (see the maxResponseBodyBytes doc comment above), so an
// unnecessarily torn-down connection on every error response is not free.
func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBodyBytes))
	_ = resp.Body.Close()
}

// validateClientBaseURL checks that the client's base URL is a well-formed https
// destination — matching validateServer's own https requirement in the controller
// package, which this client's baseURL is sourced from (see FetchValue). http is
// additionally allowed for a loopback host (matching this repo's own convention
// elsewhere, e.g. internal/storage/remote/config.go's isLoopbackHost), which is what
// this package's own tests connect to via httptest.NewServer.
func validateClientBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("keyorix: invalid base URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("keyorix: base URL %q is missing a host", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" || !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("keyorix: base URL %q must use https", raw)
	}
	return nil
}

// classifyTransportError wraps a failed http.Client.Do error with ErrTimeout (deadline
// exceeded, client or request timeout) or ErrUnreachable (anything else that stopped a
// response arriving). A cancelled context is neither: the reconcile was abandoned, not
// the server at fault, so the error is returned unclassified.
func classifyTransportError(err error) error {
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("request failed: %w", err)
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return fmt.Errorf("request failed: %w: %w", err, ErrTimeout)
	default:
		return fmt.Errorf("request failed: %w: %w", err, ErrUnreachable)
	}
}

// isLoopbackHost reports whether host is localhost or a loopback IP.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Value is a fetched secret value with the source secret's metadata the controller
// reports on.
type Value struct {
	Data []byte
	// Expiration is the source secret's expiration, nil when it has none or the server
	// did not send it.
	Expiration *time.Time
}

// FetchValue returns the current value of the secret referenced by
// "project/environment/name".
func (c *Client) FetchValue(ctx context.Context, ref string) ([]byte, error) {
	v, err := c.FetchValueInfo(ctx, ref)
	if err != nil {
		return nil, err
	}
	return v.Data, nil
}

// FetchValueInfo is FetchValue plus the source secret's expiration, which the
// controller uses to warn ahead of it.
func (c *Client) FetchValueInfo(ctx context.Context, ref string) (Value, error) {
	// c.hc (built in New above) already sets CheckRedirect to refuseRedirect, and the
	// caller (KeyorixSecretReconciler.buildDesired) already validates ks.Spec.Server
	// against an operator-configured --allowed-servers allowlist via validateServer
	// before ever constructing this Client — see keyorixsecret_controller.go. That
	// upstream check operates on a differently-named field (KeyorixSecretSpec.Server)
	// three call frames away, so this direct read of c.baseURL itself is what lets a
	// static analyzer connect a validation call to this exact destination.
	if err := validateClientBaseURL(c.baseURL); err != nil {
		return Value{}, err
	}
	q := url.Values{}
	q.Set("ref", ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/secrets/value?"+q.Encode(), nil)
	if err != nil {
		return Value{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return Value{}, classifyTransportError(err)
	}
	defer drainAndClose(resp)

	code, clearCopies := "", false
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusConflict {
		code, clearCopies = errorEnvelope(resp)
	}
	switch {
	case code == codeOutsideSchedule || code == codeMaxReadsExhausted:
		return Value{}, fmt.Errorf("secret reference %q: %s (HTTP %d): %w", ref, code, resp.StatusCode, ErrSecretUnavailable)
	case code == codeSuspended && clearCopies:
		return Value{}, fmt.Errorf("secret reference %q: %s (HTTP %d, clear_synced_copies): %w: %w", ref, code, resp.StatusCode, ErrSecretSuspended, ErrClearSyncedCopies)
	case code == codeSuspended:
		return Value{}, fmt.Errorf("secret reference %q: %s (HTTP %d): %w", ref, code, resp.StatusCode, ErrSecretSuspended)
	case code == codeExpired && clearCopies:
		// The server judges expiry before suspension, so a secret that is both expired and
		// suspended with the clear marker answers SecretExpired carrying the marker (#3215).
		// It is classified as suspended-with-clear (the suspended branch is tested first by the
		// controller), so the copies are cleared, not retained; ErrSecretExpired stays in the
		// chain so the state is still discoverable.
		return Value{}, fmt.Errorf("secret reference %q: %s (HTTP %d, clear_synced_copies): %w: %w: %w", ref, code, resp.StatusCode, ErrSecretSuspended, ErrClearSyncedCopies, ErrSecretExpired)
	case code == codeExpired:
		return Value{}, fmt.Errorf("secret reference %q: %s (HTTP %d): %w", ref, code, resp.StatusCode, ErrSecretExpired)
	case resp.StatusCode == http.StatusNotFound:
		// The server's ref-resolution collapses "never existed" and "soft-deleted"
		// into an identical 404 (closing an existence oracle) — either way the
		// secret this reference names is gone.
		return Value{}, fmt.Errorf("secret reference %q not found: %w", ref, ErrSecretGone)
	case resp.StatusCode == http.StatusForbidden:
		// Distinct from 401: this means the request was authenticated but the
		// caller's own scope/grant for THIS reference was denied — e.g. a revoked
		// machine-identity role. Treated the same as "gone". (A schedule refusal is
		// also a 403 but carries its own code, handled above.)
		return Value{}, fmt.Errorf("secret reference %q forbidden (HTTP 403) — access revoked: %w", ref, ErrSecretGone)
	case resp.StatusCode == http.StatusUnauthorized:
		// Unlike 403, a 401 says the token itself is invalid/expired — it says
		// nothing about whether the referenced secret still exists or is still
		// permitted, so this must NOT be treated as ErrSecretGone. It is wrapped as
		// ErrUnauthorized (see its doc comment); the controller keeps the target Secret.
		return Value{}, fmt.Errorf("not authorized (HTTP 401) — check the token is valid: %w", ErrUnauthorized)
	case resp.StatusCode == http.StatusBadRequest:
		return Value{}, fmt.Errorf("invalid reference %q (want project/environment/name)", ref)
	case resp.StatusCode >= 500:
		return Value{}, fmt.Errorf("server returned HTTP %d: %w", resp.StatusCode, ErrServerError)
	case resp.StatusCode >= 400:
		return Value{}, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	// Value is a *string (not string) so decoding can tell "data.value absent from the
	// response" (nil) apart from "data.value present as an explicit empty string" (non-nil,
	// ""). A plain string field can't make that distinction -- both shapes decode to the
	// same "" zero value -- which used to let a malformed/unexpected response silently
	// materialize an empty Kubernetes Secret value with no error anywhere (finding
	// operator-keyorix.json#0). The server's success path for this exact endpoint
	// (SecretHandler.GetSecretValueByRef, server/http/handlers/secrets_crud.go) has exactly
	// one 200 response shape and it unconditionally sets "value" in the response map, so an
	// absent field on a 200 is never legitimate -- it means the upstream contract changed,
	// a proxy/gateway mangled the body, or the server has a bug. An explicit "" IS treated
	// as success (not an error): nothing in this client's wire contract forbids it, even
	// though today's server-side validation never produces one in practice (secret creation
	// requires a non-empty value and update ignores an empty one).
	var body struct {
		Data struct {
			Value  *string `json:"value"`
			Secret struct {
				Expiration *time.Time `json:"expiration"`
			} `json:"secret"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&body); err != nil {
		return Value{}, fmt.Errorf("decode response: %w", err)
	}
	if body.Data.Value == nil {
		return Value{}, fmt.Errorf("decode response: success (HTTP 200) but response is missing data.value")
	}
	return Value{Data: []byte(*body.Data.Value), Expiration: body.Data.Secret.Expiration}, nil
}
