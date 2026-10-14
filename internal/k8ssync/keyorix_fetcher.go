package k8ssync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUpstreamGone is a sentinel a Fetch error wraps when the failure is DEFINITIVE —
// the secret no longer exists upstream (404, or absent from the environment listing)
// or access to it has been revoked (403) — as opposed to a transient failure
// (network error, timeout, 5xx) that might clear on the next reconcile pass. #140:
// the sync loop uses this distinction to actively remove a de-authorized/deleted
// secret's stale materialized value from the cluster, rather than leaving it as-is
// indefinitely (which a plain, unclassified fetch error did).
var ErrUpstreamGone = errors.New("k8ssync: secret not found or access revoked upstream")

// ErrUnauthorized is what a Fetch error wraps on HTTP 401, classified from the response
// status alone: the agent's OWN bearer token was rejected (invalid, expired or rotated).
// That says nothing about the referenced secret or the agent's grant on it, so it is NOT
// ErrUpstreamGone: the engine never wipes on it, whatever prune_on_revoke says (Andrei,
// 2026-10-13). The target Secret is kept, the failure is counted as auth_failed and
// reported, and the pass backs off like any failure until the token is fixed.
var ErrUnauthorized = errors.New("k8ssync: Keyorix rejected the agent's credential (HTTP 401)")

// ErrUnreachable, ErrTimeout and ErrServerError are what a Fetch error wraps when Keyorix
// could not answer: no response arrived (connection refused, DNS, TLS), the request timed
// out, or the server answered 5xx. They are classified from the transport error and the
// status alone and mirror the operator's keyorix.ErrUnreachable / ErrTimeout /
// ErrServerError. The target Secret is kept, the target is counted failed AND
// keyorix_unreachable, and the pass log says KeyorixUnreachable with the reason.
var (
	ErrUnreachable = errors.New("k8ssync: Keyorix server unreachable")
	ErrTimeout     = errors.New("k8ssync: Keyorix request timed out")
	ErrServerError = errors.New("k8ssync: Keyorix server error (5xx)")
)

// fetchUnavailableReason returns "unreachable", "timeout" or "server_error" (the same
// reason values as the operator's keyorix_operator_fetch_errors_total label) for an error
// wrapping one of the could-not-answer sentinels, "" otherwise.
func fetchUnavailableReason(err error) string {
	switch {
	case errors.Is(err, ErrTimeout):
		return "timeout"
	case errors.Is(err, ErrServerError):
		return "server_error"
	case errors.Is(err, ErrUnreachable):
		return "unreachable"
	}
	return ""
}

// classifyTransportError wraps a failed http.Client.Do error with ErrTimeout or
// ErrUnreachable. A cancelled context (the pass was abandoned) is left unclassified.
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

// ErrSourceSuspended and ErrSourceExpired are what a Fetch error wraps when the server
// answers 409 SecretSuspended / SecretExpired. Neither says the secret is gone or access
// was cut (resuming or extending restores the read), so neither is ErrUpstreamGone and
// neither removes anything: the engine retains the target Secret (or, for a suspended
// source with on_suspend: clear, empties its keys) and reports the state.
var (
	ErrSourceSuspended = errors.New("k8ssync: source secret is suspended")
	ErrSourceExpired   = errors.New("k8ssync: source secret has expired")
)

// ErrSourceClearRequested is wrapped together with ErrSourceSuspended when the 409
// SecretSuspended envelope carries details.clear_synced_copies=true: whoever suspended the
// secret asked, for this suspension, that the synced copies be cleared (a compromise
// response). The engine then treats that mapping as on_suspend: clear whatever the config
// says, with exactly the clear semantics (empty only that key in a Secret the agent owns).
// It is never set on any other refusal.
var ErrSourceClearRequested = errors.New("k8ssync: the suspension requests clearing the synced copies")

// secretStateRefusal classifies a 403/409 whose envelope names a secret-state
// refusal of a value read (server/http/handlers/openapi.yaml, SecretReadRefused;
// ERRMAP-1), or returns nil for any other body. Suspended and expired wrap their own
// sentinels (never ErrUpstreamGone); a read outside the secret's access schedule, or
// with its max-reads budget spent, is a plain transient error. In every case the synced
// value stays. It reads at most maxResponseBodyBytes of the body.
func secretStateRefusal(resp *http.Response) error {
	var env struct {
		Error   string          `json:"error"`
		Details json.RawMessage `json:"details"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&env) != nil {
		return nil
	}
	switch env.Error {
	case "SecretSuspended":
		// details is decoded on its own: a shape this agent does not know drops only the
		// request marker (the config's own on_suspend then decides), never the code.
		var details struct {
			ClearSyncedCopies bool `json:"clear_synced_copies"`
		}
		if len(env.Details) > 0 {
			_ = json.Unmarshal(env.Details, &details)
		}
		if details.ClearSyncedCopies {
			return fmt.Errorf("%s (HTTP %d, clear_synced_copies): %w: %w", env.Error, resp.StatusCode, ErrSourceSuspended, ErrSourceClearRequested)
		}
		return fmt.Errorf("%s (HTTP %d): %w", env.Error, resp.StatusCode, ErrSourceSuspended)
	case "SecretExpired":
		// An expired secret that is also suspended with the clear marker answers
		// SecretExpired carrying details.clear_synced_copies (#3215): clear, not retain.
		// Wrapped as suspended+clear (the engine tests suspended first); ErrSourceExpired
		// stays in the chain. An expired secret without the marker is unchanged.
		var details struct {
			ClearSyncedCopies bool `json:"clear_synced_copies"`
		}
		if len(env.Details) > 0 {
			_ = json.Unmarshal(env.Details, &details)
		}
		if details.ClearSyncedCopies {
			return fmt.Errorf("%s (HTTP %d, clear_synced_copies): %w: %w: %w", env.Error, resp.StatusCode, ErrSourceSuspended, ErrSourceClearRequested, ErrSourceExpired)
		}
		return fmt.Errorf("%s (HTTP %d): %w", env.Error, resp.StatusCode, ErrSourceExpired)
	case "SecretAccessOutsideSchedule", "SecretMaxReadsExhausted":
		return fmt.Errorf("value read refused: %s (HTTP %d)", env.Error, resp.StatusCode)
	}
	return nil
}

// maxServerPageSize is the Keyorix server's maximum accepted page_size for
// GET /api/v1/secrets (server/http/handlers/secrets_list.go: 1 <= page_size <= 100;
// anything outside that range is silently ignored and the server falls back to its
// default of 20). Requesting more than this is not an error — it is silently
// downgraded — so resolveID must both cap at this value AND paginate rather than
// assume one page holds every secret (#Bug2).
const maxServerPageSize = 100

// maxResponseBodyBytes caps how much of a Keyorix server response this fetcher will
// buffer during json.Decode, so a compromised/misbehaving server (or a DNS-rebound
// response) can't exhaust process memory with an oversized reply.
const maxResponseBodyBytes = 10 << 20 // 10MiB

// KeyorixFetcher reads secret values from a Keyorix server over HTTP, resolving a
// reference of the form "<environment>/<name>" (e.g. "production/db-password") to the
// secret's current value. It satisfies Fetcher. Auth is a bearer token (typically a
// machine-identity / service-account token); the token is sent on every request and
// never logged.
//
// A ref names only an environment and a secret, never a project — environment names
// are unique per-project, not globally (the same name, e.g. "production", can exist
// in many different projects). projectID pins every lookup this fetcher performs to
// the single project its token belongs to (a MachineIdentity, and so its token, is
// always scoped to exactly one project), so a same-named secret in a DIFFERENT
// project can never be resolved instead (#Bug1).
// envCacheTTL bounds how long a resolved environment name->id mapping is trusted
// before resolveEnvironmentID forces a fresh lookup, even on a cache HIT. Without
// this, a renamed-then-reused environment name (e.g. "production" moved from id 5
// to a new id 7) would resolve to the stale id for the remaining process lifetime —
// silently, since the stale id typically still exists and is still readable. This
// bounds that drift window without adding per-lookup network overhead for the
// common case of an unchanged environment.
const envCacheTTL = 10 * time.Minute

type KeyorixFetcher struct {
	baseURL   string
	token     string
	projectID uint
	hc        *http.Client
	now       func() time.Time // overridden in tests; real clock otherwise

	mu          sync.Mutex
	envByName   map[string]uint // environment name -> id, within projectID; lazily populated
	envCachedAt time.Time       // when envByName was last (re)populated
}

// NewKeyorixFetcher builds a fetcher for the given Keyorix base URL (e.g.
// https://keyorix.internal), bearer token, and the numeric id of the project the
// token's machine identity belongs to. A nil-safe default HTTP client with a sane
// timeout is used.
func NewKeyorixFetcher(baseURL, token string, projectID uint) *KeyorixFetcher {
	return &KeyorixFetcher{
		baseURL:   strings.TrimRight(baseURL, "/"),
		token:     token,
		projectID: projectID,
		hc:        &http.Client{Timeout: 30 * time.Second, CheckRedirect: refuseRedirect},
		now:       time.Now,
	}
}

// refuseRedirect stops this fetcher from following any redirect: without this, a
// 3xx response from a compromised/misconfigured Keyorix server could bounce the
// bearer-token-bearing request to an internal host (e.g. cloud IMDS) at request
// time, even though baseURL itself was validated at config-load time (CWE-918).
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("k8ssync: refusing to follow redirect to %q", req.URL)
}

// validateFetcherBaseURL checks that baseURL is a well-formed absolute http(s) URL,
// allowing http for any loopback host (not just the literal "localhost" that
// validateKeyorixURL's stricter K8SSYNC-007 rule requires at config-load time) — this
// is a redundant runtime re-check on every request, not the primary gate, and this
// package's own tests connect to httptest.NewServer's 127.0.0.1 addresses.
func validateFetcherBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid keyorix_url %q", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" || !isLoopbackHostname(u.Hostname()) {
		return fmt.Errorf("keyorix_url %q must use https (http is allowed only for a loopback host)", raw)
	}
	return nil
}

// isLoopbackHostname reports whether host is localhost or a loopback IP.
func isLoopbackHostname(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Fetch resolves ref ("<environment>/<name>") to the secret's id and returns its
// current value.
func (f *KeyorixFetcher) Fetch(ctx context.Context, ref string) ([]byte, error) {
	v, _, err := f.FetchWithExpiry(ctx, ref)
	return v, err
}

// FetchWithExpiry is Fetch plus the secret's expiration (nil when it has none), which
// the engine uses to warn ahead of it. It satisfies ExpiryFetcher.
func (f *KeyorixFetcher) FetchWithExpiry(ctx context.Context, ref string) ([]byte, *time.Time, error) {
	env, name, err := parseRef(ref)
	if err != nil {
		return nil, nil, err
	}
	id, err := f.resolveID(ctx, env, name)
	if err != nil {
		return nil, nil, err
	}
	return f.fetchValue(ctx, id)
}

// parseRef splits "<environment>/<name>" into its parts. The name may itself contain
// slashes (a path-like secret name); only the first segment is the environment.
func parseRef(ref string) (env, name string, err error) {
	ref = strings.TrimSpace(ref)
	i := strings.IndexByte(ref, '/')
	if i <= 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("invalid ref %q: expected \"<environment>/<name>\"", ref)
	}
	return ref[:i], ref[i+1:], nil
}

// resolveID finds the id of the secret named name in environment env, within this
// fetcher's project. env is first resolved to its numeric id (resolveEnvironmentID)
// so the list call below can scope by BOTH project_id and environment_id — the
// server filters server-side on those, so the result set a same-named secret could
// hide in is exactly one project's one environment, never a broader, unscoped list
// (#Bug1). The list is paginated at the server's actual maximum page size, walking
// every page until the target is found or the set is exhausted, so a secret ranked
// past position 20 (the server's silent-fallback default) or 100 (page 1's cap) is
// still found rather than wrongly reported gone (#Bug2). The name match is exact —
// not case-insensitive — so a differently-cased duplicate created by another
// principal in the same environment can never shadow the intended secret (#Bug3).
func (f *KeyorixFetcher) resolveID(ctx context.Context, env, name string) (uint, error) {
	envID, err := f.resolveEnvironmentID(ctx, env)
	if err != nil {
		return 0, err
	}

	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("project_id", strconv.FormatUint(uint64(f.projectID), 10))
		q.Set("environment_id", strconv.FormatUint(uint64(envID), 10))
		q.Set("page_size", strconv.Itoa(maxServerPageSize))
		q.Set("page", strconv.Itoa(page))

		var body struct {
			Secrets []struct {
				ID   uint   `json:"ID"`
				Name string `json:"Name"`
			} `json:"secrets"`
			TotalPages int `json:"total_pages"`
		}
		if err := f.getJSON(ctx, "/api/v1/secrets?"+q.Encode(), &body); err != nil {
			return 0, fmt.Errorf("list secrets in project %d environment %q (page %d): %w", f.projectID, env, page, err)
		}
		for _, s := range body.Secrets {
			if s.Name == name {
				return s.ID, nil
			}
		}
		if page >= body.TotalPages {
			break
		}
	}
	return 0, fmt.Errorf("secret %q not found in environment %q: %w", name, env, ErrUpstreamGone)
}

// resolveEnvironmentID resolves an environment NAME to its numeric id within this
// fetcher's fixed project (GET /api/v1/projects/{project_id}/environments — scoped to
// exactly one project, so it never has to search, or risk matching, an environment
// belonging to a different project). The full list is fetched once and cached for the
// life of the fetcher; a lookup miss triggers exactly one forced refresh (to pick up
// an environment created after the cache was first populated) before failing.
func (f *KeyorixFetcher) resolveEnvironmentID(ctx context.Context, name string) (uint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.envByName != nil && f.now().Sub(f.envCachedAt) < envCacheTTL {
		if id, ok := f.envByName[name]; ok {
			return id, nil
		}
	}
	if err := f.loadEnvironmentsLocked(ctx); err != nil {
		return 0, fmt.Errorf("resolve environment %q: %w", name, err)
	}
	if id, ok := f.envByName[name]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("environment %q not found in project %d: %w", name, f.projectID, ErrUpstreamGone)
}

// loadEnvironmentsLocked fetches every environment in this fetcher's project and
// (re)populates envByName. Caller must hold f.mu.
func (f *KeyorixFetcher) loadEnvironmentsLocked(ctx context.Context) error {
	var body struct {
		Environments []struct {
			ID   uint   `json:"ID"`
			Name string `json:"Name"`
		} `json:"environments"`
	}
	path := fmt.Sprintf("/api/v1/projects/%d/environments", f.projectID)
	if err := f.getJSON(ctx, path, &body); err != nil {
		return fmt.Errorf("list environments in project %d: %w", f.projectID, err)
	}
	m := make(map[string]uint, len(body.Environments))
	for _, e := range body.Environments {
		m[e.Name] = e.ID
	}
	f.envByName = m
	f.envCachedAt = f.now()
	return nil
}

// fetchValue returns the decrypted value of the secret with the given id and the
// secret's expiration (nil when it has none).
func (f *KeyorixFetcher) fetchValue(ctx context.Context, id uint) ([]byte, *time.Time, error) {
	var body struct {
		Value  string `json:"value"`
		Secret struct {
			Expiration *time.Time `json:"expiration"`
		} `json:"secret"`
	}
	if err := f.getJSON(ctx, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), &body); err != nil {
		return nil, nil, fmt.Errorf("read secret %d value: %w", id, err)
	}
	return []byte(body.Value), body.Secret.Expiration, nil
}

// getJSON performs an authenticated GET and decodes the {"data": …} envelope into out.
func (f *KeyorixFetcher) getJSON(ctx context.Context, path string, out interface{}) error {
	// f.baseURL is sourced from Config.KeyorixURL, already validated by
	// validateKeyorixURL at config-load time (Config.Validate) — but that validated
	// a different field read (the Config struct's own KeyorixURL), so this direct
	// read of f.baseURL is what a static analyzer needs to recognize the same
	// validation as covering this field too. Deliberately uses the more lenient
	// validateFetcherBaseURL, not validateKeyorixURL's stricter K8SSYNC-007
	// localhost-only rule -- this is a redundant defense-in-depth re-check on every
	// request, not the primary config-load gate, so it allows any loopback host
	// (matching this repo's convention elsewhere) rather than only "localhost".
	if err := validateFetcherBaseURL(f.baseURL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Accept", "application/json")

	resp, err := f.hc.Do(req)
	if err != nil {
		return classifyTransportError(err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusConflict {
		if err := secretStateRefusal(resp); err != nil {
			return err
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("not authorized (HTTP 401) — check the agent's token is valid and not expired or rotated: %w", ErrUnauthorized)
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("not authorized (HTTP 403) — check the agent's permissions: %w", ErrUpstreamGone)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("not found (HTTP 404): %w", ErrUpstreamGone)
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("server returned HTTP %d: %w", resp.StatusCode, ErrServerError)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&env); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if env.Data == nil {
		return fmt.Errorf("empty data in response")
	}
	return json.Unmarshal(env.Data, out)
}
