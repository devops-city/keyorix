// vault.go — the HashiCorp Vault read-through connector. GetSecret reads a path via
// Vault's HTTP API (GET {address}/v1/{ref}) with a token, and returns the secret's
// data as JSON. KV v2 is detected and unwrapped (the value lives under data.data).
//
// Implemented directly over net/http (no Vault SDK dependency): a KV read is a
// single authenticated GET. The token comes from an environment variable (trusted,
// like the other backends' ambient credentials), never from the request.
package connect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// vaultMaxResponseBytes caps the read body (a KV secret is small); guards a hostile/
// misbehaving endpoint.
const vaultMaxResponseBytes = 1 << 20 // 1 MiB

// VaultConnector reads secrets from HashiCorp Vault over its HTTP API.
type VaultConnector struct {
	name        string
	address     string // e.g. https://vault.example.com:8200
	token       string
	allowedRefs []string
	client      *http.Client

	// mountVersionsMu guards mountVersions: a per-connector cache of KV mount
	// version (1 or 2), keyed by the mount's own path as Vault reports it (e.g.
	// "secret/"). Populated by resolveKVMountVersion so a connector serving many
	// reads under the same mount(s) queries sys/internal/ui/mounts at most once
	// per distinct mount, not once per GetSecret call.
	mountVersionsMu sync.Mutex
	mountVersions   map[string]int
}

// NewVaultConnector builds a Vault connector. address is the Vault base URL; token
// is the Vault token (sourced from the environment by the caller). allowedRefs, when
// non-empty, restricts readable paths to those with one of the given prefixes.
func NewVaultConnector(name, address, token string, allowedRefs []string) *VaultConnector {
	return &VaultConnector{
		name:        name,
		address:     strings.TrimRight(address, "/"),
		token:       token,
		allowedRefs: allowedRefs,
		client: &http.Client{
			Timeout: 15 * time.Second,
			// Transport: connectGuardedDialer's link-local-refusing dialer (no
			// legitimate Vault deployment lives at IMDS/link-local, unlike general
			// RFC-1918/on-prem, which stays permitted) wrapped in
			// sizeCappedRoundTripper's post-decompression response-size cap
			// (hardened_client.go). Vault's own io.LimitReader below is kept too —
			// this is belt-and-suspenders at the same bound, not a replacement.
			// vaultBaseTransport() is Go's own stdlib default -- Vault never had
			// any SDK layer or custom transport tuning to preserve here.
			Transport: newConnectHardenedTransport(vaultBaseTransport()),
			// Refuse to follow any redirect. Go's default redirect policy strips
			// Authorization/Cookie/WWW-Authenticate on a cross-host hop, but
			// X-Vault-Token is a custom header it does NOT know to strip — so a
			// compromised or MITM'd Vault endpoint that answers with a 3xx to an
			// attacker-controlled host would otherwise receive the live Vault
			// token (#98). Vault's real KV-read API has no legitimate reason to
			// redirect a GET, so refusing outright is correct, not merely safe.
			CheckRedirect: refuseRedirect,
		},
	}
}

func (c *VaultConnector) Name() string { return c.name }
func (c *VaultConnector) Type() string { return "vault" }

// sanitizeVaultRef turns a caller-supplied Vault ref into a safe URL path. It
// rejects path-traversal (`.`/`..`) segments and control characters, then
// percent-escapes each remaining segment (neutralizing `?`, `#`, spaces, etc.) and
// rejoins them with `/`. The result can only address the literal path the ref
// names — it cannot climb out of an allowed_refs prefix or inject a query string.
func sanitizeVaultRef(ref string) (string, error) {
	clean := make([]string, 0, 8)
	for seg := range strings.SplitSeq(strings.TrimLeft(ref, "/"), "/") {
		if seg == "" {
			continue // collapse empty/duplicate slashes
		}
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("vault: ref %q must not contain path-traversal segments", ref)
		}
		for _, r := range seg {
			if r < 0x20 || r == 0x7f {
				return "", fmt.Errorf("vault: ref %q contains a control character", ref)
			}
		}
		clean = append(clean, url.PathEscape(seg))
	}
	if len(clean) == 0 {
		return "", fmt.Errorf("vault: ref %q has no usable path", ref)
	}
	return strings.Join(clean, "/"), nil
}

// CheckTokenTTL performs a token self-lookup and returns the remaining TTL in
// seconds. Returns (0, false, nil) for root tokens (TTL = 0). Returns an error if the
// lookup fails or the token is invalid.
func (c *VaultConnector) CheckTokenTTL(ctx context.Context) (ttlSeconds int, renewable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.address+"/v1/auth/token/lookup-self", nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, false, fmt.Errorf("vault: token TTL lookup failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, vaultMaxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("vault: token lookup returned %d", resp.StatusCode)
	}
	var result struct {
		Data struct {
			TTL       int  `json:"ttl"`
			Renewable bool `json:"renewable"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, false, fmt.Errorf("vault: token lookup parse error: %w", err)
	}
	return result.Data.TTL, result.Data.Renewable, nil
}

// validateConnectorURL checks that a connector destination is a well-formed absolute
// http(s) URL. Deliberately does NOT reject private/loopback hosts: Vault connectors
// are admin-configured and commonly point at on-prem/private-network instances by
// design (#1390 already deferred adding an IP-blocking check here as a separate
// product decision) -- this only rejects a malformed or non-HTTP(S) destination
// (e.g. a "file://" or garbled address) reaching the outbound client.
func validateConnectorURL(address string) error {
	u, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("vault: invalid connector address %q: %w", address, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("vault: connector address %q must use http or https", address)
	}
	if u.Host == "" {
		return fmt.Errorf("vault: connector address %q is missing a host", address)
	}
	return nil
}

// resolveKVMountVersion determines whether the KV mount serving safeRef is v1 or
// v2 by querying Vault's sys/internal/ui/mounts/<path> API directly (the
// endpoint Vault's own CLI/UI use for this exact purpose), instead of
// inferring it from the shape of a secret-read response. Response-shape
// sniffing has two concrete failure modes it replaces: (1) a genuine KV v1
// secret whose own stored fields happen to be literally named "data" and
// "metadata" is misdetected as v2, silently discarding every other field; (2)
// a soft-deleted KV v2 secret (`{"data": null, "metadata": {...}}`) fails a
// naive non-empty check on "data" and falls through to returning Vault's
// entire internal envelope as if it were the plaintext secret. Querying the
// mount directly has neither failure mode: the version is a property of the
// MOUNT, never the stored data.
//
// Results are cached per mount path (as Vault itself reports it, e.g.
// "secret/") for this connector's lifetime — the KV version of a live mount
// essentially never changes, and a connector is typically used repeatedly
// across many reads under the same mount(s), so this keeps the common case to
// one extra round-trip per distinct mount rather than one per read.
func (c *VaultConnector) resolveKVMountVersion(ctx context.Context, safeRef string) (int, error) {
	c.mountVersionsMu.Lock()
	for mountPath, version := range c.mountVersions {
		if strings.HasPrefix(safeRef, mountPath) {
			c.mountVersionsMu.Unlock()
			return version, nil
		}
	}
	c.mountVersionsMu.Unlock()

	reqURL := c.address + "/v1/sys/internal/ui/mounts/" + safeRef
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, fmt.Errorf("vault: new mount-info request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("vault: mount-info lookup failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, vaultMaxResponseBytes))
		return 0, fmt.Errorf("vault: mount-info lookup for %q returned HTTP %d", safeRef, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, vaultMaxResponseBytes))
	if err != nil {
		return 0, fmt.Errorf("vault: read response: %w", err)
	}

	var mountResp struct {
		Data struct {
			Path    string `json:"path"`
			Options struct {
				Version string `json:"version"`
			} `json:"options"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &mountResp); err != nil {
		return 0, fmt.Errorf("vault: parse mount-info response: %w", err)
	}

	version := 1
	if mountResp.Data.Options.Version == "2" {
		version = 2
	}
	mountPath := mountResp.Data.Path
	if mountPath == "" {
		// Should not normally happen for a real Vault response, but fall back to
		// caching under the exact ref rather than caching nothing, so a repeat
		// lookup of the identical ref is still free.
		mountPath = safeRef
	}
	c.mountVersionsMu.Lock()
	if c.mountVersions == nil {
		c.mountVersions = make(map[string]int)
	}
	c.mountVersions[mountPath] = version
	c.mountVersionsMu.Unlock()
	return version, nil
}

func (c *VaultConnector) GetSecret(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("vault: secret reference (path) is required, e.g. secret/data/myapp")
	}
	if !prefixAllowed(c.allowedRefs, ref) {
		return "", fmt.Errorf("vault: ref %q is not permitted by this connector's allowed_refs", ref)
	}
	if c.address == "" {
		return "", fmt.Errorf("vault: connector address is not configured")
	}
	if err := validateConnectorURL(c.address); err != nil {
		return "", err
	}
	if err := validateConnectorAddressNotLinkLocal("vault", c.address); err != nil {
		return "", err
	}
	if c.token == "" {
		return "", fmt.Errorf("vault: no token configured (set the connector's token_env)")
	}

	// The ref is caller-supplied (the ?ref= query param / gRPC field). It is
	// concatenated into the Vault API path, so it must be sanitized before building
	// the URL: a prefix allowlist alone is a start-only HasPrefix check that does NOT
	// stop `secret/team-a/../../sys/...` from climbing to another Vault path, nor
	// `secret/x?list=true` from injecting a query string. Reject traversal/control
	// characters and percent-escape each path segment so metacharacters become
	// literals and the ref can only ever address the path the allowlist permitted.
	safeRef, err := sanitizeVaultRef(ref)
	if err != nil {
		return "", err
	}

	// Determine KV v1 vs v2 explicitly, via Vault's own mount-info API, before
	// ever looking at the secret response's shape (see resolveKVMountVersion's
	// doc comment for the two concrete bugs this replaces).
	kvVersion, err := c.resolveKVMountVersion(ctx, safeRef)
	if err != nil {
		return "", fmt.Errorf("vault: could not determine KV mount version for %q: %w", ref, err)
	}

	reqURL := c.address + "/v1/" + safeRef
	// The query traces this sink's taint back to server/http/handlers/connect.go's
	// r.URL.Query().Get("ref") (an incoming-request field that happens to match
	// the query's url/host/dsn/webhook/callback field-name heuristic) via this
	// function's ref parameter -- but ref only ever contributes a PATH SEGMENT
	// appended after c.address (itself validated above by validateConnectorURL),
	// never the request's host/scheme, and sanitizeVaultRef above rejects
	// traversal/control characters and percent-escapes the rest, so it cannot
	// reinterpret the URL's structure either. Not a real unvalidated destination --
	// a coincidental name match on net/http.Request.URL. The codeql[...] tag MUST
	// be the single comment line directly above the sink (CodeQL's
	// AlertSuppression.qll requires the comment's own end line == alert line - 1);
	// splitting the justification above and keeping this line alone is
	// deliberate, not style.
	// codeql[go/keyorix-ssrf-unvalidated-outbound-request]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("vault: new request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: get %q: %w", ref, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, vaultMaxResponseBytes))
		return "", fmt.Errorf("vault: %s returned HTTP %d for %q", c.address, resp.StatusCode, ref)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, vaultMaxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("vault: read response: %w", err)
	}

	// Vault wraps the secret under "data". KV v2 nests it again under data.data
	// (alongside data.metadata); KV v1 puts the secret map directly under data.
	// Which shape to expect is now decided by kvVersion (resolved above via
	// Vault's own mount-info API), never by sniffing which fields happen to be
	// present in the response — see resolveKVMountVersion's doc comment for why
	// shape-sniffing is unsafe.
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 {
		return "", fmt.Errorf("vault: secret %q has no data", ref)
	}
	if kvVersion == 1 {
		return string(env.Data), nil // KV v1: the data map itself, whatever fields it contains
	}

	// KV v2: unwrap data.data. A soft-deleted (but not yet destroyed) version
	// reads back as `{"data": null, "metadata": {...}}` — a 200 OK, not a 404 —
	// so it must be handled explicitly here as "not found," not returned as if
	// the null were the plaintext secret value or, worse, the whole envelope
	// (including Vault's internal version/deletion-time metadata) mistaken for
	// the secret.
	var kv2 struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(env.Data, &kv2); err != nil {
		return "", fmt.Errorf("vault: parse KV v2 envelope for %q: %w", ref, err)
	}
	if len(kv2.Data) == 0 || string(kv2.Data) == "null" {
		return "", fmt.Errorf("vault: secret %q not found (KV v2 version has no data — likely deleted or destroyed)", ref)
	}
	return string(kv2.Data), nil
}
