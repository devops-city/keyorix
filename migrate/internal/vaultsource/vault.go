// Package vaultsource reads a HashiCorp Vault (or OpenBao) KV tree over Vault's HTTP API —
// no Vault SDK dependency, matching cli/cmd/secret/source_vault.go and
// internal/connect/vault.go's precedent of a small hand-rolled client for a KV read/list.
// This tool needs more than either existing client: recursive-tree KV v1/v2 walk (ported from
// source_vault.go), mount-version resolution via Vault's own mounts API rather than
// response-shape sniffing (ported from internal/connect/vault.go, see resolveKVMountVersion's
// doc comment), plus AppRole auth and Vault Enterprise/OpenBao namespace support (new — neither
// existing client has either). See docs/design-keyorix-migrate.md's "Vault client" section for
// which parts are ported vs. new.
package vaultsource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// clientTimeout bounds every request this client makes to a configured Vault server, matching
// source_vault.go's vaultClientTimeout precedent (#G71 sibling).
const clientTimeout = 30 * time.Second

// maxResponseBytes caps how much of a Vault HTTP response body this client reads into memory,
// matching source_vault.go's maxVaultResponseBytes precedent -- generous enough for large KV
// trees/secrets, still bounded against a malicious or misbehaving Vault response.
const maxResponseBytes = 10 << 20 // 10MB

// Config holds every connection/auth setting a Client needs. Exactly one of Token or
// (RoleID, SecretID) must be set; namespace and KV version are optional (KV version is
// auto-detected per mount when zero, via resolveKVMountVersion).
type Config struct {
	Addr      string
	Namespace string // Vault Enterprise / OpenBao; sent as X-Vault-Namespace on every request.
	Mount     string // KV mount path, e.g. "secret".

	Token string // direct token auth.

	RoleID   string // AppRole auth (used when Token == "").
	SecretID string

	// CACertPath / CACertDir configure the TLS trust root for an on-prem or air-gapped Vault
	// signed by an internal CA (PR #2077 review item 1) -- matching Vault's own $VAULT_CACERT/
	// $VAULT_CAPATH convention. When either is set, RootCAs is built ONLY from the given
	// cert(s), replacing (not appending to) the system trust store -- pinning to a specific CA
	// is the point, the same reason validateConnectorURL-adjacent code in this repo never adds
	// a skip-verify escape hatch. Deliberately NO InsecureSkipVerify option exists anywhere in
	// this package.
	CACertPath string
	CACertDir  string
}

// Client talks to a Vault KV engine over HTTP.
type Client struct {
	addr      string
	namespace string
	mount     string
	token     string
	hc        *http.Client

	// mountVersionsMu guards mountVersions: a per-client cache of KV mount version (1 or 2),
	// keyed by the mount path Vault itself reports (e.g. "secret/") — ported from
	// internal/connect/vault.go's resolveKVMountVersion, see its doc comment there for why
	// querying the mount directly (not sniffing response shape) is required for correctness,
	// not just a performance nicety.
	mountVersionsMu sync.Mutex
	mountVersions   map[string]int
}

// New builds a Client, performing AppRole login immediately if configured (so a bad
// role-id/secret-id fails fast at startup, not on the first KV read).
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("vault address is required (--vault-addr or $VAULT_ADDR)")
	}
	if cfg.Token == "" && (cfg.RoleID == "" || cfg.SecretID == "") {
		return nil, fmt.Errorf("vault auth is required: --vault-token/$VAULT_TOKEN, or both --vault-role-id and --vault-secret-id")
	}

	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{
		Timeout: clientTimeout,
		// No redirect is legitimate for a fixed, operator-supplied Vault address — see
		// source_vault.go's refuseVaultRedirect / internal/connect/vault.go's
		// refuseRedirect for the shared rationale (a compromised/misconfigured Vault
		// must never receive the live token via a followed 3xx to another host).
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if tlsConfig != nil {
		hc.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	c := &Client{
		addr:      strings.TrimRight(cfg.Addr, "/"),
		namespace: cfg.Namespace,
		mount:     strings.Trim(cfg.Mount, "/"),
		hc:        hc,
	}

	if cfg.Token != "" {
		c.token = cfg.Token
		return c, nil
	}
	token, err := c.appRoleLogin(ctx, cfg.RoleID, cfg.SecretID)
	if err != nil {
		return nil, fmt.Errorf("vault AppRole login: %w", err)
	}
	c.token = token
	return c, nil
}

// buildTLSConfig returns nil (use Go's default system trust store) when neither CACertPath nor
// CACertDir is set, or a *tls.Config whose RootCAs is built EXCLUSIVELY from the given
// cert(s) otherwise — matching Vault's own $VAULT_CACERT/$VAULT_CAPATH semantics (pin to a
// specific CA, don't merge with the system store). See Config's doc comment for why this
// package has no skip-verify escape hatch.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.CACertPath == "" && cfg.CACertDir == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath) // #nosec G304 -- operator-supplied CA cert path, a CLI flag, not user/network input
		if err != nil {
			return nil, fmt.Errorf("read --vault-cacert %q: %w", cfg.CACertPath, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--vault-cacert %q contains no usable PEM certificates", cfg.CACertPath)
		}
	}
	if cfg.CACertDir != "" {
		entries, err := os.ReadDir(cfg.CACertDir)
		if err != nil {
			return nil, fmt.Errorf("read --vault-capath %q: %w", cfg.CACertDir, err)
		}
		loaded := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			pem, err := os.ReadFile(filepath.Join(cfg.CACertDir, e.Name())) // #nosec G304 -- operator-supplied CA directory, a CLI flag, not user/network input
			if err != nil {
				return nil, fmt.Errorf("read %q in --vault-capath: %w", e.Name(), err)
			}
			if pool.AppendCertsFromPEM(pem) {
				loaded++
			}
		}
		if loaded == 0 {
			return nil, fmt.Errorf("--vault-capath %q contains no usable PEM certificates", cfg.CACertDir)
		}
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// appRoleLogin exchanges an AppRole role-id/secret-id pair for a client token via
// POST {addr}/v1/auth/approle/login. New code — neither source_vault.go nor
// internal/connect/vault.go supports AppRole; both are token-only.
func (c *Client) appRoleLogin(ctx context.Context, roleID, secretID string) (string, error) {
	body, err := json.Marshal(struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}{RoleID: roleID, SecretID: secretID})
	if err != nil {
		return "", fmt.Errorf("build AppRole login body: %w", err)
	}

	reqURL := c.addr + "/v1/auth/approle/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("build AppRole login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setCommonHeaders(req, "")

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("AppRole login request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("AppRole login returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&result); err != nil {
		return "", fmt.Errorf("decode AppRole login response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("AppRole login response carried no client_token")
	}
	return result.Auth.ClientToken, nil
}

// setCommonHeaders sets the token (when non-empty) and namespace headers every request needs.
// token is passed explicitly rather than always using c.token so appRoleLogin (which runs
// before c.token is set) can share this helper.
func (c *Client) setCommonHeaders(req *http.Request, token string) {
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	req.Header.Set("Accept", "application/json")
}

// Entry is one Vault KV field, ready to become a Keyorix secret. Path is the KV path (without
// mount) the value was read from; Field is the KV field name ("value" for a single-field
// leaf's own sentinel field, mirroring source_vault.go's readLeaf convention). Metadata carries
// Vault's own custom_metadata (KV v2 only) for mapping into Keyorix's metadata. Version and
// CreatedAt are KV v2's own version number and its created_time (RFC3339) -- zero/empty for
// KV v1, which has no version history. Andrei's 2026-09-25 decision (docs/design-keyorix-migrate.md
// "All-versions import (deferred)"): every imported secret records which source version it
// came from, even though only the latest version is ever imported.
type Entry struct {
	Path      string
	Field     string
	Value     string
	Metadata  map[string]string
	Version   int
	CreatedAt string
}

// Skipped is one KV leaf (or, for a multi-field leaf, one "path#field") Walk found but did not
// import, with a human-readable reason. Produced for a KV v2 leaf whose latest version is
// soft-deleted or destroyed (Andrei's 2026-09-25 decision: these must be reported, not silently
// dropped), and for a leaf with no fields or a field with an empty value or name (#2543, same
// rule).
type Skipped struct {
	Path   string
	Reason string
}

// SourceID is a stable identifier for this entry within this Vault, used as
// docs/design-keyorix-migrate.md's idempotency key. It intentionally excludes the token/
// credentials — only the address, mount, KV version and path/field identify "where this data
// came from," which is what must stay stable across runs with different auth.
func (e Entry) SourceID(addr, mount string, kvVersion int) string {
	field := e.Field
	if field == "" {
		field = "value"
	}
	return fmt.Sprintf("%s|%s|kv%d|%s|%s", strings.TrimRight(addr, "/"), strings.Trim(mount, "/"), kvVersion, e.Path, field)
}

// Walk recursively lists the KV tree under root and returns every field as an Entry, plus every
// leaf that was found but not imported (skipped, with a reason). allVersions=false (the
// default) reads only the current version of each leaf; allVersions=true is not yet supported
// (see docs/design-keyorix-migrate.md's "All-versions import (deferred)") and returns an error
// rather than silently behaving like allVersions=false.
func (c *Client) Walk(ctx context.Context, root string, allVersions bool) ([]Entry, []Skipped, error) {
	if allVersions {
		return nil, nil, fmt.Errorf("--all-versions is not yet supported (see docs/design-keyorix-migrate.md's \"All-versions import (deferred)\" — Keyorix's secret-version-create API isn't wired into this tool yet); omit the flag to import the latest version of each secret")
	}
	var entries []Entry
	var skipped []Skipped
	if err := c.walk(ctx, strings.Trim(root, "/"), &entries, &skipped); err != nil {
		return nil, nil, err
	}
	return entries, skipped, nil
}

func (c *Client) walk(ctx context.Context, prefix string, out *[]Entry, skipped *[]Skipped) error {
	keys, err := c.list(ctx, prefix)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return c.readLeaf(ctx, prefix, out, skipped)
	}
	for _, k := range keys {
		var child string
		if prefix != "" {
			child = prefix + "/" + strings.TrimSuffix(k, "/")
		} else {
			child = strings.TrimSuffix(k, "/")
		}
		if strings.HasSuffix(k, "/") {
			if err := c.walk(ctx, child, out, skipped); err != nil {
				return err
			}
			continue
		}
		if err := c.readLeaf(ctx, child, out, skipped); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) readLeaf(ctx context.Context, path string, out *[]Entry, skipped *[]Skipped) error {
	r, err := c.read(ctx, path)
	if err != nil {
		return err
	}
	if r.skipReason != "" {
		*skipped = append(*skipped, Skipped{Path: path, Reason: r.skipReason})
		return nil
	}
	if r.fields == nil {
		return nil // never existed / 404 — nothing to report, not a skip.
	}
	if len(r.fields) == 0 {
		// The leaf exists (a 200 read decoded a non-null, empty data object) but holds no
		// fields at all — reported, not silently dropped (#2543).
		*skipped = append(*skipped, Skipped{Path: path, Reason: emptyLeafSkipReason})
		return nil
	}
	if len(r.fields) == 1 {
		if v, ok := r.fields["value"]; ok {
			if isEmptyFieldValue(v) {
				*skipped = append(*skipped, Skipped{Path: path, Reason: emptyValueSkipReason})
				return nil
			}
			*out = append(*out, Entry{Path: path, Field: "", Value: fmt.Sprintf("%v", v), Metadata: r.metadata, Version: r.version, CreatedAt: r.createdAt})
			return nil
		}
	}
	for k, v := range r.fields {
		if k == "" {
			*skipped = append(*skipped, Skipped{Path: path + "#", Reason: emptyFieldNameSkipReason})
			continue
		}
		if isEmptyFieldValue(v) {
			*skipped = append(*skipped, Skipped{Path: path + "#" + k, Reason: emptyValueSkipReason})
			continue
		}
		*out = append(*out, Entry{Path: path, Field: k, Value: fmt.Sprintf("%v", v), Metadata: r.metadata, Version: r.version, CreatedAt: r.createdAt})
	}
	return nil
}

// emptyValueSkipReason / emptyFieldNameSkipReason are the Skipped reasons for a KV field this
// tool cannot carry over faithfully (#2543). Keyorix has no empty-value secret to map an empty
// Vault value onto, and a field with no name has no target name to derive -- so both are
// refused, but always reported in the plan/report, never silently dropped: an absent row is
// indistinguishable from a path that never existed.
const (
	emptyValueSkipReason     = "field has an empty value (Keyorix cannot store an empty secret) — not imported"
	emptyFieldNameSkipReason = "field has an empty name (no Keyorix secret name can be derived) — not imported"
	emptyLeafSkipReason      = "secret has no fields (nothing to import)"
)

// isEmptyFieldValue reports whether a decoded KV field value carries no data: the empty string
// or a JSON null. A null is treated as empty rather than stringified, since fmt's "%v" would
// otherwise import it as the literal text "<nil>".
func isEmptyFieldValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && s == ""
}

// list returns the child keys at path (sub-paths end in "/"); a 404 means path is not a
// listable folder and yields no keys.
func (c *Client) list(ctx context.Context, path string) ([]string, error) {
	kvVersion, err := c.resolveKVMountVersion(ctx, path)
	if err != nil {
		return nil, err
	}
	reqURL := c.metadataURL(path, kvVersion) + "?list=true"
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := c.do(ctx, http.MethodGet, reqURL, &body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	return body.Data.Keys, nil
}

// readResult is what read() found at one KV leaf path.
type readResult struct {
	fields    map[string]any
	metadata  map[string]string
	version   int
	createdAt string
	// skipReason is non-empty when the leaf's latest version is soft-deleted or destroyed
	// (KV v2 only) -- fields/metadata/version/createdAt are meaningless in that case.
	skipReason string
}

// read returns what's at a KV leaf path. A 404 (the path never held a secret) yields a zero
// readResult with no error and no skipReason -- there is nothing to report. A KV v2 leaf whose
// latest version is soft-deleted or destroyed is a 200 OK with null data (see the comment
// below); read reports it via skipReason rather than silently treating it as absent, per
// Andrei's 2026-09-25 decision.
func (c *Client) read(ctx context.Context, path string) (readResult, error) {
	kvVersion, err := c.resolveKVMountVersion(ctx, path)
	if err != nil {
		return readResult{}, err
	}
	// A soft-deleted or destroyed KV v2 version's data read is HTTP 404, not 200 -- verified
	// directly against a real Vault 1.15 server (the body carries the same {"data": null,
	// "metadata": {...}} envelope a 200 read would, just under a 404 status). The existing
	// comments in internal/connect/vault.go's GetSecret and cli/cmd/secret/source_vault.go
	// claiming "200 OK, not 404" for this case do not match observed behavior -- this package
	// does not inherit that assumption; it reads the body on both 200 and 404 and lets the
	// decoded metadata (not the status code) decide what happened. A genuinely nonexistent
	// path is also a 404, but with an {"errors":[]} body carrying no "data" key at all.
	status, raw, err := c.doRawRead(ctx, c.dataURL(path, kvVersion))
	if err != nil {
		return readResult{}, err
	}

	if kvVersion == 1 {
		if status == http.StatusNotFound {
			return readResult{}, nil // KV v1 has no version history; 404 always means absent.
		}
		var v1 struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &v1); err != nil {
			return readResult{}, fmt.Errorf("decode vault read %q: %w", path, err)
		}
		return readResult{fields: v1.Data}, nil
	}

	// KV v2: the secret lives at data.data; data.metadata carries the version number,
	// created_time, custom_metadata, and (when the latest version has no live data)
	// deletion_time/destroyed. Unmarshaling a genuinely-absent path's {"errors":[]} body into
	// this struct leaves every field at its zero value (no "data" key to match), which is
	// exactly how "never existed" is told apart from "soft-deleted"/"destroyed" below: the
	// former has an all-zero metadata, the latter always has at least Version set (Vault
	// version numbers start at 1).
	var v2 struct {
		Data struct {
			Data     json.RawMessage `json:"data"`
			Metadata struct {
				CustomMetadata map[string]string `json:"custom_metadata"`
				Version        int               `json:"version"`
				CreatedTime    string            `json:"created_time"`
				DeletionTime   string            `json:"deletion_time"`
				Destroyed      bool              `json:"destroyed"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &v2); err != nil {
		return readResult{}, fmt.Errorf("decode vault read %q: %w", path, err)
	}
	meta := v2.Data.Metadata
	if len(v2.Data.Data) == 0 || string(v2.Data.Data) == "null" {
		if meta.Version == 0 && meta.DeletionTime == "" && !meta.Destroyed {
			return readResult{}, nil // genuinely absent -- no metadata at all.
		}
		reason := fmt.Sprintf("version %d has no live data", meta.Version)
		switch {
		case meta.Destroyed:
			reason = fmt.Sprintf("version %d was destroyed", meta.Version)
		case meta.DeletionTime != "":
			reason = fmt.Sprintf("version %d was soft-deleted at %s", meta.Version, meta.DeletionTime)
		}
		return readResult{skipReason: reason}, nil
	}
	var fields map[string]any
	if err := json.Unmarshal(v2.Data.Data, &fields); err != nil {
		return readResult{}, fmt.Errorf("decode vault KV v2 fields %q: %w", path, err)
	}
	return readResult{
		fields:    fields,
		metadata:  meta.CustomMetadata,
		version:   meta.Version,
		createdAt: meta.CreatedTime,
	}, nil
}

// doRawRead issues an authenticated GET and returns the raw response body alongside the HTTP
// status, for both 200 and 404 (read's own logic needs the 404 body — see read's doc comment).
// Any other status is still treated as an error, matching do()'s convention.
func (c *Client) doRawRead(ctx context.Context, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	c.setCommonHeaders(req, c.token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusForbidden {
		return resp.StatusCode, nil, fmt.Errorf("vault denied access (HTTP 403) for %s — check token/AppRole permissions", url)
	}
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		return resp.StatusCode, nil, fmt.Errorf("vault returned HTTP %d for %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// resolveKVMountVersion determines whether the mount serving path is KV v1 or v2 by querying
// Vault's sys/internal/ui/mounts/<path> API directly, exactly as internal/connect/vault.go
// does (ported unchanged — see that file's doc comment for the two response-shape-sniffing
// bugs this avoids: a v1 secret whose own fields are literally named "data"/"metadata", and a
// soft-deleted v2 version's null-data envelope). Cached per mount path for this Client's
// lifetime.
func (c *Client) resolveKVMountVersion(ctx context.Context, path string) (int, error) {
	c.mountVersionsMu.Lock()
	for mountPath, version := range c.mountVersions {
		if strings.HasPrefix(path, mountPath) || path == strings.TrimSuffix(mountPath, "/") {
			c.mountVersionsMu.Unlock()
			return version, nil
		}
	}
	c.mountVersionsMu.Unlock()

	full := c.mount
	if path != "" {
		full = c.mount + "/" + path
	}
	reqURL := c.addr + "/v1/sys/internal/ui/mounts/" + escapePath(full)
	var mountResp struct {
		Data struct {
			Path    string `json:"path"`
			Options struct {
				Version string `json:"version"`
			} `json:"options"`
		} `json:"data"`
	}
	if _, err := c.do(ctx, http.MethodGet, reqURL, &mountResp); err != nil {
		return 0, fmt.Errorf("resolve KV mount version for %q: %w", path, err)
	}

	version := 1
	if mountResp.Data.Options.Version == "2" {
		version = 2
	}
	mountPath := mountResp.Data.Path
	if mountPath == "" {
		mountPath = c.mount + "/"
	}
	c.mountVersionsMu.Lock()
	if c.mountVersions == nil {
		c.mountVersions = make(map[string]int)
	}
	c.mountVersions[mountPath] = version
	c.mountVersionsMu.Unlock()
	return version, nil
}

// do issues an authenticated request and decodes a non-404 success body into out (when out is
// non-nil), returning the HTTP status so callers can treat 404 as "absent."
func (c *Client) do(ctx context.Context, method, url string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	c.setCommonHeaders(req, c.token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return resp.StatusCode, nil
	}
	if resp.StatusCode == http.StatusForbidden {
		return resp.StatusCode, fmt.Errorf("vault denied access (HTTP 403) for %s — check token/AppRole permissions", url)
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("vault returned HTTP %d for %s", resp.StatusCode, url)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return resp.StatusCode, nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("decode vault response: %w", err)
	}
	return resp.StatusCode, nil
}

func (c *Client) metadataURL(path string, kvVersion int) string {
	if kvVersion == 2 {
		return c.join("metadata", path)
	}
	return c.join("", path)
}

func (c *Client) dataURL(path string, kvVersion int) string {
	if kvVersion == 2 {
		return c.join("data", path)
	}
	return c.join("", path)
}

// join assembles {addr}/v1/{mount}[/{segment}]/{path}, path-escaping the mount and path
// components per segment — ported from source_vault.go's join/escapePath, same rationale
// (Vault permits URL-significant characters in secret/key names; escaping keeps them literal
// instead of mangling the request).
func (c *Client) join(segment, path string) string {
	parts := []string{c.addr, "v1", escapePath(c.mount)}
	if segment != "" {
		parts = append(parts, segment)
	}
	if p := escapePath(path); p != "" {
		parts = append(parts, p)
	}
	return strings.Join(parts, "/")
}

func escapePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
