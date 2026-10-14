// Package mcp implements a Model Context Protocol (MCP) server that exposes read-only
// Keyorix secret access to an AI agent over stdio (ADR-061). It is a thin, audited proxy
// in front of the Keyorix API: every call carries a least-privilege machine-identity
// token and is subject to Keyorix's scoped permission, max_reads, suspension, and audit.
// Secret values are never logged.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KeyorixClient reads secrets from a Keyorix server with a bearer (machine-identity)
// token. It satisfies SecretReader.
type KeyorixClient struct {
	baseURL string
	token   string
	hc      *http.Client
}

// NewKeyorixClient builds a client for the given Keyorix base URL and bearer token.
// Rejects a non-https baseURL unless the host is loopback (#122): every read carries
// the bearer token in its Authorization header AND returns a plaintext secret value in
// its response body, so an http:// endpoint (misconfiguration, or a MITM downgrading a
// redirect) ships both in cleartext over the network. Mirrors the same
// https-except-loopback rule already enforced for KEYORIX_URL-style bearer-token
// clients elsewhere (internal/k8ssync/config.go, internal/storage/remote/config.go).
func NewKeyorixClient(baseURL, token string) (*KeyorixClient, error) {
	if err := validateKeyorixClientURL(baseURL); err != nil {
		return nil, err
	}
	c := &KeyorixClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc:      &http.Client{Timeout: 30 * time.Second, CheckRedirect: refuseRedirect},
	}
	// Re-validate via a direct read of c.baseURL (not just the constructor's baseURL
	// parameter above): a CodeQL static-analysis limitation can't connect a validator
	// call on a parameter to a later read of the field it was stored into, so without
	// this second, field-level call every c.baseURL read downstream (getJSON below)
	// is indistinguishable from an unvalidated destination to that analysis.
	if err := validateKeyorixClientURL(c.baseURL); err != nil {
		return nil, err
	}
	return c, nil
}

// refuseRedirect blocks the http.Client from following ANY redirect. Go's default
// redirect behavior only strips the Authorization header when the redirect target's
// Host differs from the original — it never checks scheme. A same-host redirect from
// https:// to http:// (a misconfigured reverse proxy in front of the Keyorix server, or
// a compromised server) would otherwise keep this client's bearer token attached and
// send it — and the plaintext secret value in the response — over cleartext.
// validateKeyorixClientURL above already refuses a non-loopback http:// baseURL up front, but
// that only checks the INITIAL request's scheme; Go's redirect-following would still
// happily downgrade mid-request without this. This client only ever talks to a single,
// fixed, caller-supplied KEYORIX_URL and has no legitimate reason to follow a redirect
// at all, so refusing every redirect outright is the simplest and safest fix.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("keyorix: refusing to follow redirect to %q", req.URL)
}

// validateKeyorixClientURL rejects a Keyorix base URL that is not https (http is allowed only
// for a loopback host — local development/testing against a Keyorix instance running
// on the same machine as the MCP server).
func validateKeyorixClientURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid KEYORIX_URL %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("KEYORIX_URL %q must use https (http is allowed only for localhost): the bearer token and every secret value read through it would otherwise travel in plaintext", raw)
	default:
		return fmt.Errorf("KEYORIX_URL %q must use https", raw)
	}
}

// SecretInfo is a discovery entry: a usable reference plus minimal metadata (no value).
type SecretInfo struct {
	Ref  string `json:"ref"`
	Type string `json:"type,omitempty"`
}

// GetSecret returns the value of the secret referenced by "project/environment/name"
// via the by-reference read endpoint (ADR-059).
func (c *KeyorixClient) GetSecret(ctx context.Context, ref string) (string, error) {
	q := url.Values{}
	q.Set("ref", ref)
	var body struct {
		Value string `json:"value"`
	}
	if err := c.getJSON(ctx, "/api/v1/secrets/value?"+q.Encode(), &body); err != nil {
		return "", err
	}
	return body.Value, nil
}

// ListSecrets returns the references the token can see, optionally filtered to one
// environment. Metadata only — no values are read. Capped at one page (100).
// The second return value is true when the server returned a full page (≥100 entries),
// indicating that results may be incomplete (MCP-005).
func (c *KeyorixClient) ListSecrets(ctx context.Context, environment string) ([]SecretInfo, bool, error) {
	var body struct {
		Secrets []struct {
			Name            string `json:"Name"`
			Type            string `json:"Type"`
			ProjectName     string `json:"project_name"`
			EnvironmentName string `json:"environment_name"`
		} `json:"secrets"`
	}
	if err := c.getJSON(ctx, "/api/v1/secrets?page_size=100", &body); err != nil {
		return nil, false, err
	}
	truncated := len(body.Secrets) >= 100
	out := make([]SecretInfo, 0, len(body.Secrets))
	for _, s := range body.Secrets {
		if environment != "" && !strings.EqualFold(s.EnvironmentName, environment) {
			continue
		}
		if s.ProjectName == "" || s.EnvironmentName == "" || s.Name == "" {
			continue // can't form an unambiguous ref without all three parts
		}
		out = append(out, SecretInfo{
			Ref:  s.ProjectName + "/" + s.EnvironmentName + "/" + s.Name,
			Type: s.Type,
		})
	}
	return out, truncated, nil
}

// getJSON performs an authenticated GET and decodes the {"data": …} envelope into out.
// secretStateRefusal returns a fixed description of a 403/409 whose envelope names a
// secret-state refusal of a value read (server/http/handlers/openapi.yaml,
// SecretReadRefused; ERRMAP-1), or "" for any other body. The token is fine in these
// cases, so "not authorized" would send the assistant after the wrong fix. The text
// is local, never the server's.
func secretStateRefusal(resp *http.Response) string {
	var env struct {
		Error string `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&env) != nil {
		return ""
	}
	return map[string]string{
		"SecretAccessOutsideSchedule": "the secret is outside its access schedule (SecretAccessOutsideSchedule)",
		"SecretExpired":               "the secret has expired (SecretExpired)",
		"SecretSuspended":             "the secret is suspended (SecretSuspended)",
		"SecretMaxReadsExhausted":     "the secret has reached its maximum number of reads (SecretMaxReadsExhausted)",
	}[env.Error]
}

func (c *KeyorixClient) getJSON(ctx context.Context, path string, out any) error {
	// c.hc (built in NewKeyorixClient above) already sets CheckRedirect to
	// refuseRedirect, and c.baseURL is scheme-validated by validateKeyorixClientURL in
	// NewKeyorixClient (both the constructor parameter AND a direct c.baseURL
	// field read, so this destination is validated by the query's own model too).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusConflict {
		if reason := secretStateRefusal(resp); reason != "" {
			return fmt.Errorf("%s (HTTP %d)", reason, resp.StatusCode)
		}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("not authorized (HTTP %d) — check the token and its secrets.read permission", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("not found")
	case resp.StatusCode == http.StatusBadRequest:
		return fmt.Errorf("invalid request (want a project/environment/name reference)")
	case resp.StatusCode >= 400:
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&env); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if env.Data == nil {
		return fmt.Errorf("empty data in response")
	}
	return json.Unmarshal(env.Data, out)
}
