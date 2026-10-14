// kubernetes.go — the Kubernetes dynamic-secret backend (ADR-035, cloud-IAM): mints a
// short-lived ServiceAccount token via the Kubernetes TokenRequest API
// (POST …/serviceaccounts/{sa}/token). Like AWS STS and GCP these are ephemeral —
// Kubernetes enforces the token's expiry, so Renew is refused (issue a fresh lease
// instead) — but unlike AWS/Azure/GCP, Revoke is NOT always a no-op here (#97
// residual, investigated):
//
// Kubernetes TokenRequest tokens can be bound to a live Kubernetes object via
// spec.boundObjectRef (this is exactly the documented mechanism `kubectl create
// token --bound-object-kind=Secret` uses, and how kubelet's projected-volume
// tokens are bound to their Pod). The API server's ServiceAccount token
// authenticator checks the bound object's live existence + UID on EVERY request,
// independent of the token's own exp claim — so deleting the bound object
// invalidates the token immediately, before its natural expiry.
//
// This is opt-in per config ("revocable":true — see below), OFF by default, for
// two reasons: (1) it requires the calling identity to also hold create/delete on
// `secrets` in the target namespace, on top of the `create` on
// `serviceaccounts/token` every config already needs — a real permission
// expansion that must be a deliberate operator choice, not a silent new
// requirement for every existing deployment; (2) the bound object is scoped to
// THIS ONE lease (a dedicated, empty per-lease Secret named after the lease's
// role label), so revoking it has no blast radius on other leases or on the
// ServiceAccount itself — unlike AWS/Azure's only revocation workarounds, which
// would deny/invalidate every concurrent session on the shared role/identity
// (see awssts.go / azure.go for why those remain no-ops).
//
// The encrypted "admin DSN" carries this backend's JSON config:
//
//	{"namespace":"default","service_account":"my-app",
//	 "audiences":["https://my-service"],   // optional; omit for the API-server audience
//	 "revocable":true,                     // optional; see header above (default false)
//	 "api_server":"https://10.0.0.1:443",  // optional; omit to use in-cluster config
//	 "ca_cert":"<PEM>","token":"<bearer>"} // required when api_server is set
//
// namespace + service_account are required. When api_server is omitted the engine uses
// the standard in-cluster configuration (KUBERNETES_SERVICE_HOST/PORT + the mounted
// service-account token and CA) — so no credentials live in Keyorix config when the
// server runs in the cluster. The identity making the call (in-cluster SA or the
// configured token) must hold `create` on the `serviceaccounts/token` subresource for
// the target ServiceAccount, plus `create`+`delete` on `secrets` in the namespace when
// revocable is true. To stay dependency-free (no client-go) every call is a small REST
// request over net/http, mirroring the Kubernetes sync agent's REST sink.
//
// Kubernetes is a legitimate air-gapped (on-prem cluster) integration (ADR-109 step
// 6 decision) and stays registered in the noaws,noazure,nogcp profile. The nok8s tag
// below exists for completeness — an unsupported combination must still compile —
// not because AIR-GAPPED excludes it. This file has no cloud SDK dependency to drop
// (see the doc note above), so nok8s only removes this backend's registration.
//
//go:build !nok8s

package dynamic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	bearerPrefix = "Bearer "
	mimeJSON     = "application/json"
)

// maxK8sAPIResponseBytes caps how much of a Kubernetes API server response
// body this backend will read into memory before decoding. Both call sites
// that use it decode a single Kubernetes API object (a TokenRequest result or
// a created Secret's metadata) — normally tiny — but the cap is kept generous
// rather than tuned tight, since the API server is a semi-trusted but still
// network-reachable peer whose response size this client does not otherwise
// control. This bounds a misbehaving or compromised API server from
// exhausting client memory via an unbounded json.Decode of resp.Body.
const maxK8sAPIResponseBytes = 5 << 20 // 5MB

// k8sMinExpirationSeconds is the Kubernetes TokenRequest minimum (10 minutes); the
// API server silently bumps anything lower, so we floor it for an honest lease TTL.
const k8sMinExpirationSeconds = 600

const (
	k8sSATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- well-known path, not a credential
	k8sSACAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// boundObjectRef identifies the per-lease Secret a revocable token's
// spec.boundObjectRef points to (see the file header).
type boundObjectRef struct {
	Name string
	UID  string
}

// k8sTokenMinter is the slice of Kubernetes the engine uses — an interface seam so the
// engine is unit-tested with a fake and the REST/TLS plumbing stays contained here.
type k8sTokenMinter interface {
	mintToken(ctx context.Context, namespace, serviceAccount string, audiences []string, expiration time.Duration, bound *boundObjectRef) (token string, expiry time.Time, err error)
	// createBoundSecret creates an empty, per-lease Secret used only as a
	// TokenRequest boundObjectRef target, returning its UID. Only called when the
	// lease's config sets "revocable":true.
	createBoundSecret(ctx context.Context, namespace, name string) (uid string, err error)
	// deleteBoundSecret deletes the Secret created by createBoundSecret,
	// immediately invalidating any token bound to it. Idempotent: deleting an
	// already-gone Secret is not an error.
	deleteBoundSecret(ctx context.Context, namespace, name string) error
}

// KubernetesEngine mints short-lived ServiceAccount tokens via the TokenRequest API.
type KubernetesEngine struct {
	minter k8sTokenMinter // nil uses the real REST minter built from the config
}

func (e *KubernetesEngine) BackendType() string        { return "kubernetes" }
func (e *KubernetesEngine) SupportsNativeExpiry() bool { return true } // Kubernetes enforces the token TTL
func (e *KubernetesEngine) IsEphemeralBackend() bool   { return true }

type k8sConfig struct {
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"service_account"`
	Audiences      []string `json:"audiences,omitempty"`
	// AllowedNamespaces, when non-empty, restricts which namespaces a lease may
	// target (DYN-004). If empty, any namespace in the cluster is permitted.
	AllowedNamespaces []string `json:"allowed_namespaces,omitempty"`
	// Revocable opts this config into bound-token revocation (see the file
	// header): Issue creates a dedicated per-lease Secret and binds the token to
	// it, so Revoke can delete that Secret to invalidate the token early. Default
	// false preserves the original no-op behavior and requires no extra RBAC.
	Revocable bool   `json:"revocable,omitempty"`
	APIServer string `json:"api_server,omitempty"`
	CACert    string `json:"ca_cert,omitempty"`
	Token     string `json:"token,omitempty"`
}

func validateK8sCfg(cfg k8sConfig) error {
	if strings.TrimSpace(cfg.Namespace) == "" {
		return fmt.Errorf("kubernetes: namespace is required")
	}
	if strings.TrimSpace(cfg.ServiceAccount) == "" {
		return fmt.Errorf("kubernetes: service_account is required")
	}
	return nil
}

func k8sCredentialFields(cfg k8sConfig, token string, expiry time.Time) map[string]string {
	fields := map[string]string{
		"token":           token,
		"namespace":       cfg.Namespace,
		"service_account": cfg.ServiceAccount,
	}
	if !expiry.IsZero() {
		fields["expiration"] = expiry.UTC().Format(time.RFC3339)
	}
	return fields
}

// Issue mints a token for the configured ServiceAccount. roleName is the lease
// label; when Revocable is set it is also the name of the per-lease bound Secret
// created below (needed by Revoke to find and delete it later). creationTemplate
// is unused.
func (e *KubernetesEngine) Issue(ctx context.Context, adminDSN, _ string, ttl time.Duration) (Credential, string, error) {
	var cfg k8sConfig
	if err := json.Unmarshal([]byte(adminDSN), &cfg); err != nil {
		return Credential{}, "", fmt.Errorf("kubernetes: config must be JSON ({\"namespace\":...,\"service_account\":...}): %w", err)
	}
	if err := validateK8sCfg(cfg); err != nil {
		return Credential{}, "", err
	}
	if len(cfg.AllowedNamespaces) > 0 && !slices.Contains(cfg.AllowedNamespaces, cfg.Namespace) {
		return Credential{}, "", fmt.Errorf("kubernetes: namespace %q is not in the allowed_namespaces list", cfg.Namespace)
	}

	// K8s rejects/bumps anything lower than the minimum expiration.
	expiration := max(ttl, k8sMinExpirationSeconds*time.Second)

	minter := e.minter
	if minter == nil {
		m, err := newRealK8sMinter(cfg)
		if err != nil {
			return Credential{}, "", err
		}
		minter = m
	}

	// Generated up front (rather than after minting) so it can double as the
	// per-lease bound Secret's name when revocable is set.
	suffix, err := randString(12)
	if err != nil {
		return Credential{}, "", err
	}
	label := "keyorix-dyn-" + suffix

	var bound *boundObjectRef
	if cfg.Revocable {
		uid, err := minter.createBoundSecret(ctx, cfg.Namespace, label)
		if err != nil {
			return Credential{}, "", fmt.Errorf("kubernetes: create bound secret for revocation: %w", err)
		}
		bound = &boundObjectRef{Name: label, UID: uid}
	}

	token, expiry, err := minter.mintToken(ctx, cfg.Namespace, cfg.ServiceAccount, cfg.Audiences, expiration, bound)
	if err != nil {
		if bound != nil {
			// The TokenRequest failed after the Secret was created — clean it up
			// (best-effort) rather than leave an orphaned bound object nothing was
			// ever minted against.
			_ = minter.deleteBoundSecret(ctx, cfg.Namespace, bound.Name)
		}
		return Credential{}, "", fmt.Errorf("kubernetes: request token: %w", err)
	}

	return Credential{Fields: k8sCredentialFields(cfg, token, expiry)}, label, nil
}

// Revoke is a no-op unless the lease's config set "revocable":true, in which case
// roleName is also the name of the per-lease Secret created at Issue and bound
// into the token's spec.boundObjectRef — deleting it here immediately invalidates
// the token (see the file header for why this is safe: it is scoped to this one
// lease). Deleting an already-gone Secret is treated as success, so a retried or
// double revoke doesn't fail.
func (e *KubernetesEngine) Revoke(ctx context.Context, adminDSN, roleName string) error {
	var cfg k8sConfig
	if err := json.Unmarshal([]byte(adminDSN), &cfg); err != nil {
		return fmt.Errorf("kubernetes: config must be JSON ({\"namespace\":...,\"service_account\":...}): %w", err)
	}
	if !cfg.Revocable {
		return nil // no bound object was created for this lease — self-expiring, nothing to drop
	}

	minter := e.minter
	if minter == nil {
		m, err := newRealK8sMinter(cfg)
		if err != nil {
			return err
		}
		minter = m
	}
	if err := minter.deleteBoundSecret(ctx, cfg.Namespace, roleName); err != nil {
		return fmt.Errorf("kubernetes: delete bound secret %s/%s: %w", cfg.Namespace, roleName, err)
	}
	return nil
}

// RevokeInvalidatesCredential reports whether this lease's config opted into
// bound-token revocation ("revocable":true — see the file header). A malformed
// adminDSN fails closed to false: understating a genuine revoke (rare — Issue
// would already have failed on the same malformed config) is far safer than an
// audit trail overclaiming that a credential was killed when it wasn't.
func (e *KubernetesEngine) RevokeInvalidatesCredential(adminDSN string) bool {
	var cfg k8sConfig
	if err := json.Unmarshal([]byte(adminDSN), &cfg); err != nil {
		return false
	}
	return cfg.Revocable
}

// Renew is refused: a token's lifetime is fixed at issue. core.RenewLease guards on
// IsEphemeralBackend before reaching here; this is a defensive backstop.
func (e *KubernetesEngine) Renew(_ context.Context, _, _ string, _ time.Time) error {
	return fmt.Errorf("kubernetes: tokens are not renewable; issue a new lease instead")
}

// realK8sMinter calls the TokenRequest API over net/http, authenticating with either an
// explicitly-configured api_server/token/ca or the in-cluster service-account config.
type realK8sMinter struct {
	host  string // e.g. https://10.0.0.1:443
	token string // bearer token for the TokenRequest call
	hc    *http.Client
}

func newRealK8sMinter(cfg k8sConfig) (*realK8sMinter, error) {
	var host, token string
	var caPEM []byte

	if strings.TrimSpace(cfg.APIServer) != "" {
		// Out-of-cluster: everything comes from the config. A CA is required — we never
		// skip TLS verification (an unverified API server could hand back any token).
		host = strings.TrimRight(cfg.APIServer, "/")
		token = strings.TrimSpace(cfg.Token)
		if token == "" {
			return nil, fmt.Errorf("kubernetes: token is required when api_server is set")
		}
		if strings.TrimSpace(cfg.CACert) == "" {
			return nil, fmt.Errorf("kubernetes: ca_cert is required when api_server is set")
		}
		caPEM = []byte(cfg.CACert)
	} else {
		// In-cluster: the standard env + mounted service-account token and CA.
		h, p := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if h == "" || p == "" {
			return nil, fmt.Errorf("kubernetes: not in-cluster and no api_server set (KUBERNETES_SERVICE_HOST/PORT unset)")
		}
		host = "https://" + net.JoinHostPort(h, p)
		tb, err := os.ReadFile(k8sSATokenPath) // #nosec G304 -- well-known in-cluster path
		if err != nil {
			return nil, fmt.Errorf("kubernetes: read in-cluster token: %w", err)
		}
		token = strings.TrimSpace(string(tb))
		caPEM, err = os.ReadFile(k8sSACAPath) // #nosec G304 -- well-known in-cluster path
		if err != nil {
			return nil, fmt.Errorf("kubernetes: read in-cluster CA: %w", err)
		}
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("kubernetes: no certificates in ca bundle")
	}
	m := &realK8sMinter{
		host:  host,
		token: token,
		hc: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
			CheckRedirect: refuseRedirect,
		},
	}
	if err := validateAPIServerHost(m.host); err != nil {
		return nil, err
	}
	return m, nil
}

// validateAPIServerHost checks that the resolved Kubernetes API server host is a
// well-formed absolute https URL. Both code paths that set it (an operator-configured
// api_server, or the in-cluster KUBERNETES_SERVICE_HOST/PORT env vars) always
// produce https — this only rejects a malformed or non-HTTPS destination reaching
// the TokenRequest/Secret client.
func validateAPIServerHost(host string) error {
	u, err := url.Parse(host)
	if err != nil {
		return fmt.Errorf("kubernetes: invalid api_server %q: %w", host, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("kubernetes: api_server %q must use https", host)
	}
	if u.Host == "" {
		return fmt.Errorf("kubernetes: api_server %q is missing a host", host)
	}
	return nil
}

// refuseRedirect stops the TokenRequest/Secret-create/Secret-delete client from
// following any redirect: without this, a 3xx response from the configured API
// server (validated at config-write time, but not re-checked per request) could
// bounce the bearer-token-bearing request to an internal host (e.g. cloud IMDS)
// at request time (CWE-918).
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("kubernetes: refusing to follow redirect to %q", req.URL)
}

// drainAndClose discards any unread response body before closing it, so the
// underlying connection can be returned to net/http's keep-alive pool instead
// of being torn down. Every realK8sMinter method below used to defer a bare
// resp.Body.Close() and then return without reading the body on several
// branches (the 401/403/>=400 error branches, and deleteBoundSecret's success
// branch) — this closes the gap for all of them in one place.
func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxK8sAPIResponseBytes))
	_ = resp.Body.Close()
}

func (m *realK8sMinter) mintToken(ctx context.Context, namespace, serviceAccount string, audiences []string, expiration time.Duration, bound *boundObjectRef) (string, time.Time, error) {
	expSeconds := int64(expiration.Seconds())
	spec := map[string]any{
		"expirationSeconds": expSeconds,
	}
	if len(audiences) > 0 {
		spec["audiences"] = audiences
	}
	if bound != nil {
		// Binds the token's validity to this Secret's live existence + UID (see
		// the file header) — this is what makes Revoke's delete an immediate,
		// real invalidation instead of local bookkeeping.
		spec["boundObjectRef"] = map[string]any{
			"kind":       "Secret",
			"apiVersion": "v1",
			"name":       bound.Name,
			"uid":        bound.UID,
		}
	}
	reqBody := map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec":       spec,
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal TokenRequest: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/serviceaccounts/%s/token",
		m.host, pathSegment(namespace), pathSegment(serviceAccount))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw)) // #nosec G107 -- host is operator-configured/in-cluster
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+m.token)
	req.Header.Set("Content-Type", mimeJSON)
	req.Header.Set("Accept", mimeJSON)

	resp, err := m.hc.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", time.Time{}, fmt.Errorf("not authorized (HTTP %d) — the caller needs create on serviceaccounts/token for %s/%s", resp.StatusCode, namespace, serviceAccount)
	}
	if resp.StatusCode >= 400 {
		return "", time.Time{}, fmt.Errorf("TokenRequest returned HTTP %d", resp.StatusCode)
	}

	var out struct {
		Status struct {
			Token               string `json:"token"`
			ExpirationTimestamp string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxK8sAPIResponseBytes)).Decode(&out); err != nil {
		return "", time.Time{}, fmt.Errorf("decode TokenRequest response: %w", err)
	}
	if out.Status.Token == "" {
		return "", time.Time{}, fmt.Errorf("TokenRequest returned no token")
	}
	var expiry time.Time
	if out.Status.ExpirationTimestamp != "" {
		expiry, _ = time.Parse(time.RFC3339, out.Status.ExpirationTimestamp)
	}
	return out.Status.Token, expiry, nil
}

// createBoundSecret creates an empty, labeled Secret used only as a TokenRequest
// boundObjectRef target (see the file header), returning its UID so it can be
// embedded in that boundObjectRef.
func (m *realK8sMinter) createBoundSecret(ctx context.Context, namespace, name string) (string, error) {
	reqBody := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name": name,
			"labels": map[string]any{
				"app.kubernetes.io/managed-by": "keyorix",
				"keyorix.io/purpose":           "dynamic-secret-token-binding",
			},
		},
		"type": "Opaque",
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal Secret: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", m.host, pathSegment(namespace))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw)) // #nosec G107 -- host is operator-configured/in-cluster
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+m.token)
	req.Header.Set("Content-Type", mimeJSON)
	req.Header.Set("Accept", mimeJSON)

	resp, err := m.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("not authorized (HTTP %d) — the caller needs create on secrets in %s (required when revocable is true)", resp.StatusCode, namespace)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("create Secret returned HTTP %d", resp.StatusCode)
	}

	var out struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxK8sAPIResponseBytes)).Decode(&out); err != nil {
		return "", fmt.Errorf("decode Secret response: %w", err)
	}
	if out.Metadata.UID == "" {
		return "", fmt.Errorf("create Secret returned no uid")
	}
	return out.Metadata.UID, nil
}

// deleteBoundSecret deletes the Secret created by createBoundSecret, immediately
// invalidating any token bound to it. A 404 is treated as success so Revoke stays
// idempotent (a retried, or already-cleaned-up, revoke must not fail).
func (m *realK8sMinter) deleteBoundSecret(ctx context.Context, namespace, name string) error {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", m.host, pathSegment(namespace), pathSegment(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil) // #nosec G107 -- host is operator-configured/in-cluster
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+m.token)
	req.Header.Set("Accept", mimeJSON)

	resp, err := m.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode == http.StatusNotFound {
		return nil // already gone — revoke is idempotent
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("not authorized (HTTP %d) — the caller needs delete on secrets in %s (required when revocable is true)", resp.StatusCode, namespace)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete Secret returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// pathSegment guards a namespace/service-account name placed into the request path: K8s
// names are DNS labels (lowercase alphanumerics and '-'), so anything else is rejected
// rather than escaped, closing off path traversal in the constructed URL. The '.'
// character is rejected explicitly to block dot-segment sequences (`.`, `..`) even
// when combined with url.PathEscape, then url.PathEscape is applied to the accepted
// value to neutralise any unexpected metacharacters that survive the allowlist.
func pathSegment(s string) string {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/?#%.") {
		return "INVALID"
	}
	return url.PathEscape(s)
}

func init() {
	registerCloudEngine("kubernetes", func() (CredentialEngine, error) { return &KubernetesEngine{}, nil })
}
