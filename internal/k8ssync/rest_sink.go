package k8ssync

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// RESTSink writes Kubernetes Secrets by talking to the Kubernetes API directly over
// HTTPS, using the in-cluster service-account credentials. It deliberately avoids a
// client-go dependency: a Secret get/apply is a small, well-defined REST call, and
// staying dependency-free keeps the agent tiny (mirrors how the Azure rotation
// backend talks to Graph over net/http rather than pulling the SDK). Satisfies Sink.
type RESTSink struct {
	host         string // e.g. https://10.0.0.1:443
	token        string // service-account bearer token
	fieldManager string // Server-Side Apply field manager
	hc           *http.Client
}

const (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- well-known k8s path, not a credential
	saCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	contentTypeJSON = "application/json"
)

// maxResponseBodyBytes (keyorix_fetcher.go) caps how much of a single Kubernetes
// API response this sink will buffer during json.Decode.

// drainAndClose discards any unread response body before closing it, so the
// underlying connection can be returned to net/http's keep-alive pool instead
// of being torn down. Every RESTSink method below (and KeyorixFetcher.getJSON
// in keyorix_fetcher.go, same package) used to defer a bare
// resp.Body.Close() and return without reading the body on several
// branches (every >=400/404/409 error branch, and createSecret/
// applyOwnedSecret/Delete's success branches, which never decode a body at
// all).
func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBodyBytes))
	_ = resp.Body.Close()
}

// NewInClusterSink builds a RESTSink from the standard in-cluster environment: the
// API host/port from KUBERNETES_SERVICE_HOST/PORT and the projected service-account
// token + CA bundle. Returns an error when not running inside a cluster.
func NewInClusterSink() (*RESTSink, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not running in-cluster: KUBERNETES_SERVICE_HOST/PORT unset")
	}
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service-account token: %w", err)
	}
	caPEM, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, fmt.Errorf("read service-account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates in %s", saCAPath)
	}
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	return &RESTSink{
		host:         "https://" + net.JoinHostPort(host, port),
		token:        strings.TrimSpace(string(token)),
		fieldManager: "keyorix-sync",
		hc:           hc,
	}, nil
}

// Get returns the decoded data of the named Secret, or (nil, nil) when it does not
// exist.
func (s *RESTSink) Get(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	req, err := s.newRequest(ctx, http.MethodGet, s.secretPath(namespace, name), "", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("get secret %s/%s: HTTP %d", namespace, name, resp.StatusCode)
	}

	var body struct {
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode secret %s/%s: %w", namespace, name, err)
	}
	out := make(map[string][]byte, len(body.Data))
	for k, b64 := range body.Data {
		dec, derr := base64.StdEncoding.DecodeString(b64)
		if derr != nil {
			return nil, fmt.Errorf("decode key %q of %s/%s: %w", k, namespace, name, derr)
		}
		out[k] = dec
	}
	return out, nil
}

// errNotManaged is returned by Apply when a pre-existing Secret at the target
// name lacks this agent's managed-by label — the caller should skip/report it,
// not overwrite it.
var errNotManaged = fmt.Errorf("k8ssync: refusing to write: a pre-existing Secret is not managed by this agent")

// ErrNotManaged reports whether err is the "pre-existing unmanaged Secret" refusal
// Apply returns — exported so callers (the sync loop) can distinguish it from a
// transient/network failure and report it distinctly rather than retrying forever.
func ErrNotManaged(err error) bool { return errors.Is(err, errNotManaged) }

// Apply create-or-updates the named Secret to hold exactly data. The agent owns the
// data field via its field manager, so keys it no longer maps are pruned on the next
// apply.
//
// Before writing, it checks whether a Secret ALREADY EXISTS at this name and, if so,
// refuses unless it already carries this agent's managed-by label (#139). That
// getOwnedMeta read and the write below are two separate requests, so — same as
// Delete — there is a window between them for the observed state to change; unlike
// Delete (which already pins uid+resourceVersion as DeleteOptions preconditions),
// Apply used to issue an unconditional force=true Server-Side-Apply PATCH with no
// precondition at all, so a Secret created in that window (e.g. by a namespace-scoped
// attacker racing the agent's own target name) would be silently claimed and
// overwritten with the real secret value (#Bug4). Two writes close this, matching
// what each observed state actually needs:
//
//   - !exists: a plain POST create. Kubernetes create is atomic against the object's
//     existence — if something raced into existence at this name between the read
//     above and this request, the POST itself fails with 409 AlreadyExists rather
//     than silently overwriting it. There is no read-then-write window at all.
//   - exists && owned: a Server-Side-Apply PATCH, but with the exact resourceVersion
//     just observed set on the submitted object as an optimistic-concurrency
//     precondition. Kubernetes checks a submitted resourceVersion against the
//     object's current stored value for any write, PATCH included, and rejects with
//     a conflict if it no longer matches — resourceVersion is a cluster-wide,
//     strictly-increasing etcd revision that is never reused, so even a delete
//     immediately followed by a recreate under the same name between our read and
//     this write yields a different resourceVersion and is still caught (uid
//     preconditions, as Delete uses, would add nothing beyond what resourceVersion
//     already catches here, since SSA has no DeleteOptions-equivalent to carry a uid
//     precondition on a PATCH).
func (s *RESTSink) Apply(ctx context.Context, namespace, name string, data map[string][]byte) error {
	_, rv, exists, owned, err := s.getOwnedMeta(ctx, namespace, name)
	if err != nil {
		return err
	}
	if exists && !owned {
		return fmt.Errorf("%s/%s: %w", namespace, name, errNotManaged)
	}

	encoded := make(map[string]string, len(data))
	for k, v := range data {
		encoded[k] = base64.StdEncoding.EncodeToString(v)
	}
	metadata := map[string]any{
		"name":      name,
		"namespace": namespace,
		// Stamp ownership so orphan cleanup can find Secrets this agent created
		// (and only those) via a label selector.
		"labels": map[string]string{managedByLabel: managedByValue},
	}
	payload := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   metadata,
		"type":       "Opaque",
		"data":       encoded,
	}

	if !exists {
		return s.createSecret(ctx, namespace, name, payload)
	}
	metadata["resourceVersion"] = rv
	return s.applyOwnedSecret(ctx, namespace, name, payload)
}

// createSecret POSTs a brand-new, EMPTY-data Secret to the namespace's collection
// endpoint (see below for why data is withheld here), then immediately Server-Side
// Applies the real data onto it. A 409 on the POST means something raced into
// existence at this name since Apply's ownership check — the create is left to fail
// rather than falling back to an unconditional overwrite, so the race can never
// result in silently claiming a Secret this agent never observed as its own.
//
// The POST carries no `data` so that the resulting phantom field manager (a plain POST
// is not a Server-Side Apply request, so the API server attributes every field it
// creates to a synthetic manager derived from this client's unset User-Agent, not
// fieldManager "keyorix-sync") never claims ownership of any individual key. This
// matters because of a real, confirmed-live SSA subtlety: applying a field to the
// SAME value it already has is not a conflict, so force=true does not transfer sole
// ownership away from a prior claimant the way it does for a field whose value
// actually differs — the two managers end up CO-owning it instead, and a field with
// any remaining co-owner is never pruned no matter how many later applies drop it from
// keyorix-sync's own intent. An earlier version of this fix had createSecret POST the
// full payload (including data) and then immediately re-apply the identical payload —
// which looked correct (keyorix-sync's own managedFields entry did list every key) but
// did NOT actually fix pruning for any key whose value never changed after creation,
// confirmed live: removing that key's mapping left it in the target Secret forever
// regardless of how many subsequent passes ran. Withholding data from the POST means
// the phantom manager never claims any data key in the first place, so the follow-up
// SSA apply is always the FIRST and ONLY claimant of every key from creation onward —
// no co-ownership possible, no special-casing needed for the "value never changed"
// case.
func (s *RESTSink) createSecret(ctx context.Context, namespace, name string, payload map[string]any) error {
	emptyDataPayload := make(map[string]any, len(payload))
	maps.Copy(emptyDataPayload, payload)
	emptyDataPayload["data"] = map[string]string{}

	raw, err := json.Marshal(emptyDataPayload)
	if err != nil {
		return fmt.Errorf("marshal secret %s/%s: %w", namespace, name, err)
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets", url.PathEscape(namespace))
	req, err := s.newRequest(ctx, http.MethodPost, path, contentTypeJSON, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("create secret %s/%s: HTTP %d", namespace, name, resp.StatusCode)
	}
	return s.applyOwnedSecret(ctx, namespace, name, payload)
}

// applyOwnedSecret Server-Side-Applies payload (which must already carry
// metadata.resourceVersion as an optimistic-concurrency precondition — see Apply) onto
// a Secret this agent has already verified it owns.
func (s *RESTSink) applyOwnedSecret(ctx context.Context, namespace, name string, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal secret %s/%s: %w", namespace, name, err)
	}

	q := url.Values{}
	q.Set("fieldManager", s.fieldManager)
	q.Set("force", "true")
	path := s.secretPath(namespace, name) + "?" + q.Encode()

	// Server-Side Apply: PATCH with the apply content type. JSON is valid YAML, so the
	// apply-patch+yaml media type accepts this body.
	req, err := s.newRequest(ctx, http.MethodPatch, path, "application/apply-patch+yaml", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("apply secret %s/%s: HTTP %d", namespace, name, resp.StatusCode)
	}
	return nil
}

// List returns the names of agent-owned Secrets in the namespace — those carrying the
// managed-by label. Used by orphan cleanup; the label selector scopes the listing so
// the agent never sees (and so can never delete) Secrets it did not create.
func (s *RESTSink) List(ctx context.Context, namespace string) ([]string, error) {
	q := url.Values{}
	q.Set("labelSelector", managedByLabel+"="+managedByValue)
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets?%s", url.PathEscape(namespace), q.Encode())
	req, err := s.newRequest(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("list secrets in %s: HTTP %d", namespace, resp.StatusCode)
	}
	var body struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode secret list for %s: %w", namespace, err)
	}
	names := make([]string, 0, len(body.Items))
	for _, it := range body.Items {
		names = append(names, it.Metadata.Name)
	}
	return names, nil
}

// Delete removes the named Secret, but only while it still belongs to this agent. It
// re-verifies the managed-by label and pins the exact (uid, resourceVersion) it saw,
// so a Secret that lost the label or was replaced between the orphan listing and here
// is left untouched — closing the list→delete TOCTOU on a destructive action. A 404 is
// success (already gone); a 409 means it changed under us (uid/resourceVersion no
// longer match), so we skip rather than delete a different object.
func (s *RESTSink) Delete(ctx context.Context, namespace, name string) error {
	uid, rv, _, owned, err := s.getOwnedMeta(ctx, namespace, name)
	if err != nil {
		return err
	}
	if !owned {
		return nil // gone, or no longer ours — must not delete
	}
	opts := map[string]any{
		"apiVersion":    "v1",
		"kind":          "DeleteOptions",
		"preconditions": map[string]string{"uid": uid, "resourceVersion": rv},
	}
	raw, err := json.Marshal(opts)
	if err != nil {
		return fmt.Errorf("marshal delete options %s/%s: %w", namespace, name, err)
	}
	req, err := s.newRequest(ctx, http.MethodDelete, s.secretPath(namespace, name), contentTypeJSON, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)
	switch {
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusConflict:
		// 404: already gone. 409: the object changed since our owner-check (precondition
		// mismatch) — the Secret we verified is no longer the one on the server, so skip.
		return nil
	case resp.StatusCode >= 400:
		return fmt.Errorf("delete secret %s/%s: HTTP %d", namespace, name, resp.StatusCode)
	}
	return nil
}

// getOwnedMeta fetches the Secret's uid + resourceVersion and reports whether it
// exists at all, and — when it does — whether it still carries this agent's
// managed-by label. exists=false (owned=false) means absent; exists=true,
// owned=false means a pre-existing Secret this agent does not own.
func (s *RESTSink) getOwnedMeta(ctx context.Context, namespace, name string) (uid, resourceVersion string, exists, owned bool, err error) {
	req, err := s.newRequest(ctx, http.MethodGet, s.secretPath(namespace, name), "", nil)
	if err != nil {
		return "", "", false, false, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return "", "", false, false, fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode == http.StatusNotFound {
		return "", "", false, false, nil
	}
	if resp.StatusCode >= 400 {
		return "", "", false, false, fmt.Errorf("get secret %s/%s: HTTP %d", namespace, name, resp.StatusCode)
	}
	var body struct {
		Metadata struct {
			UID             string            `json:"uid"`
			ResourceVersion string            `json:"resourceVersion"`
			Labels          map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&body); err != nil {
		return "", "", false, false, fmt.Errorf("decode secret %s/%s: %w", namespace, name, err)
	}
	owned = body.Metadata.Labels[managedByLabel] == managedByValue
	return body.Metadata.UID, body.Metadata.ResourceVersion, true, owned, nil
}

func (s *RESTSink) secretPath(namespace, name string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", url.PathEscape(namespace), url.PathEscape(name))
}

// newRequest builds an authenticated request; contentType is set when non-empty.
func (s *RESTSink) newRequest(ctx context.Context, method, path, contentType string, body *bytes.Reader) (*http.Request, error) {
	var r *http.Request
	var err error
	if body != nil {
		r, err = http.NewRequestWithContext(ctx, method, s.host+path, body)
	} else {
		r, err = http.NewRequestWithContext(ctx, method, s.host+path, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	r.Header.Set("Authorization", "Bearer "+s.token)
	r.Header.Set("Accept", contentTypeJSON)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r, nil
}
