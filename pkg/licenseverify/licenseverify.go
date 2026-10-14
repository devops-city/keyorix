// Package licenseverify implements Keyorix's offline license validation (ADR-065, ADR-062
// Phase 2): issuing a signed token (maintainer-only, `keyorix license issue`, never wired
// into the thin CLI) and evaluating one offline against an embedded ed25519 public key
// (pkg/trust) -- the customer-facing half (`keyorix license install/status`). It is a
// public leaf package (FINISH-SPLIT step 2, docs/cli-split-inventory.md §7 PR 10) so the
// thin CLI module (cli/) can call it directly without importing internal/core,
// internal/storage, internal/config, or any cloud SDK -- the same reason pkg/trust and
// pkg/bundleverify exist. internal/license re-exports this package's API as aliases so the
// server (Gate) and the old CLI keep working unchanged.
//
// A license is a compact, signed token — base64url(payload).base64url(sig) — that a
// deployment validates locally. There is no phone-home.
//
// The enforcement posture is deliberately the INVERSE of update bundles. Bundles are
// fail-CLOSED: an unverifiable bundle must never be trusted. A license is fail-SAFE: a
// missing, expired, or invalid license must never deny access to existing secrets or stop
// the server — availability is itself a security property for a secrets manager, and a
// license lapse must not brick production. So Evaluate never errors out; it degrades to
// the community baseline (no commercial features) with a reason the caller surfaces as an
// admin warning + audit event. Enforcement gates commercial features only.
package licenseverify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/pkg/trust"
)

// expiringSoonWindow is how long before not_after a still-valid license is flagged
// "expiring soon" so operators can renew ahead of a lapse.
const expiringSoonWindow = 30 * 24 * time.Hour

// Commercial feature keys gated by an offline license. These are the canonical strings that
// appear in a license's Features list and in HasFeature checks — use the constants, never
// bare strings, so the gated set stays discoverable in one place.
const (
	// FeatureAirgapUpdates gates `keyorix bundle import` — staging a signed update bundle
	// for an air-gapped rollout (ADR-064). Bundle *verification* is always free; only the
	// import (delivery) action is commercial.
	FeatureAirgapUpdates = "airgap_updates"

	// FeatureBilling gates the FinOps billing report (GET /api/v1/admin/billing/report
	// and `keyorix billing report`).
	FeatureBilling = "billing"
)

// License is the signed payload. Features are commercial-feature keys this license grants.
type License struct {
	Licensee     string    `json:"licensee"`
	Plan         string    `json:"plan"`
	Features     []string  `json:"features"`
	IssuedAt     time.Time `json:"issued_at"`
	NotAfter     time.Time `json:"not_after"`
	DeploymentID string    `json:"deployment_id,omitempty"`
	MaxSeats     int       `json:"max_seats,omitempty"`
	KeyID        string    `json:"key_id"`
}

// State is the evaluated license state. Only Active and ExpiringSoon grant features.
type State string

const (
	StateActive       State = "active"        // valid, in date
	StateExpiringSoon State = "expiring_soon" // valid and feature-granting, but near/just past expiry (within grace)
	StateExpired      State = "expired"       // past not_after + grace → baseline
	StateInvalid      State = "invalid"       // unparseable / bad signature / deployment mismatch → baseline
	StateNone         State = "none"          // no license installed → baseline
)

// Status is the result of evaluating a token. Features is the EFFECTIVE feature set —
// empty (community baseline) whenever the state is not feature-granting.
type Status struct {
	State        State
	Licensee     string
	Plan         string
	Features     []string
	NotAfter     time.Time
	DeploymentID string
	MaxSeats     int
	Reason       string // why degraded (for admin warning + audit); empty when Active
}

// Grants reports whether the license currently grants commercial features.
func (s Status) Grants() bool {
	return s.State == StateActive || s.State == StateExpiringSoon
}

// HasFeature reports whether feature f is granted right now. It is the single gate the rest
// of the server should call; it is false for every feature under a degraded license.
func (s Status) HasFeature(f string) bool {
	if !s.Grants() {
		return false
	}
	return slices.Contains(s.Features, f)
}

// Issue marshals and signs a license into a compact token. Maintainer-only (`keyorix
// license issue` -- the private key is the offline license-signing secret; it never ships).
func Issue(lic License, priv ed25519.PrivateKey) (string, error) {
	if strings.TrimSpace(lic.KeyID) == "" {
		return "", fmt.Errorf("license: key-id is required")
	}
	if strings.TrimSpace(lic.Licensee) == "" {
		return "", fmt.Errorf("license: licensee is required")
	}
	if lic.NotAfter.IsZero() {
		return "", fmt.Errorf("license: not_after is required")
	}
	payload, err := json.Marshal(&lic)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return enc(payload) + "." + enc(sig), nil
}

// parseToken splits and decodes a token into its raw payload bytes, signature, and the
// parsed License. It does not verify the signature.
func parseToken(token string) (payload, sig []byte, lic *License, err error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, nil, nil, fmt.Errorf("license: malformed token (want payload.sig)")
	}
	payload, err = dec(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("license: decode payload: %w", err)
	}
	sig, err = dec(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("license: decode signature: %w", err)
	}
	var l License
	if err := json.Unmarshal(payload, &l); err != nil {
		return nil, nil, nil, fmt.Errorf("license: parse payload: %w", err)
	}
	return payload, sig, &l, nil
}

// Evaluate validates a token offline and returns the effective Status. It NEVER returns an
// error: every failure mode (no token, bad signature, expiry, deployment mismatch) degrades
// to the community baseline with a Reason — the caller surfaces that as an admin warning and
// an audit event, but the server keeps running. deploymentID, when non-empty on both sides,
// must match (anti-copy binding). grace is the post-expiry tolerance window.
func Evaluate(token string, reg *trust.KeyRegistry, deploymentID string, now time.Time, grace time.Duration) Status {
	if strings.TrimSpace(token) == "" {
		return Status{State: StateNone, Reason: "no license installed — running the community baseline"}
	}
	payload, sig, lic, err := parseToken(token)
	if err != nil {
		return Status{State: StateInvalid, Reason: err.Error()}
	}
	if strings.TrimSpace(lic.KeyID) == "" {
		return Status{State: StateInvalid, Reason: "license has no key-id"}
	}
	if err := reg.Verify(trust.PurposeLicense, lic.KeyID, payload, sig); err != nil {
		return Status{State: StateInvalid, Reason: "signature: " + err.Error()}
	}

	base := Status{
		Licensee:     lic.Licensee,
		Plan:         lic.Plan,
		NotAfter:     lic.NotAfter,
		DeploymentID: lic.DeploymentID,
		MaxSeats:     lic.MaxSeats,
	}

	if lic.DeploymentID != "" {
		if deploymentID == "" {
			base.State = StateInvalid
			base.Reason = "license is bound to a specific deployment but this deployment has no deployment_id configured"
			return base
		}
		if lic.DeploymentID != deploymentID {
			base.State = StateInvalid
			base.Reason = fmt.Sprintf("license is bound to deployment %q, not this deployment", lic.DeploymentID)
			return base
		}
	}

	switch {
	case now.After(lic.NotAfter.Add(grace)):
		base.State = StateExpired
		base.Reason = fmt.Sprintf("license expired on %s — running the community baseline", lic.NotAfter.UTC().Format(time.RFC3339))
		return base
	case now.After(lic.NotAfter):
		base.State = StateExpiringSoon
		base.Features = lic.Features
		base.Reason = fmt.Sprintf("license expired on %s and is in its grace period — renew now", lic.NotAfter.UTC().Format(time.RFC3339))
		return base
	case now.After(lic.NotAfter.Add(-expiringSoonWindow)):
		base.State = StateExpiringSoon
		base.Features = lic.Features
		base.Reason = fmt.Sprintf("license expires on %s — renew soon", lic.NotAfter.UTC().Format(time.RFC3339))
		return base
	default:
		base.State = StateActive
		base.Features = lic.Features
		return base
	}
}

// --- helpers ---

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func dec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
}

// ParsePrivateKeyPEM decodes a PKCS#8 PEM (as written by `keyorix trust keygen`) into an
// ed25519 license-signing key. Maintainer-only.
func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("license: no PEM block in signing key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("license: parse signing key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("license: signing key is not ed25519 (%T)", key)
	}
	return priv, nil
}

// Gate is the server-side feature gate built from an installed license token. It evaluates
// the token freshly on every call (Evaluate is cheap — one ed25519 verify), so the reported
// state always reflects the current time without any cached-state or background-timer
// lifecycle: a license that lapses while the server runs is observed on the next call.
//
// A nil *Gate is valid and behaves as "no license installed" (community baseline) — so a
// server with no license configured needs no special-casing at call sites.
type Gate struct {
	token        string
	reg          *trust.KeyRegistry
	deploymentID string
	grace        time.Duration
	now          func() time.Time // injectable for tests; defaults to time.Now
}

// NewGate builds a gate over an installed token. A nil registry or empty token still yields
// a usable gate that simply evaluates to the baseline (fail-safe).
func NewGate(token string, reg *trust.KeyRegistry, deploymentID string, grace time.Duration) *Gate {
	if grace <= 0 {
		grace = 14 * 24 * time.Hour
	}
	return &Gate{token: token, reg: reg, deploymentID: deploymentID, grace: grace, now: time.Now}
}

// Status evaluates the license against the current time. It never errors — a degraded
// license returns a baseline Status with a Reason. A nil gate reports StateNone.
func (g *Gate) Status() Status {
	if g == nil {
		return Status{State: StateNone, Reason: "no license configured — running the community baseline"}
	}
	reg := g.reg
	if reg == nil {
		reg = trust.NewRegistry()
	}
	now := time.Now
	if g.now != nil {
		now = g.now
	}
	return Evaluate(g.token, reg, g.deploymentID, now(), g.grace)
}

// HasFeature reports whether commercial feature f is currently granted. This is the single
// gate the rest of the server calls before enabling a commercial-only capability; it is
// false for every feature under a degraded, expired, missing, or unconfigured license.
func (g *Gate) HasFeature(f string) bool {
	return g.Status().HasFeature(f)
}
