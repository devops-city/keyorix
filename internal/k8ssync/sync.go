// Package k8ssync holds the reconciliation engine for the Keyorix Kubernetes sync
// agent: it materialises selected Keyorix secrets into Kubernetes Secrets and keeps
// them current as the upstream values rotate.
//
// The engine is deliberately decoupled from both Keyorix and Kubernetes via the
// Fetcher and Sink interfaces, so the diff/apply logic is pure and unit-testable;
// later changes wire the real Keyorix API client (Fetcher) and a client-go-backed
// Sink. Values are held only as long as a reconcile pass needs them and are never
// logged.
package k8ssync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Kubernetes object-name constraints. A namespace is an RFC1123 DNS label; a Secret
// name is an RFC1123 DNS subdomain. Validating these before they reach the API path
// keeps a malformed (or hostile) config mapping from targeting an unintended object.
var (
	dns1123Label     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	dns1123Subdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	// k8sSecretKey is the set of characters valid in a Kubernetes Secret data key
	// (validated by the API server as "must be a valid filename": printable ASCII,
	// no path separators — K8SSYNC-001). Without this, a mapping whose Key contains
	// path metacharacters (/, ..) could reach the Kubernetes API with an invalid key
	// name and trigger an opaque server-side rejection rather than a clear local error.
	k8sSecretKey = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
)

func isDNS1123Label(s string) bool     { return len(s) <= 63 && dns1123Label.MatchString(s) }
func isDNS1123Subdomain(s string) bool { return len(s) <= 253 && dns1123Subdomain.MatchString(s) }
func isK8sSecretKey(s string) bool     { return k8sSecretKey.MatchString(s) }

// SecretMapping maps one Keyorix secret reference to a key inside a target
// Kubernetes Secret. Several mappings may target the same Secret with different keys.
type SecretMapping struct {
	Ref       string `yaml:"ref"`       // Keyorix secret reference, e.g. "production/db-password"
	Namespace string `yaml:"namespace"` // target Kubernetes namespace
	Name      string `yaml:"name"`      // target Kubernetes Secret name
	Key       string `yaml:"key"`       // key within the Secret's data map
}

// Fetcher retrieves a secret value by reference from Keyorix.
type Fetcher interface {
	Fetch(ctx context.Context, ref string) ([]byte, error)
}

// Sink reads and writes Kubernetes Secrets. Get returns (nil, nil) when the Secret
// does not exist. Apply creates or replaces the Secret's data. List returns the names
// of agent-owned Secrets in a namespace (those carrying the managed-by label) and
// Delete removes one — both used only by orphan cleanup.
type Sink interface {
	Get(ctx context.Context, namespace, name string) (map[string][]byte, error)
	Apply(ctx context.Context, namespace, name string, data map[string][]byte) error
	List(ctx context.Context, namespace string) ([]string, error)
	Delete(ctx context.Context, namespace, name string) error
}

// Result summarises one reconcile pass. Created/Updated/Unchanged count target
// Secrets (not individual keys); Failed counts targets skipped due to an error;
// Deleted counts orphaned Secrets reaped by cleanup (or that WOULD be, in dry-run).
// Revoked counts targets whose materialized Secret was actually wiped/trimmed
// because the upstream value is definitively gone (deleted or access revoked) —
// #140. Suspected counts targets whose confirmed-gone/revoked state was detected
// but NOT acted on because the mass-revocation circuit breaker tripped (coordinator
// decision, 2026-09-25 inbox item 1) and no valid mass_prune_ack was present — see
// massRevocationTripped.
type Result struct {
	Created   int
	Updated   int
	Unchanged int
	Failed    int
	Deleted   int
	Revoked   int
	Suspected int
	// SourceSuspended / SourceExpired / SourceExpiring count targets observed this pass
	// with a suspended source, an expired source, or a source inside an expiry warning
	// window (see source_state.go). They are not failures and not revocations: the
	// target Secret is retained (or, for a suspended source with on_suspend clear, has
	// that key emptied) and the loop keeps its normal interval.
	SourceSuspended int
	SourceExpired   int
	SourceExpiring  int
	// AuthFailed counts targets skipped because Keyorix answered 401 to the agent's own
	// credential (ErrUnauthorized). The target Secret is left untouched; such a target is
	// ALSO counted in Failed, so the loop backs off.
	AuthFailed int
	// KeyorixUnreachable counts targets skipped because Keyorix could not answer
	// (ErrUnreachable, ErrTimeout, ErrServerError: no response, timeout or 5xx). The
	// target Secret is left untouched; such a target is ALSO counted in Failed.
	KeyorixUnreachable int
	// Notes are informational log lines (state changes of sources), distinct from Errors.
	Notes  []string
	Errors []string
}

// target is the (namespace, name) identity of a Kubernetes Secret.
type target struct {
	namespace string
	name      string
}

func (t target) String() string { return t.namespace + "/" + t.name }

// Reconcile groups the mappings by target Secret, fetches each referenced value,
// and creates/updates the Secret only when its desired data differs from what's
// already there. A TRANSIENT fetch or apply failure for one target is recorded and
// skipped — it never aborts the pass or writes a partial Secret — so other targets
// still sync unaffected. A DEFINITIVE per-key failure (ErrUpstreamGone: the upstream
// secret was deleted, or this agent's access to it was revoked) instead drops only
// that one key and applies the Secret with its remaining, still-valid keys — or
// removes the Secret entirely if none are left — so one revoked key in a Secret
// backed by several mappings never collaterally wipes out unrelated live keys
// (G05). See buildDesired for the fetch-time split between the two cases. The
// returned Result tallies the outcome.
func (e *Engine) Reconcile(ctx context.Context, mappings []SecretMapping) (Result, error) { // NOSONAR -- cognitive complexity 31, suppress go:S3776
	var res Result

	grouped, errs := groupByTarget(mappings)
	res.Errors = append(res.Errors, errs...)
	res.Failed += len(errs)

	// Stable order so logs and tests are deterministic.
	targets := make([]target, 0, len(grouped))
	for t := range grouped {
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].String() < targets[j].String() })

	// Phase 1: fetch every target's desired data BEFORE deciding whether to act on
	// any confirmed-gone/revoked result. The mass-revocation circuit breaker (below)
	// needs the FULL pass's revoked-vs-total ratio to decide whether this looks like
	// one shared credential event rather than N independent ones — a decision that
	// can only be made once every target for this pass has been fetched, not
	// target-by-target as the original single-loop version did.
	states := make([]reconcileState, 0, len(targets))
	revokedCount := 0
	for _, t := range targets {
		desired, revokedRefs, rep, ferr := e.buildDesired(ctx, grouped[t])
		refs := make([]string, 0, len(grouped[t]))
		for _, m := range grouped[t] {
			refs = append(refs, m.Ref)
		}
		states = append(states, reconcileState{t: t, desired: desired, revokedRefs: revokedRefs, rep: rep, refs: refs, ferr: ferr})
		if ferr == nil && len(revokedRefs) > 0 {
			revokedCount++
		}
	}

	// Mass-revocation circuit breaker (coordinator decision, 2026-09-25 inbox item
	// 1, restoring the secure default reverted below): more than massPruneMinCount
	// targets AND more than massPruneFraction of ALL targets in this SAME pass
	// confirmed gone/revoked looks like one shared credential rotation/revocation —
	// e.g. the agent's own machine-identity token was rotated, which reads as a
	// 401/403 on every mapping's fetch at once — not N unrelated per-secret events.
	// Tripped means none of them are wiped this pass, no matter how confidently each
	// one individually looks gone, until massPruneAckValid says an operator
	// explicitly acknowledged it via mass_prune_ack. A single revocation (or a few,
	// below the threshold) is unaffected and still wipes immediately below.
	massTripped := e.pruneOnRevoke && massRevocationTripped(revokedCount, len(targets))
	massBlocked := massTripped && !e.massPruneAckValid(e.clockNow())

	for _, st := range states {
		t := st.t
		if st.ferr != nil {
			// A TRANSIENT failure (network/5xx — never ErrUpstreamGone, see
			// buildDesired) just skips this pass and retries next time: the value
			// may still be valid, so the existing Secret is left completely
			// untouched rather than written with a key missing or removed outright.
			res.Failed++
			if errors.Is(st.ferr, ErrUnauthorized) {
				res.AuthFailed++
				res.Errors = append(res.Errors, fmt.Sprintf("%s: KeyorixAuthFailed: %v — target Secret left unchanged (a 401 never prunes)", t, st.ferr))
				continue
			}
			if reason := fetchUnavailableReason(st.ferr); reason != "" {
				res.KeyorixUnreachable++
				res.Errors = append(res.Errors, fmt.Sprintf("%s: KeyorixUnreachable (%s): %v — target Secret left unchanged", t, reason, st.ferr))
				continue
			}
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", t, st.ferr))
			continue
		}
		desired := st.desired
		revokedRefs := st.revokedRefs

		// Suspended / expired / soon-to-expire sources: counted and logged (not errors).
		// A held key (expired source, or suspended with on_suspend retain) keeps its live
		// value; the target's other keys keep syncing in the same single Apply (carried
		// over below, so Apply's field ownership does not prune the held keys). Only a
		// target whose every mapping is held, with nothing to clear or prune, is skipped
		// outright. A revoked ref in the same target takes the revoked path below.
		e.recordSourceStates(&res, st.t, st.rep, st.refs)
		held := st.rep.hold(e.clearOnSuspend)
		clearing := st.rep.clearing(e.clearOnSuspend)
		if held && len(revokedRefs) == 0 && len(desired) == 0 && !clearing {
			continue
		}

		if len(revokedRefs) > 0 {
			switch {
			case !e.pruneOnRevoke:
				// prune_on_revoke is explicitly false (opt-out of the secure
				// default): a confirmed revoke/gone is surfaced but NOT acted on —
				// the target is skipped entirely, exactly like a transient failure,
				// leaving any existing Secret (every key, not just the revoked one)
				// completely untouched. Applying only the still-valid keys instead
				// of skipping outright isn't safe either: Apply's Server-Side-Apply
				// field-manager ownership prunes any key NOT present in the applied
				// data, so a "partial" apply would still silently drop the revoked
				// key's last-known value.
				res.Revoked++
				res.Errors = append(res.Errors, fmt.Sprintf("%s: upstream secret gone or access revoked for %s; prune_on_revoke is false, target Secret left unchanged", t, strings.Join(revokedRefs, ", ")))
				continue
			case massBlocked:
				res.Suspected++
				res.Errors = append(res.Errors, fmt.Sprintf(
					"%s: upstream secret gone or access revoked for %s; MASS REVOCATION SUSPECTED (%d/%d targets confirmed gone/revoked this pass) — target Secret left unchanged, prune_on_revoke NOT applied. Set mass_prune_ack to an RFC3339 timestamp within the last %s to acknowledge and proceed",
					t, strings.Join(revokedRefs, ", "), revokedCount, len(targets), massPruneAckWindow))
				continue
			default:
				// #140 / G05: a DEFINITIVE failure for one or more mappings (the
				// upstream secret was deleted, or this agent's access to it was
				// revoked — 404/401/403, never a transient network/5xx error) must
				// propagate to the cluster rather than being left at its last-known,
				// possibly-compromised or now-unauthorized value indefinitely (skip
				// and retry never converges, since the SAME definitive failure
				// recurs every pass). Only the affected key(s) are dropped here —
				// unrelated keys mapped to the same target Secret that fetched fine
				// are still applied below; the Secret itself is removed only if
				// buildDesired left nothing valid for it at all.
				action := "dropping the affected key(s) from the Secret"
				if len(desired) == 0 {
					action = "removing the now-empty Secret entirely"
				}
				res.Errors = append(res.Errors, fmt.Sprintf("%s: upstream secret gone or access revoked for %s; %s", t, strings.Join(revokedRefs, ", "), action))
			}
		}

		if held {
			if cerr := e.carryOverHeld(ctx, t, st.rep, desired); cerr != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("%s: read: %v", t, cerr))
				continue
			}
		}

		if len(desired) == 0 && len(revokedRefs) == 0 {
			// on_suspend clear and every source is suspended: nothing to write. Empty the
			// keys in a Secret the agent manages; never create an empty one.
			current, gerr := e.sink.Get(ctx, t.namespace, t.name)
			if gerr != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("%s: read: %v", t, gerr))
				continue
			}
			if len(current) == 0 {
				res.Unchanged++
				continue
			}
			if !e.dryRun {
				if aerr := e.sink.Apply(ctx, t.namespace, t.name, map[string][]byte{}); aerr != nil {
					res.Failed++
					res.Errors = append(res.Errors, fmt.Sprintf("%s: apply: %v", t, aerr))
					continue
				}
			}
			res.Updated++
			continue
		}

		if len(desired) == 0 {
			// Every mapping for this target came back revoked/gone: nothing valid
			// remains to materialize, so the stale Secret is removed outright.
			if e.dryRun {
				res.Revoked++
				continue
			}
			if derr := e.sink.Delete(ctx, t.namespace, t.name); derr != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("%s: failed to remove revoked secret: %v", t, derr))
				continue
			}
			res.Revoked++
			continue
		}

		current, gerr := e.sink.Get(ctx, t.namespace, t.name)
		if gerr != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: read: %v", t, gerr))
			continue
		}

		if dataEqual(current, desired) {
			res.Unchanged++
			continue
		}

		// In dry-run, tally what WOULD change but don't write.
		if e.dryRun {
			if current == nil {
				res.Created++
			} else {
				res.Updated++
			}
			continue
		}

		if aerr := e.sink.Apply(ctx, t.namespace, t.name, desired); aerr != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: apply: %v", t, aerr))
			continue
		}
		if current == nil {
			res.Created++
		} else {
			res.Updated++
		}
	}

	// With cleanup enabled, reap Secrets the agent previously created (carrying its
	// managed-by label) whose target is no longer in the config — otherwise a removed
	// mapping leaves a stale Secret behind forever. Runs after the apply loop so the
	// desired set reflects everything this config still wants.
	if e.cleanup {
		e.cleanupOrphans(ctx, grouped, &res)
	}
	return res, nil
}

// managedByLabel marks every Secret the agent owns; cleanup only ever lists and
// deletes Secrets carrying it, so operator- or other-tool-created Secrets are never
// touched. Mirrors the Server-Side Apply field manager (keyorix-sync).
const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "keyorix-sync"
)

// cleanupOrphans lists agent-owned Secrets in every namespace the config still
// references and deletes those whose target is no longer desired. It is scoped to the
// managed-by label (never touches foreign Secrets) and to namespaces present in the
// config — dropping a namespace from the config entirely leaves its Secrets unreaped
// (documented). A target still in the config is kept even if its fetch failed this
// pass, so a transient upstream error can't trigger a delete.
func (e *Engine) cleanupOrphans(ctx context.Context, grouped map[target][]SecretMapping, res *Result) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	desired := make(map[target]bool, len(grouped))
	nsSet := make(map[string]struct{})
	for t := range grouped {
		desired[t] = true
		nsSet[t.namespace] = struct{}{}
	}
	namespaces := make([]string, 0, len(nsSet))
	for ns := range nsSet {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	for _, ns := range namespaces {
		owned, err := e.sink.List(ctx, ns)
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: list owned: %v", ns, err))
			continue
		}
		sort.Strings(owned) // deterministic order for logs/tests
		for _, name := range owned {
			t := target{namespace: ns, name: name}
			if desired[t] {
				continue
			}
			if e.dryRun {
				res.Deleted++ // report the would-delete without removing anything
				continue
			}
			if derr := e.sink.Delete(ctx, ns, name); derr != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("%s: delete orphan: %v", t, derr))
				continue
			}
			res.Deleted++
		}
	}
}

// reconcileState holds one target's Phase-1 fetch result, computed for every target
// up front so the mass-revocation circuit breaker (see Reconcile) can see the WHOLE
// pass's revoked-vs-total ratio before any target is actually acted on.
type reconcileState struct {
	t           target
	desired     map[string][]byte
	revokedRefs []string
	rep         sourceReport
	refs        []string // every ref of the target, for recovery logging
	ferr        error
}

// massPruneMinCount and massPruneFraction define the mass-revocation circuit
// breaker's trip threshold (coordinator decision, 2026-09-25 inbox item 1): a pass
// that confirms MORE than massPruneMinCount targets gone/revoked AND that count is
// MORE than massPruneFraction of every managed target is treated as a suspected
// shared-credential event (e.g. the agent's own machine-identity token was rotated
// or revoked, which reads as a definitive failure on every mapping at once) rather
// than that many independent, coincidental per-secret revocations. A single
// revocation — however large a fraction of a very small target set it is — never
// trips this on its own: massPruneMinCount requires more than one.
const (
	massPruneMinCount = 1
	massPruneFraction = 0.20
)

// massRevocationTripped implements the mass-revocation circuit breaker's pure
// threshold decision (see massPruneMinCount/massPruneFraction), split out from
// Reconcile so the boundary (exactly massPruneMinCount, exactly
// massPruneFraction) is directly unit-testable without constructing a full
// Engine/Reconcile pass.
func massRevocationTripped(revokedCount, totalTargets int) bool {
	if totalTargets == 0 || revokedCount <= massPruneMinCount {
		return false
	}
	return float64(revokedCount) > massPruneFraction*float64(totalTargets)
}

// massPruneAckWindow bounds how long an operator's explicit mass-prune
// acknowledgement (the mass_prune_ack config field) stays valid after being set —
// so a stale ack left over from a past, already-resolved incident doesn't silently
// authorize wiping a FUTURE, unrelated mass-revocation event forever. 1 hour
// comfortably covers "I just saw the alert and am unblocking this pass" while still
// requiring a fresh, deliberate action for the next incident.
const massPruneAckWindow = 1 * time.Hour

// massPruneAckValid reports whether e's configured mass-prune ack timestamp is
// present and falls within massPruneAckWindow of now (and not in the future, which
// would only ever indicate clock skew or a mis-set config value, not a genuine
// acknowledgement of an event that has already happened).
func (e *Engine) massPruneAckValid(now time.Time) bool {
	if e.massPruneAck.IsZero() {
		return false
	}
	age := now.Sub(e.massPruneAck)
	return age >= 0 && age < massPruneAckWindow
}

// clockNow returns the current time via e.now, defaulting to time.Now — overridden
// in tests for deterministic massPruneAckValid checks.
func (e *Engine) clockNow() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now()
}

// Engine reconciles Keyorix secrets into Kubernetes Secrets via a Fetcher and Sink.
type Engine struct {
	fetcher Fetcher
	sink    Sink
	dryRun  bool
	cleanup bool
	// pruneOnRevoke gates whether a confirmed-gone/revoked upstream reference
	// actually wipes/trims its target Secret (see the Reconcile branch it guards).
	// Defaults to true (NewEngine) — the secure default (coordinator decision,
	// 2026-09-25 inbox item 1, restoring commit 03d08f23's original "#428/#676"
	// behavior after a brief default-keep regression): a secret confirmed gone or
	// access confirmed revoked must not stay readable in the cluster indefinitely.
	// The mass-revocation circuit breaker above bounds the blast radius of this
	// default when many targets are confirmed gone/revoked in the SAME pass (a
	// shared credential rotation, not independent per-secret events) — see
	// massRevocationTripped. Set explicitly to false (WithKeepOnRevoke) to opt out
	// entirely for deployments that prefer availability over immediate reap.
	pruneOnRevoke bool
	massPruneAck  time.Time
	now           func() time.Time
	// clearOnSuspend (WithClearOnSuspend, config on_suspend: clear): a suspended source's
	// key is emptied in the target Secret instead of retained. See source_state.go.
	clearOnSuspend bool
	// sourceSeen remembers each "target|ref" state so a state change is logged once.
	sourceSeen map[string]string
}

// Option configures an Engine.
type Option func(*Engine)

// WithDryRun makes the engine compute the diff and report what WOULD change without
// writing any Secret — for config validation and safe previews.
func WithDryRun() Option {
	return func(e *Engine) { e.dryRun = true }
}

// WithCleanup makes the engine reap orphaned Secrets — agent-owned Secrets whose
// target is no longer in the config. Off by default: deleting Secrets is destructive,
// so it must be opted into explicitly. Combines with WithDryRun to preview deletions.
func WithCleanup() Option {
	return func(e *Engine) { e.cleanup = true }
}

// WithPruneOnRevoke makes the engine actually remove/trim a target Secret when the
// upstream Keyorix reference for one of its mappings is confirmed gone or the
// agent's access is confirmed revoked (see the pruneOnRevoke branch in Reconcile).
// This is now also NewEngine's default — WithPruneOnRevoke is kept as an explicit,
// idempotent knob (K8S track / coordinator decision: "keep prune_on_revoke as an
// explicit knob") so config wiring and existing call sites can still state the
// intent directly instead of relying on the zero-value default.
func WithPruneOnRevoke() Option {
	return func(e *Engine) { e.pruneOnRevoke = true }
}

// WithKeepOnRevoke opts OUT of the secure default: a confirmed-gone/revoked upstream
// reference is surfaced (Result.Revoked) but the target Secret is left completely
// untouched, for deployments that prefer availability over immediate reap. See
// pruneOnRevoke's doc comment for the default this reverses.
func WithKeepOnRevoke() Option {
	return func(e *Engine) { e.pruneOnRevoke = false }
}

// WithClearOnSuspend makes a suspended source empty its key in the target Secret
// instead of leaving the last value in place (the default, "retain"). The Secret object
// is never deleted and a Secret the agent does not own is never touched. An expired
// source is always retained. See source_state.go.
func WithClearOnSuspend() Option {
	return func(e *Engine) { e.clearOnSuspend = true }
}

// WithMassPruneAck sets the mass-revocation circuit breaker's acknowledgement
// timestamp (see massPruneAckValid) — sourced from Config.GetMassPruneAck (the
// mass_prune_ack config field). A zero Time (the field left unset) never
// acknowledges anything.
func WithMassPruneAck(ack time.Time) Option {
	return func(e *Engine) { e.massPruneAck = ack }
}

// NewEngine constructs an Engine over the given Fetcher and Sink. pruneOnRevoke
// defaults to true (the secure default — see its doc comment); pass
// WithKeepOnRevoke to opt out.
func NewEngine(fetcher Fetcher, sink Sink, opts ...Option) *Engine {
	e := &Engine{fetcher: fetcher, sink: sink, pruneOnRevoke: true}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// buildDesired fetches every mapping's referenced value and assembles the target
// Secret's desired data map. The two fetch-error cases are handled differently:
//
//   - ErrUpstreamGone (a DEFINITIVE failure: the referenced Keyorix secret was
//     deleted, or this agent's access was revoked) drops only THAT mapping's key
//     from the desired map and records its ref in the returned revoked slice, then
//     keeps fetching the rest — so one revoked key never discards the other,
//     still-valid keys mapped to the same target Secret.
//   - Any OTHER (transient network/5xx) error aborts the whole build and returns
//     an error: the value may still be valid, so a transient blip must not
//     silently drop — nor overwrite with a partial result — a key from an
//     otherwise-complete Secret. The caller skips this target entirely for the
//     pass in that case.
func (e *Engine) buildDesired(ctx context.Context, mappings []SecretMapping) (desired map[string][]byte, revoked []string, rep sourceReport, err error) {
	desired = make(map[string][]byte, len(mappings))
	expiryF, hasExpiry := e.fetcher.(ExpiryFetcher)
	for _, m := range mappings {
		var val []byte
		var exp *time.Time
		var ferr error
		if hasExpiry {
			val, exp, ferr = expiryF.FetchWithExpiry(ctx, m.Ref)
		} else {
			val, ferr = e.fetcher.Fetch(ctx, m.Ref)
		}
		if ferr != nil {
			switch {
			case errors.Is(ferr, ErrSourceSuspended):
				rep.suspended = append(rep.suspended, heldRef{ref: m.Ref, key: m.Key, clearRequested: errors.Is(ferr, ErrSourceClearRequested)})
				continue
			case errors.Is(ferr, ErrSourceExpired):
				rep.expired = append(rep.expired, heldRef{ref: m.Ref, key: m.Key})
				continue
			case errors.Is(ferr, ErrUpstreamGone):
				revoked = append(revoked, m.Ref)
				continue
			}
			return nil, nil, sourceReport{}, fmt.Errorf("fetch %q: %w", m.Ref, ferr)
		}
		rep.noteExpiry(m.Ref, exp, e.clockNow())
		desired[m.Key] = val
	}
	return desired, revoked, rep, nil
}

// carryOverHeld copies the current value of every retained key (an expired source, or a
// suspended one under on_suspend retain) into desired, so applying a target that also has
// a revoked ref leaves the retained keys as they were instead of pruning them.
func (e *Engine) carryOverHeld(ctx context.Context, t target, rep sourceReport, desired map[string][]byte) error {
	keys := rep.heldKeys(e.clearOnSuspend)
	if len(keys) == 0 {
		return nil
	}
	current, err := e.sink.Get(ctx, t.namespace, t.name)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if v, ok := current[k]; ok {
			desired[k] = v
		}
	}
	return nil
}

// groupByTarget buckets mappings by their target Secret, validating each and
// rejecting duplicate keys within one target. Invalid mappings are returned as error
// strings (and excluded) rather than aborting the whole set.
func groupByTarget(mappings []SecretMapping) (map[target][]SecretMapping, []string) {
	grouped := make(map[target][]SecretMapping)
	seen := make(map[string]bool) // "ns/name/key" → already mapped
	var errs []string
	for i, m := range mappings {
		if err := validateMapping(m); err != nil {
			errs = append(errs, fmt.Sprintf("mapping %d: %v", i, err))
			continue
		}
		t := target{namespace: m.Namespace, name: m.Name}
		dk := t.String() + "/" + m.Key
		if seen[dk] {
			errs = append(errs, fmt.Sprintf("mapping %d: duplicate key %q for Secret %s", i, m.Key, t))
			continue
		}
		seen[dk] = true
		grouped[t] = append(grouped[t], m)
	}
	return grouped, errs
}

// validateMapping rejects a mapping missing any required field.
func validateMapping(m SecretMapping) error {
	switch {
	case strings.TrimSpace(m.Ref) == "":
		return fmt.Errorf("ref is required")
	case strings.TrimSpace(m.Namespace) == "":
		return fmt.Errorf("namespace is required")
	case strings.TrimSpace(m.Name) == "":
		return fmt.Errorf("name is required")
	case strings.TrimSpace(m.Key) == "":
		return fmt.Errorf("key is required")
	case !isK8sSecretKey(m.Key):
		return fmt.Errorf("key %q is not a valid Kubernetes Secret data key (must match [-._a-zA-Z0-9]+)", m.Key)
	case !isDNS1123Label(m.Namespace):
		return fmt.Errorf("namespace %q is not a valid RFC1123 label", m.Namespace)
	case !isDNS1123Subdomain(m.Name):
		return fmt.Errorf("name %q is not a valid Kubernetes Secret name (RFC1123 subdomain)", m.Name)
	}
	return nil
}

// dataEqual reports whether two Secret data maps hold exactly the same keys and bytes.
func dataEqual(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || !bytes.Equal(av, bv) {
			return false
		}
	}
	return true
}
