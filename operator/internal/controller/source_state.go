package controller

// source_state.go — what the reconciler does and says when a referenced Keyorix
// secret is SUSPENDED or EXPIRED, or about to expire (FIX-3175B, following ERRMAP-1).
//
// Policy (Andrei, 2026-10-13):
//   - A fetch that fails for any reason other than a definitive "gone / access
//     revoked" answer (server unreachable, timeout, 5xx, a missing token Secret) never
//     modifies the target Secret; the error condition is set and the reconcile retries.
//   - EXPIRED: that ref's keys keep their last value (Retain); the target's other keys
//     keep syncing in the same single update. No setting.
//   - SUSPENDED: spec.onSuspend, Retain (default) freezes that ref's keys like an expiry;
//     Clear empties them (also while a sibling is expired) in a Secret the operator owns;
//     it never deletes the Secret and never touches one it does not own. Resuming
//     restores the data on the next reconcile.
//   - A suspension can ask, for itself, to clear the synced copies (a compromise
//     response: the server's 409 SecretSuspended carries details.clear_synced_copies).
//     That makes the ref Clear whatever spec.onSuspend says, with the same semantics;
//     resuming removes the request and the next reconcile restores the data.
//   - A held key is never overwritten or deleted. Only when EVERY ref is held (and none
//     is being cleared) is nothing written at all.
//   - Always: a SourceSecretHealthy=False condition, a Warning Event
//     (SourceSecretSuspended / SourceSecretExpired / SourceSecretExpiring) and the
//     keyorix_operator_source_secrets{state} gauge, all cleared on recovery. Ahead of
//     an expiry the Event fires when the secret first comes within 30 days, then 7, then 1.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
	"github.com/keyorixhq/keyorix/operator/internal/keyorix"
)

const (
	// conditionSourceHealthy is False while any referenced secret is suspended, expired
	// or inside an expiry warning window, and absent otherwise.
	conditionSourceHealthy = "SourceSecretHealthy"

	reasonSourceSuspended = "SourceSecretSuspended"
	reasonSourceExpired   = "SourceSecretExpired"
	reasonSourceExpiring  = "SourceSecretExpiring"
	reasonSourceRecovered = "SourceSecretRecovered"

	// eventAction is the events.k8s.io "action" of these Events.
	eventAction = "SyncSource"
)

// expiryWarnWindows are the warning thresholds ahead of an expiry, widest first.
var expiryWarnWindows = []struct {
	label string
	d     time.Duration
}{
	{"30d", 30 * 24 * time.Hour},
	{"7d", 7 * 24 * time.Hour},
	{"1d", 24 * time.Hour},
}

// sourceSecretsGauge is the number of KeyorixSecrets currently affected, by state:
// suspended, expired, or expiring (inside an expiry warning window).
var sourceSecretsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "keyorix_operator_source_secrets",
	Help: "KeyorixSecrets that currently reference a suspended, expired or soon-to-expire Keyorix secret, by state.",
}, []string{"state"})

func init() {
	ctrlmetrics.Registry.MustRegister(sourceSecretsGauge)
	for _, st := range []string{"suspended", "expired", "expiring"} {
		sourceSecretsGauge.WithLabelValues(st).Set(0)
	}
}

// valueInfoFetcher is implemented by fetchers that also report the source secret's
// expiration (keyorix.Client). Fetchers that only implement valueFetcher simply give no
// expiry warnings.
type valueInfoFetcher interface {
	FetchValueInfo(ctx context.Context, ref string) (keyorix.Value, error)
}

// sourceReport is what one reconcile learned about the referenced secrets' state.
type sourceReport struct {
	suspended []string // refs refused with 409 SecretSuspended
	expired   []string // refs refused with 409 SecretExpired
	// expiring maps a warning window label ("30d", "7d", "1d") to the refs inside it
	// (each ref in its tightest window only).
	expiring map[string][]string
	// heldKeys are the target Secret keys whose refs are held this reconcile: expired, or
	// suspended with onSuspend=Retain. Their live values are carried over untouched.
	heldKeys []string
	// clearing is true when some suspended ref's key is being emptied this reconcile:
	// spec.onSuspend=Clear, or the suspension itself asked for the synced copies to be
	// cleared (clearRequested).
	clearing bool
	// clearRequested are the suspended refs whose suspension asked to clear the synced
	// copies (409 SecretSuspended with details.clear_synced_copies), whatever
	// spec.onSuspend says.
	clearRequested []string
}

// heldReason is the reason of a hold: expired wins over suspended.
func (rp *sourceReport) heldReason() string {
	if len(rp.expired) > 0 {
		return reasonSourceExpired
	}
	return reasonSourceSuspended
}

// partialHold describes a reconcile that synced the readable keys but carried the held
// ones over unchanged; nil when no key is held.
func (rp *sourceReport) partialHold() *sourceHeldError {
	if len(rp.heldKeys) == 0 {
		return nil
	}
	_, _, msg, _ := rp.summary()
	return &sourceHeldError{
		reason: rp.heldReason(),
		msg:    fmt.Sprintf("%s — held key(s) %s left unchanged, the other keys were synced", msg, joinSorted(rp.heldKeys)),
	}
}

func (rp *sourceReport) noteExpiry(ref string, exp *time.Time, now time.Time) {
	if exp == nil {
		return
	}
	remaining := exp.Sub(now)
	label := ""
	for _, w := range expiryWarnWindows {
		if remaining <= w.d {
			label = w.label // keep narrowing: the last matching (tightest) window wins
		}
	}
	if label == "" {
		return
	}
	if rp.expiring == nil {
		rp.expiring = map[string][]string{}
	}
	rp.expiring[label] = append(rp.expiring[label], ref)
}

// summary returns the condition reason, the gauge state and a deterministic message
// (it names refs and windows, never the remaining days, so it only changes when the
// situation does), or ok=false when everything is healthy.
func (rp *sourceReport) summary() (reason, state, msg string, ok bool) {
	var parts []string
	if len(rp.suspended) > 0 {
		parts = append(parts, "suspended: "+joinSorted(rp.suspended))
		if len(rp.clearRequested) > 0 {
			parts = append(parts, "synced copies cleared at the suspension's request: "+joinSorted(rp.clearRequested))
		}
		reason, state = reasonSourceSuspended, "suspended"
	}
	if len(rp.expired) > 0 {
		parts = append(parts, "expired: "+joinSorted(rp.expired))
		if reason == "" {
			reason, state = reasonSourceExpired, "expired"
		}
	}
	for _, w := range expiryWarnWindows {
		if refs := rp.expiring[w.label]; len(refs) > 0 {
			parts = append(parts, fmt.Sprintf("expires within %s: %s", w.label, joinSorted(refs)))
			if reason == "" {
				reason, state = reasonSourceExpiring, "expiring"
			}
		}
	}
	if reason == "" {
		return "", "", "", false
	}
	return reason, state, strings.Join(parts, "; "), true
}

func joinSorted(refs []string) string {
	cp := append([]string(nil), refs...)
	sort.Strings(cp)
	return strings.Join(cp, ", ")
}

// sourceHeldError is returned by buildDesired when the reconcile must not change the
// target Secret at all because EVERY referenced secret is held (expired, or suspended
// with onSuspend Retain). The target keeps its last value; the reconcile requeues at the
// refresh interval (not with error backoff), so a resume is picked up within one
// interval. When only some refs are held it is not an error: partialHold builds the same
// value for the Ready condition while the readable keys sync.
type sourceHeldError struct {
	reason string
	msg    string
}

func (e *sourceHeldError) Error() string { return e.msg }

func asSourceHeld(err error) (*sourceHeldError, bool) {
	var h *sourceHeldError
	if errors.As(err, &h) {
		return h, true
	}
	return nil, false
}

// recordSourceState sets or clears the SourceSecretHealthy condition on ks (in memory;
// the caller persists status), emits a Warning Event when the situation is new or has
// changed (a Normal one on recovery), and refreshes the gauge. It emits nothing while
// the same situation persists, so a suspension does not produce an Event per reconcile.
func (r *KeyorixSecretReconciler) recordSourceState(ks *secretsv1alpha1.KeyorixSecret, rep *sourceReport) {
	key := types.NamespacedName{Namespace: ks.Namespace, Name: ks.Name}
	// A copy: setCondition below overwrites the slice element in place.
	var prev *metav1.Condition
	if c := findCondition(ks.Status.Conditions, conditionSourceHealthy); c != nil {
		cp := *c
		prev = &cp
	}
	reason, state, msg, unhealthy := rep.summary()
	if !unhealthy {
		if prev != nil {
			removeCondition(&ks.Status.Conditions, conditionSourceHealthy)
			if r.Recorder != nil {
				r.Recorder.Eventf(ks, nil, corev1.EventTypeNormal, reasonSourceRecovered, eventAction,
					"referenced Keyorix secrets are readable again; target Secret %q is in sync", targetNameOf(ks))
			}
		}
		r.sourceTracker.set(key, "")
		return
	}
	setCondition(&ks.Status.Conditions, metav1.Condition{
		Type:               conditionSourceHealthy,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ks.Generation,
		LastTransitionTime: metav1.Now(),
	})
	if r.Recorder != nil && (prev == nil || prev.Reason != reason || prev.Message != msg) {
		r.Recorder.Eventf(ks, nil, corev1.EventTypeWarning, reason, eventAction, "%s", msg)
	}
	r.sourceTracker.set(key, state)
}

func targetNameOf(ks *secretsv1alpha1.KeyorixSecret) string {
	if ks.Spec.Target.Name != "" {
		return ks.Spec.Target.Name
	}
	return ks.Name
}

func findCondition(conds []metav1.Condition, t string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

func removeCondition(conds *[]metav1.Condition, t string) {
	out := (*conds)[:0]
	for _, c := range *conds {
		if c.Type != t {
			out = append(out, c)
		}
	}
	*conds = out
}

// sourceStateTracker remembers each KeyorixSecret's current state so the gauge can be
// recomputed. The zero value is ready to use.
type sourceStateTracker struct {
	mu    sync.Mutex
	state map[types.NamespacedName]string
}

// set records key's state ("" = healthy or gone) and refreshes the gauge.
func (t *sourceStateTracker) set(key types.NamespacedName, state string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == nil {
		t.state = map[types.NamespacedName]string{}
	}
	if state == "" {
		delete(t.state, key)
	} else {
		t.state[key] = state
	}
	counts := map[string]float64{"suspended": 0, "expired": 0, "expiring": 0}
	for _, s := range t.state {
		counts[s]++
	}
	for s, n := range counts {
		sourceSecretsGauge.WithLabelValues(s).Set(n)
	}
}
