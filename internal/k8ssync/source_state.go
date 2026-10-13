package k8ssync

// source_state.go — what the sync engine does and says when a referenced Keyorix
// secret is SUSPENDED or EXPIRED, or about to expire (FIX-3175B, following ERRMAP-1).
//
// Policy (Andrei, 2026-10-13), the same as the operator's:
//   - A fetch that fails for any other reason than a definitive "gone / access revoked"
//     answer (server unreachable, timeout, 5xx) never modifies the target Secret; the
//     pass records the failure and the next pass retries.
//   - EXPIRED: that ref's key keeps its last value (retained); the target's other keys
//     keep syncing in the same Apply. No setting.
//   - SUSPENDED: on_suspend, "retain" (default) or "clear". Retain freezes that ref's key
//     like an expiry. Clear empties that ref's key (also while a sibling is expired); it
//     never deletes the Secret and never touches one the agent does not own. Resuming
//     restores the data on the next pass.
//   - Always: a log line when a source enters or leaves a state, and the outcome labels
//     source_suspended / source_expired / source_expiring on keyorix_k8s_sync_secrets_total
//     (targets observed in that state during a pass). Ahead of an expiry the line is
//     logged when the secret first comes within 30 days, then 7, then 1.
//
// These states do not count towards the loop's failure backoff (see Run): they are
// expected, operator-driven and reversible, and a resume is picked up within one interval.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ExpiryFetcher is implemented by fetchers that also report a secret's expiration
// (KeyorixFetcher). Fetchers that only implement Fetcher simply give no expiry warnings.
type ExpiryFetcher interface {
	FetchWithExpiry(ctx context.Context, ref string) ([]byte, *time.Time, error)
}

var expiryWarnWindows = []struct {
	label string
	d     time.Duration
}{
	{"30d", 30 * 24 * time.Hour},
	{"7d", 7 * 24 * time.Hour},
	{"1d", 24 * time.Hour},
}

// heldRef is a mapping whose source is suspended or expired this pass.
type heldRef struct{ ref, key string }

// sourceReport is what one target's fetches learned about its sources' state.
type sourceReport struct {
	suspended []heldRef
	expired   []heldRef
	// expiring maps a warning window label to the refs inside it (each in its tightest).
	expiring map[string][]string
}

func (rp *sourceReport) noteExpiry(ref string, exp *time.Time, now time.Time) {
	if exp == nil {
		return
	}
	remaining := exp.Sub(now)
	label := ""
	for _, w := range expiryWarnWindows {
		if remaining <= w.d {
			label = w.label
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

// hold reports whether some key of the target is held: an expired source, or a suspended
// one while on_suspend is retain. Only the held keys are frozen (carryOverHeld); the
// target's other keys keep syncing.
func (rp *sourceReport) hold(clearOnSuspend bool) bool {
	return len(rp.expired) > 0 || (len(rp.suspended) > 0 && !clearOnSuspend)
}

// heldKeys returns the Secret keys whose sources are retained this pass.
func (rp *sourceReport) heldKeys(clearOnSuspend bool) []string {
	var keys []string
	for _, h := range rp.expired {
		keys = append(keys, h.key)
	}
	if !clearOnSuspend {
		for _, h := range rp.suspended {
			keys = append(keys, h.key)
		}
	}
	return keys
}

// recordSourceStates counts the target's states into res (once per pass, so the metric
// reads as "targets observed in this state") and logs a line whenever a ref's state
// changes: entering suspended / expired / an expiry window, or recovering.
func (e *Engine) recordSourceStates(res *Result, t target, rp sourceReport, refs []string) {
	if len(rp.suspended) > 0 {
		res.SourceSuspended++
	}
	if len(rp.expired) > 0 {
		res.SourceExpired++
	}
	if len(rp.expiring) > 0 {
		res.SourceExpiring++
	}

	now := map[string]string{} // ref -> state this pass ("" = healthy)
	for _, h := range rp.suspended {
		now[h.ref] = "suspended"
	}
	for _, h := range rp.expired {
		now[h.ref] = "expired"
	}
	for label, rs := range rp.expiring {
		for _, r := range rs {
			now[r] = "expires within " + label
		}
	}
	if e.sourceSeen == nil {
		e.sourceSeen = map[string]string{}
	}
	for _, ref := range refs {
		was, st := e.sourceSeen[t.String()+"|"+ref], now[ref]
		if was == st {
			continue
		}
		if st == "" {
			delete(e.sourceSeen, t.String()+"|"+ref)
			res.Notes = append(res.Notes, fmt.Sprintf("%s: source secret %q is readable again (was %s); target Secret is in sync", t, ref, was))
			continue
		}
		e.sourceSeen[t.String()+"|"+ref] = st
		reason := map[string]string{"suspended": ReasonSourceSecretSuspended, "expired": ReasonSourceSecretExpired}[st]
		if reason == "" {
			reason = ReasonSourceSecretExpiring
		}
		action := "its key is left unchanged in the target Secret; the other keys keep syncing"
		if st == "suspended" && e.clearOnSuspend {
			action = "on_suspend is clear: its key is emptied in the target Secret"
		}
		if strings.HasPrefix(st, "expires") {
			action = "the target Secret keeps syncing until then"
		}
		res.Notes = append(res.Notes, fmt.Sprintf("WARNING %s: %s: source secret %q %s; %s", reason, t, ref, st, action))
	}
}

// Reasons, shared with the operator's Events and conditions so one name follows an
// incident through logs, metrics and status.
const (
	ReasonSourceSecretSuspended = "SourceSecretSuspended"
	ReasonSourceSecretExpired   = "SourceSecretExpired"
	ReasonSourceSecretExpiring  = "SourceSecretExpiring"
)
