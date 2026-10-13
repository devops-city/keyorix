// Package controller holds the KeyorixSecret reconciler: it reads the referenced
// Keyorix secret values and materialises them into a native Kubernetes Secret, owned by
// the KeyorixSecret so Kubernetes garbage-collects the Secret when the CR is deleted.
package controller

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/recorder"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
	"github.com/keyorixhq/keyorix/operator/internal/keyorix"
)

const (
	defaultRefreshInterval = 5 * time.Minute
	// minRefreshInterval floors spec.refreshInterval (#124): with no floor, a CR
	// author (or a compromised CR-writer) could set an absurdly small value (e.g.
	// "1ms") and every successful reconcile would immediately requeue itself —
	// each pass reads the CR, reads the token Secret, calls out to the external
	// Keyorix server, and writes .status — driving a reconcile/API/etcd storm that
	// starves the single shared workqueue for every other KeyorixSecret in the
	// cluster.
	minRefreshInterval = 30 * time.Second
	conditionReady     = "Ready"
	// maxConcurrentReconciles bounds how many KeyorixSecret reconciles run in parallel
	// (r143). ctrl.NewControllerManagedBy defaults to exactly 1 with no override — the
	// operator is deployed as a single cluster-wide instance (see cmd/main.go), so that
	// default means ONE shared worker services every KeyorixSecret in every namespace: a
	// single slow or malicious reconcile (a large Data array, or an entry pointed at an
	// allow-listed-but-slow server) stalls the sole worker and starves reconciliation of
	// every other tenant's KeyorixSecret cluster-wide. A small, fixed pool bounds how much
	// one bad reconcile can crowd out — kept low (rather than "unbounded") because higher
	// concurrency multiplies simultaneous outbound calls to the (trusted, but still
	// external) Keyorix server and simultaneous token-Secret reads; nothing else in this
	// module exposes reconciler tuning via a flag (cf. minRefreshInterval above), so this
	// follows the same fixed-constant convention rather than adding a new --flag.
	maxConcurrentReconciles = 5
	// reconcileTimeout bounds the total wall-clock time a single Reconcile call may run,
	// as defense in depth alongside KeyorixSecretSpec.Data's MaxItems=50 cap (r143):
	// buildDesired fetches every Data entry sequentially, each over HTTP with its own 30s
	// timeout (internal/keyorix.Client), so even a MaxItems-bounded array of entries that
	// are each slow-but-within-timeout could otherwise occupy a worker for up to
	// 50*30s=25m. 5 minutes is comfortably above any realistic sync (fetches normally
	// complete in well under a second each) while capping the worst case to a fraction of
	// that 25-minute ceiling.
	reconcileTimeout = 5 * time.Minute

	// confirmPruneAnnotation is the explicit escape hatch for the mass-revocation
	// circuit breaker (see massRevocationSuspected): set to an RFC3339 timestamp
	// (valid for massPruneAckWindow after it's set) to acknowledge a suspected mass
	// revocation and proceed with the wipe anyway. Coordinator decision, 2026-09-25
	// inbox item 1.
	confirmPruneAnnotation = "keyorix.io/confirm-prune"
	// massPruneAckWindow bounds how long confirmPruneAnnotation stays valid after
	// being set, so a stale ack left over from a past, already-resolved incident
	// doesn't silently authorize wiping a FUTURE, unrelated mass-revocation event
	// forever. 1 hour comfortably covers "I just saw the alert and am unblocking
	// this reconcile" while still requiring a fresh, deliberate action for the next
	// incident.
	massPruneAckWindow = 1 * time.Hour
	// massPruneMinCount and massPruneFraction define the mass-revocation circuit
	// breaker's trip threshold: more than massPruneMinCount KeyorixSecrets sharing
	// one TokenSecretRef AND more than massPruneFraction of that group confirmed
	// gone/revoked at once looks like one shared credential event (a rotation or
	// revocation of the token itself), not that many independent, coincidental
	// per-secret revocations. A single revocation — however large a fraction of a
	// very small group it is — never trips this on its own.
	massPruneMinCount = 1
	massPruneFraction = 0.20
	// massPruneProbeCap bounds how many OTHER KeyorixSecrets sharing this CR's
	// TokenSecretRef get live-probed by massRevocationSuspected before deciding
	// whether to wipe THIS CR's target Secret. Uncapped, a pathologically large
	// group sharing one token would turn a single confirmed-gone/revoked reconcile
	// into an unbounded fan-out of extra Keyorix requests. 100 is far above any
	// realistic fleet sharing one machine-identity token in practice.
	massPruneProbeCap = 100
	// reasonMassRevocationSuspected is the Ready condition reason set when the
	// circuit breaker withholds a wipe — distinct from UpstreamSecretGone/
	// UpstreamAccessRevoked (the underlying cause is still in the message) so a
	// reader of .status can tell "wipe withheld, suspected mass event" apart from
	// "wipe applied" or "wipe deliberately skipped by PrunePolicy Keep".
	reasonMassRevocationSuspected = "MassRevocationSuspected"
	// reasonKeyorixAuthFailed is the Warning Event reason (and the leading word of the Ready
	// message) set when Keyorix answers 401 to the operator's own credential. The target
	// Secret is kept.
	reasonKeyorixAuthFailed = "KeyorixAuthFailed"
	// reasonUpstreamAccessRevoked is the Ready condition reason of a 401. It is the reason
	// this path has always used (it used to wipe the Secret); it is kept so alerts that
	// match it keep firing, although the Secret is now kept. The precise cause is in the
	// Ready message ("KeyorixAuthFailed: ...") and in the Event reason.
	reasonUpstreamAccessRevoked = "UpstreamAccessRevoked"
	// reasonSyncError is the generic Ready reason for a failed sync. It is also the Ready
	// reason of an outage, so alerts matching it keep firing.
	reasonSyncError = "SyncError"
	// reasonInvalidSpec is the Ready reason of a spec with a duplicate spec.data secretKey.
	reasonInvalidSpec = "InvalidSpec"
	// reasonKeyorixUnreachable leads the Ready message and is the Warning Event reason set
	// when Keyorix could not answer a value read: unreachable, timed out or 5xx. The Ready
	// reason itself stays SyncError. The target Secret is kept. reasonKeyorixRecovered is
	// the Normal Event raised when the next reconcile reads successfully again.
	reasonKeyorixUnreachable = "KeyorixUnreachable"
	reasonKeyorixRecovered   = "KeyorixRecovered"
)

// authFailuresTotal counts reconciles where Keyorix rejected the operator's own
// credential (HTTP 401) and the target Secret was therefore kept as-is.
var authFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_operator_auth_failures_total",
	Help: "KeyorixSecret reconciles where Keyorix rejected the operator's own credential (HTTP 401); the target Secret was kept untouched.",
})

// fetchErrorsTotal counts reconciles where Keyorix could not answer a value read and the
// target Secret was therefore kept as-is. reason is unreachable (no response: connection
// refused, DNS, TLS), timeout, or server_error (HTTP 5xx). It counts every failed
// reconcile; the Warning Event is raised only on entry into the state.
var fetchErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_operator_fetch_errors_total",
	Help: "KeyorixSecret reconciles where Keyorix could not answer a value read (reason=unreachable|timeout|server_error); the target Secret was kept untouched.",
}, []string{"reason"})

// massRevocationSuspectedTotal counts reconciles where the mass-revocation circuit
// breaker withheld a confirmed-gone/revoked wipe pending an explicit
// keyorix.io/confirm-prune ack. Registered once at package init via
// controller-runtime's own metrics registry (served on the manager's existing
// /metrics endpoint — see newMetricsOptions in cmd/main.go), matching this
// module's convention of no separate custom metrics server.
var massRevocationSuspectedTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_operator_mass_revocation_suspected_total",
	Help: "KeyorixSecret reconciles where the mass-revocation circuit breaker withheld a confirmed-gone/revoked wipe pending an explicit keyorix.io/confirm-prune ack.",
})

func init() {
	ctrlmetrics.Registry.MustRegister(massRevocationSuspectedTotal)
	ctrlmetrics.Registry.MustRegister(authFailuresTotal)
	ctrlmetrics.Registry.MustRegister(fetchErrorsTotal)
	for _, reason := range []string{fetchReasonUnreachable, fetchReasonTimeout, fetchReasonServerError} {
		fetchErrorsTotal.WithLabelValues(reason)
	}
}

// Label values of keyorix_operator_fetch_errors_total{reason}.
const (
	fetchReasonUnreachable = "unreachable"
	fetchReasonTimeout     = "timeout"
	fetchReasonServerError = "server_error"
)

// fetchFailureReason maps a buildDesired error to the fetch_errors reason label, "" when
// the error is not a Keyorix-could-not-answer failure (token Secret missing, apply
// error, 4xx other than the classified ones...), which stays a plain SyncError.
func fetchFailureReason(err error) string {
	switch {
	case errors.Is(err, keyorix.ErrTimeout):
		return fetchReasonTimeout
	case errors.Is(err, keyorix.ErrServerError):
		return fetchReasonServerError
	case errors.Is(err, keyorix.ErrUnreachable):
		return fetchReasonUnreachable
	}
	return ""
}

// massRevocationTripped implements the mass-revocation circuit breaker's pure
// threshold decision (see massPruneMinCount/massPruneFraction), split out so the
// boundary is directly unit-testable without constructing a full reconciler/List.
func massRevocationTripped(revokedCount, groupSize int) bool {
	if groupSize == 0 || revokedCount <= massPruneMinCount {
		return false
	}
	return float64(revokedCount) > massPruneFraction*float64(groupSize)
}

// effectivePrunePolicy resolves ks.Spec.PrunePolicy's effective value, treating an
// EMPTY policy the same as PrunePolicyDelete (the restored secure default,
// 2026-09-25 coordinator decision) — defense in depth alongside the CRD's own
// +kubebuilder:default=Delete admission-time defaulting, for any path that builds
// a KeyorixSecret without going through API-server admission (a test, a direct
// client.Create, an object created under an older CRD version before this default
// existed).
func effectivePrunePolicy(p secretsv1alpha1.PrunePolicy) secretsv1alpha1.PrunePolicy {
	if p == "" {
		return secretsv1alpha1.PrunePolicyDelete
	}
	return p
}

// KeyorixSecretReconciler reconciles KeyorixSecret objects.
type KeyorixSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// AllowedServers is the set of trusted Keyorix base URLs (scheme://host) the operator
	// will send tokens to. A CR's spec.server MUST match one of these. Without it the
	// operator is a confused deputy: it holds cluster-wide Secret read and would ship a
	// CR-named Secret's value (the "token") to a CR-chosen server — letting a tenant who
	// can only create a CR exfiltrate any namespace Secret to an attacker. Empty = reject
	// every CR (fail closed); configured at startup from --allowed-servers.
	AllowedServers []string
	// newClient builds a value fetcher for a server/token; nil uses the real HTTP client.
	// Overridden in tests.
	newClient func(server, token string) valueFetcher
	// APIReader bypasses the manager's shared cache for reads that must not be
	// cached/watched cluster-wide — the token Secret lookup (#124). It is set from
	// mgr.GetAPIReader() at startup; nil falls back to the cached Client (tests
	// construct a reconciler directly and don't need the distinction).
	APIReader client.Reader
	// hashKey is a random, per-process HMAC key generated once at construction
	// (NewReconciler), used to fingerprint synced values into .status.syncedHash
	// (#124). status is a subresource of the CR, which is very commonly readable
	// by principals who hold no RBAC on the underlying Secret at all — an
	// unsalted, unkeyed sha256 there let any CR-getter run an offline brute-force/
	// dictionary attack against a low-entropy value with zero Secret-read access.
	// The key lives only in memory for this process's lifetime: the hash is a
	// point-in-time fingerprint for drift detection, not something requiring
	// cross-restart stability, so a fresh key on every restart is correct.
	hashKey []byte
	// Recorder emits Kubernetes Events (kubectl describe / events -n <ns>) for
	// reconcile-visible incidents — currently only the mass-revocation circuit
	// breaker tripping (see failSuspected). nil is safe (guarded at every call
	// site): tests that don't exercise that path construct the struct literal
	// directly and have no need for one. The events.k8s.io/v1 recorder API
	// (mgr.GetEventRecorder, not the deprecated GetEventRecorderFor/
	// corev1 record.EventRecorder) — see cmd/main.go's wiring.
	Recorder recorder.EventRecorder
	// now returns the current time; overridden in tests for deterministic
	// massPruneAcked window checks. nil (the zero value from a struct literal, as
	// tests that don't exercise the mass-revocation breaker use) falls back to
	// time.Now via clockNow.
	now func() time.Time
	// sourceTracker remembers which KeyorixSecrets reference a suspended, expired or
	// soon-to-expire secret, for the keyorix_operator_source_secrets gauge.
	sourceTracker sourceStateTracker
}

// NewReconciler builds a KeyorixSecretReconciler with a fresh random HMAC key for
// status.syncedHash (#124). Use this rather than constructing the struct literal
// directly in production code; tests that don't exercise hashData may still build
// the struct literal directly.
func NewReconciler(c client.Client, scheme *runtime.Scheme, apiReader client.Reader, allowedServers []string, rec recorder.EventRecorder) (*KeyorixSecretReconciler, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate status-hash HMAC key: %w", err)
	}
	return &KeyorixSecretReconciler{
		Client:         c,
		Scheme:         scheme,
		APIReader:      apiReader,
		AllowedServers: allowedServers,
		hashKey:        key,
		Recorder:       rec,
	}, nil
}

// clockNow returns the current time via r.now, defaulting to time.Now.
func (r *KeyorixSecretReconciler) clockNow() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// validateServer rejects a CR-supplied server that is not https or not in the operator's
// configured allow-list. This is the control that stops the confused-deputy exfiltration:
// the token (a possibly-arbitrary namespace Secret value) only ever travels to a trusted,
// TLS-protected destination the operator was explicitly configured to trust.
func (r *KeyorixSecretReconciler) validateServer(server string) error {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid server URL %q", server)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing server %q: only https is allowed (the bearer token must not travel in cleartext)", server)
	}
	if len(r.AllowedServers) == 0 {
		return fmt.Errorf("refusing CR-specified server %q: the operator has no allowed-servers configured and will not send a token to an arbitrary destination — set --allowed-servers to the trusted Keyorix URL(s)", server)
	}
	target := u.Scheme + "://" + u.Host
	for _, a := range r.AllowedServers {
		if au, perr := url.Parse(strings.TrimRight(strings.TrimSpace(a), "/")); perr == nil && au.Scheme+"://"+au.Host == target {
			return nil
		}
	}
	return fmt.Errorf("server %q is not in the operator's allowed-servers list", server)
}

// valueFetcher is the slice of the Keyorix client the reconciler needs (a seam for tests).
type valueFetcher interface {
	FetchValue(ctx context.Context, ref string) ([]byte, error)
}

// RBAC (#327/#427): `make manifests` generates operator/config/rbac/role.yaml
// from these markers via controller-gen, which fully regenerates that file on
// every run and does not preserve hand-written content in it -- so the
// rationale below lives here, at the actual source of truth, not in the
// generated output where a routine regen would silently discard it (as
// happened once already: an unpinned `make manifests` run stripped this exact
// explanation from role.yaml before anyone had committed it).
//
// This grants a ClusterRole (not a namespaced Role) because by DEFAULT the
// operator is deployed as a single cluster-wide instance that watches
// KeyorixSecret CRs (a namespaced CRD) across every namespace -- with no
// static namespace list configured it genuinely cannot predict ahead of time
// which namespace the next CR (and its TokenSecretRef/target Secret) will
// land in. Kubernetes RBAC also has no way to scope list/watch by
// resourceNames or to a dynamically changing namespace set, so narrowing this
// to per-namespace RoleBindings isn't possible for that deployment model.
//
// Operators who instead run one instance PER namespace (or per bounded tenant
// set) can opt into least-privilege, namespace-scoped RBAC: see the
// watchNamespaces value in deploy/helm/keyorix-operator, which passes the
// corresponding -watch-namespaces flag (operator/cmd/main.go) and swaps this
// same ClusterRole's binding from a cluster-wide ClusterRoleBinding to a
// namespace-scoped RoleBinding per watched namespace -- the ClusterRole
// definition here stays reusable across both modes (ADR-076).
//
// The verbs below are the minimum the reconcile logic actually uses:
// create/update/patch/get/list/watch to materialise and refresh the target
// Secret, and delete for wipeTargetSecret (this file), which removes the
// target Secret once the upstream Keyorix reference is confirmed gone (#428)
// -- no broader verb (e.g. deletecollection) is granted.
//
// What operator/cmd/main.go ALSO does to bound the blast radius of this (in
// the default cluster-wide mode, necessarily cluster-wide) grant: it scopes
// the manager's Secret informer cache to only Secrets carrying the operator's
// managed-by label (see secretCacheOptions in operator/cmd/main.go), so a
// compromised operator process can't trivially dump every cluster Secret
// straight out of its own in-memory cache -- only ones it already owns via
// this same RBAC.
//
// No marker is declared for keyorixsecrets/finalizers: this controller has no
// finalizer logic (garbage collection of the target Secret relies solely on
// the Kubernetes owner-reference GC, not a finalizer), so that grant would be
// unused, excess RBAC.
// +kubebuilder:rbac:groups=secrets.keyorix.io,resources=keyorixsecrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=secrets.keyorix.io,resources=keyorixsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile reads the referenced Keyorix values and writes them into the target Secret.
func (r *KeyorixSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Bound total reconcile time (r143): defense in depth alongside spec.data's MaxItems
	// cap, so a pathological case (many entries, each near its individual 30s HTTP
	// timeout) still can't monopolize this reconciler's limited worker pool
	// (maxConcurrentReconciles) indefinitely.
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)

	var ks secretsv1alpha1.KeyorixSecret
	if err := r.Get(ctx, req.NamespacedName, &ks); err != nil {
		// Deleted: the owned Secret is garbage-collected via its owner reference.
		if apierrors.IsNotFound(err) {
			r.sourceTracker.set(req.NamespacedName, "")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	interval := defaultRefreshInterval
	if ks.Spec.RefreshInterval != nil && ks.Spec.RefreshInterval.Duration > 0 {
		interval = ks.Spec.RefreshInterval.Duration
	}
	if interval < minRefreshInterval {
		interval = minRefreshInterval
	}

	secretName := ks.Spec.Target.Name
	if secretName == "" {
		secretName = ks.Name
	}

	// Duplicate secretKey values are rejected by the CRD schema (listType=map), but a CR
	// stored before that schema existed can still carry them. With a duplicate, a readable
	// entry could overwrite a key another entry holds frozen, so nothing is fetched or
	// written until the spec is fixed.
	if dup := duplicateSecretKey(ks.Spec.Data); dup != "" {
		return r.failInvalidSpec(ctx, &ks, dup)
	}

	desired, token, rep, err := r.buildDesired(ctx, &ks)
	if err != nil {
		if held, ok := asSourceHeld(err); ok {
			r.noteFetchRecovered(&ks)
			return r.holdSource(ctx, &ks, rep, held, interval)
		}
		logger.Error(err, "failed to assemble secret data")
		switch {
		case errors.Is(err, keyorix.ErrSecretGone):
			// The upstream Keyorix server AFFIRMATIVELY reported (404/403) that a
			// referenced secret no longer exists or is no longer accessible — as
			// opposed to a transient failure (network error, timeout, 5xx) where the
			// target Secret must be left untouched. Without this, a revoked/deleted
			// upstream secret leaves the previously synced target Secret sitting in
			// the cluster indefinitely, fully readable by every workload that mounts
			// it, with no indication anything is wrong (#428).
			return r.wipeAndFailGone(ctx, &ks, secretName, "UpstreamSecretGone", err, token)
		case errors.Is(err, keyorix.ErrUnauthorized):
			// A 401 means the operator's OWN credential (the token in tokenSecretRef) was
			// rejected: invalid, expired or rotated. It says nothing about whether this
			// workload's grant on the referenced secret was cut (that is a 403/404), so
			// it never wipes, whatever prunePolicy says (Andrei, 2026-10-13). The target
			// Secret stays as it is; the failure is surfaced and retried with backoff
			// until the credential is fixed.
			return r.failAuth(ctx, &ks, err)
		case fetchFailureReason(err) != "":
			// Keyorix could not answer (unreachable, timeout, 5xx): says nothing about the
			// secret or the grant, so the target Secret stays as it is; surfaced and retried
			// with backoff.
			return r.failFetch(ctx, &ks, err)
		default:
			return r.fail(ctx, &ks, err)
		}
	}
	r.noteFetchRecovered(&ks)

	hash := hashData(r.hashKey, desired)

	// A resumed or healthy source clears SourceSecretHealthy; a suspended one under
	// onSuspend=Clear (or one inside an expiry warning window) sets it. In memory
	// here, persisted by succeed()/fail() below.
	r.recordSourceState(&ks, rep)

	if len(desired) == 0 {
		// onSuspend=Clear and every referenced secret is suspended: there is nothing to
		// write. Empty the keys in a Secret we own, but never create an empty one.
		if err := r.emptyManagedSecret(ctx, &ks, secretName, rep.heldKeys); err != nil {
			logger.Error(err, "failed to clear the target Secret")
			return r.fail(ctx, &ks, err)
		}
	} else if err := r.applySecret(ctx, &ks, secretName, desired, rep.heldKeys); err != nil {
		logger.Error(err, "failed to apply target Secret")
		return r.fail(ctx, &ks, err)
	}

	// spec.target.name is mutable — if it changed since the last successful sync, the
	// Secret materialised under the OLD name is now orphaned: no later reconcile ever
	// revisits it by name again (Reconcile only ever looks at the CURRENT secretName),
	// so it would otherwise sit in the cluster forever with its last-synced, possibly
	// since-rotated, plaintext value, still owned by this (now-repurposed) CR, mountable
	// by any workload with ordinary Secret-read RBAC in the namespace.
	//
	// Wipe it only now, AFTER the NEW-named target Secret above has been confirmed built
	// and applied successfully — never before. Wiping the OLD Secret first (as this used
	// to do) turned a rename that then failed to sync (a typo'd ref, a revoked upstream
	// token, a transient outage) into a full availability outage: the old Secret gone,
	// the new one never created, so every workload mounting the old name lost it with no
	// rollback. Deferring the wipe to last means the worst case is instead a brief window
	// where BOTH the old- and new-named Secrets exist at once, which is harmless: they're
	// two independently-named Secrets (a single owning CR can own any number of objects
	// via OwnerReference — there's no one-child invariant to violate), applySecret above
	// already refuses to adopt/overwrite anything it doesn't manage, and wipeTargetSecret
	// below only ever touches a Secret this same CR actually controls. It's a no-op if
	// nothing exists under the old name, or if this is the CR's first-ever reconcile
	// (LastTargetName is unset).
	//
	// If the wipe itself fails, orphanWipeErr is threaded through to succeed() below:
	// status.LastTargetName is deliberately NOT advanced to the new name in that case,
	// so the next reconcile retries the orphan wipe instead of forgetting about it. Note
	// this can no longer coincide with a fail() call in the same reconcile — by the time
	// the orphan wipe runs, the new target's own sync has already succeeded — so unlike
	// fail(), succeed() is the only place orphanWipeErr is ever threaded through.
	var orphanWipeErr error
	if ks.Status.LastTargetName != "" && ks.Status.LastTargetName != secretName {
		if wipeErr := r.wipeTargetSecret(ctx, &ks, ks.Status.LastTargetName); wipeErr != nil {
			orphanWipeErr = wipeErr
			logger.Error(wipeErr, "failed to wipe orphaned target Secret after spec.target.name changed",
				"oldTargetName", ks.Status.LastTargetName, "newTargetName", secretName)
		}
	}

	if err := r.succeed(ctx, &ks, hash, secretName, orphanWipeErr, rep.partialHold()); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// buildDesired reads the token and fetches every referenced value, assembling the
// target Secret's data. Any failure fails the whole reconcile so a Secret is never
// written with a partially-fetched set of keys. The token is also returned (even on
// a fetch error, once obtained) so the caller can reuse it for the mass-revocation
// circuit breaker's live peer probe (see massRevocationSuspected) without a second
// token Secret read.
func (r *KeyorixSecretReconciler) buildDesired(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret) (desired map[string][]byte, token string, rep *sourceReport, err error) {
	// Validate the destination BEFORE reading the token Secret, so a CR pointing at an
	// untrusted server can't even cause the operator to read (let alone transmit) a Secret.
	if err := r.validateServer(ks.Spec.Server); err != nil {
		return nil, "", nil, err
	}
	tokenKey := ks.Spec.TokenSecretRef.Key
	if tokenKey == "" {
		tokenKey = "token"
	}
	var tokenSecret corev1.Secret
	ref := types.NamespacedName{Namespace: ks.Namespace, Name: ks.Spec.TokenSecretRef.Name}
	// A direct (uncached) read, not the manager's cached Client (#124): the shared
	// informer cache is scoped to only Secrets this operator manages (see
	// SetupWithManager) so it never pulls arbitrary namespace Secrets — including
	// every token Secret CR authors reference — into the operator's memory. A
	// token Secret is a one-off, per-reconcile lookup; it has no reason to be
	// watched/cached at all.
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	if err := reader.Get(ctx, ref, &tokenSecret); err != nil {
		// Deliberately NOT treated as a wipe-worthy "access confirmed cut" signal (unlike
		// ErrSecretGone/ErrUnauthorized in Reconcile): a missing/unreadable token Secret
		// means the operator couldn't even ASK the Keyorix server whether access is still
		// valid — it could be a typo in tokenSecretRef, an accidental deletion, transient
		// RBAC drift, or a GC race, none of which confirm the upstream secret or grant was
		// actually revoked. Wiping the target Secret on a merely-ambiguous "we don't know"
		// failure would cause an unnecessary outage for every workload depending on it,
		// the same reasoning that already keeps network errors/5xx out of the wipe path.
		return nil, "", nil, fmt.Errorf("read token secret %s: %w", ref, err)
	}
	// A CRD-write-only principal (the CRD's own documented least-privilege deployment
	// model has no direct core-Secret read/write RBAC) can name ANY pre-existing Secret
	// in the namespace here — the operator resolves it with its own cluster-wide `get
	// secrets` RBAC, not the requester's. validateServer above already stops the token
	// from being shipped to an attacker-controlled destination, but without this gate
	// the operator would still read an arbitrary Secret's bytes and send them as a
	// bearer token to the (now-trusted) Keyorix server — a residual probe/abuse
	// primitive, and exactly the "point at a Secret you don't have RBAC to read" attack
	// the CRD's threat model is meant to exclude. Require the Secret to already carry a
	// label only a principal with real Secret-write RBAC could have set (a CRD-write-only
	// attacker cannot), so an unlabeled pre-existing Secret can never be used as a token
	// source, however it got created.
	if tokenSecret.Labels[tokenSecretLabel] != tokenSecretValue {
		return nil, "", nil, fmt.Errorf("token secret %s is missing the required label %s=%s (only a Secret explicitly marked as a Keyorix token source may be used as tokenSecretRef)",
			ref, tokenSecretLabel, tokenSecretValue)
	}
	token = string(tokenSecret.Data[tokenKey])
	if token == "" {
		return nil, "", nil, fmt.Errorf("token secret %s has no key %q", ref, tokenKey)
	}

	fetcher := r.fetcher(ks.Spec.Server, token)
	info, hasInfo := fetcher.(valueInfoFetcher)
	rep = &sourceReport{}
	desired = make(map[string][]byte, len(ks.Spec.Data))
	for _, d := range ks.Spec.Data {
		var val []byte
		var exp *time.Time
		var ferr error
		if hasInfo {
			var v keyorix.Value
			v, ferr = info.FetchValueInfo(ctx, d.Ref)
			val, exp = v.Data, v.Expiration
		} else {
			val, ferr = fetcher.FetchValue(ctx, d.Ref)
		}
		switch {
		case errors.Is(ferr, keyorix.ErrSecretSuspended):
			// Reads are switched off, not gone: never a reason to remove anything.
			// What the target holds meanwhile is decided below by spec.onSuspend.
			rep.suspended = append(rep.suspended, d.Ref)
			if ks.Spec.OnSuspend != secretsv1alpha1.OnSuspendClear {
				rep.heldKeys = append(rep.heldKeys, d.SecretKey)
			}
			continue
		case errors.Is(ferr, keyorix.ErrSecretExpired):
			rep.expired = append(rep.expired, d.Ref)
			rep.heldKeys = append(rep.heldKeys, d.SecretKey)
			continue
		case ferr != nil:
			return nil, token, nil, fmt.Errorf("fetch %q: %w", d.Ref, ferr)
		}
		rep.noteExpiry(d.Ref, exp, r.clockNow())
		desired[d.SecretKey] = val
	}
	// A held ref (expired, or suspended under Retain) freezes only ITS key: the other refs'
	// keys keep syncing in the same single update and applySecret carries the held keys
	// over from the live Secret. Only when nothing at all would change (every ref is held
	// and no ref is being cleared) does the reconcile skip the write altogether.
	clearing := len(rep.suspended) > 0 && ks.Spec.OnSuspend == secretsv1alpha1.OnSuspendClear
	if len(rep.heldKeys) > 0 && len(desired) == 0 && !clearing {
		_, _, msg, _ := rep.summary()
		return nil, token, rep, &sourceHeldError{reason: rep.heldReason(), msg: msg}
	}
	// onSuspend=Clear: the suspended refs' keys are simply absent from desired, so the
	// applied Secret no longer carries them; keys of readable refs stay current.
	return desired, token, rep, nil
}

// holdSource handles a reconcile that must leave the target Secret exactly as it is
// because a referenced secret is expired, or suspended with onSuspend=Retain: it records
// the SourceSecretHealthy condition, Event and gauge, marks Ready=False with the same
// reason, and requeues at the refresh interval. It deliberately returns no error: this is
// an expected, operator-driven state, not a fault to back off from, and a resume must be
// picked up within one interval rather than after exponential error backoff.
func (r *KeyorixSecretReconciler) holdSource(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, rep *sourceReport, held *sourceHeldError, interval time.Duration) (ctrl.Result, error) {
	r.recordSourceState(ks, rep)
	r.setReady(ks, metav1.ConditionFalse, held.reason, held.msg+" — the target Secret was left unchanged")
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// emptyManagedSecret removes every data key from the target Secret when onSuspend=Clear
// leaves nothing to write, except the held keys (an expired sibling), which keep their
// live value. The Secret object stays (workloads that mount it keep a valid, empty
// reference). It touches only a Secret this operator manages AND this CR controls,
// exactly like wipeTargetSecret, and does nothing when there is none.
func (r *KeyorixSecretReconciler) emptyManagedSecret(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, name string, held []string) error {
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ks.Namespace, Name: name}, &secret); err != nil {
		return client.IgnoreNotFound(err)
	}
	if secret.Labels[ManagedByLabel] != ManagedByValue || !metav1.IsControlledBy(&secret, ks) {
		return nil
	}
	kept := carryOverHeld(map[string][]byte{}, secret.Data, held)
	if len(secret.Data) == len(kept) {
		return nil // nothing outside the held keys to remove
	}
	secret.Data = kept
	return r.Update(ctx, &secret)
}

func (r *KeyorixSecretReconciler) fetcher(server, token string) valueFetcher {
	if r.newClient != nil {
		return r.newClient(server, token)
	}
	return keyorix.New(server, token)
}

// applySecret create-or-updates the target Secret with an owner reference to the
// KeyorixSecret, so deleting the CR garbage-collects the Secret. held names the keys whose
// source is expired or suspended (Retain): their live value is carried into the same single
// update, so a held key is never overwritten or deleted and the write stays atomic.
func (r *KeyorixSecretReconciler) applySecret(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, name string, data map[string][]byte, held []string) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ks.Namespace}}
	secretType := ks.Spec.Target.Type
	if secretType == "" {
		secretType = corev1.SecretTypeOpaque
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		// Refuse to adopt-and-overwrite a pre-existing Secret we don't manage. A non-empty
		// ResourceVersion means the object already existed; without a managed-by guard,
		// SetControllerReference would adopt an UNOWNED Secret (e.g. one created manually
		// or by Helm) and replace its data — letting a CR author clobber another workload's
		// same-named Secret. A Secret we created carries the managed-by label and is
		// allowed through.
		if secret.ResourceVersion != "" && secret.Labels[ManagedByLabel] != ManagedByValue {
			return fmt.Errorf("refusing to overwrite existing unmanaged Secret %s/%s", ks.Namespace, name)
		}
		if err := controllerutil.SetControllerReference(ks, secret, r.Scheme); err != nil {
			return err
		}
		if secret.Labels == nil {
			secret.Labels = map[string]string{}
		}
		secret.Labels[ManagedByLabel] = ManagedByValue
		secret.Type = secretType
		// operator owns the whole data set; removed keys are pruned, held keys are kept
		secret.Data = carryOverHeld(data, secret.Data, held)
		return nil
	})
	return err
}

// carryOverHeld returns desired plus, for every held key present in live, live's value. It
// never replaces a key desired already carries and never mutates its inputs.
func carryOverHeld(desired, live map[string][]byte, held []string) map[string][]byte {
	if len(held) == 0 {
		return desired
	}
	out := make(map[string][]byte, len(desired)+len(held))
	for k, v := range desired {
		out[k] = v
	}
	for _, k := range held {
		if _, ok := out[k]; ok {
			continue
		}
		if v, ok := live[k]; ok {
			out[k] = v
		}
	}
	return out
}

// adopt or overwrite a Secret it didn't create. Exported so cmd/main.go can scope the
// manager's Secret informer cache to only Secrets carrying this label (see #327): the
// operator is deployed as a single cluster-wide instance, so its RBAC necessarily grants
// Secret access in every namespace, but the informer backing Owns(&corev1.Secret{}) has no
// reason to list/watch/cache Secrets it doesn't manage. Token Secrets and pre-existing
// unmanaged target Secrets never carry this label, so reads of those are excluded from that
// cache (they're read live instead) and remain unaffected.
const (
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedByValue = "keyorix-operator"
)

// tokenSecretLabel/tokenSecretValue gate which Secrets buildDesired will resolve as a
// TokenSecretRef. Must be set out-of-band (by whoever creates the token Secret — the
// operator never sets it itself, unlike managedByLabel above) before the controller will
// read that Secret's data and use it as a bearer token.
const (
	tokenSecretLabel = "secrets.keyorix.io/token-secret"
	tokenSecretValue = "true"
)

// fail records an ordinary sync failure (SyncError) on the Ready condition and requeues
// with backoff.
//
// This intentionally does NOT take an orphanWipeErr the way succeed() does: the
// spec.target.name orphan-wipe (see Reconcile) now runs only AFTER buildDesired and
// applySecret have already succeeded, so a call to fail() — which only ever happens
// BEFORE that point, when buildDesired or applySecret itself errors — can never
// coincide with an orphan-wipe attempt in the same reconcile. An earlier version of this
// function did carry a same-reconcile orphanWipeErr (#G54), back when the orphan wipe
// ran first and could fail independently of a later buildDesired/applySecret failure;
// reordering the wipe to run last removed that combination entirely.
func (r *KeyorixSecretReconciler) fail(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, cause error) (ctrl.Result, error) {
	r.setReady(ks, metav1.ConditionFalse, reasonSyncError, cause.Error())
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	// Return the cause so the controller's rate-limited workqueue backs off.
	return ctrl.Result{}, cause
}

// duplicateSecretKey returns the first secretKey that appears in more than one spec.data
// entry, "" when all are unique.
func duplicateSecretKey(data []secretsv1alpha1.KeyorixSecretData) string {
	seen := make(map[string]struct{}, len(data))
	for _, d := range data {
		if _, dup := seen[d.SecretKey]; dup {
			return d.SecretKey
		}
		seen[d.SecretKey] = struct{}{}
	}
	return ""
}

// failInvalidSpec records a spec that cannot be reconciled safely (duplicate secretKey):
// Ready=False/InvalidSpec, a Warning Event once per entry, and nothing read or written.
// No error is returned: retrying cannot help, and the next spec edit triggers a reconcile.
func (r *KeyorixSecretReconciler) failInvalidSpec(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, key string) (ctrl.Result, error) {
	alreadyReported := readyReason(ks) == reasonInvalidSpec
	msg := fmt.Sprintf("spec.data has more than one entry with secretKey %q; each secretKey must be unique. Nothing was read or written; fix the spec and syncing resumes.", key)
	r.setReady(ks, metav1.ConditionFalse, reasonInvalidSpec, msg)
	if r.Recorder != nil && !alreadyReported {
		r.Recorder.Eventf(ks, nil, corev1.EventTypeWarning, reasonInvalidSpec, "InvalidSpec",
			"spec.data has a duplicate secretKey %q; the target Secret was left unchanged", key)
	}
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// failAuth records that Keyorix rejected the operator's own bearer token (HTTP 401) and
// leaves the target Secret completely untouched: Ready=False with reason
// KeyorixAuthFailed, a Warning Event (once per entry into the state, not on every
// backoff retry) and keyorix_operator_auth_failures_total. It returns the cause so the
// rate-limited workqueue retries with backoff; once the credential is fixed the next
// successful reconcile syncs normally and Ready goes back to True.
func (r *KeyorixSecretReconciler) failAuth(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, cause error) (ctrl.Result, error) {
	alreadyReported := readyReason(ks) == reasonUpstreamAccessRevoked
	msg := fmt.Sprintf("%s: %s — the operator's own credential (tokenSecretRef %q) was rejected; the target Secret was left unchanged. Fix or rotate the token Secret; syncing resumes on the next retry.",
		reasonKeyorixAuthFailed, cause.Error(), ks.Spec.TokenSecretRef.Name)
	r.setReady(ks, metav1.ConditionFalse, reasonUpstreamAccessRevoked, msg)
	if r.Recorder != nil && !alreadyReported {
		r.Recorder.Eventf(ks, nil, corev1.EventTypeWarning, reasonKeyorixAuthFailed, "AuthFailed",
			"Keyorix rejected the credential in tokenSecretRef %q (HTTP 401); the target Secret was left unchanged", ks.Spec.TokenSecretRef.Name)
	}
	authFailuresTotal.Inc()
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, cause
}

// readyReason returns the current reason of the Ready condition, "" when absent.
func readyReason(ks *secretsv1alpha1.KeyorixSecret) string {
	for _, c := range ks.Status.Conditions {
		if c.Type == conditionReady {
			return c.Reason
		}
	}
	return ""
}

// readyIsKeyorixUnreachable reports whether the Ready condition currently records an outage
// (Ready=False, reason SyncError, message starting "KeyorixUnreachable"). The Ready reason
// stays SyncError so alerts that match it keep firing; the detail lives in the message.
func readyIsKeyorixUnreachable(ks *secretsv1alpha1.KeyorixSecret) bool {
	for _, c := range ks.Status.Conditions {
		if c.Type == conditionReady {
			return c.Status == metav1.ConditionFalse && c.Reason == reasonSyncError &&
				strings.HasPrefix(c.Message, reasonKeyorixUnreachable)
		}
	}
	return false
}

// failFetch records that Keyorix could not answer a value read (unreachable, timeout or
// 5xx) and leaves the target Secret completely untouched: Ready=False with reason
// SyncError (unchanged, for existing alerts) and a message starting KeyorixUnreachable, a Warning Event (once per entry into the state, not on every backoff
// retry) and keyorix_operator_fetch_errors_total{reason}. It returns the cause so the
// rate-limited workqueue retries with backoff; the first successful read raises the
// Normal KeyorixRecovered Event (noteFetchRecovered) and Ready goes back to True.
func (r *KeyorixSecretReconciler) failFetch(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, cause error) (ctrl.Result, error) {
	reason := fetchFailureReason(cause)
	alreadyReported := readyIsKeyorixUnreachable(ks)
	msg := fmt.Sprintf("%s: %s — Keyorix could not answer the read (%s); the target Secret was left unchanged. Syncing resumes on the next successful retry.",
		reasonKeyorixUnreachable, cause.Error(), reason)
	r.setReady(ks, metav1.ConditionFalse, reasonSyncError, msg)
	if r.Recorder != nil && !alreadyReported {
		r.Recorder.Eventf(ks, nil, corev1.EventTypeWarning, reasonKeyorixUnreachable, "FetchFailed",
			"Keyorix could not answer the read (%s) for server %q; the target Secret was left unchanged", reason, ks.Spec.Server)
	}
	fetchErrorsTotal.WithLabelValues(reason).Inc()
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, cause
}

// noteFetchRecovered raises the Normal KeyorixRecovered Event when the previous reconcile
// left Ready=False/KeyorixUnreachable and every value read has now succeeded. It runs
// before anything rewrites the Ready condition; the caller's own success/hold/fail path
// then replaces the reason, so the Event is raised once per recovery.
func (r *KeyorixSecretReconciler) noteFetchRecovered(ks *secretsv1alpha1.KeyorixSecret) {
	if r.Recorder != nil && readyIsKeyorixUnreachable(ks) {
		r.Recorder.Eventf(ks, nil, corev1.EventTypeNormal, reasonKeyorixRecovered, "FetchRecovered",
			"Keyorix answered the read again; syncing resumed")
	}
}

// wipeAndFailGone wipes the target Secret — ONLY when effectivePrunePolicy is
// PrunePolicyDelete — and records the failure on the Ready condition via failGone,
// distinguishing a successful wipe, a failed wipe, and a deliberately-skipped one
// (PrunePolicyKeep — see KeyorixSecretSpec.PrunePolicy for why). Before PrunePolicy
// existed, a wipeTargetSecret failure was only passed to logger.Error and otherwise
// discarded: the CR's Ready condition would still read as an ordinary confirmed-gone
// sync failure with no indication the stale (possibly revoked/rotated) Secret was
// NOT actually removed — a delete-blocking admission webhook, RBAC drift, or a
// transient API error could leave it silently mounted into every workload that
// references it, with nothing in .status to say so.
//
// Before actually wiping, the mass-revocation circuit breaker (massRevocationSuspected,
// coordinator decision 2026-09-25 inbox item 1) gets a chance to withhold the wipe
// entirely if this looks like a shared-credential event across several KeyorixSecrets,
// not an independent per-secret revocation — see failSuspected. A breaker-evaluation
// error (e.g. the List call itself failed) fails OPEN toward the wipe, matching the
// pre-breaker behavior, rather than letting a transient error in the SAFETY check
// silently defeat the restored secure default.
func (r *KeyorixSecretReconciler) wipeAndFailGone(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, secretName, reason string, cause error, token string) (ctrl.Result, error) {
	pruned := effectivePrunePolicy(ks.Spec.PrunePolicy) == secretsv1alpha1.PrunePolicyDelete
	if pruned && token != "" {
		suspected, groupSize, revokedInGroup, serr := r.massRevocationSuspected(ctx, ks, token)
		if serr != nil {
			log.FromContext(ctx).Error(serr, "failed to evaluate the mass-revocation circuit breaker; proceeding without it")
		} else if suspected && !r.massPruneAcked(ks) {
			return r.failSuspected(ctx, ks, cause, groupSize, revokedInGroup)
		}
	}
	var wipeErr error
	if pruned {
		if err := r.wipeTargetSecret(ctx, ks, secretName); err != nil {
			wipeErr = err
			log.FromContext(ctx).Error(err, "failed to wipe target Secret after upstream access was confirmed cut off")
		}
	}
	return r.failGone(ctx, ks, reason, cause, wipeErr, pruned)
}

// massRevocationSuspected implements the operator side of the mass-revocation
// circuit breaker (coordinator decision, 2026-09-25 inbox item 1). TokenSecretRef is
// commonly SHARED across several KeyorixSecrets, so one credential rotation/
// revocation reads as the identical confirmed-gone/revoked failure on every CR built
// on it — wiping every one of them in response to a single event is the exact blast
// radius an earlier default-Keep change (reverted alongside this fix) was trying to
// prevent, just applied unconditionally instead of only when a mass event is
// actually happening.
//
// Unlike a design that only trusts each peer's LAST PERSISTED status (which would
// let the very FIRST CR to reconcile after a rotation wipe before any peer has had a
// chance to record its own failure), this LIVE-PROBES one representative ref from
// every OTHER KeyorixSecret in the group, using the SAME already-validated server
// and already-obtained bearer token this reconcile just used — so it sees the
// group's CURRENT state, not a stale one, and correctly protects even the first CR
// to detect the event. The cost is one extra lightweight request per peer (capped at
// massPruneProbeCap), only on the confirmed-gone/revoked path, never on an ordinary
// successful reconcile.
//
// A peer whose probe itself errors transiently (not a confirmed
// ErrSecretGone/ErrUnauthorized) is excluded from BOTH the numerator and the
// denominator — an ambiguous probe result must not be allowed to either force a trip
// or mask one.
func (r *KeyorixSecretReconciler) massRevocationSuspected(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, token string) (suspected bool, groupSize, revokedInGroup int, err error) {
	var list secretsv1alpha1.KeyorixSecretList
	if err := r.List(ctx, &list, client.InNamespace(ks.Namespace)); err != nil {
		return false, 0, 0, err
	}

	fetcher := r.fetcher(ks.Spec.Server, token)
	groupSize = 1 // this CR itself
	revokedInGroup = 1
	probed := 0
	for i := range list.Items {
		if probed >= massPruneProbeCap {
			break
		}
		peer := &list.Items[i]
		if peer.Name == ks.Name && peer.Namespace == ks.Namespace {
			continue
		}
		if peer.Spec.TokenSecretRef.Name != ks.Spec.TokenSecretRef.Name || peer.Spec.TokenSecretRef.Key != ks.Spec.TokenSecretRef.Key {
			continue
		}
		if len(peer.Spec.Data) == 0 {
			continue
		}
		probed++
		_, ferr := fetcher.FetchValue(ctx, peer.Spec.Data[0].Ref)
		switch {
		case ferr == nil:
			groupSize++
		case errors.Is(ferr, keyorix.ErrSecretGone), errors.Is(ferr, keyorix.ErrUnauthorized):
			groupSize++
			revokedInGroup++
		default:
			// Ambiguous/transient probe failure: excluded from both numerator and
			// denominator, not counted either way.
		}
	}

	return massRevocationTripped(revokedInGroup, groupSize), groupSize, revokedInGroup, nil
}

// massPruneAcked reports whether ks carries a fresh confirmPruneAnnotation — an
// operator's explicit acknowledgement that a suspected mass revocation is expected
// (e.g. a planned credential rotation) and the wipe should proceed anyway. Bounded to
// massPruneAckWindow so a stale ack left from a past incident can't silently
// authorize a future, unrelated one.
func (r *KeyorixSecretReconciler) massPruneAcked(ks *secretsv1alpha1.KeyorixSecret) bool {
	raw := ks.Annotations[confirmPruneAnnotation]
	if raw == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	age := r.clockNow().Sub(t)
	return age >= 0 && age < massPruneAckWindow
}

// failSuspected records that this reconcile's confirmed-gone/revoked wipe was
// withheld because the mass-revocation circuit breaker tripped (see
// massRevocationSuspected) and no valid confirmPruneAnnotation ack is present. The
// target Secret's last-known value is left completely untouched — exactly like
// PrunePolicy Keep — but with a status reason, an Event, and a metric that make
// clear this is a suspected mass event, not a deliberate per-CR policy choice, and
// how to unblock it.
func (r *KeyorixSecretReconciler) failSuspected(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, cause error, groupSize, revokedInGroup int) (ctrl.Result, error) {
	msg := fmt.Sprintf(
		"%s — MASS REVOCATION SUSPECTED: %d/%d KeyorixSecrets sharing tokenSecretRef %q are confirmed gone/revoked right now, which looks like one shared credential event rather than independent ones. The target Secret was left untouched; prunePolicy Delete was NOT applied. Set the %s=<RFC3339 timestamp> annotation on this CR (valid for %s after it's set) to acknowledge and proceed with the wipe.",
		cause.Error(), revokedInGroup, groupSize, ks.Spec.TokenSecretRef.Name, confirmPruneAnnotation, massPruneAckWindow)
	r.setReady(ks, metav1.ConditionFalse, reasonMassRevocationSuspected, msg)
	if r.Recorder != nil {
		r.Recorder.Eventf(ks, nil, corev1.EventTypeWarning, reasonMassRevocationSuspected, "PruneWithheld",
			"%d/%d KeyorixSecrets sharing tokenSecretRef %q confirmed gone/revoked at once; wipe withheld pending %s ack",
			revokedInGroup, groupSize, ks.Spec.TokenSecretRef.Name, confirmPruneAnnotation)
	}
	massRevocationSuspectedTotal.Inc()
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	// Still return the cause so the workqueue keeps retrying (with backoff): once
	// acknowledged (or the group's ratio drops back below threshold), a later
	// reconcile proceeds with the wipe.
	return ctrl.Result{}, cause
}

// failGone is fail's counterpart for a confirmed access-cut upstream failure (#428): it
// records a distinct reason ("UpstreamSecretGone" for a confirmed-gone 404/403 — see the
// ErrSecretGone handling in Reconcile) so the CR's status makes the outcome visible and explicable, rather than
// looking like an ordinary transient sync failure.
//
// pruned reflects effectivePrunePolicy(ks.Spec.PrunePolicy) at the time
// wipeAndFailGone ran: false (PrunePolicyKeep) means wipeTargetSecret was never even
// attempted — the message says so explicitly, so a reader of .status can't mistake
// "left alone on purpose" for "wipe attempted and silently succeeded". When pruned is
// true, wipeErr (non-nil meaning wipeTargetSecret itself failed) still gets its own
// distinct "WipeFailed" reason suffix and message, exactly as before PrunePolicy
// existed.
func (r *KeyorixSecretReconciler) failGone(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, reason string, cause, wipeErr error, pruned bool) (ctrl.Result, error) {
	msg := cause.Error()
	switch {
	case !pruned:
		msg = fmt.Sprintf("%s — prunePolicy is Keep: the target Secret's last-known value was left untouched, not deleted. Set spec.prunePolicy: Delete (the default) to reap it automatically.", cause.Error())
	case wipeErr != nil:
		reason += "WipeFailed"
		msg = fmt.Sprintf("%s — additionally, wiping the stale target Secret failed, it may still contain revoked/rotated data: %v", cause.Error(), wipeErr)
	}
	r.setReady(ks, metav1.ConditionFalse, reason, msg)
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	// Still return the cause so the workqueue keeps retrying (with backoff): if the
	// secret or access is restored upstream, the next successful reconcile re-syncs it.
	return ctrl.Result{}, cause
}

// wipeTargetSecret deletes the target Secret when the upstream Keyorix reference has
// been confirmed gone (404/403 — see the ErrSecretGone handling in Reconcile; a 401 never
// wipes, see failAuth) or when a retarget
// (spec.target.name change) has orphaned the Secret previously materialised under an
// old name. Only a Secret this operator actually manages AND that THIS CR controls is
// ever touched. Two
// checks, mirroring applySecret's write-side rigor:
//   - ManagedByLabel: applySecret already refuses to adopt a pre-existing unmanaged
//     Secret sharing the target name, so wiping an unlabeled Secret here too would risk
//     deleting an unrelated workload's own Secret that merely happens to collide on name.
//   - metav1.IsControlledBy(&secret, ks): ks.Spec.Target.Name is attacker-controlled —
//     it comes straight from the caller's OWN CR spec. Without this check, an attacker
//     with only ordinary namespaced KeyorixSecret-create RBAC could set spec.target.name
//     to the name of a Secret already owned by a DIFFERENT, victim CR and spec.data[0].ref
//     to any nonexistent Keyorix ref: their reconcile would hit ErrSecretGone and delete
//     the victim's Secret on every reconcile, despite never owning it — a sustained,
//     cross-tenant availability attack. Checking ownership, not just the shared label,
//     closes it: only the CR that actually owns the Secret (via SetControllerReference in
//     applySecret) may wipe it. A missing target Secret is a no-op.
func (r *KeyorixSecretReconciler) wipeTargetSecret(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, name string) error {
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: ks.Namespace, Name: name}
	if err := r.Get(ctx, key, &secret); err != nil {
		return client.IgnoreNotFound(err)
	}
	if secret.Labels[ManagedByLabel] != ManagedByValue {
		return nil
	}
	if !metav1.IsControlledBy(&secret, ks) {
		return nil
	}
	return client.IgnoreNotFound(r.Delete(ctx, &secret))
}

// succeed records Ready=True and the synced fingerprint. targetName is the CURRENT
// target Secret name (secretName in Reconcile); orphanWipeErr, when non-nil, means a
// retarget (spec.target.name change) was detected this reconcile but wiping the
// Secret orphaned under the OLD name failed.
//
// held, when non-nil, means some keys were carried over unchanged because their source is
// expired or suspended (Retain) while the readable keys synced: the sync fields above are
// still recorded, but Ready stays False with the hold's reason so the stale key is not
// reported as healthy and alerts matching SourceSecretExpired / SourceSecretSuspended fire.
func (r *KeyorixSecretReconciler) succeed(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, hash, targetName string, orphanWipeErr error, held *sourceHeldError) error {
	now := metav1.Now()
	ks.Status.LastSyncTime = &now
	ks.Status.SyncedHash = hash
	ks.Status.ObservedGeneration = ks.Generation
	if orphanWipeErr == nil {
		// The common case (no retarget, or the retarget's orphan wipe succeeded):
		// advance LastTargetName so a later retarget compares against the right name.
		ks.Status.LastTargetName = targetName
		r.setReady(ks, metav1.ConditionTrue, "Synced", "target Secret is up to date")
	} else {
		// The new target Secret synced fine, but the operator failed to wipe the
		// Secret orphaned under the OLD target name. Deliberately leave
		// LastTargetName pointing at the OLD name (NOT targetName) so the next
		// reconcile retries that wipe instead of silently forgetting about it, and
		// surface the failure in the message so it isn't lost the way a
		// log-only wipeErr previously was (mirrors the wipeAndFailGone fix for the
		// ErrSecretGone/ErrUnauthorized path).
		r.setReady(ks, metav1.ConditionTrue, "Synced",
			fmt.Sprintf("target Secret is up to date; WARNING: failed to wipe the orphaned Secret %q left behind by a spec.target.name change, it may still contain stale data: %v",
				ks.Status.LastTargetName, orphanWipeErr))
	}
	if held != nil {
		r.setReady(ks, metav1.ConditionFalse, held.reason, held.msg)
	}
	return r.Status().Update(ctx, ks)
}

func (r *KeyorixSecretReconciler) setReady(ks *secretsv1alpha1.KeyorixSecret, status metav1.ConditionStatus, reason, msg string) {
	meta := metav1.Condition{
		Type:               conditionReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ks.Generation,
		LastTransitionTime: metav1.Now(),
	}
	setCondition(&ks.Status.Conditions, meta)
}

// SetupWithManager wires the reconciler to watch KeyorixSecrets and the Secrets it owns.
// The manager's shared cache (wired in cmd/main.go) is label-scoped to only Secrets
// carrying ManagedByLabel=ManagedByValue (#124) — this controller always stamps that
// label on target Secrets it creates (applySecret), so Owns() still fires correctly
// on changes to them, while arbitrary other namespace Secrets (including every token
// Secret CR authors reference) are never pulled into the operator's memory.
func (r *KeyorixSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	_, err := r.setupController(mgr)
	return err
}

// setupController is the guts of SetupWithManager, split out so a test can inspect the
// built controller.Controller (e.g. its MaxConcurrentReconciles) without needing to
// duplicate this exact builder chain — SetupWithManager itself just discards the
// returned controller, matching what builder.Builder.Complete does internally.
// setupController deliberately does NOT set WithOptions' RateLimiter (K8S track
// backlog item 3b: "no retry storm — bounded backoff with jitter"): leaving it unset
// keeps controller-runtime's own default, workqueue.DefaultTypedControllerRateLimiter
// — a per-item (per KeyorixSecret NamespacedName) exponential backoff already bounded
// at a 1000s cap. Reconcile returning a non-nil error (which it always does on a
// confirmed-gone/revoked failure, PrunePolicy Keep or Delete — see failGone) is what
// drives that requeue; a Keep-policy pass returning nil here instead would silently
// defeat it. Jitter is NOT layered on top of that default, unlike
// internal/k8ssync/runner.go's poll loop: that agent's backoff exists because ALL of
// its mappings share ONE fixed-interval ticker, so many consecutive-failure agents (or
// replicas) recovering from a shared Keyorix outage would otherwise retry in lockstep.
// This controller's backoff is already per-object and independently seeded by each
// KeyorixSecret's own failure history — normally exactly one active instance owns the
// workqueue (leaderElection keeps standbys idle) — so there is no shared tick for
// jitter to desynchronize.
func (r *KeyorixSecretReconciler) setupController(mgr ctrl.Manager) (controller.Controller, error) {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.KeyorixSecret{}).
		Owns(&corev1.Secret{}).
		// See maxConcurrentReconciles (r143): without this, controller-runtime's default
		// of exactly 1 concurrent reconcile means a single shared worker services every
		// KeyorixSecret in every namespace cluster-wide.
		WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrentReconciles}).
		Build(r)
}

// hashData fingerprints the desired data deterministically (sorted keys) so an
// unchanged reconcile produces the same hash. Keyed with an HMAC (#124): the
// fingerprint is persisted into .status.syncedHash, a CR subresource commonly
// readable without any RBAC on the underlying Secret — a plain sha256 there would
// let a CR-getter brute-force a low-entropy value offline with zero Secret-read
// access. key must be non-empty; see NewReconciler.
func hashData(key []byte, data map[string][]byte) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := hmac.New(sha256.New, key)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(data[k])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// setCondition upserts a condition by type, preserving LastTransitionTime when the status
// is unchanged.
func setCondition(conds *[]metav1.Condition, c metav1.Condition) {
	for i := range *conds {
		if (*conds)[i].Type == c.Type {
			if (*conds)[i].Status == c.Status {
				c.LastTransitionTime = (*conds)[i].LastTransitionTime
			}
			(*conds)[i] = c
			return
		}
	}
	*conds = append(*conds, c)
}
