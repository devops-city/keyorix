package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
	"github.com/keyorixhq/keyorix/operator/internal/keyorix"
)

// fakeFetcher serves values from a map. Refs in failRefs error with a plain
// (non-ErrSecretGone) error, simulating a transient failure (network/5xx). Refs in
// goneRefs error wrapping keyorix.ErrSecretGone, simulating a confirmed 404/403 from
// the upstream Keyorix server (#428). Refs in unauthorizedRefs error wrapping
// keyorix.ErrUnauthorized, simulating a 401 (revoked/rotated machine-identity
// credential).
type fakeFetcher struct {
	values           map[string][]byte
	failRefs         map[string]bool
	goneRefs         map[string]bool
	unauthorizedRefs map[string]bool
}

func (f *fakeFetcher) FetchValue(_ context.Context, ref string) ([]byte, error) {
	if f.goneRefs[ref] {
		return nil, fmt.Errorf("ref %q gone: %w", ref, keyorix.ErrSecretGone)
	}
	if f.unauthorizedRefs[ref] {
		return nil, fmt.Errorf("ref %q unauthorized: %w", ref, keyorix.ErrUnauthorized)
	}
	if f.failRefs[ref] {
		return nil, errors.New("boom")
	}
	v, ok := f.values[ref]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, secretsv1alpha1.AddToScheme(s))
	return s
}

func newReconciler(t *testing.T, fetcher valueFetcher, objs ...client.Object) (*KeyorixSecretReconciler, client.Client) {
	t.Helper()
	s := testScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
		WithObjects(objs...).
		Build()
	return &KeyorixSecretReconciler{
		Client: c,
		Scheme: s,
		// Trust the fixture's server so the (now fail-closed) allow-list passes; the
		// server-validation behavior itself is covered by TestValidateServer.
		AllowedServers: []string{"https://keyorix.internal"},
		newClient:      func(_, _ string) valueFetcher { return fetcher },
		hashKey:        []byte("test-fixture-hmac-key"),
	}, c
}

// ksFixture sets PrunePolicy: Delete explicitly — this now MATCHES the real-world
// default (coordinator decision, 2026-09-25 inbox item 1, restoring the secure
// default after a brief default-Keep regression; see KeyorixSecretSpec.PrunePolicy),
// but stays explicit rather than relying on the zero-value/effectivePrunePolicy
// fallback so the large pre-existing suite of wipe-on-confirmed-gone/revoked tests
// below states its precondition directly. TestReconcile_Keep* below use their own
// fixture (ksFixtureKeep) to cover the explicit opt-out.
func ksFixture() *secretsv1alpha1.KeyorixSecret {
	return &secretsv1alpha1.KeyorixSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "app", Generation: 1},
		Spec: secretsv1alpha1.KeyorixSecretSpec{
			Server:         "https://keyorix.internal",
			TokenSecretRef: secretsv1alpha1.SecretKeySelector{Name: "kx-token", Key: "token"},
			Target:         secretsv1alpha1.KeyorixSecretTarget{Name: "db-creds"},
			Data: []secretsv1alpha1.KeyorixSecretData{
				{SecretKey: "DB_PASSWORD", Ref: "app/production/db-password"},
				{SecretKey: "API_KEY", Ref: "app/production/api-key"},
			},
			PrunePolicy: secretsv1alpha1.PrunePolicyDelete,
		},
	}
}

// ksFixtureKeep is ksFixture with PrunePolicy explicitly set to PrunePolicyKeep —
// the opt-out (see KeyorixSecretSpec.PrunePolicy). An EMPTY PrunePolicy no longer
// means Keep: effectivePrunePolicy treats "" the same as PrunePolicyDelete (the
// restored default), so this fixture must set Keep explicitly to exercise that path.
func ksFixtureKeep() *secretsv1alpha1.KeyorixSecret {
	ks := ksFixture()
	ks.Spec.PrunePolicy = secretsv1alpha1.PrunePolicyKeep
	return ks
}

func tokenSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kx-token",
			Namespace: "app",
			Labels:    map[string]string{tokenSecretLabel: tokenSecretValue},
		},
		Data: map[string][]byte{"token": []byte("machine-tok")},
	}
}

func reconcile(t *testing.T, r *KeyorixSecretReconciler) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "db", Namespace: "app"},
	})
}

func TestReconcile_CreatesTargetSecretOwnedByCR(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret())

	res, err := reconcile(t, r)
	require.NoError(t, err)
	assert.Positive(t, res.RequeueAfter, "reconcile requeues for the next refresh")

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got))
	assert.Equal(t, []byte("p4ss"), got.Data["DB_PASSWORD"])
	assert.Equal(t, []byte("k3y"), got.Data["API_KEY"])
	assert.Equal(t, corev1.SecretTypeOpaque, got.Type)

	// Owner reference makes the Secret garbage-collected when the CR is deleted.
	require.Len(t, got.OwnerReferences, 1)
	assert.Equal(t, "KeyorixSecret", got.OwnerReferences[0].Kind)
	assert.Equal(t, "db", got.OwnerReferences[0].Name)
	require.NotNil(t, got.OwnerReferences[0].Controller)
	assert.True(t, *got.OwnerReferences[0].Controller)

	// Status reflects success.
	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, "Ready", ks.Status.Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, ks.Status.Conditions[0].Status)
	assert.NotEmpty(t, ks.Status.SyncedHash)
	assert.NotNil(t, ks.Status.LastSyncTime)
	assert.Equal(t, int64(1), ks.Status.ObservedGeneration)
}

// TestReconcile_RefreshIntervalFloored pins #124: spec.refreshInterval had no
// minimum, so a CR author (or a compromised CR-writer) could set an absurdly
// small value (e.g. "1ms") and every successful reconcile would immediately
// requeue itself, driving a reconcile/API/etcd storm that starves the shared
// workqueue for every other KeyorixSecret in the cluster.
func TestReconcile_RefreshIntervalFloored(t *testing.T) {
	ks := ksFixture()
	ks.Spec.RefreshInterval = &metav1.Duration{Duration: time.Millisecond}
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
	}}
	r, _ := newReconciler(t, fetcher, ks, tokenSecret())

	res, err := reconcile(t, r)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, res.RequeueAfter, minRefreshInterval,
		"an absurdly small refreshInterval must be floored, not honored verbatim")
}

func TestReconcile_RefusesToOverwriteUnmanagedSecret(t *testing.T) {
	// A pre-existing Secret with the target name that the operator did NOT create.
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "app"},
		Data:       map[string][]byte{"OTHER": []byte("do-not-clobber")},
	}
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret(), foreign)

	_, err := reconcile(t, r)
	require.Error(t, err, "must refuse to adopt/overwrite an unmanaged Secret")

	// The foreign Secret's data is untouched — not clobbered with the synced keys.
	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got))
	assert.Equal(t, []byte("do-not-clobber"), got.Data["OTHER"])
	assert.NotContains(t, got.Data, "DB_PASSWORD")
}

func TestReconcile_DefaultsTargetNameToCR(t *testing.T) {
	ks := ksFixture()
	ks.Spec.Target.Name = "" // unset → defaults to the CR name "db"
	r, c := newReconciler(t, &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("x"), "app/production/api-key": []byte("y"),
	}}, ks, tokenSecret())

	_, err := reconcile(t, r)
	require.NoError(t, err)
	var got corev1.Secret
	assert.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &got))
}

func TestReconcile_FetchFailureFailsClosed(t *testing.T) {
	// One ref fails: the target Secret must NOT be written with a partial key set.
	fetcher := &fakeFetcher{
		values:   map[string][]byte{"app/production/db-password": []byte("p4ss")},
		failRefs: map[string]bool{"app/production/api-key": true},
	}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret())

	_, err := reconcile(t, r)
	require.Error(t, err, "a fetch failure requeues with error for backoff")

	var got corev1.Secret
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	assert.Error(t, err, "no Secret is written when any value fails to fetch")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, ks.Status.Conditions[0].Status)
	assert.Equal(t, "SyncError", ks.Status.Conditions[0].Reason)
}

// TestReconcile_UpstreamGoneWipesTargetSecret pins #428: a fetch failure that
// AFFIRMATIVELY indicates the upstream secret is gone (404/403, wrapped as
// keyorix.ErrSecretGone) must actively delete the previously synced target Secret —
// otherwise every workload mounting it goes on reading a revoked/deleted value
// indefinitely, with the CR's Ready condition the only (easy-to-miss) hint anything is
// wrong.
func TestReconcile_UpstreamGoneWipesTargetSecret(t *testing.T) {
	// First reconcile succeeds and creates the target Secret normally.
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got),
		"precondition: the target Secret exists after a successful sync")

	// The upstream secret is now confirmed gone (404/403) on the next reconcile.
	fetcher.goneRefs = map[string]bool{"app/production/db-password": true}

	_, err = reconcile(t, r)
	require.Error(t, err, "a confirmed-gone upstream ref still requeues with error for backoff")
	assert.True(t, errors.Is(err, keyorix.ErrSecretGone))

	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	assert.Error(t, err, "the target Secret must be wiped once the upstream secret is confirmed gone")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, ks.Status.Conditions[0].Status)
	assert.Equal(t, "UpstreamSecretGone", ks.Status.Conditions[0].Reason,
		"the status reason must distinguish a confirmed wipe from an ordinary SyncError")
}

// TestReconcile_TransientFetchFailureLeavesTargetSecretUntouched pins #428's other
// half: a genuinely transient/ambiguous failure (network error, timeout, 5xx — anything
// that is neither ErrSecretGone nor ErrUnauthorized) must NOT touch a previously synced
// target Secret. Wiping it on every hiccup would cause unnecessary outages for every
// workload depending on it. (A 401/ErrUnauthorized is deliberately NOT exercised here
// any more — see TestReconcile_UnauthorizedWipesTargetSecretWithDistinctReason below,
// which now DOES wipe on 401, since it's treated as a revoked/rotated credential.)
func TestReconcile_TransientFetchFailureLeavesTargetSecretUntouched(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var before corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &before))

	// A transient failure on the next reconcile — NOT wrapping ErrSecretGone.
	fetcher.failRefs = map[string]bool{"app/production/db-password": true}

	_, err = reconcile(t, r)
	require.Error(t, err)
	assert.False(t, errors.Is(err, keyorix.ErrSecretGone), "a transient failure must not be classified as gone")

	var after corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &after),
		"the target Secret must still exist after a transient fetch failure")
	assert.Equal(t, before.Data, after.Data, "a transient failure must not alter the previously synced values")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, ks.Status.Conditions[0].Status)
	assert.Equal(t, "SyncError", ks.Status.Conditions[0].Reason, "a transient failure keeps the generic SyncError reason")
}

// TestReconcile_UnauthorizedWipesTargetSecretWithDistinctReason pins the fix for the
// bug where only a confirmed-gone 404/403 wiped the target Secret: revoking or rotating
// the machine-identity credential (the overwhelmingly common real-world way an admin
// cuts a workload's access) surfaces as a 401, not a 404/403, and a 401 was previously
// routed into the generic r.fail() branch that leaves the previously-synced target
// Secret untouched — so every Pod mounting it kept reading the revoked value
// indefinitely. A 401 (keyorix.ErrUnauthorized) must now wipe the target Secret the same
// way ErrSecretGone does, with a status reason ("UpstreamAccessRevoked") that is still
// distinguishable from a confirmed-gone secret ("UpstreamSecretGone").
func TestReconcile_UnauthorizedWipesTargetSecretWithDistinctReason(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got),
		"precondition: the target Secret exists after a successful sync")

	// The bearer token is now rejected (401) — e.g. the machine-identity credential was
	// revoked or rotated by an admin.
	fetcher.unauthorizedRefs = map[string]bool{"app/production/db-password": true}

	_, err = reconcile(t, r)
	require.Error(t, err, "a 401 still requeues with error for backoff")
	assert.True(t, errors.Is(err, keyorix.ErrUnauthorized))

	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	assert.Error(t, err, "a 401 must wipe the target Secret the same way a confirmed-gone 404/403 does")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, ks.Status.Conditions[0].Status)
	assert.Equal(t, "UpstreamAccessRevoked", ks.Status.Conditions[0].Reason,
		"a 401 gets a status reason distinct from a confirmed-gone 404/403")
}

// PrunePolicy Keep (ksFixtureKeep, an explicit opt-out — see
// KeyorixSecretSpec.PrunePolicy for the restored Delete default). The
// confirmed-gone/revoked state must still be surfaced on the Ready condition, but
// the target Secret must be left completely untouched, not wiped.

func TestReconcile_Keep_UpstreamGoneLeavesTargetSecretUntouched(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixtureKeep(), tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var before corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &before),
		"precondition: the target Secret exists after a successful sync")

	fetcher.goneRefs = map[string]bool{"app/production/db-password": true}

	_, err = reconcile(t, r)
	require.Error(t, err, "a confirmed-gone upstream ref still requeues with error for backoff")
	assert.True(t, errors.Is(err, keyorix.ErrSecretGone))

	var after corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &after),
		"prunePolicy is Keep: the target Secret must NOT be wiped")
	assert.Equal(t, before.Data, after.Data, "the last-known value must survive untouched")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, ks.Status.Conditions[0].Status)
	assert.Equal(t, "UpstreamSecretGone", ks.Status.Conditions[0].Reason,
		"the confirmed-gone state is still surfaced distinctly, even though nothing was deleted")
	assert.Contains(t, ks.Status.Conditions[0].Message, "prunePolicy is Keep",
		"the message must say explicitly that the Secret was left untouched, not silently wiped")
}

func TestReconcile_Keep_UnauthorizedLeavesTargetSecretUntouched(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixtureKeep(), tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	fetcher.unauthorizedRefs = map[string]bool{"app/production/db-password": true}

	_, err = reconcile(t, r)
	require.Error(t, err)
	assert.True(t, errors.Is(err, keyorix.ErrUnauthorized))

	var after corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &after),
		"prunePolicy is Keep: the target Secret must NOT be wiped on a 401 either")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	assert.Equal(t, "UpstreamAccessRevoked", ks.Status.Conditions[0].Reason)
	assert.Contains(t, ks.Status.Conditions[0].Message, "prunePolicy is Keep")
}

// TestReconcile_Keep_SharedTokenRevocationDoesNotMassDeleteAllTargets: with
// PrunePolicy explicitly Keep, reconciling every CR sharing a revoked token must NOT
// delete any target Secret — the explicit opt-out is unconditional, independent of
// the mass-revocation circuit breaker (see TestReconcile_Delete_SharedTokenMassRevocationTripsCircuitBreaker
// below for the PrunePolicy=Delete counterpart, where the BREAKER is what prevents
// the mass deletion instead).
func TestReconcile_Keep_SharedTokenRevocationDoesNotMassDeleteAllTargets(t *testing.T) {
	ksA := ksFixtureKeep()
	ksB := ksFixtureKeep()
	ksB.Name = "api"
	ksB.Spec.Target = secretsv1alpha1.KeyorixSecretTarget{Name: "api-creds"}
	ksB.Spec.Data = []secretsv1alpha1.KeyorixSecretData{
		{SecretKey: "TOKEN", Ref: "app/production/other-token"},
	}

	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
		"app/production/other-token": []byte("t0k"),
	}}
	r, c := newReconciler(t, fetcher, ksA, ksB, tokenSecret())

	req := func(name string) ctrl.Request {
		return ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: "app"}}
	}
	_, err := r.Reconcile(context.Background(), req("db"))
	require.NoError(t, err)
	_, err = r.Reconcile(context.Background(), req("api"))
	require.NoError(t, err)

	// The shared credential is now revoked -- every ref behind it fails identically.
	fetcher.unauthorizedRefs = map[string]bool{
		"app/production/db-password": true,
		"app/production/api-key":     true,
		"app/production/other-token": true,
	}

	_, errA := r.Reconcile(context.Background(), req("db"))
	assert.True(t, errors.Is(errA, keyorix.ErrUnauthorized))
	_, errB := r.Reconcile(context.Background(), req("api"))
	assert.True(t, errors.Is(errB, keyorix.ErrUnauthorized))

	var dbCreds, apiCreds corev1.Secret
	assert.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &dbCreds),
		"a shared-token revocation must not delete db-creds")
	assert.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "api-creds", Namespace: "app"}, &apiCreds),
		"a shared-token revocation must not delete api-creds either")
}

// sharedTokenFixtures builds two KeyorixSecrets ("db" and "api") sharing one
// TokenSecretRef, each with PrunePolicy Delete (the restored secure default) — the
// setup shared by the mass-revocation circuit breaker tests below.
func sharedTokenFixtures() (ksA, ksB *secretsv1alpha1.KeyorixSecret) {
	ksA = ksFixture()
	ksB = ksFixture()
	ksB.Name = "api"
	ksB.Spec.Target = secretsv1alpha1.KeyorixSecretTarget{Name: "api-creds"}
	ksB.Spec.Data = []secretsv1alpha1.KeyorixSecretData{
		{SecretKey: "TOKEN", Ref: "app/production/other-token"},
	}
	return ksA, ksB
}

// TestReconcile_Delete_SharedTokenMassRevocationTripsCircuitBreaker is the
// PrunePolicy=Delete (the restored default) counterpart to
// TestReconcile_Keep_SharedTokenRevocationDoesNotMassDeleteAllTargets: with the
// secure default restored, it's the mass-revocation circuit breaker — not an
// always-Keep default — that must stop a shared-token revocation from deleting
// every target Secret backed by that token. Reconciling "db" FIRST (before "api" has
// ever reconciled once with the revoked credential) must still be protected: the
// breaker LIVE-PROBES peers using the same already-obtained token, rather than only
// trusting a peer's last-persisted status, specifically so the first CR to detect a
// mass event isn't the one unprotected case.
func TestReconcile_Delete_SharedTokenMassRevocationTripsCircuitBreaker(t *testing.T) {
	ksA, ksB := sharedTokenFixtures()
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
		"app/production/other-token": []byte("t0k"),
	}}
	r, c := newReconciler(t, fetcher, ksA, ksB, tokenSecret())

	req := func(name string) ctrl.Request {
		return ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: "app"}}
	}
	_, err := r.Reconcile(context.Background(), req("db"))
	require.NoError(t, err)
	_, err = r.Reconcile(context.Background(), req("api"))
	require.NoError(t, err)

	// The shared credential is now revoked -- every ref behind it fails identically.
	fetcher.unauthorizedRefs = map[string]bool{
		"app/production/db-password": true,
		"app/production/api-key":     true,
		"app/production/other-token": true,
	}

	_, errA := r.Reconcile(context.Background(), req("db"))
	assert.True(t, errors.Is(errA, keyorix.ErrUnauthorized))
	_, errB := r.Reconcile(context.Background(), req("api"))
	assert.True(t, errors.Is(errB, keyorix.ErrUnauthorized))

	var dbCreds, apiCreds corev1.Secret
	assert.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &dbCreds),
		"mass revocation suspected: db-creds must not be wiped despite prunePolicy Delete, even though db reconciled FIRST")
	assert.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "api-creds", Namespace: "app"}, &apiCreds),
		"mass revocation suspected: api-creds must not be wiped either")

	for _, name := range []string{"db", "api"} {
		var ks secretsv1alpha1.KeyorixSecret
		require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "app"}, &ks))
		last := ks.Status.Conditions[len(ks.Status.Conditions)-1]
		assert.Equal(t, "MassRevocationSuspected", last.Reason, "CR %q", name)
		assert.Contains(t, last.Message, confirmPruneAnnotation, "CR %q", name)
	}
}

// TestReconcile_Delete_SharedTokenMassRevocationProceedsWithAck confirms the
// explicit escape hatch: a CR carrying a fresh keyorix.io/confirm-prune annotation
// proceeds with the wipe despite the breaker's threshold being crossed.
func TestReconcile_Delete_SharedTokenMassRevocationProceedsWithAck(t *testing.T) {
	ksA, ksB := sharedTokenFixtures()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	ksA.Annotations = map[string]string{confirmPruneAnnotation: now.Add(-5 * time.Minute).Format(time.RFC3339)}

	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
		"app/production/other-token": []byte("t0k"),
	}}
	r, c := newReconciler(t, fetcher, ksA, ksB, tokenSecret())
	r.now = func() time.Time { return now }

	req := func(name string) ctrl.Request {
		return ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: "app"}}
	}
	_, err := r.Reconcile(context.Background(), req("db"))
	require.NoError(t, err)
	_, err = r.Reconcile(context.Background(), req("api"))
	require.NoError(t, err)

	fetcher.unauthorizedRefs = map[string]bool{
		"app/production/db-password": true,
		"app/production/api-key":     true,
		"app/production/other-token": true,
	}

	_, errA := r.Reconcile(context.Background(), req("db"))
	assert.True(t, errors.Is(errA, keyorix.ErrUnauthorized))

	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &corev1.Secret{})
	assert.Error(t, err, "a fresh ack on this CR proceeds with the wipe despite the breaker's own threshold being crossed")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	last := ks.Status.Conditions[len(ks.Status.Conditions)-1]
	assert.Equal(t, "UpstreamAccessRevoked", last.Reason, "an acked wipe still records the underlying cause, not a generic success or the Suspected reason")
}

// TestReconcile_Delete_SharedTokenMassRevocationIgnoresStaleAck confirms
// massPruneAckWindow is enforced: an ack set long before this incident must not
// silently authorize a NEW mass revocation.
func TestReconcile_Delete_SharedTokenMassRevocationIgnoresStaleAck(t *testing.T) {
	ksA, ksB := sharedTokenFixtures()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	ksA.Annotations = map[string]string{confirmPruneAnnotation: now.Add(-2 * time.Hour).Format(time.RFC3339)} // older than massPruneAckWindow

	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
		"app/production/other-token": []byte("t0k"),
	}}
	r, c := newReconciler(t, fetcher, ksA, ksB, tokenSecret())
	r.now = func() time.Time { return now }

	req := func(name string) ctrl.Request {
		return ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: "app"}}
	}
	_, err := r.Reconcile(context.Background(), req("db"))
	require.NoError(t, err)
	_, err = r.Reconcile(context.Background(), req("api"))
	require.NoError(t, err)

	fetcher.unauthorizedRefs = map[string]bool{
		"app/production/db-password": true,
		"app/production/api-key":     true,
		"app/production/other-token": true,
	}

	_, errA := r.Reconcile(context.Background(), req("db"))
	assert.True(t, errors.Is(errA, keyorix.ErrUnauthorized))

	var dbCreds corev1.Secret
	assert.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &dbCreds),
		"a stale ack must not unblock a new mass-revocation event")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	last := ks.Status.Conditions[len(ks.Status.Conditions)-1]
	assert.Equal(t, "MassRevocationSuspected", last.Reason)
}

// TestMassRevocationTripped pins the breaker's exact threshold boundary (more than
// massPruneMinCount targets AND more than massPruneFraction of the group), the same
// pure decision used by both the k8s-sync engine and this controller.
func TestMassRevocationTripped(t *testing.T) {
	cases := []struct {
		name         string
		revokedCount int
		groupSize    int
		want         bool
	}{
		{"single revocation never trips", 1, 10, false},
		{"single revocation at 100% never trips", 1, 1, false},
		{"exactly the fraction threshold does not trip", 2, 10, false},
		{"just over the fraction threshold trips", 3, 10, true},
		{"count and fraction both satisfied at small scale", 2, 2, true},
		{"zero group never trips", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, massRevocationTripped(tc.revokedCount, tc.groupSize))
		})
	}
}

// TestMassPruneAcked pins the ack-window boundary (present, recent, not future).
func TestMassPruneAcked(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		ack  string
		want bool
	}{
		{"no annotation is never acked", "", false},
		{"malformed timestamp is never acked", "not-a-timestamp", false},
		{"just now is acked", now.Format(time.RFC3339), true},
		{"59 minutes ago is acked", now.Add(-59 * time.Minute).Format(time.RFC3339), true},
		{"exactly 1 hour ago is no longer acked", now.Add(-1 * time.Hour).Format(time.RFC3339), false},
		{"in the future is not acked", now.Add(1 * time.Minute).Format(time.RFC3339), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &KeyorixSecretReconciler{now: func() time.Time { return now }}
			ks := &secretsv1alpha1.KeyorixSecret{}
			if tc.ack != "" {
				ks.Annotations = map[string]string{confirmPruneAnnotation: tc.ack}
			}
			assert.Equal(t, tc.want, r.massPruneAcked(ks))
		})
	}
}

// TestEffectivePrunePolicy pins the defense-in-depth default: an EMPTY PrunePolicy
// (a test fixture, a direct client.Create, or an object from before this default
// existed — anything that skips the CRD's own admission-time defaulting) resolves to
// Delete, not Keep.
func TestEffectivePrunePolicy(t *testing.T) {
	assert.Equal(t, secretsv1alpha1.PrunePolicyDelete, effectivePrunePolicy(""))
	assert.Equal(t, secretsv1alpha1.PrunePolicyDelete, effectivePrunePolicy(secretsv1alpha1.PrunePolicyDelete))
	assert.Equal(t, secretsv1alpha1.PrunePolicyKeep, effectivePrunePolicy(secretsv1alpha1.PrunePolicyKeep))
}

// deleteBlockingClient wraps a client.Client but fails every Delete call for an object
// named blockDeleteName, simulating a delete-blocking admission webhook, RBAC drift, or
// a transient API error during wipeTargetSecret — used to exercise the wipe-failure-
// surfaced-in-status path (Bug 3) and the retarget-wipe-failure path (Bug 2's failure
// branch).
type deleteBlockingClient struct {
	client.Client
	blockDeleteName string
}

func (c *deleteBlockingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if obj.GetName() == c.blockDeleteName {
		return fmt.Errorf("simulated delete-blocking webhook rejected deletion of %s", obj.GetName())
	}
	return c.Client.Delete(ctx, obj, opts...)
}

// TestReconcile_WipeFailureSurfacedInStatus pins the fix for the bug where a
// wipeTargetSecret failure (e.g. a delete-blocking admission webhook, RBAC drift, or a
// transient API error) was only passed to logger.Error and otherwise discarded: the
// CR's Ready condition still read as an ordinary confirmed-gone sync failure
// ("UpstreamSecretGone") with no indication the stale, possibly-revoked target Secret
// was NOT actually removed. The reason must now carry a distinct "WipeFailed" suffix and
// the message must say the wipe itself failed.
func TestReconcile_WipeFailureSurfacedInStatus(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	s := testScheme(t)
	inner := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
		WithObjects(ksFixture(), tokenSecret()).
		Build()
	blocked := &deleteBlockingClient{Client: inner, blockDeleteName: "db-creds"}
	r := &KeyorixSecretReconciler{
		Client:         blocked,
		Scheme:         s,
		AllowedServers: []string{"https://keyorix.internal"},
		newClient:      func(_, _ string) valueFetcher { return fetcher },
		hashKey:        []byte("test-fixture-hmac-key"),
	}

	_, err := reconcile(t, r)
	require.NoError(t, err)

	// Confirmed gone on the next reconcile, but Delete is blocked (simulated webhook).
	fetcher.goneRefs = map[string]bool{"app/production/db-password": true}
	_, err = reconcile(t, r)
	require.Error(t, err)
	assert.True(t, errors.Is(err, keyorix.ErrSecretGone))

	// The Secret is still there — the wipe was blocked.
	var got corev1.Secret
	require.NoError(t, blocked.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got),
		"the wipe was blocked, so the stale Secret must still exist")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, blocked.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, "UpstreamSecretGoneWipeFailed", ks.Status.Conditions[0].Reason,
		"a wipe failure must be distinguishable in status from a successful wipe")
	assert.Contains(t, ks.Status.Conditions[0].Message, "wiping the stale target Secret failed",
		"the message must say the wipe itself failed, not just that the fetch failed")
}

// TestReconcile_RetargetWipesOrphanedSecretUnderOldName pins the fix for the bug where
// changing spec.target.name orphaned the previously-materialised Secret forever: no
// later reconcile ever revisited it by the OLD name, so it lingered indefinitely with
// its last-synced (possibly since-rotated) plaintext value. status.LastTargetName must
// track the materialised name, and a mismatch on the next reconcile must wipe the OLD
// Secret before syncing the new one.
func TestReconcile_RetargetWipesOrphanedSecretUnderOldName(t *testing.T) {
	ks := ksFixture()
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ks, tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var oldSecret corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &oldSecret),
		"precondition: the target Secret exists under the original name")

	var got secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &got))
	assert.Equal(t, "db-creds", got.Status.LastTargetName, "LastTargetName tracks the materialised target after a successful sync")

	// Retarget: spec.target.name changes to a brand-new name.
	got.Spec.Target.Name = "db-creds-v2"
	require.NoError(t, c.Update(context.Background(), &got))

	_, err = reconcile(t, r)
	require.NoError(t, err)

	// The Secret orphaned under the OLD name is gone.
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &oldSecret)
	assert.Error(t, err, "the Secret orphaned under the OLD target name must be wiped on retarget")

	// The new Secret exists with the synced data.
	var newSecret corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds-v2", Namespace: "app"}, &newSecret))
	assert.Equal(t, []byte("p4ss"), newSecret.Data["DB_PASSWORD"])

	// status.LastTargetName now tracks the new name.
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &got))
	assert.Equal(t, "db-creds-v2", got.Status.LastTargetName)
}

// TestReconcile_RetargetWipeFailureKeepsOldLastTargetNameAndWarns exercises Bug 2's
// failure branch together with Bug 3's status-surfacing fix: if wiping the orphaned OLD
// Secret fails during a retarget, the new target's sync must still succeed (a blocked
// cleanup of an unrelated old resource shouldn't hold the CR's real sync hostage), but
// status.LastTargetName must NOT advance to the new name — so the next reconcile retries
// the orphan wipe instead of silently forgetting about it — and the Ready message must
// say so.
func TestReconcile_RetargetWipeFailureKeepsOldLastTargetNameAndWarns(t *testing.T) {
	ks := ksFixture()
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	s := testScheme(t)
	inner := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
		WithObjects(ks, tokenSecret()).
		Build()
	blocked := &deleteBlockingClient{Client: inner, blockDeleteName: "db-creds"}
	r := &KeyorixSecretReconciler{
		Client:         blocked,
		Scheme:         s,
		AllowedServers: []string{"https://keyorix.internal"},
		newClient:      func(_, _ string) valueFetcher { return fetcher },
		hashKey:        []byte("test-fixture-hmac-key"),
	}
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var got secretsv1alpha1.KeyorixSecret
	require.NoError(t, blocked.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &got))
	require.Equal(t, "db-creds", got.Status.LastTargetName)

	got.Spec.Target.Name = "db-creds-v2"
	require.NoError(t, blocked.Update(context.Background(), &got))

	_, err = reconcile(t, r)
	require.NoError(t, err, "the new target's sync must succeed even though the OLD Secret's wipe was blocked")

	// The new Secret exists.
	var newSecret corev1.Secret
	require.NoError(t, blocked.Get(context.Background(), types.NamespacedName{Name: "db-creds-v2", Namespace: "app"}, &newSecret))

	// The old Secret still exists — its wipe was blocked.
	var oldSecret corev1.Secret
	require.NoError(t, blocked.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &oldSecret))

	require.NoError(t, blocked.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &got))
	assert.Equal(t, "db-creds", got.Status.LastTargetName,
		"LastTargetName must stay at the OLD name so the next reconcile retries the orphan wipe")
	require.Len(t, got.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionTrue, got.Status.Conditions[0].Status, "the new target's own sync still succeeded")
	assert.Contains(t, got.Status.Conditions[0].Message, "failed to wipe the orphaned Secret",
		"a blocked orphan wipe must be visible in the Ready message, not just logged")
}

// TestReconcile_RetargetSyncFailureLeavesOldSecretInPlace is the regression test for the
// fix to the "delete-then-create" rename bug: a spec.target.name rename used to wipe the
// Secret materialised under the OLD name UNCONDITIONALLY, before buildDesired/applySecret
// had confirmed the NEW-named Secret could actually be synced. If that later sync then
// failed (a bad ref, a revoked token, a transient upstream outage — anything), NEITHER
// Secret was left in the cluster: the old one was already gone, and the new one never got
// created — a self-inflicted availability outage for every workload mounting the old
// name. The fix reorders Reconcile to build-and-apply the NEW Secret FIRST and only wipe
// the OLD one after that succeeds, so a failed rename now leaves the OLD (still-working)
// Secret in place instead. This pins that: with the new target's own fetch made to fail,
// the OLD Secret must survive the failed reconcile untouched, and the NEW Secret must
// never have been created.
func TestReconcile_RetargetSyncFailureLeavesOldSecretInPlace(t *testing.T) {
	ks := ksFixture()
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ks, tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var before corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &before),
		"precondition: the target Secret exists under the original name")

	var got secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &got))
	require.Equal(t, "db-creds", got.Status.LastTargetName)

	// Retarget AND make the new target's own fetch fail (NOT ErrSecretGone — a plain
	// transient-style failure), so buildDesired for "db-creds-v2" never succeeds.
	got.Spec.Target.Name = "db-creds-v2"
	require.NoError(t, c.Update(context.Background(), &got))
	fetcher.failRefs = map[string]bool{"app/production/db-password": true}

	_, err = reconcile(t, r)
	require.Error(t, err, "the fetch failure must still fail this reconcile")

	// The OLD Secret must still be present, untouched — this is the availability
	// guarantee the fix restores: a failed rename must not delete a still-working Secret.
	var after corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &after),
		"the OLD target Secret must survive a reconcile where the NEW target's sync failed")
	assert.Equal(t, before.Data, after.Data, "the surviving OLD Secret's data must be untouched")

	// The NEW Secret must never have been created — buildDesired failed before
	// applySecret ever ran.
	var newSecret corev1.Secret
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds-v2", Namespace: "app"}, &newSecret)
	assert.Error(t, err, "the NEW target Secret must not exist when its own sync failed")

	// status.LastTargetName must stay at the OLD name so the next reconcile retries the
	// whole rename (build the new Secret, then wipe the old one) instead of forgetting.
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &got))
	assert.Equal(t, "db-creds", got.Status.LastTargetName)
	require.Len(t, got.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, got.Status.Conditions[0].Status)
	assert.Equal(t, "SyncError", got.Status.Conditions[0].Reason)
}

// TestReconcile_RetargetApplyFailureLeavesOldSecretInPlace is
// TestReconcile_RetargetSyncFailureLeavesOldSecretInPlace's sibling for the OTHER way the
// new target's sync can fail after buildDesired succeeds: applySecret itself erroring
// (e.g. attempting to adopt a pre-existing unmanaged Secret at the new name). The OLD
// Secret must still survive, exactly as when buildDesired fails.
func TestReconcile_RetargetApplyFailureLeavesOldSecretInPlace(t *testing.T) {
	ks := ksFixture()
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	// A pre-existing, unmanaged Secret already sits at the NEW target name — applySecret
	// refuses to adopt it, so applying the new target fails.
	foreignNewTarget := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db-creds-v2", Namespace: "app"},
		Data:       map[string][]byte{"OTHER": []byte("do-not-touch")},
	}
	r, c := newReconciler(t, fetcher, ks, tokenSecret(), foreignNewTarget)
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var before corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &before),
		"precondition: the target Secret exists under the original name")

	got := &secretsv1alpha1.KeyorixSecret{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, got))
	got.Spec.Target.Name = "db-creds-v2"
	require.NoError(t, c.Update(context.Background(), got))

	_, err = reconcile(t, r)
	require.Error(t, err, "applySecret must refuse to adopt the unmanaged Secret at the new name")

	// The OLD Secret must still be present, untouched.
	var after corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &after),
		"the OLD target Secret must survive a reconcile where applying the NEW target failed")
	assert.Equal(t, before.Data, after.Data)

	// The foreign Secret at the new name must be untouched too (still not ours).
	var foreign corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds-v2", Namespace: "app"}, &foreign))
	assert.Equal(t, []byte("do-not-touch"), foreign.Data["OTHER"])

	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, got))
	assert.Equal(t, "db-creds", got.Status.LastTargetName)
}

// TestReconcile_RetargetHappyPathEndsWithOnlyNewSecret confirms the fix didn't regress the
// success path: when the rename's new-named sync succeeds, the result is exactly the same
// as before — only the NEW-named Secret remains, and the OLD one is cleaned up. (This
// mirrors TestReconcile_RetargetWipesOrphanedSecretUnderOldName; kept here as an explicit
// "only one Secret survives" assertion alongside the two failure-path siblings above.)
func TestReconcile_RetargetHappyPathEndsWithOnlyNewSecret(t *testing.T) {
	ks := ksFixture()
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ks, tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	got := &secretsv1alpha1.KeyorixSecret{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, got))
	got.Spec.Target.Name = "db-creds-v2"
	require.NoError(t, c.Update(context.Background(), got))

	_, err = reconcile(t, r)
	require.NoError(t, err, "the rename's new-named sync succeeds")

	var newSecret corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds-v2", Namespace: "app"}, &newSecret),
		"the NEW target Secret must exist")
	assert.Equal(t, []byte("p4ss"), newSecret.Data["DB_PASSWORD"])

	var oldSecret corev1.Secret
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &oldSecret)
	assert.Error(t, err, "the OLD target Secret must be gone — only the new one survives a successful rename")

	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, got))
	assert.Equal(t, "db-creds-v2", got.Status.LastTargetName)
}

// A target Secret this operator does NOT manage (no ManagedByLabel — applySecret
// already refuses to adopt it) must never be deleted, even when the upstream secret is
// confirmed gone: it isn't ours to touch, and it may belong to an unrelated workload
// that merely collides on name.
func TestReconcile_UpstreamGoneDoesNotDeleteUnmanagedSecret(t *testing.T) {
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "app"},
		Data:       map[string][]byte{"OTHER": []byte("do-not-touch")},
	}
	fetcher := &fakeFetcher{goneRefs: map[string]bool{"app/production/db-password": true}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret(), foreign)

	_, err := reconcile(t, r)
	require.Error(t, err)
	assert.True(t, errors.Is(err, keyorix.ErrSecretGone))

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got),
		"an unmanaged Secret sharing the target name must not be deleted")
	assert.Equal(t, []byte("do-not-touch"), got.Data["OTHER"])
}

// TestReconcile_UpstreamGoneDoesNotDeleteSecretOwnedByAnotherCR pins the cross-tenant
// delete confused-deputy fixed alongside #428's wipe feature: ks.Spec.Target.Name is
// taken directly from the reconciling CR's OWN spec, fully attacker-controlled. Before
// this fix, wipeTargetSecret only checked the SHARED ManagedByLabel before deleting —
// which every Secret this operator manages carries, regardless of which CR owns it. An
// attacker with only ordinary namespaced KeyorixSecret-create RBAC could set their own
// CR's spec.target.name to the name of a Secret already owned by a DIFFERENT, victim
// CR, and point spec.data[0].ref at any nonexistent Keyorix ref: their reconcile would
// hit ErrSecretGone and delete the victim's Secret — despite never owning it — on every
// requeue, a sustained cross-tenant availability attack. This mirrors
// TestReconcile_RefusesToAdoptSecretOwnedByAnotherCR (the write-side sibling) but for
// the delete path: the fix adds metav1.IsControlledBy(&secret, ks) alongside the
// existing label check.
func TestReconcile_UpstreamGoneDoesNotDeleteSecretOwnedByAnotherCR(t *testing.T) {
	victim := &secretsv1alpha1.KeyorixSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "victim-cr", Namespace: "app", UID: "victim-uid"},
	}
	owned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-creds",
			Namespace: "app",
			Labels:    map[string]string{ManagedByLabel: ManagedByValue},
		},
		Data: map[string][]byte{"OTHER": []byte("owned-by-victim-cr")},
	}
	// Give `owned` a real controller owner reference to `victim`, mirroring what a prior
	// reconcile of the victim CR would have set via applySecret.
	s := testScheme(t)
	require.NoError(t, controllerutil.SetControllerReference(victim, owned, s))

	// The attacker's own CR ("db", from ksFixture) targets the SAME Secret name, and its
	// own upstream ref is confirmed gone — driving Reconcile into the wipe path.
	fetcher := &fakeFetcher{goneRefs: map[string]bool{"app/production/db-password": true}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret(), owned)

	_, err := reconcile(t, r)
	require.Error(t, err, "a confirmed-gone upstream ref still requeues with error for backoff")
	assert.True(t, errors.Is(err, keyorix.ErrSecretGone))

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got),
		"a Secret controlled by a DIFFERENT CR must not be deleted just because the shared managed-by label matches")
	assert.Equal(t, []byte("owned-by-victim-cr"), got.Data["OTHER"], "the victim CR's Secret data must be untouched")
	require.Len(t, got.OwnerReferences, 1)
	assert.Equal(t, "victim-cr", got.OwnerReferences[0].Name, "ownership must not have moved or been disturbed")
}

// TestReconcile_TokenSecretReadUsesAPIReader pins #124: the token Secret lookup
// must go through the uncached APIReader (when set), not the shared/cached
// Client — the shared cache is scoped to only Secrets this operator manages, so
// an arbitrary token Secret would never appear there in production. Prove the
// reconciler actually reads via APIReader by giving it a SEPARATE fake client
// that holds the token Secret while the main Client does not.
func TestReconcile_TokenSecretReadUsesAPIReader(t *testing.T) {
	s := testScheme(t)
	mainClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
		WithObjects(ksFixture()). // no token Secret here
		Build()
	apiReader := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(tokenSecret()). // the token Secret lives only in the "uncached" reader
		Build()

	r := &KeyorixSecretReconciler{
		Client:         mainClient,
		Scheme:         s,
		APIReader:      apiReader,
		AllowedServers: []string{"https://keyorix.internal"},
		newClient: func(_, _ string) valueFetcher {
			return &fakeFetcher{values: map[string][]byte{
				"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
			}}
		},
		hashKey: []byte("test-fixture-hmac-key"),
	}

	_, err := reconcile(t, r)
	require.NoError(t, err, "the token Secret must be found via APIReader even though it is absent from Client")
}

func TestReconcile_MissingTokenSecretFails(t *testing.T) {
	// No token Secret present.
	r, _ := newReconciler(t, &fakeFetcher{}, ksFixture())
	_, err := reconcile(t, r)
	require.Error(t, err)
}

func TestReconcile_DeletedCRIsNoOp(t *testing.T) {
	// No KeyorixSecret object at all → reconcile returns cleanly (owned Secret is GC'd).
	r, _ := newReconciler(t, &fakeFetcher{})
	res, err := reconcile(t, r)
	require.NoError(t, err)
	assert.Zero(t, res.RequeueAfter)
}

func TestReconcile_RemovedKeyIsPruned(t *testing.T) {
	// First sync writes two keys; dropping one from spec prunes it on the next sync,
	// because the operator owns the whole data set.
	ks := ksFixture()
	r, c := newReconciler(t, &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
	}}, ks, tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	// Drop API_KEY from the spec and reconcile again.
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, ks))
	ks.Spec.Data = ks.Spec.Data[:1]
	require.NoError(t, c.Update(context.Background(), ks))
	_, err = reconcile(t, r)
	require.NoError(t, err)

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got))
	assert.Contains(t, got.Data, "DB_PASSWORD")
	assert.NotContains(t, got.Data, "API_KEY", "a dropped mapping is pruned from the Secret")
}

func TestHashData_StableAndSensitive(t *testing.T) {
	key := []byte("test-hmac-key")
	a := map[string][]byte{"x": []byte("1"), "y": []byte("2")}
	b := map[string][]byte{"y": []byte("2"), "x": []byte("1")}
	assert.Equal(t, hashData(key, a), hashData(key, b), "hash is independent of map iteration order")
	assert.NotEqual(t, hashData(key, a), hashData(key, map[string][]byte{"x": []byte("1"), "y": []byte("3")}))
}

// TestHashData_KeyedAgainstBruteForce pins #124: status.syncedHash is a CR
// subresource commonly readable without any RBAC on the underlying Secret. A
// plain, unkeyed sha256 there would let a CR-getter brute-force a low-entropy
// value offline with zero Secret-read access. Keying the hash means an
// observer who only ever sees the hash (never the key, which lives in the
// operator process's memory) cannot precompute/verify guesses against it.
func TestHashData_KeyedAgainstBruteForce(t *testing.T) {
	data := map[string][]byte{"password": []byte("hunter2")}
	h1 := hashData([]byte("key-one"), data)
	h2 := hashData([]byte("key-two"), data)
	assert.NotEqual(t, h1, h2, "the same data must hash differently under a different key")

	// An attacker who only knows a candidate value and the algorithm (sha256,
	// no key) cannot reproduce a keyed hash — confirms this isn't just a plain
	// sha256 in disguise.
	plainSHA := sha256.Sum256([]byte("password\x00hunter2\x00"))
	assert.NotEqual(t, hex.EncodeToString(plainSHA[:]), h1)
}

// validateServer is the confused-deputy guard: the operator must only ever send a token
// to an https destination it was explicitly configured to trust, so a tenant who can
// create a CR cannot redirect a (possibly arbitrary) namespace Secret's value to an
// attacker server.
func TestValidateServer(t *testing.T) {
	allow := &KeyorixSecretReconciler{AllowedServers: []string{"https://keyorix.internal", "https://kx.example.com/"}}
	cases := []struct {
		name    string
		r       *KeyorixSecretReconciler
		server  string
		wantErr bool
	}{
		{"allowed host", allow, "https://keyorix.internal", false},
		{"allowed host trailing-slash config", allow, "https://kx.example.com", false},
		{"http rejected", allow, "http://keyorix.internal", true},
		{"not in allow-list rejected", allow, "https://attacker.example", true},
		{"empty allow-list rejects everything (fail closed)", &KeyorixSecretReconciler{}, "https://keyorix.internal", true},
		{"garbage rejected", allow, "::nope", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.r.validateServer(tc.server)
			if tc.wantErr && err == nil {
				t.Errorf("validateServer(%q) = nil; want error", tc.server)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateServer(%q) = %v; want nil", tc.server, err)
			}
		})
	}
}

// A CR pointing at an untrusted server is rejected BEFORE the operator reads the token
// Secret — so it cannot be used to exfiltrate a namespace Secret to an attacker.
func TestReconcile_RejectsUntrustedServer(t *testing.T) {
	ks := ksFixture()
	ks.Spec.Server = "https://attacker.example"
	r, c := newReconciler(t, &fakeFetcher{}, ks, tokenSecret())
	_, err := reconcile(t, r)
	require.Error(t, err, "a CR with a non-allowlisted server must fail the reconcile")

	// No target Secret was written.
	var got corev1.Secret
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	require.Error(t, err, "no Secret is created for a rejected server")
}

// #184 (confused deputy, second half): even with validateServer pinning the
// destination, a CRD-write-only principal (no core-Secret RBAC of their own) must not
// be able to point tokenSecretRef at an arbitrary pre-existing Secret and have the
// operator's cluster-wide Secret-read RBAC ship its bytes to the (trusted) Keyorix
// server. Only a Secret explicitly labeled as a token source may be resolved.
func TestReconcile_RejectsUnlabeledTokenSecret(t *testing.T) {
	unlabeled := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kx-token", Namespace: "app"}, // no label
		Data:       map[string][]byte{"token": []byte("some-secret-value")},
	}
	r, c := newReconciler(t, &fakeFetcher{}, ksFixture(), unlabeled)

	_, err := reconcile(t, r)
	require.Error(t, err, "an unlabeled Secret must not be usable as tokenSecretRef")
	assert.Contains(t, err.Error(), tokenSecretLabel)

	var got corev1.Secret
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	require.Error(t, err, "no Secret is created when the token source is unlabeled")
}

// A Secret carrying an unrelated/incorrect label value (not exactly the required
// marker) is treated the same as unlabeled — no partial-match bypass.
func TestReconcile_RejectsTokenSecretWithWrongLabelValue(t *testing.T) {
	wrongLabel := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kx-token",
			Namespace: "app",
			Labels:    map[string]string{tokenSecretLabel: "false"},
		},
		Data: map[string][]byte{"token": []byte("some-secret-value")},
	}
	r, _ := newReconciler(t, &fakeFetcher{}, ksFixture(), wrongLabel)
	_, err := reconcile(t, r)
	require.Error(t, err)
}

// #185: a same-named Secret already owned (controller ref) by a DIFFERENT KeyorixSecret
// CR must never be silently re-adopted by this CR, even though it already carries the
// operator's managed-by label (set by the other CR's earlier reconcile). This is the
// second line of defense beyond the managed-by label check: SetControllerReference
// itself refuses to move a controller ref from one owner to another.
func TestReconcile_RefusesToAdoptSecretOwnedByAnotherCR(t *testing.T) {
	other := &secretsv1alpha1.KeyorixSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "other-cr", Namespace: "app", UID: "other-uid"},
	}
	owned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-creds",
			Namespace: "app",
			Labels:    map[string]string{ManagedByLabel: ManagedByValue},
		},
		Data: map[string][]byte{"OTHER": []byte("owned-by-other-cr")},
	}
	// Give `owned` a real controller owner reference to `other`, mirroring what a prior
	// reconcile of the other CR would have set.
	s := testScheme(t)
	require.NoError(t, controllerutil.SetControllerReference(other, owned, s))

	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret(), owned)

	_, err := reconcile(t, r)
	require.Error(t, err, "must refuse to steal ownership of a Secret controlled by a different CR")

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got))
	assert.Equal(t, []byte("owned-by-other-cr"), got.Data["OTHER"], "the other CR's Secret data must be untouched")
	assert.NotContains(t, got.Data, "DB_PASSWORD")
	require.Len(t, got.OwnerReferences, 1)
	assert.Equal(t, "other-cr", got.OwnerReferences[0].Name, "ownership must not have moved to the new CR")
}

// TestNewReconciler_ProducesUsableReconciler covers the constructor's happy path (the
// error branch — crypto/rand.Read failing — isn't reasonably triggerable without
// injecting a fake randomness source, and NewReconciler intentionally has none). It
// checks the returned reconciler wires the constructor args straight through, and
// that hashKey is populated with real per-call randomness (#124: a fresh, non-empty key
// every process start), not a fixed/zero value.
func TestNewReconciler_ProducesUsableReconciler(t *testing.T) {
	s := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	apiReader := fake.NewClientBuilder().WithScheme(s).Build()
	allowed := []string{"https://keyorix.internal"}

	r, err := NewReconciler(c, s, apiReader, allowed, nil)
	require.NoError(t, err)
	require.NotNil(t, r)
	assert.Same(t, s, r.Scheme)
	assert.Equal(t, allowed, r.AllowedServers)
	require.Len(t, r.hashKey, 32, "hashKey must be a full 32-byte HMAC key")

	r2, err := NewReconciler(c, s, apiReader, allowed, nil)
	require.NoError(t, err)
	assert.NotEqual(t, r.hashKey, r2.hashKey, "each constructed reconciler gets its own fresh random key")
}

// TestFetcher_DefaultsToRealKeyorixClient covers the production path of fetcher() — when
// newClient is unset (nil), which is always true outside tests (only test fixtures ever
// override it) — building a real *keyorix.Client rather than the test seam.
func TestFetcher_DefaultsToRealKeyorixClient(t *testing.T) {
	r := &KeyorixSecretReconciler{}
	f := r.fetcher("https://keyorix.internal", "tok")
	require.NotNil(t, f)
	_, ok := f.(*keyorix.Client)
	assert.True(t, ok, "with no newClient override, fetcher must build the real keyorix.Client")
}

// TestReconcile_TokenKeyDefaultsToToken covers buildDesired's default for an unset
// spec.tokenSecretRef.key: it must fall back to the literal key "token" rather than
// failing to find any key at all.
func TestReconcile_TokenKeyDefaultsToToken(t *testing.T) {
	ks := ksFixture()
	ks.Spec.TokenSecretRef.Key = "" // unset → defaults to "token"
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ks, tokenSecret())

	_, err := reconcile(t, r)
	require.NoError(t, err, "an unset tokenSecretRef.key must default to reading the 'token' key")

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got))
	assert.Equal(t, []byte("p4ss"), got.Data["DB_PASSWORD"])
}

// TestReconcile_EmptyTokenValueFails covers buildDesired's guard against a token Secret
// that carries the expected key but an empty value — distinct from the key being
// entirely absent (already covered by TestReconcile_MissingTokenSecretFails's sibling
// paths): an empty bearer token must not be sent to the upstream server as if it were a
// real credential.
func TestReconcile_EmptyTokenValueFails(t *testing.T) {
	emptyToken := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kx-token",
			Namespace: "app",
			Labels:    map[string]string{tokenSecretLabel: tokenSecretValue},
		},
		Data: map[string][]byte{"token": []byte("")},
	}
	r, c := newReconciler(t, &fakeFetcher{}, ksFixture(), emptyToken)

	_, err := reconcile(t, r)
	require.Error(t, err, "an empty token value must not be used as a bearer credential")
	assert.Contains(t, err.Error(), "has no key")

	var got corev1.Secret
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	require.Error(t, err, "no Secret is created when the token value is empty")
}

// statusUpdateBlockingClient wraps a client.Client but fails every Status().Update call,
// simulating an API-server error (etcd unavailable, conflict, RBAC drift) while writing
// the CR's status subresource — used to exercise the error-return branches in fail(),
// failGone(), and Reconcile's own succeed() call, none of which are reachable by making
// the underlying fetch/apply fail (those already return before status-write failure can
// occur) or succeed (succeed()'s own status write must independently be able to fail).
type statusUpdateBlockingClient struct {
	client.Client
}

func (c *statusUpdateBlockingClient) Status() client.SubResourceWriter {
	return &blockingStatusWriter{SubResourceWriter: c.Client.Status()}
}

type blockingStatusWriter struct {
	client.SubResourceWriter
}

func (w *blockingStatusWriter) Update(_ context.Context, _ client.Object, _ ...client.SubResourceUpdateOption) error {
	return errors.New("simulated status subresource update failure")
}

func newStatusBlockedReconciler(t *testing.T, fetcher valueFetcher, objs ...client.Object) (*KeyorixSecretReconciler, client.Client) {
	t.Helper()
	s := testScheme(t)
	inner := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
		WithObjects(objs...).
		Build()
	blocked := &statusUpdateBlockingClient{Client: inner}
	return &KeyorixSecretReconciler{
		Client:         blocked,
		Scheme:         s,
		AllowedServers: []string{"https://keyorix.internal"},
		newClient:      func(_, _ string) valueFetcher { return fetcher },
		hashKey:        []byte("test-fixture-hmac-key"),
	}, blocked
}

// TestReconcile_SucceedStatusUpdateFailureSurfaces covers Reconcile's own error check on
// succeed()'s return (the branch right after "spec.target.name is mutable..."): when the
// fetch and apply both succeed but writing the success status back fails, Reconcile must
// propagate that status-write error instead of silently reporting success.
func TestReconcile_SucceedStatusUpdateFailureSurfaces(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, _ := newStatusBlockedReconciler(t, fetcher, ksFixture(), tokenSecret())

	_, err := reconcile(t, r)
	require.Error(t, err, "a status-write failure on an otherwise-successful sync must still be surfaced")
	assert.Contains(t, err.Error(), "simulated status subresource update failure")
}

// TestReconcile_FailStatusUpdateFailureSurfaces covers fail()'s own status-write error
// branch: an ordinary sync failure (a plain fetch error) whose status write ALSO fails
// must return the status-write error (so the workqueue backs off), not silently drop it.
func TestReconcile_FailStatusUpdateFailureSurfaces(t *testing.T) {
	fetcher := &fakeFetcher{failRefs: map[string]bool{"app/production/db-password": true}}
	r, _ := newStatusBlockedReconciler(t, fetcher, ksFixture(), tokenSecret())

	_, err := reconcile(t, r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated status subresource update failure",
		"fail()'s own Status().Update error must be returned, not the original fetch cause")
}

// TestReconcile_FailGoneStatusUpdateFailureSurfaces is FailStatusUpdateFailureSurfaces's
// sibling for the confirmed-gone path: failGone()'s own status-write error branch.
func TestReconcile_FailGoneStatusUpdateFailureSurfaces(t *testing.T) {
	fetcher := &fakeFetcher{goneRefs: map[string]bool{"app/production/db-password": true}}
	r, _ := newStatusBlockedReconciler(t, fetcher, ksFixture(), tokenSecret())

	_, err := reconcile(t, r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated status subresource update failure",
		"failGone()'s own Status().Update error must be returned, not the original ErrSecretGone cause")
}

// getErrorClient wraps a client.Client but fails every Get for an object named
// errorGetName with a plain (non-NotFound) error, simulating a transient API-server
// error distinct from "the object doesn't exist" — used to exercise wipeTargetSecret's
// error-propagation branch (client.IgnoreNotFound(err) only swallows NotFound; any other
// error must still surface as wipeErr).
type getErrorClient struct {
	client.Client
	errorGetName string
	// active gates when errorGetName starts erroring, so the FIRST reconcile (whose
	// applySecret also Gets the target Secret, via controllerutil.CreateOrUpdate, to
	// decide create-vs-update) can still succeed normally; only the LATER
	// wipeTargetSecret call under test should observe the simulated error.
	active bool
}

func (c *getErrorClient) Get(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
	if c.active && key.Name == c.errorGetName {
		return errors.New("simulated transient API error reading target Secret")
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

// TestReconcile_WipeTargetSecretGetErrorSurfacedInStatus covers wipeTargetSecret's other
// failure branch (besides Delete failing, already pinned by
// TestReconcile_WipeFailureSurfacedInStatus): the preliminary r.Get(ctx, key, &secret)
// itself erroring with something other than NotFound (e.g. a transient API-server
// error). That must be treated the same as a Delete failure — surfaced via the
// "WipeFailed" status suffix — not swallowed the way a genuine NotFound is.
func TestReconcile_WipeTargetSecretGetErrorSurfacedInStatus(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	s := testScheme(t)
	inner := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
		WithObjects(ksFixture(), tokenSecret()).
		Build()
	erroring := &getErrorClient{Client: inner, errorGetName: "db-creds"}
	r := &KeyorixSecretReconciler{
		Client:         erroring,
		Scheme:         s,
		AllowedServers: []string{"https://keyorix.internal"},
		newClient:      func(_, _ string) valueFetcher { return fetcher },
		hashKey:        []byte("test-fixture-hmac-key"),
	}

	_, err := reconcile(t, r)
	require.NoError(t, err)

	// Confirmed gone on the next reconcile; wipeTargetSecret's own Get on the target
	// Secret now fails with a non-NotFound error.
	erroring.active = true
	fetcher.goneRefs = map[string]bool{"app/production/db-password": true}
	_, err = reconcile(t, r)
	require.Error(t, err)
	assert.True(t, errors.Is(err, keyorix.ErrSecretGone))

	erroring.active = false // let the final status re-read through
	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, erroring.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, "UpstreamSecretGoneWipeFailed", ks.Status.Conditions[0].Reason,
		"a non-NotFound Get error inside wipeTargetSecret must surface the same way a Delete failure does")
}

// TestSetupWithManager_PropagatesBuildError covers SetupWithManager itself
// (setupController's thin public wrapper, which discards the built
// controller.Controller and returns only the error) — everything else in this file
// exercises setupController directly so it can inspect the built controller, but
// nothing had called the actual public entrypoint cmd/main.go uses.
//
// This deliberately builds the manager with a scheme that does NOT have
// secretsv1alpha1 registered, so ctrl.NewControllerManagedBy(...).For(&KeyorixSecret{})
// fails at the GVK lookup — a deterministic, self-contained failure. This is used
// (rather than a scheme built via testScheme, which WOULD succeed) specifically to
// avoid controller-runtime's process-global controller-name registry: a second
// successful build of a "keyorixsecret"-named controller in this same test binary
// would collide with the one TestSetupController_SetsMaxConcurrentReconciles already
// registers ("controller with name keyorixsecret already exists"), regardless of test
// execution order. SetupWithManager's body has no branch of its own — it's a single
// assign-then-return block — so exercising either outcome (error or success) covers it
// equally; the error path is the only one that's order-independent here.
func TestSetupWithManager_PropagatesBuildError(t *testing.T) {
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s)) // no secretsv1alpha1 registered

	mgr, err := ctrl.NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, ctrl.Options{
		Scheme:                 s,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	require.NoError(t, err, "manager construction must not require a live API server connection")

	r := &KeyorixSecretReconciler{Client: fake.NewClientBuilder().WithScheme(s).Build(), Scheme: s, hashKey: []byte("test-fixture-hmac-key")}
	err = r.SetupWithManager(mgr)
	assert.Error(t, err, "SetupWithManager must propagate setupController's build error, not swallow it")
}

// SetupWithManager must configure a small, fixed MaxConcurrentReconciles (r143). Without
// it, controller-runtime's default of exactly 1 means one shared worker services every
// KeyorixSecret in every namespace cluster-wide — a single slow/malicious CR (large Data
// array, or an entry pointed at an allow-listed-but-slow server) can stall reconciliation
// of every other tenant. This builds a real manager/controller (never Start()ed, so no
// network/API-server access happens) via setupController — the exact function
// SetupWithManager itself calls — and inspects the constructed controller-runtime
// controller. Because controller-runtime's own controller.Controller interface exposes no
// public accessor for MaxConcurrentReconciles (it's a field on an internal-package
// struct), this reads it via reflection on the concrete value — a legitimate technique
// here since we only need runtime reflection, not a compile-time import of the internal
// package.
//
// controller-runtime keeps controller names in a process-global registry, so under
// -count>1 (or any second build of the "keyorixsecret" controller in this binary) the
// second build fails with "controller with name keyorixsecret already exists". This test
// is about the built controller's configuration, not about the registry, so it opts out
// of name validation on its own manager (Options.Controller.SkipNameValidation). That is
// a test-only setting: production wiring (SetupWithManager, cmd/main.go) is unchanged and
// still validates names.
func TestSetupController_SetsMaxConcurrentReconciles(t *testing.T) {
	s := testScheme(t)
	skipNameValidation := true
	mgr, err := ctrl.NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, ctrl.Options{
		Scheme:                 s,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller:             ctrlconfig.Controller{SkipNameValidation: &skipNameValidation},
	})
	require.NoError(t, err, "manager construction must not require a live API server connection")

	r := &KeyorixSecretReconciler{Client: fake.NewClientBuilder().WithScheme(s).Build(), Scheme: s, hashKey: []byte("test-fixture-hmac-key")}
	c, err := r.setupController(mgr)
	require.NoError(t, err)

	v := reflect.ValueOf(c)
	for v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	field := v.FieldByName("MaxConcurrentReconciles")
	require.True(t, field.IsValid(), "controller-runtime's controller type must still expose a MaxConcurrentReconciles field (reflection target); if this fails after a controller-runtime upgrade, the field/type may have been renamed")
	assert.EqualValues(t, maxConcurrentReconciles, field.Int(),
		"the constructed controller must run with the operator's small, fixed reconcile-concurrency bound, not controller-runtime's default of 1")
	assert.Equal(t, 5, maxConcurrentReconciles, "documents the chosen bound so a future change to the constant is a deliberate, reviewed diff here too")
}
