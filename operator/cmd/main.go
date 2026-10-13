// Command keyorix-operator runs the KeyorixSecret controller: it reconciles
// KeyorixSecret resources into native Kubernetes Secrets and keeps them current.
package main

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
	"github.com/keyorixhq/keyorix/operator/internal/controller"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(secretsv1alpha1.AddToScheme(scheme))
}

// namespaceScope is the fully-validated outcome of resolving -watch-namespaces,
// -all-namespaces, and POD_NAMESPACE (ADR-076). It has exactly two valid shapes: a
// concrete, non-empty list of namespaces to watch, or explicit all-namespaces. There is
// no third, ambiguous state — resolveScope never returns a zero-value namespaceScope
// without an error, and callers must not construct one directly outside a test.
type namespaceScope struct {
	namespaces    []string // non-empty unless allNamespaces is true
	allNamespaces bool
}

// resolveScope implements ADR-076's fail-closed namespace-scope contract:
//
//   - -watch-namespaces set (and -all-namespaces not): watch exactly those namespaces.
//   - -all-namespaces set (and -watch-namespaces not): watch every namespace in the
//     cluster. This is the ONLY route to a cluster-wide watch — there is no implicit one.
//   - both set: a startup validation error, never resolved by precedence. #1224 already
//     demonstrated what precedence-based resolution of contradictory chart config does
//     (a silent no-RBAC-binding render); the binary does not repeat that mistake.
//   - neither set: fall back to the pod's OWN namespace, read from podNamespaceEnv
//     (POD_NAMESPACE, populated by the Helm chart via the Kubernetes Downward API) — never
//     to all-namespaces. If podNamespaceEnv is also empty, this is a startup validation
//     error naming POD_NAMESPACE specifically, not a silent cluster-wide fallback:
//     controller-runtime treats an empty-string key in cache.Options.DefaultNamespaces as
//     cache.AllNamespaces (= metav1.NamespaceAll = ""), so passing through an unchecked
//     blank POD_NAMESPACE would silently produce a cluster-wide watch through code that
//     reads, at the call site, as correctly namespace-scoped.
func resolveScope(watchNamespacesFlag string, allNamespacesFlag bool, podNamespaceEnv string) (namespaceScope, error) {
	var watchNS []string
	for _, ns := range strings.Split(watchNamespacesFlag, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			watchNS = append(watchNS, ns)
		}
	}

	switch {
	case len(watchNS) > 0 && allNamespacesFlag:
		return namespaceScope{}, fmt.Errorf(
			"-watch-namespaces and -all-namespaces are mutually exclusive; set exactly one, " +
				"or set neither to default to the pod's own namespace (POD_NAMESPACE)")
	case allNamespacesFlag:
		return namespaceScope{allNamespaces: true}, nil
	case len(watchNS) > 0:
		return namespaceScope{namespaces: watchNS}, nil
	}

	podNamespace := strings.TrimSpace(podNamespaceEnv)
	if podNamespace == "" {
		return namespaceScope{}, fmt.Errorf(
			"neither -watch-namespaces nor -all-namespaces is set, and POD_NAMESPACE is " +
				"empty or unset -- refusing to start with an ambiguous scope rather than " +
				"defaulting to a cluster-wide watch (ADR-076). Set -watch-namespaces, pass " +
				"-all-namespaces explicitly, or ensure POD_NAMESPACE is populated (the Helm " +
				"chart does this via the Downward API; a hand-rolled deployment must too)")
	}
	return namespaceScope{namespaces: []string{podNamespace}}, nil
}

// secretCacheOptions scopes the manager's Secret informer to only Secrets the operator
// itself manages, and routes every other Secret read straight to the API server instead
// of through that (now-restricted) cache. The namespace scope itself (s) is resolved
// beforehand by resolveScope per ADR-076 — this function only ever renders an
// already-validated scope into cache.Options, it does not decide the scope itself.
//
// By DEFAULT (ADR-076) the operator watches only its own namespace — s.allNamespaces is
// false and s.namespaces holds exactly one entry, the pod's own namespace. Operators who
// need one instance to watch a bounded set of tenants set -watch-namespaces explicitly;
// operators who need a single cluster-wide instance (the ORIGINAL default, see #327/#427
// and ADR-076 for the reversal history) must pass -all-namespaces explicitly, which is the
// only way s.allNamespaces becomes true. See operator/config/rbac/role.yaml /
// deploy/helm/keyorix-operator/templates/rbac.yaml for how the corresponding RBAC binding
// (RoleBinding vs ClusterRoleBinding) is kept in lockstep with this same scope.
//
// What IS always avoided, regardless of namespace scoping, is controller-runtime's
// default behavior of caching every Secret in the cluster in the operator's own process
// memory just because SetupWithManager calls Owns(&corev1.Secret{}) to watch the Secrets
// it owns. That default cache would hold the full contents of every Secret it can see —
// including ones this operator has no relationship to — turning a compromise of the
// operator process (e.g. the SSRF/dependency findings #184/#240) into a trivial in-memory
// dump of Secrets instead of just the ones it manages. Restricting the informer to
// controller.ManagedByLabel closes that gap: only Secrets this operator previously created
// (and therefore already has full read/write RBAC over anyway) are ever resident in its
// cache.
//
// Token Secrets (read via TokenSecretRef) and not-yet-adopted target Secrets never carry
// that label, so DisableFor routes their reads around the label-restricted cache to a live
// API call — they stay correctly readable on every reconcile, just uncached.
func secretCacheOptions(s namespaceScope) (cache.Options, client.Options) {
	managedByThisOperator := labels.SelectorFromSet(map[string]string{
		controller.ManagedByLabel: controller.ManagedByValue,
	})
	opts := cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {Label: managedByThisOperator},
		},
	}
	if !s.allNamespaces {
		// s.namespaces is guaranteed non-empty here by resolveScope's contract — never
		// constructed from an unvalidated/possibly-empty string, so this map never ends
		// up with the "" (cache.AllNamespaces) sentinel key by accident.
		defaultNamespaces := make(map[string]cache.Config, len(s.namespaces))
		for _, ns := range s.namespaces {
			defaultNamespaces[ns] = cache.Config{}
		}
		// Left unset on the Secret ByObject entry above so it defaults from
		// DefaultNamespaces (controller-runtime's precedence rule): the label
		// restriction and the namespace restriction combine, rather than one
		// overriding the other.
		opts.DefaultNamespaces = defaultNamespaces
	}
	// s.allNamespaces == true is the ONLY path that leaves DefaultNamespaces unset
	// (cluster-wide, controller-runtime's own len(DefaultNamespaces) > 0 check) — always
	// the result of an explicit, validated -all-namespaces flag, never a fallback.
	return opts, client.Options{
		Cache: &client.CacheOptions{
			DisableFor: []client.Object{&corev1.Secret{}},
		},
	}
}

// metricsFilterProvider builds a controller-runtime metrics FilterProvider (the framework's
// own extension point for gating its metrics server, wired in via ctrl.Options.Metrics.
// FilterProvider below) that requires a matching "Authorization: Bearer <token>" header when
// token is non-empty, and mirrors server/http/router.go's own MetricsToken gate on the main
// Keyorix server's /metrics endpoint (constant-time comparison, same header shape) so both
// binaries in this repo authenticate their metrics endpoints the same way.
//
// controller-runtime also ships its own kube-rbac-proxy-style filter,
// metrics/filters.WithAuthenticationAndAuthorization, which authenticates via the
// apiserver's TokenReview/SubjectAccessReview APIs instead of a static token. It was
// deliberately NOT used here: it requires a new k8s.io/apiserver dependency, and --
// more importantly -- TokenReview/SubjectAccessReview are cluster-scoped, non-namespaced
// resources, so granting them needs a ClusterRoleBinding specifically. That conflicts with
// ADR-076 (see resolveScope/secretCacheOptions above and deploy/helm/keyorix-operator's own
// rbac.yaml comment): this operator's default, and most common, deployment shape binds its
// ClusterRole via a namespace-scoped RoleBinding, which cannot grant a cluster-scoped
// permission at all -- every metrics scrape would 403 out of the box for that default
// shape. A static bearer token has no such conflict and matches this repo's own existing
// convention for the identical problem on the main server.
//
// When token is empty the endpoint is left unauthenticated -- matching the main server's own
// documented default (see router.go: "When unset, the endpoint is unauthenticated ... keep
// it inside your perimeter") -- so this is opt-in, not a breaking change for existing
// deployments that don't set one. TLS (SecureServing, wired in main below) is unconditional
// regardless of whether a token is configured: controller-runtime auto-generates a
// self-signed certificate for it when no CertDir/TLSOpts are supplied (matching
// kube-controller-manager's own documented use of self-signed certs for this exact purpose),
// so it costs nothing and needs no operator-supplied config to close the "no TLS" half of
// this finding.
// newMetricsOptions builds the metricsserver.Options passed to ctrl.Options.Metrics in main
// below. Split out (mirroring secretCacheOptions above) so a test can pin that
// SecureServing/FilterProvider are actually wired in, not just that metricsFilterProvider
// behaves correctly in isolation.
func newMetricsOptions(metricsAddr, bearerToken string) metricsserver.Options {
	return metricsserver.Options{
		BindAddress: metricsAddr,
		// SecureServing serves metrics over TLS unconditionally: with no CertDir/TLSOpts
		// configured, controller-runtime auto-generates a self-signed certificate (see its
		// own doc comment on Options.SecureServing) -- no operator-supplied cert, key, or new
		// dependency needed, so there's no reason not to always have it on.
		SecureServing: true,
		// FilterProvider gates access behind an optional static bearer token -- see
		// metricsFilterProvider's own doc comment for why this, and not controller-runtime's
		// built-in TokenReview/SubjectAccessReview filter
		// (metrics/filters.WithAuthenticationAndAuthorization), was chosen.
		FilterProvider: metricsFilterProvider(bearerToken),
	}
}

func metricsFilterProvider(token string) func(*rest.Config, *http.Client) (metricsserver.Filter, error) {
	return func(*rest.Config, *http.Client) (metricsserver.Filter, error) {
		return func(_ logr.Logger, handler http.Handler) (http.Handler, error) {
			if token == "" {
				return handler, nil
			}
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if len(auth) < 8 || auth[:7] != "Bearer " || subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(token)) != 1 {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				handler.ServeHTTP(w, r)
			}), nil
		}, nil
	}
}

func main() {
	var metricsAddr, probeAddr, allowedServers, watchNamespaces, metricsBearerToken string
	var enableLeaderElection, allNamespaces bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address the metric endpoint binds to")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "address the probe endpoint binds to")
	// Default "", not os.Getenv: flag's usage output prints every non-empty default,
	// so an env-backed default would put the token in the log on any bad flag.
	flag.StringVar(&metricsBearerToken, "metrics-bearer-token", "",
		"OPTIONAL bearer token (or set KEYORIX_METRICS_TOKEN) required on the metrics endpoint's Authorization header (e.g. by a Prometheus scrape "+
			"config's authorization.credentials). The metrics endpoint is always served over TLS (a self-signed "+
			"certificate is generated automatically) regardless of this flag; when this flag is unset the endpoint "+
			"itself is left unauthenticated -- matching the main Keyorix server's own MetricsToken default -- so set "+
			"it, or restrict network access with a NetworkPolicy, for internet-reachable or multi-tenant clusters.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"enable leader election for controller manager (run a single active replica)")
	flag.StringVar(&allowedServers, "allowed-servers", os.Getenv("KEYORIX_ALLOWED_SERVERS"),
		"comma-separated list of trusted Keyorix base URLs (https://host) a KeyorixSecret's spec.server must match. "+
			"REQUIRED: without it every CR is rejected, so the operator never sends a token to a CR-chosen destination.")
	flag.StringVar(&watchNamespaces, "watch-namespaces", os.Getenv("KEYORIX_WATCH_NAMESPACES"),
		"OPTIONAL comma-separated list of namespaces this instance manages KeyorixSecret CRs and their target "+
			"Secrets in. Mutually exclusive with -all-namespaces. Leave both unset (the default) to watch only the "+
			"pod's own namespace (read from POD_NAMESPACE, e.g. via the Downward API) — see -all-namespaces for a "+
			"genuinely cluster-wide watch (ADR-076).")
	flag.BoolVar(&allNamespaces, "all-namespaces", false,
		"Watch every namespace in the cluster. The ONLY way to run in cluster-wide mode (ADR-076) — requires a "+
			"cluster-wide ClusterRoleBinding (#327/#427). Mutually exclusive with -watch-namespaces.")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	metricsBearerToken = flagOrEnv(flag.CommandLine, "metrics-bearer-token", metricsBearerToken, "KEYORIX_METRICS_TOKEN")

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	scope, err := resolveScope(watchNamespaces, allNamespaces, os.Getenv("POD_NAMESPACE"))
	if err != nil {
		setupLog.Error(err, "invalid namespace-scope configuration")
		os.Exit(1)
	}
	if scope.allNamespaces {
		setupLog.Info("watching all namespaces (-all-namespaces)")
	} else {
		setupLog.Info("restricting watched namespaces", "namespaces", scope.namespaces)
	}

	if metricsBearerToken == "" {
		setupLog.Info("WARNING: -metrics-bearer-token is not set; the metrics endpoint is reachable over TLS but " +
			"without authentication -- set it or restrict network access via a NetworkPolicy")
	}

	secretCache, secretClient := secretCacheOptions(scope)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                newMetricsOptions(metricsAddr, metricsBearerToken),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "keyorix-operator.secrets.keyorix.io",
		// Bound the blast radius of the cluster-wide Secret RBAC this operator must hold
		// (see secretCacheOptions and #327/#124): don't cache every Secret in the cluster,
		// only ones this operator manages.
		Cache:  secretCache,
		Client: secretClient,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	var allowed []string
	for _, s := range strings.Split(allowedServers, ",") {
		if s = strings.TrimSpace(s); s != "" {
			allowed = append(allowed, s)
		}
	}
	if len(allowed) == 0 {
		setupLog.Info("WARNING: --allowed-servers is not set; every KeyorixSecret will be REJECTED until you configure the trusted Keyorix server URL(s)")
	}
	reconciler, err := controller.NewReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetAPIReader(), allowed,
		mgr.GetEventRecorder("keyorixsecret-controller"))
	if err != nil {
		setupLog.Error(err, "unable to initialize controller", "controller", "KeyorixSecret")
		os.Exit(1)
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeyorixSecret")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting keyorix-operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// flagOrEnv returns the value of the string flag name when it was given on the
// command line, otherwise the environment variable envVar. It stands in for an
// os.Getenv default on flags that carry a secret: flag.PrintDefaults prints every
// non-empty default verbatim (on -h and on any bad flag), which would copy the
// secret into the log (semgrep keyorix-secret-env-as-flag-default).
func flagOrEnv(fs *flag.FlagSet, name, flagValue, envVar string) string {
	given := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	if given {
		return flagValue
	}
	return os.Getenv(envVar)
}
