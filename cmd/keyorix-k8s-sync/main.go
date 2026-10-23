/*
Keyorix Kubernetes sync agent — materialises selected Keyorix secrets into
Kubernetes Secrets and keeps them current as upstream values rotate.

Runs in-cluster: it authenticates to Keyorix with a machine-identity token
(KEYORIX_TOKEN) and writes Secrets via the Kubernetes API using its mounted
service-account credentials. Configure the mappings in a YAML file (default
/etc/keyorix/k8s-sync.yaml, or -config / KEYORIX_K8S_SYNC_CONFIG).

Copyright (C) 2025 Keyorix Contributors. Licensed under the AGPL-3.0-or-later.
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/keyorix/internal/k8ssync"
	"github.com/keyorixhq/keyorix/internal/secretenv"
)

func main() {
	configPath := flag.String("config", envOr("KEYORIX_K8S_SYNC_CONFIG", "/etc/keyorix/k8s-sync.yaml"),
		"path to the sync config (YAML)")
	once := flag.Bool("once", false, "run a single reconcile pass and exit (for CI / one-shot Jobs)")
	dryRun := flag.Bool("dry-run", false, "report what would change without writing any Secret")
	cleanup := flag.Bool("cleanup", false, "delete orphaned Secrets the agent owns whose mapping was removed")
	// Default "", not os.Getenv: flag's usage output prints every non-empty default,
	// so an env-backed default would put the token in the log on any bad flag.
	metricsBearerTokenFlag := flag.String("metrics-bearer-token", "",
		"OPTIONAL bearer token (or set KEYORIX_METRICS_TOKEN) required on /metrics' Authorization header (e.g. by a Prometheus scrape "+
			"config's authorization.credentials). /healthz, /readyz, and /status stay unauthenticated -- "+
			"Kubernetes' own kubelet must reach them, and they expose no secret values. When this flag is "+
			"unset, /metrics itself is left unauthenticated too -- matching this repo's other two "+
			"Prometheus-scraped endpoints' own defaults -- so set it, or restrict network access with a "+
			"NetworkPolicy, for internet-reachable or multi-tenant clusters.")
	flag.Parse()
	metricsBearerToken := flagOrEnv(flag.CommandLine, "metrics-bearer-token", *metricsBearerTokenFlag, "KEYORIX_METRICS_TOKEN")

	cfg, err := k8ssync.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("k8s-sync: config: %v", err)
	}

	token, err := resolveToken()
	if err != nil {
		log.Fatalf("k8s-sync: %v", err)
	}

	sink, err := k8ssync.NewInClusterSink()
	if err != nil {
		log.Fatalf("k8s-sync: kubernetes: %v", err)
	}
	fetcher := k8ssync.NewKeyorixFetcher(cfg.KeyorixURL, token, cfg.ProjectID)
	os.Exit(runAgent(cfg, fetcher, sink, *once, *dryRun, *cleanup, metricsBearerToken))
}

// resolveToken resolves the Keyorix machine-identity token: KEYORIX_TOKEN_FILE (a
// path to a mounted Secret volume, e.g. /etc/keyorix/token) takes precedence when
// set. A token that only ever lives on a mounted, read-only volume never appears in
// the pod spec itself, unlike an env var sourced from a secretKeyRef -- the
// Kubernetes API still returns that verbatim to anyone who can read the pod (e.g. via
// `kubectl get pod -o yaml`), which a file mount does not. Falls back to KEYORIX_TOKEN
// for backward compatibility with existing deployments that already inject it as an
// env var; that fallback is not going away, so upgrading this agent's image alone
// never breaks a deployment that hasn't switched to KEYORIX_TOKEN_FILE yet.
func resolveToken() (string, error) {
	// A whitespace-only KEYORIX_TOKEN_FILE counts as unset, as before.
	if fvs := secretenv.FileVars("KEYORIX_TOKEN"); len(fvs) > 0 && strings.TrimSpace(fvs[0].Path) != "" {
		fv, path := fvs[0], strings.TrimSpace(fvs[0].Path)
		// secretenv.ReadFile: regular file only (a FIFO or device is refused without
		// blocking), size-capped, and the contents never appear in an error. The path
		// is named through secretenv.DescribeFile: a relative one is not shown, it
		// may be the token itself.
		raw, err := secretenv.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %w", secretenv.NewFileError(fv.Var(), path, err))
		}
		token := strings.TrimSpace(raw)
		if token == "" {
			return "", secretenv.NewFileError(fv.Var(), path, errors.New("is empty (whitespace only)"))
		}
		return token, nil
	}
	token := strings.TrimSpace(os.Getenv("KEYORIX_TOKEN"))
	if token == "" {
		return "", fmt.Errorf("KEYORIX_TOKEN is required (the Keyorix machine-identity token); " +
			"set KEYORIX_TOKEN, or KEYORIX_TOKEN_FILE to read it from a mounted Secret volume instead")
	}
	return token, nil
}

// runAgent holds everything that happens once a Fetcher and Sink exist: engine
// wiring, the one-shot/loop split, and (loop mode only) the health server. Split out
// from main so tests can drive it with a fake Fetcher/Sink instead of the real
// in-cluster ones (which need a live Kubernetes API and mounted service-account
// files main() can't fake). Returns the process exit code instead of calling
// os.Exit directly, so deferred cleanup (context cancel, signal.Stop, health server
// shutdown) always runs.
func runAgent(cfg *k8ssync.Config, fetcher k8ssync.Fetcher, sink k8ssync.Sink, once, dryRun, cleanup bool, metricsBearerToken string) int {
	var engineOpts []k8ssync.Option
	if dryRun {
		engineOpts = append(engineOpts, k8ssync.WithDryRun())
	}
	// Cleanup is enabled by either the config file or the -cleanup flag; the flag lets a
	// one-shot run preview/perform a reap without editing the mounted config.
	if cfg.Cleanup || cleanup {
		engineOpts = append(engineOpts, k8ssync.WithCleanup())
	}
	// prune_on_revoke is config-file-only (no CLI flag, unlike cleanup above): it's a
	// steady-state safety posture an operator sets once, not something a one-shot run
	// typically needs to override ad hoc. Defaults to true (wipe) — see
	// Config.GetPruneOnRevoke and pruneOnRevoke's own doc comment; only an explicit
	// `prune_on_revoke: false` opts out.
	if cfg.GetPruneOnRevoke() {
		engineOpts = append(engineOpts, k8ssync.WithPruneOnRevoke())
	} else {
		engineOpts = append(engineOpts, k8ssync.WithKeepOnRevoke())
	}
	// on_suspend (config-file-only): "retain" (default) or "clear"; see Config.OnSuspend.
	if cfg.GetOnSuspend() == k8ssync.OnSuspendClear {
		engineOpts = append(engineOpts, k8ssync.WithClearOnSuspend())
	}
	// mass_prune_ack acknowledges the mass-revocation circuit breaker (see
	// WithMassPruneAck's own doc comment); a zero Time (unset) never acknowledges
	// anything, so this is always safe to wire unconditionally.
	engineOpts = append(engineOpts, k8ssync.WithMassPruneAck(cfg.GetMassPruneAck()))
	engine := k8ssync.NewEngine(fetcher, sink, engineOpts...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		log.Println("k8s-sync: shutdown signal received")
		cancel()
	}()

	// One-shot mode: a single reconcile, then exit non-zero if anything failed (handy
	// as a CI gate or a Kubernetes Job). No health server / loop.
	if once {
		mode := ""
		if dryRun {
			mode = " (dry-run)"
		}
		log.Printf("k8s-sync: one-shot reconcile of %d mapping(s) from %s%s",
			len(cfg.Mappings), cfg.KeyorixURL, mode)
		res := k8ssync.Sync(ctx, engine, cfg.Mappings, log.Printf)
		if res.Failed > 0 {
			return 1
		}
		return 0
	}

	// Health/readiness server for Kubernetes probes (/healthz, /readyz, /status).
	status := k8ssync.NewStatus()
	healthSrv := newHealthServer(fmt.Sprintf(":%d", cfg.GetHealthPort()), status.HandlerWithToken(metricsBearerToken))
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("k8s-sync: health server error: %v", err)
		}
	}()
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = healthSrv.Shutdown(shutdownCtx)
	}()

	loopMode := ""
	if dryRun {
		loopMode = " (dry-run)"
	}
	log.Printf("k8s-sync: syncing %d mapping(s) from %s every %s (health :%d)%s",
		len(cfg.Mappings), cfg.KeyorixURL, cfg.GetInterval(), cfg.GetHealthPort(), loopMode)
	k8ssync.Run(ctx, engine, cfg.Mappings, cfg.GetInterval(), log.Printf, status)
	log.Println("k8s-sync: stopped")
	return 0
}

// newHealthServer builds the probe/metrics listener. Every connection-level
// timeout is set: with only ReadHeaderTimeout, a client could hold a connection
// open indefinitely by never reading the response or by idling on keep-alive.
func newHealthServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
