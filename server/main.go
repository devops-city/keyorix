/*
Keyorix Server - Enterprise Secret Management System
Copyright (C) 2025 Keyorix Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/hardening"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/logging"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/solewriter"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/version"
	"github.com/keyorixhq/keyorix/server/admin"
)

// isAdminDispatch reports whether argv routes to `keyorix-server admin`
// (ADR-108 §B, PR 11) rather than the plain server. Extracted from main()
// so this exact routing decision is unit-testable without invoking main()
// itself (which os/exec.Command'ing the built binary aside, `go test` never
// calls): only os.Args[1] == "admin" diverts — every other invocation,
// including one whose first argument happens to start with "-admin" or is
// simply absent, falls through to the unchanged flag-based server startup.
func isAdminDispatch(args []string) bool {
	return len(args) > 1 && args[1] == "admin"
}

// isVersionRequest reports whether argv is exactly `keyorix-server --version`
// (or -version). It is checked before any config, storage or flag parsing, so
// the build info prints on a host with no config file and never starts a
// listener.
func isVersionRequest(args []string) bool {
	return len(args) == 2 && (args[1] == "--version" || args[1] == "-version")
}

func main() { // NOSONAR -- cognitive complexity 22, suppress go:S3776
	// #1647: see main.go's identical call for the full rationale -- an explicit,
	// restrictive process umask means the SQLite database and its -wal/-shm sidecars
	// (created deep inside the driver, with no mode this process's Go code controls
	// directly) are born at 0600 regardless of what umask this process inherited.
	syscall.Umask(0o077)

	// `keyorix-server admin <cmd>` (ADR-108 §B, PR 11): a completely separate
	// command tree for offline/host-side operations (init, validate, audit,
	// diagnose, migrate) that must never start a listener. Dispatched BEFORE
	// this binary's own flag.Parse() below, so it never touches (and cannot be
	// confused with) the plain `keyorix-server` flag set --
	// --passphrase-fd/--passphrase-file/--passphrase-stdin keep their existing
	// meaning and behavior for every other invocation, unchanged.
	if isVersionRequest(os.Args) {
		fmt.Print(version.Info())
		return
	}

	if isAdminDispatch(os.Args) {
		os.Exit(admin.Execute(os.Args[2:]))
	}

	// Byte-based master-passphrase sources (ADR-099): fd is the strongest -- it
	// never touches argv, an env var, or a path this process opens by name -- and
	// is the usual answer for systemd's LoadCredential= (redirect the credential
	// file to an inherited fd in the unit's ExecStart). file and stdin cover the
	// remaining non-interactive and interactive cases. KEYORIX_MASTER_PASSWORD
	// keeps working as the last-resort fallback -- see ADR-099 for why it's the
	// weakest option.
	// flag.Func, not IntVar: ResolvePassphrase only honours the fd when FDSet is
	// true, and IntVar never sets it, so --passphrase-fd was silently ignored and
	// the server reported "no master passphrase available". FDSet is true exactly
	// when the flag was passed, including --passphrase-fd=0.
	flag.Func("passphrase-fd", "Read the master passphrase from this already-open file descriptor",
		func(s string) error {
			n, err := strconv.Atoi(s)
			if err != nil || n < 0 {
				return fmt.Errorf("invalid file descriptor %q", s)
			}
			masterPassphraseSource.FD, masterPassphraseSource.FDSet = n, true
			return nil
		})
	flag.StringVar(&masterPassphraseSource.FilePath, "passphrase-file", "",
		"Read the master passphrase from this file (refused if group- or world-readable, or owned by anyone but you or root)")
	flag.BoolVar(&masterPassphraseSource.Stdin, "passphrase-stdin", false,
		"Read the master passphrase from stdin")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// #G-blank-storage-default: the server's own boot path is the ONE caller
	// allowed to treat a blank storage.type as "local" -- see the matching
	// comment in internal/storage/factory.go's CreateStorage, which (along with
	// Config.Validate() below) now hard-errors on a blank type for every OTHER
	// caller (CLI commands run with no usable config, test fixtures building a
	// zero-value config.Config{}). This preserves an operator's existing
	// "no storage: block in the config file = local SQLite" deployment shape
	// without moving that default into the shared config.Load()/Validate()
	// functions the CLI also uses. Must run BEFORE the Validate() call
	// immediately below, since Validate() itself now rejects a blank type.
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}

	// Schema/sanity validation (ports, TLS cert/key presence, storage DSN/path) — always
	// enforced, independent of any security flag: a malformed config should never boot.
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration is invalid: %v", err)
	}

	// server.log.format: from here on every log line is a JSON object when "json".
	// Before this point (config load/validation failures) lines are plain text. Must
	// precede NewRouter: the access logger picks its formatter when the router is built.
	if err := logging.Setup(cfg.Server.Log.EffectiveFormat(), os.Stderr); err != nil {
		// cfg.Validate() above already refused an unknown server.log.format, so this is
		// the logger failing, not the file being invalid (BOOT-REFUSALS-1 item 9).
		log.Fatalf("Failed to set up logging (server.log.format %q): %v", cfg.Server.Log.EffectiveFormat(), err)
	}

	// ADR-112 opt-out rule (item 2): a deprecated alias (an old key renamed to its
	// current insecure_ form) found in this config file gets a warning on EVERY
	// start — never silent. See warnDeprecatedSettingAliases below.
	warnDeprecatedSettingAliases(cfg)
	warnHTTPOnlySettingsUnderGRPC(cfg)

	// ADR-112: decide, once and from the database, whether this boot is an upgraded
	// deployment still inside the file-permission-check grace period, then warn about
	// every insecure_ setting in effect (opt-out rule item 2: on EVERY start, never
	// silent). See resolveADR112BootPosture. Must run before
	// runStartupValidation/enforceKeyFilePermissions, which both read the grace result.
	resolveADR112BootPosture(cfg)

	// Run the file-permission / encryption-key / database-reachability checks that were
	// previously reachable ONLY via the manual `keyorix-server admin validate` CLI subcommand
	// (#330), despite official docs and that command's own help text claiming they run
	// automatically on every boot.
	if err := runStartupValidation(cfg); err != nil {
		log.Fatalf("startup validation: %v", err)
	}

	// Disable core dumps before any key material or decrypted secret value is ever
	// allocated (ADR-098). Narrows, not closes, the memory-zeroization gap: it protects
	// a core file from surviving a crash, not the transient in-memory exposure of a
	// live, healthy process documented alongside #1653's "three unwiped heap copies".
	// This package previously also called mlockall to protect against swap; that was
	// removed (ADR-100) — it pinned RSS well above the shipped Helm chart's default
	// memory limit with no ceiling, and cannot work as intended in a garbage-collected
	// runtime. Swap exposure is now addressed at the deployment level (disable swap on
	// the node / in the container runtime) rather than in-process.
	if err := hardening.ApplyMemoryHardening(); err != nil {
		log.Fatalf("memory hardening: %v", err)
	}

	// Initialize i18n system
	if err := i18n.Initialize(cfg); err != nil {
		log.Fatalf("Failed to initialize i18n system: %v", err)
	}

	// Print startup info
	if cfg.Server.HTTP.Enabled {
		scheme := "http"
		if cfg.Server.HTTP.TLS.Enabled {
			scheme = "https"
		}
		log.Printf("HTTP server will bind %s://%s%s", scheme, cfg.Server.HTTP.ListenAddr(), bindScopeNote(cfg.Server.HTTP.BindHost()))
	} else {
		log.Printf("HTTP server is disabled (check keyorix.yaml)")
	}
	if cfg.Server.GRPC.Enabled {
		log.Printf("gRPC server will bind %s%s", cfg.Server.GRPC.ListenAddr(), bindScopeNote(cfg.Server.GRPC.BindHost()))
	}
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Refuse (or loudly warn about) serving bearer tokens + secret values in cleartext.
	if err := checkTransportTLSPosture(cfg); err != nil {
		log.Fatalf("transport security: %v", err)
	}

	// No-NTP edge devices: warn when the clock is implausible or the TLS
	// certificate window does not contain it (never refuses to start).
	warnClockAndCertificate(cfg)
	go watchClockSteps(ctx, 15*time.Second, realClockSample(), log.Printf)

	// Key-file, secret-file and SCIM-token refusals, in order (bootRefusals below).
	for _, r := range bootRefusals {
		if err := r.check(cfg); err != nil {
			log.Fatalf("%s: %v", r.name, err)
		}
	}

	// ADR-112: security.require_mfa now defaults to true (see config.Load). This is
	// visibility only, not an enforcement gate — logWarnOnImplicitRequireMFADefault.
	logWarnOnImplicitRequireMFADefault(cfg)

	// Mark this process as a live server attached to cfg's database (ADR-108 §B,
	// PR 11) — held for the whole process lifetime, released on shutdown. Lets
	// `keyorix-server admin` commands detect and refuse to run concurrently
	// with a live server (unless the operator passes --force), and the
	// reverse: refuses THIS boot, fast and with a specific message, if an
	// admin command is already mid-operation against the same database,
	// rather than racing it or hanging waiting for it to finish. SHARED, so
	// concurrent server replicas against a shared Postgres database (ADR-039
	// HA) never conflict with each other or with this check; see
	// internal/serverguard's package doc for the full mechanism and its
	// limits. The error message here is exactly what AcquirePresence
	// returns (already specific -- "an admin operation is running against
	// this database; retry when it finishes" -- when that is the cause);
	// this does not re-wrap it in a generic "failed to acquire..." prefix.
	//
	// The transaction-pooler tripwire runs first: with an undeclared
	// transaction-mode pooler the presence lock would be a session lock left
	// on a server connection the pooler shares, and refusing afterwards (in
	// the storage factory) would not release it.
	if err := appstorage.RefuseUndeclaredTransactionPooler(cfg); err != nil {
		if authErr, ok := errors.AsType[*config.PostgresAuthError](err); ok {
			log.Fatalf("%v\n(driver detail, secrets redacted: %s)", err, authErr.Detail())
		}
		log.Fatalf("%v", err)
	}
	// Registered first so it runs last: a lost process-wide lock (presence or
	// single_writer, see awaitShutdown below) ends the process with a failure
	// status after the normal shutdown.
	var lockLost atomic.Bool
	defer func() {
		if lockLost.Load() {
			os.Exit(1)
		}
	}()
	presence, err := serverguard.AcquirePresence(cfg)
	if err != nil {
		if authErr, ok := errors.AsType[*config.PostgresAuthError](err); ok {
			log.Fatalf("%v\n(driver detail, secrets redacted: %s)", err, authErr.Detail())
		}
		log.Fatalf("%v", err)
	}
	defer presence.Release() //nolint:errcheck

	// storage.database.single_writer (docs/specs/single-writer-cache.md):
	// take the holder lock and record this boot as the only writer BEFORE any
	// pool opens, so every connection the server makes carries the session tag
	// the write fence checks. Without the setting, refuse while a single-writer
	// server holds the database and remove a fence an earlier one left.
	var swGuard *solewriter.Guard
	if cfg.Storage.Database.SingleWriter {
		swGuard, err = solewriter.Start(ctx, cfg, solewriter.Options{ExpectOwnPresence: true})
		if err != nil {
			log.Fatalf("single_writer: %v", err)
		}
		defer swGuard.Close()
	} else if err := solewriter.CheckOff(ctx, cfg); err != nil {
		log.Fatalf("%v", err)
	}

	// #G12: construct the core service (and its owned singletons — encryption
	// Service + exclusive DEK flock, SIEM Forwarder + spool, dynamic-secrets-sweep
	// flag) exactly ONCE for the whole process, shared by both the HTTP and gRPC
	// servers. Previously startHTTPServer and startGRPCServer each called
	// initializeCoreService independently: two exclusive DEK flock acquisitions
	// raced (only one could actually win it), the gRPC server's own
	// *encryption.Service was discarded and never Shutdown() (the KEK was never
	// wiped from memory on that path), and two SIEM Forwarder instances
	// independently wrote the same on-disk spool file with no cross-instance
	// coordination.
	coreService, encSvc, err := initializeCoreService(cfg)
	if err != nil {
		log.Fatalf("failed to initialize core service: %v", err)
	}
	// Ensure KEK is wiped from memory on shutdown.
	if encSvc != nil {
		defer encSvc.Shutdown()
	}
	// ADR-112 #2923: hand the require_mfa grace window (if any) to core, which ends it
	// at the first admin MFA enrolment or the 30-day deadline, without a restart.
	armADR112MFAGrace(cfg, coreService)
	// ADR-112: a boot that enforced enable_file_permission_check (checks passed, nothing
	// softened) or require_mfa ratchets this deployment to enforced for that key for good.
	recordADR112Markers(cfg)
	// #G56: flush/close the SIEM audit forwarder (if configured) on shutdown — it
	// queues events in memory (worker.go's Deliver is non-blocking, async), and
	// nothing would otherwise call Close() to drain that queue before the process
	// exits, silently losing whatever was in flight at SIGTERM.
	defer closeAuditForwarder(coreService)
	// OPT-LASTUSED-1: write the coalesced last_used_at / last_seen_at stamps on
	// a graceful stop. Deferred after the servers have drained (defers run after
	// the shutdown wait below) and before swGuard.Close releases the
	// single-writer hold. A crash loses at most one flush interval of stamps.
	defer flushLastUsedOnShutdown(coreService)

	// single_writer: the fence goes on once the security tables exist
	// (migrations ran in initializeCoreService). No fence, no server.
	if swGuard != nil {
		if err := swGuard.InstallFence(ctx); err != nil {
			log.Fatalf("%v (storage.database.single_writer never runs without its write fence)", err)
		}
		if err := swGuard.Settle(ctx); err != nil {
			log.Fatalf("%v", err)
		}
		swGuard.Run(ctx)
		log.Println(swGuard.StartupLine())
	}

	// Record the evaluated license state once at startup (ADR-065), so the
	// entitlement (and any degrade reason) is on the audit record.
	coreService.AuditLicenseState(ctx)

	// ADR-112 opt-out rule (item 2): the start-to-start settings diff. Config has no
	// hot reload, so this is the only place a security-relevant setting changing
	// between two starts ever becomes visible — audits old vs. new value for any
	// difference since the previous start.
	coreService.ReconcileSecurityPostureSnapshot(ctx, securityPostureSnapshot(cfg))

	// Start every background scheduler exactly once, regardless of which of
	// HTTP/gRPC is enabled (#G12) — see startSchedulers' doc comment.
	startSchedulers(ctx, cfg, coreService)

	var wg sync.WaitGroup

	// Start HTTP server
	if cfg.Server.HTTP.Enabled {
		wg.Go(func() {
			if err := startHTTPServer(ctx, cfg, coreService); err != nil {
				// A startup failure (router/TLS/listener-bind, before this ever served
				// anything) is fatal: the alternative was logging it and falling through
				// to <-sigChan, which never arrives for a boot that failed this early --
				// the process stayed alive indefinitely with no listener bound (RELEASE-QA
				// finding: `docker ps`/`kubectl get pods` shows "Up"/"Running" while
				// nothing answers). A server.Shutdown() timeout at the end of an
				// ALREADY-intentional shutdown is not wrapped in errHTTPServerFailedToStart
				// and keeps just logging, unchanged.
				if errors.Is(err, errHTTPServerFailedToStart) {
					log.Fatalf("HTTP server error: %v", err)
				}
				log.Printf("HTTP server error: %v", err)
			}
		})
	}

	// Start gRPC server
	if cfg.Server.GRPC.Enabled {
		wg.Go(func() {
			// Every error startGRPCServer can return is a genuine startup failure
			// (its own graceful-shutdown path always returns nil) -- same fatal
			// reasoning as the HTTP server above, no sentinel needed to disambiguate.
			if err := startGRPCServer(ctx, cfg, coreService); err != nil {
				log.Fatalf("gRPC server error: %v", err)
			}
		})
	}

	// Wait for a shutdown signal, or the loss of a lock that guards the whole
	// process (lock_loss.go): the presence lock's or the single_writer holder
	// lock's backend died (terminated, PostgreSQL or PgBouncer restarted, a
	// failover, a pooler timeout), so an admin command or a second single
	// writer could now start beside this server. Stop serving rather than run
	// unguarded; the supervisor restarts the process.
	if awaitShutdown(sigChan, presence.Lost(), swGuard.Lost()) != "" {
		lockLost.Store(true)
	}

	// Cancel context to signal shutdown
	cancel()

	// Wait for all servers to shutdown
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-done:
		log.Println("All servers shut down gracefully")
	case <-time.After(30 * time.Second):
		log.Println("Shutdown timeout exceeded, forcing exit")
	}
}

// schedulerStarts is every background job, in start order (startSchedulers).
// A new job is one scheduler_<job>.go file plus one line here.
var schedulerStarts = []schedulerStart{
	startAnomalyDetectionScheduler,
	startRetentionPurgeScheduler,
	startDataRetentionScheduler,
	startRotationReminderScheduler,
	startExpiryReminderScheduler,
	startCertificateExpiryScheduler,
	startLicenseExpiryScheduler,
	startAutoRotationScheduler,
	startComplianceDigestScheduler,
	startRecertificationScheduler,
	startEvidenceDeliveryScheduler,
	startAuditCheckpointScheduler,
	startJITAccessExpiryScheduler,
	startDynamicSecretSweepScheduler,
	startLoginAttemptPruneScheduler,
	startAuditOwedBackfillScheduler,
	startMFAStepUpGrantPruneScheduler,
	startRecoverAdminAlertScheduler,
	startBreakGlassReviewReminderScheduler,
	startReadQuotaAlertsScheduler,
}

// coreWiringSteps is every core wiring step, in the order initializeCoreService
// runs them after the storage, encryption and core service exist. Order matters:
// the encryptor is wired (and checked) before the notification-URL backfill, and
// the signing keys before DefaultIntegrations. A new step is one function in its
// own wire_<domain>.go file plus one line here.
var coreWiringSteps = []coreWiringStep{
	wireSoftDeleteRetention,
	wireAuditSkipReads,
	wireRecoverAdminMode,
	wireAuditDurabilityNotice,
	wireAccessLogStallNotice,
	wireSCIMJITNotice,
	wireRBACPermissionCatalog,
	wireAlertsWriteRole,
	wireBootstrapToken,
	wireSecretEncryption,
	wireNotificationURLBackfill,
	wireDefaultIntegrations,
	wirePasswordPolicy,
	wireSecretValuePolicy,
	wireMaxSecretSize,
	wireSecretNamePolicy,
	wireAuthRateLimitFallback,
	wireOneTimePasswordExpiry,
	wireLoginLockout,
	wireSIEMForwarder,
	wireNotificationChannels,
	wireEvidenceTargets,
	wireMembership,
	wireSetupTokenTTL,
	wireSessionTTLs,
	wireDynamicSecretsStep,
	wireBreakGlass,
	wireDualControl,
	wireClassification,
	wireRetentionPolicy,
	wireRecertificationCadence,
	wireCredentialDelivery,
	wireOIDCFederation,
	wireAuditHighWaterWitness,
	wireWebAuthn,
	wireLicenseGate,
}

// bootRefusals run in this order after the transport-security and clock checks and
// before any storage is opened; the first error stops the boot with
// "<name>: <error>". A new boot refusal is one function in its own file plus one
// line here.
var bootRefusals = []struct {
	name  string
	check func(*config.Config) error
}{
	// Refuse (or warn) when key material on disk is readable beyond its owner.
	{"key file security", enforceKeyFilePermissions},
	// Same policy for the files behind KEYORIX_*_FILE secrets (DB password, master
	// password, bootstrap token, ...).
	{"secret file security", enforceSecretFilePermissions},
	// #3397: refuse a SCIM bearer token that is obviously not random (ADR-112
	// upgrade grace for the new checks; the length floor always refuses).
	{"scim", enforceSCIMTokenStrength},
	// Refuse to start if the installed key files are a PARTIAL set (ADR-112,
	// follow-up from #2400). Unconditional, like the permission check above: a
	// broken key set is not a "weaker but working" state to warn about. The
	// same call also applies a best-effort same-group mtime heuristic, which is
	// deliberately not claimed as a mixed-generation guarantee — see
	// keyfiles.VerifyKeySetConsistency and #2900.
	{"key file consistency", verifyKeyFileSetConsistency},
}
