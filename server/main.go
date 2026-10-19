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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/audit/siem"
	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/evidencesink"
	"github.com/keyorixhq/keyorix/internal/hardening"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/logging"
	"github.com/keyorixhq/keyorix/internal/netutil"
	"github.com/keyorixhq/keyorix/internal/notary"
	"github.com/keyorixhq/keyorix/internal/notifychan"
	"github.com/keyorixhq/keyorix/internal/rotation"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/solewriter"
	"github.com/keyorixhq/keyorix/internal/startup"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/tlsmetrics"
	"github.com/keyorixhq/keyorix/internal/tlsreload"
	"github.com/keyorixhq/keyorix/internal/version"
	"github.com/keyorixhq/keyorix/pkg/trust"
	"github.com/keyorixhq/keyorix/server/admin"
	"github.com/keyorixhq/keyorix/server/grpc"
	httpServer "github.com/keyorixhq/keyorix/server/http"
	"github.com/keyorixhq/keyorix/server/middleware"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

// masterPassphraseSource holds --passphrase-fd/--passphrase-file/--passphrase-stdin
// once main() parses flags. Zero value (all unset) makes initializeEncryption fall
// back to KEYORIX_MASTER_PASSWORD, matching this binary's historical behavior --
// including under `go test`, which never calls main() and so never touches this var.
var masterPassphraseSource crypto.PassphraseSource

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
	// previously reachable ONLY via the manual `keyorix system validate` CLI subcommand
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

	// Refuse (or warn) when key material on disk is readable beyond its owner.
	if err := enforceKeyFilePermissions(cfg); err != nil {
		log.Fatalf("key file security: %v", err)
	}

	// Same policy for the files behind KEYORIX_*_FILE secrets (DB password, master
	// password, bootstrap token, ...).
	if err := enforceSecretFilePermissions(cfg); err != nil {
		log.Fatalf("secret file security: %v", err)
	}

	// #3397: refuse a SCIM bearer token that is obviously not random (ADR-112
	// upgrade grace for the new checks; the length floor always refuses).
	if err := enforceSCIMTokenStrength(cfg); err != nil {
		log.Fatalf("scim: %v", err)
	}

	// Refuse to start if the installed key files are a PARTIAL set (ADR-112,
	// follow-up from #2400). Unconditional, like the permission check above: a
	// broken key set is not a "weaker but working" state to warn about. The
	// same call also applies a best-effort same-group mtime heuristic, which is
	// deliberately not claimed as a mixed-generation guarantee — see
	// keyfiles.VerifyKeySetConsistency and #2900.
	if err := verifyKeyFileSetConsistency(cfg); err != nil {
		log.Fatalf("key file consistency: %v", err)
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

// Scheduler advisory-lock keys (ADR-039) — arbitrary distinct constants,
// namespaced to each background job, so on PostgreSQL only one replica runs a
// given scheduler per tick. Distinct from the audit-chain key (0x4B455941_55444954).
const (
	schedLockAnomaly           int64 = 0x4B455953_414E4F4D // "KEYSANOM"
	schedLockPurge             int64 = 0x4B455953_50555247 // "KEYSPURG"
	schedLockDynamicSweep      int64 = 0x4B455953_44594E53 // "KEYSDYNS"
	schedLockLoginPrune        int64 = 0x4B455953_4C474E50 // "KEYSLGNP"
	schedLockRotationRmdr      int64 = 0x4B455953_524F5452 // "KEYSROTR"
	schedLockExpiryRmdr        int64 = 0x4B455953_45585052 // "KEYSEXPR"
	schedLockCertExpiry        int64 = 0x4B455953_43455254 // "KEYSCERT"
	schedLockAutoRotate        int64 = 0x4B455953_4155544F // "KEYSAUTO"
	schedLockAuditCkpt         int64 = 0x4B455953_41434B50 // "KEYSACKP"
	schedLockJITExpiry         int64 = 0x4B455953_4A495445 // "KEYSJITE"
	schedLockRetention         int64 = 0x4B455953_52455445 // "KEYSRETE"
	schedLockEvidence          int64 = 0x4B455953_45564944 // "KEYSEVID"
	schedLockRecertify         int64 = 0x4B455953_52454354 // "KEYSRECT"
	schedLockDigest            int64 = 0x4B455953_44494753 // "KEYSDIGS"
	schedLockLicenseExp        int64 = 0x4B455953_4C494345 // "KEYSLICE"
	schedLockReadQuota         int64 = 0x4B455953_52445154 // "KEYSRDQT"
	schedLockMFAGrantPrune     int64 = 0x4B455953_4D464147 // "KEYSMFAG"
	schedLockRecoverAdminAlert int64 = 0x4B455953_52435652 // "KEYSRCVR"
	schedLockBreakGlassReview  int64 = 0x4B455953_42475256 // "KEYSBGRV"
	schedLockOwedAudit         int64 = 0x4B455953_4F574544 // "KEYSOWED"
)

// initializeEncryption sources the KEK per the configured key provider (ADR-038)
// and returns an initialized encryption.Service. If encryption is disabled in
// config, it returns nil without error. For the default "password" provider it
// requires a master passphrase, sourced per ADR-099 (masterPassphraseSource --
// --passphrase-fd, then --passphrase-file, then --passphrase-stdin, then
// KEYORIX_MASTER_PASSWORD as the weakest fallback); for the "file"/"env"
// providers the KEK comes from key material elsewhere, so no passphrase is
// needed. auditSink, if non-nil, is wired before Initialize so that a
// key_provider.fallbacks chain actually downgrading KEK strength on THIS boot
// (not just one the config permits) is recorded as a queryable audit event
// rather than only a log line — pass store.LogAuditEvent once storage is
// available; nil is fine (tests, or contexts without a live audit trail) and
// falls back to logging only.
func initializeEncryption(cfg *config.Config, auditSink encryption.AuditSink) (*encryption.Service, error) {
	if !cfg.Storage.Encryption.Enabled {
		encryption.RegisterDisabledMetrics()
		return nil, nil
	}

	providerType := cfg.Storage.Encryption.KeyProvider.Type
	var passphrase string
	if providerType == "" || providerType == "password" {
		passphraseBytes, err := crypto.ResolvePassphrase(masterPassphraseSource, "KEYORIX_MASTER_PASSWORD")
		if err != nil {
			return nil, fmt.Errorf(
				"encryption is enabled with the password key provider but no master passphrase is "+
					"available (%w); set KEYORIX_MASTER_PASSWORD, pass --passphrase-fd/--passphrase-file/"+
					"--passphrase-stdin, or configure storage.encryption.key_provider (file/env/aws-kms)", err)
		}
		defer crypto.WipeBytes(passphraseBytes)
		passphrase = string(passphraseBytes)
	}

	// Always ".". An absolute dek_path/salt_path is reconciled by
	// NewKeyManager (normalizeKeyPaths), which is where every other
	// encryption.NewService caller benefits from it too -- the six CLI call
	// sites included, so `keyorix encryption ...` can operate on the same key
	// files this server just created.
	//
	// This previously set baseDir="" for an absolute DEKPath, meaning "the
	// path is self-contained, no base-dir restriction". No securefiles
	// primitive implements that convention: isPathInsideBase resolves "" to
	// the working directory and rejected the key file as outside it, so a
	// deployment configuring an absolute key path could never complete
	// first-boot key generation.
	baseDir := "."
	svc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	encryption.RegisterMetrics(svc)
	if auditSink != nil {
		svc.SetAuditSink(auditSink)
	}
	// Acquire the exclusive DEK lock BEFORE Initialize, not after. Initialize
	// performs first-boot key generation (ensureSaltExists/ensureWrappedDEKExists
	// in keymanager_lifecycle.go), which is an unlocked check-then-write: two
	// processes racing a shared, fresh key directory (e.g. two HA replicas'
	// simultaneous first boot) could each pass the not-exists check before
	// either wrote, silently clobbering or interleaving each other's salt/DEK
	// files. That failure is not even immediate — it surfaces as a delayed,
	// confusing "wrong passphrase or corrupted key file" on a LATER restart,
	// not a clear error at the moment of the actual race. Holding the exclusive
	// DEK lock — the same lock this server keeps for its whole lifetime anyway,
	// so DEK rotation (a separate CLI process) can never promote a new DEK
	// while this server still has the old one cached in memory (#92) — across
	// the ENTIRE first-boot sequence closes the race at its root: whichever
	// process wins the flock proceeds, the other is refused immediately with a
	// clear lock-contention error, before it ever touches a key file. Refuses
	// to start if another live holder (another server instance, or an
	// in-progress rotation) already has it.
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return nil, fmt.Errorf("failed to acquire the encryption key lock: %w", err)
	}
	// Recover any interrupted DEK-sweep rotation BEFORE Initialize, so Initialize loads the
	// correct (possibly just-promoted) active DEK. Runs under the exclusive key lock acquired
	// above. For a local backend it consults the DB's redo marker to decide whether to promote
	// the pending DEK (a rotation that committed its re-encryption sweep but crashed before the
	// dek.key file rename) or discard a stray pending file; for remote storage there is no
	// local sweep, so it falls back to the leftover-cleanup behavior.
	var keyDB *gorm.DB // kept for the DEK epoch guard below
	if cfg.Storage.Type == "remote" {
		svc.CleanPendingDEK()
	} else {
		recoverDB, derr := appstorage.OpenGormDB(cfg)
		if derr != nil {
			return nil, fmt.Errorf("failed to open database for DEK-rotation crash recovery: %w", derr)
		}
		if rerr := svc.RecoverInterruptedRotation(recoverDB); rerr != nil {
			closeGormDB(recoverDB)
			return nil, fmt.Errorf("DEK-rotation crash recovery failed: %w", rerr)
		}
		keyDB = recoverDB
	}
	if err := svc.Initialize(passphrase); err != nil {
		if keyDB != nil {
			closeGormDB(keyDB)
		}
		if providerType == "" || providerType == "password" {
			// Name the source (BOOT-REFUSALS-1 item 7): with several ways to pass the
			// passphrase, "wrong passphrase" alone does not say which one was read.
			return nil, fmt.Errorf("KEK derivation from the master passphrase read from %s failed: %w", masterPassphraseSource.Describe("KEYORIX_MASTER_PASSWORD"), err)
		}
		return nil, fmt.Errorf("KEK from key provider %q failed: %w", providerType, err)
	}
	// Cross-replica DEK epoch (#3337, internal/encryption/dek_epoch.go): refuse to
	// start when this server's DEK is not the DEK the database is encrypted under
	// (the DEK was rotated on another host and this host still has the old
	// dek.key), and refuse encrypted writes later while a rotation fences them.
	// PostgreSQL only: the guard keeps keyDB (one connection) and closes it on
	// Shutdown. On SQLite it is a no-op and keyDB is closed here.
	if keyDB != nil {
		if sqlDB, e := keyDB.DB(); e == nil {
			sqlDB.SetMaxOpenConns(1)
			sqlDB.SetMaxIdleConns(1)
		}
		if err := svc.StartDEKEpochGuard(keyDB, func() { closeGormDB(keyDB) }); err != nil {
			closeGormDB(keyDB)
			svc.Shutdown()
			return nil, fmt.Errorf("refusing to start: %w", err)
		}
		if !svc.DEKEpochGuardRunning() {
			closeGormDB(keyDB)
		}
	}

	kekSource := providerType
	if kekSource == "" {
		kekSource = "password"
	}
	log.Printf("Encryption initialised — KEK source: %s, key version: %s", kekSource, svc.GetKeyVersion())
	return svc, nil
}

// loadCertPool reads a PEM bundle from path and returns a cert pool of its
// certificates (the TSA trust anchor for verifying checkpoint anchors).
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := secretenv.ReadRegularFile("CA bundle", path) // operator-configured trusted CA bundle path; a FIFO is refused, not waited on
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}

// loadLicenseToken reads the operator-configured license file. An unset path, or a
// file that cannot be read (missing, unreadable, or not a regular file -- a FIFO
// must not hang the boot), yields "" and a warning: the server runs the community
// baseline.
func loadLicenseToken(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	b, err := secretenv.ReadRegularFile("license file", p) // operator-configured license path; a FIFO is refused, not waited on
	if err != nil {
		log.Printf("WARNING: license file %q unreadable: %v (running community baseline)", p, err)
		return ""
	}
	return strings.TrimSpace(string(b))
}

func initializeCoreService(cfg *config.Config) (*core.KeyorixCore, *encryption.Service, error) { // NOSONAR -- cognitive complexity 159, suppress go:S3776
	// #G-blank-storage-default: mirrors main()'s own default-application above —
	// a test or any other caller that builds a *config.Config by hand and skips
	// straight to this function bypassed that default too. This is the server's
	// own boot path (the one caller allowed to treat a blank storage.type as
	// "local"; see internal/storage/factory.go's CreateStorage), so apply the
	// same default here, before the Validate() call immediately below rejects a
	// blank type. This does NOT set a default for the CLI: this function lives
	// in server/main.go's package main and is never called from CLI code.
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}

	// #1475: mirrors main()'s own cfg.Validate() call above — a test or any other
	// caller that builds a *config.Config by hand and skips straight to this
	// function bypassed schema/sanity validation entirely, letting fixtures encode
	// configs production boot would refuse (e.g. autocert enabled with no domains).
	// Enforcing it here means "this function accepted the config" is only ever true
	// for a config production would actually boot with.
	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid configuration: %w", err)
	}
	// Use storage factory to support SQLite, PostgreSQL, and remote storage
	factory := appstorage.NewStorageFactory()
	store, err := factory.CreateStorage(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	encSvc, err := initializeEncryption(cfg, store.LogAuditEvent)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}

	coreService := core.NewKeyorixCore(store)
	// The configured soft-delete window, wired where the service is built (not in an
	// unrelated wireX helper) so every transport and job that shows or applies a
	// purge date (core.SecretPurgeAt) sees soft_delete.retention_days, never core's
	// 30-day library default.
	coreService.SetSoftDeleteRetentionDays(cfg.SoftDelete.GetRetentionDays())

	// ADR-112 Amendment 4: storage.database.insecure_audit_skip_reads. Set before
	// the server serves anything. The every-start WARNING comes from the
	// registry (warnInsecureSettingsInEffect); the every-start audit event is
	// written here so the chain itself records the window reads went unaudited.
	coreService.SetInsecureAuditSkipReads(cfg.Storage.Database.InsecureAuditSkipReads)
	if cfg.Storage.Database.InsecureAuditSkipReads {
		auditReadsSkippedStartup(store)
	}

	// keyless mode (docs/design-b2-recover-admin.md §5): flagged loudly and
	// repeatedly wherever an operator or auditor would look -- a startup
	// warning EVERY boot (not just the first), a boolean in /system/info
	// (server/http/handlers/system.go), and an audit event at every startup
	// while it's enabled, so the tamper-evident chain itself carries a
	// durable, repeated record that this install has been running in the
	// weaker mode -- an auditor reading the chain doesn't have to trust a
	// point-in-time config dump.
	if cfg.Security.RecoverAdmin.KeylessMode {
		log.Printf("WARNING: security.recover_admin.insecure_keyless_admin_recovery is ENABLED -- `keyorix-server admin recover-admin` " +
			"can restore ANY admin account on HOST ACCESS ALONE, with no recovery key required or checked. This " +
			"collapses host access and admin access into one trust boundary. Intended for labs/demo use only; " +
			"disable it for any real deployment.")
		auditKeylessModeStartup(store)
	} else {
		warnIfRecoveryKeyMissing(store)
	}

	// Audit durability (ADR-112 Amendment 3, docs/specs/fast-audit-mode.md):
	// one INFO line every start with the effective level and its meaning.
	// Both levels are baseline, so this is never a WARNING and writes no
	// per-start audit event; a level change between two starts is audited by
	// the start-to-start settings diff (config.TrackedSettings).
	logAuditDurability(cfg)

	// Access-log stall mode (server.access_log.on_sink_stall): always reported at
	// startup so the effective mode is visible; "drop" is a WARNING.
	if mode := cfg.Server.AccessLog.EffectiveOnSinkStall(); mode == config.AccessLogOnSinkStallDrop {
		log.Printf("WARNING: %s", startup.AccessLogDropModeWarning)
	} else {
		log.Printf("access log: server.access_log.on_sink_stall=%s (no line is dropped; requests wait for a stalled sink)", mode)
	}

	// Top up the canonical RBAC permission catalog (ADR-044): adds any permission
	// introduced in a later release to an already-initialised install, granting it to
	// its baseline roles. No-op pre-bootstrap and best-effort (never blocks startup).
	if err := coreService.ReconcileRBACPermissions(context.Background()); err != nil {
		log.Printf("RBAC permission reconciliation: %v (continuing)", err)
	}

	// F1 (ADR-110 follow-up): seed the alert_operator built-in role on an
	// install that predates it, and grant alerts.write, once, to every role that
	// already holds system.write. No-op pre-bootstrap and best-effort (never
	// blocks startup); a no-op on every subsequent restart once run.
	if err := coreService.ReconcileAlertsWriteRole(context.Background()); err != nil {
		log.Printf("alerts.write role reconciliation: %v (continuing)", err)
	}

	// Wire the bootstrap token that gates POST /system/init. Prefer an operator-set
	// KEYORIX_BOOTSTRAP_TOKEN (for automation); otherwise generate one and, while the
	// install is still empty, log it so the operator can complete first-boot init. This
	// closes the unauthenticated, first-caller-wins admin-claim race on a fresh, reachable
	// instance.
	bootstrapToken, btErr := resolveBootstrapToken()
	if btErr != nil {
		// Both KEYORIX_BOOTSTRAP_TOKEN and _FILE set, or the file unreadable: do not
		// fall through to a generated token the operator never asked for.
		return nil, nil, fmt.Errorf("bootstrap token: %w", btErr)
	}
	bootstrapTokenGenerated := false
	if bootstrapToken == "" {
		if t, gerr := core.GenerateBootstrapToken(); gerr == nil {
			bootstrapToken, bootstrapTokenGenerated = t, true
		} else {
			log.Printf("failed to generate a bootstrap token: %v (API system-init will be disabled)", gerr)
		}
	}
	coreService.SetBootstrapToken(bootstrapToken)
	// Let core token-revocation paths (e.g. revoking PATs on a password change) evict the
	// HTTP auth cache immediately, rather than waiting out the positive-cache TTL.
	coreService.SetTokenCacheInvalidator(middleware.InvalidateTokenCacheByHash)
	// Let a transition toward active (ReactivateUser) clear a STALE existing cache
	// entry without ever writing a new negative one for a never-cached credential —
	// see setAccountState's "becoming active" branch.
	coreService.SetTokenCacheClearer(middleware.ClearTokenCacheIfCached)
	// Fail-closed fallback for TransitionMachineIdentity when it can't determine exactly
	// which credential hashes to evict individually (see evictMachineIdentityCacheOrFlush).
	coreService.SetMachineTokenCacheFlusher(middleware.InvalidateAllMachineTokenCache)
	if needs, berr := coreService.SystemNeedsBootstrap(context.Background()); berr == nil && needs && bootstrapToken != "" {
		if bootstrapTokenGenerated {
			masked := bootstrapToken[:8] + "***" + bootstrapToken[len(bootstrapToken)-4:]
			log.Print(generatedBootstrapTokenHint(masked))
		} else {
			log.Printf("system not initialised — run `keyorix system init` with the configured KEYORIX_BOOTSTRAP_TOKEN")
		}
	}

	if encSvc != nil {
		// Wire the initialised encryption service for secret VALUES at rest (ADR-004
		// envelope encryption). Without this, storage.encryption.enabled would derive a
		// KEK but never actually encrypt any secret value — every secret would persist as
		// plaintext. Fail closed immediately after wiring: if encryption was configured
		// but did not actually engage, refuse to start rather than silently store
		// plaintext in a secrets manager.
		coreService.SetSecretValueEncryptor(encSvc)
		if !coreService.SecretValueEncryptionActive() {
			return nil, nil, fmt.Errorf("storage.encryption is enabled but secret-value encryption did not engage (encryptor not initialised) — refusing to start to avoid storing secrets in plaintext")
		}
		// Wire the same initialised service for reversibly-encrypted auth secrets (the
		// TOTP MFA secret, which cannot be hashed).
		coreService.SetAuthEncryptor(encSvc)
		// Derive the audit-checkpoint signing key from the DEK (ADR-029) so signed
		// checkpoints — and on-box truncation detection — are available. Unavailable
		// when encryption is off (no DEK).
		if key, keyVer, ok := encSvc.AuditCheckpointKey(); ok {
			coreService.SetAuditCheckpointKey(key, keyVer)
			// Restore the in-memory anti-rollback watermark from the persisted high-water
			// mark so a process restart cannot reset it to zero (ADR-029).
			coreService.SeedAuditWatermark(context.Background())
		}
		// Derive the evidence-pack signing key from the KEK (not the DEK — #268, so a
		// routine DEK rotation does not invalidate previously-signed packs) so
		// scheduled evidence exports are signed (and verifiable). Unavailable when
		// encryption is off.
		if key, keyVer, ok := encSvc.EvidenceSignKey(); ok {
			coreService.SetEvidenceSignKey(key, keyVer)
		}
	}

	// #2433: bring every NotificationChannel row's webhook/Slack/Teams URL (the
	// bearer credential) into the encrypted, self-describing url_enc/url_meta
	// columns -- a real envelope when encSvc is wired and enabled, an
	// explicitly-tagged plaintext passthrough otherwise. Local-storage-only
	// (notification channels have no remote-storage implementation at all).
	//
	// #2468: this FAILS STARTUP rather than logging and continuing, and that
	// choice is deliberate over the "it is idempotent, a later restart will
	// retry" alternative. The migration now has a second, recurring job besides
	// the one-time legacy backfill: upgrading a plaintext-passthrough row the
	// first time encryption is enabled (see its own doc comment). A permanently
	// failing run of THAT job leaves webhook bearer credentials in plaintext at
	// rest on an install that has explicitly configured encryption -- and
	// leaves them readable and working, so nothing else ever surfaces it. That
	// is precisely the condition the SecretValueEncryptionActive check a few
	// lines above refuses to start on, for the same reason.
	if ls, ok := store.(*localstore.LocalStorage); ok {
		var encryptor ports.EncryptionProvider
		if encSvc != nil {
			encryptor = encSvc
		}
		n, merr := ls.MigrateNotificationChannelURLsToEncrypted(context.Background(), encryptor)
		if merr != nil {
			return nil, nil, fmt.Errorf("notification channel URL encryption backfill failed: %w -- refusing to start rather than leave a webhook credential unencrypted at rest", merr)
		}
		if n > 0 {
			log.Printf("notification channel URL encryption backfill: migrated %d channel(s)", n)
		}
	}

	// Wire every ADR-109 integration that has its own wireXxx helper
	// (docs/adr-109-core-depends-on-interfaces.md, steps 1-4): external-notary
	// checkpoint anchoring (ADR-029), human SSO (OIDC + SAML), backend rotation,
	// dynamic secrets, and Keyorix Connect. Encryption (step 5) is wired
	// separately, above this call — see DefaultIntegrations' own doc comment
	// for why its wiring call site was not moved here too.
	if err := DefaultIntegrations(cfg, coreService); err != nil {
		return nil, nil, err
	}

	// Apply the configured password policy, merging any rule the operator didn't
	// explicitly set onto the core's conservative built-in defaults (ADR-025) —
	// #G37: a PARTIAL password_policy block (e.g. just reject_common_passwords)
	// must not silently zero out every other rule it didn't mention.
	coreService.SetPasswordPolicy(resolvePasswordPolicy(cfg.PasswordPolicy))

	// Apply the optional secret-value quality gate (reject weak/placeholder values).
	if svp := cfg.SecretValuePolicy; svp.Enabled {
		coreService.SetSecretValuePolicy(core.SecretValuePolicy{
			Enabled:       true,
			MinLength:     svp.MinLength,
			RejectCommon:  svp.RejectCommon,
			ExtraDenylist: svp.ExtraDenylist,
		})
		log.Printf("Secret-value policy enabled (min_length=%d, reject_common=%t, denylist=%d)",
			svp.MinLength, svp.RejectCommon, len(svp.ExtraDenylist))
	}

	// Apply the maximum secret VALUE size (bytes) — unlike the quality gate above,
	// this is always applied (not gated behind an Enabled flag): cfg.Secrets.Limits.
	// MaxSecretSize is already defaulted and ceiling-checked by cfg.Validate(), so
	// there is always a real, valid value to set here.
	coreService.SetMaxSecretSize(cfg.Secrets.Limits.MaxSecretSize)

	// Apply the optional secret naming convention (regex / max-length on names).
	if snp := cfg.SecretNamePolicy; snp.Enabled {
		if err := coreService.SetSecretNamePolicy(core.SecretNamePolicy{
			Enabled:   true,
			Pattern:   snp.Pattern,
			MaxLength: snp.MaxLength,
		}); err != nil {
			log.Fatalf("Invalid secret_name_policy: %v", err)
		}
		log.Printf("Secret-name policy enabled (pattern=%q, max_length=%d)", snp.Pattern, snp.MaxLength)
	}

	// The auth rate limits' in-memory fallback is per process; divide its limits
	// by the replicas sharing the budgets (ADR-040 amendment, AUTH-AUDIT-1).
	coreService.SetAuthRateLimitFallbackReplicas(cfg.Security.AuthRateLimitFallback.GetReplicas())
	log.Printf("Auth rate-limit storage fallback: limits divided by %d replica(s)", cfg.Security.AuthRateLimitFallback.GetReplicas())

	// Admin-created one-time passwords expire (OTP-EXPIRY-1); the recover-admin
	// password's lifetime is read by that command itself, from the same section.
	coreService.SetOneTimePasswordExpiry(cfg.Security.GetOneTimePasswordExpiry())

	// Apply per-account login lockout (brute-force protection, distinct from and
	// complementary to the per-IP rate limiter, which distributed guessing can evade).
	// Enabled BY DEFAULT — a secrets-manager login must resist online guessing out of
	// the box; set login_lockout.insecure_disable_login_lockout to opt out.
	if ll := cfg.Security.LoginLockout; !ll.Disabled {
		coreService.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
			Enabled:      true,
			MaxAttempts:  ll.GetMaxAttempts(),
			Window:       ll.GetWindow(),
			BaseCooldown: ll.GetBaseCooldown(),
			MaxCooldown:  ll.GetMaxCooldown(),
		})
		log.Printf("Per-account login lockout enabled (max_attempts=%d, window=%s, base_cooldown=%s, max_cooldown=%s)",
			ll.GetMaxAttempts(), ll.GetWindow(), ll.GetBaseCooldown(), ll.GetMaxCooldown())
	} else {
		log.Printf("WARNING: per-account login lockout is DISABLED — only the per-IP rate limiter throttles password guessing, which distributed/botnet guessing against a single account can evade")
	}

	// Wire native SIEM audit forwarding if configured. New returns (nil, nil)
	// when disabled, so SetAuditForwarder(nil) keeps forwarding off.
	if sc := cfg.Audit.SIEM; sc.Enabled {
		forwarder, ferr := siem.New(siem.Config{
			Enabled:                   sc.Enabled,
			Provider:                  siem.Provider(sc.Provider),
			Endpoint:                  sc.Endpoint,
			Token:                     sc.GetToken(),
			InsecureSkipVerify:        sc.InsecureSkipVerify,
			SpoolDir:                  sc.SpoolDir,
			AllowPrivateNetworkTarget: sc.AllowPrivateNetworkTarget,
			AllowInsecureTransport:    sc.AllowInsecureTransport,
		})
		if ferr != nil {
			return nil, nil, fmt.Errorf("failed to init SIEM audit forwarder: %w", ferr)
		}
		coreService.SetAuditForwarder(forwarder)
		log.Printf("SIEM audit forwarding enabled (provider=%s)", sc.Provider)
	}

	// Wire external notification channels if configured.
	//
	// #391: two distinct fan-out sets are built, not one. broadcastSinks (every
	// enabled channel) backs the deployment-wide, aggregate notifications
	// (compliance digest, auto-rotation-failure summary) — those are genuinely
	// relevant to the whole deployment's ops audience. recipientSinks (only
	// channels that can address a single user — currently email) backs every
	// per-user/per-project notification (secret shared, share revoked, ownership
	// transferred, access requested, anomaly alert, break-glass activation, …).
	// Slack/Teams/webhook are deliberately excluded from recipientSinks: they are
	// one fixed destination an operator configures, with no per-user chat-identity
	// mapping in this codebase to target a specific recipient, so routing a
	// per-user event there would broadcast it to everyone with channel visibility
	// regardless of project membership or secret access. See
	// internal/core/notifications.go and internal/core/service.go.
	var broadcastSinks []core.NotificationSink
	var recipientSinks []core.NotificationSink
	if wc := cfg.Notifications.Webhook; wc.Enabled {
		sink, werr := notifychan.NewWebhook(notifychan.WebhookConfig{
			Endpoint:                  wc.Endpoint,
			Token:                     wc.GetToken(),
			InsecureSkipVerify:        wc.InsecureSkipVerify,
			AllowPrivateNetworkTarget: wc.AllowPrivateNetworkTarget,
			AllowInsecureTransport:    wc.AllowInsecureTransport,
			SigningSecret:             wc.GetSigningSecret(),
		})
		if werr != nil {
			return nil, nil, fmt.Errorf("failed to init notification webhook channel: %w", werr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		log.Printf("Notification webhook channel enabled (endpoint=%s)", wc.Endpoint)
	}
	if ec := cfg.Notifications.Email; ec.Enabled {
		sink, eerr := notifychan.NewEmail(notifychan.EmailConfig{
			Host:        ec.Host,
			Port:        ec.Port,
			Username:    ec.Username,
			Password:    ec.GetPassword(),
			From:        ec.From,
			TLS:         ec.TLS,
			BroadcastTo: ec.BroadcastTo,
		})
		if eerr != nil {
			return nil, nil, fmt.Errorf("failed to init notification email channel: %w", eerr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		recipientSinks = append(recipientSinks, sink)
		log.Printf("Notification email channel enabled (host=%s)", ec.Host)
	}
	if cfg.Notifications.Slack.Enabled {
		sink, serr := notifychan.NewChat(notifychan.ChatConfig{Kind: notifychan.ChatSlack, WebhookURL: cfg.Notifications.GetSlackWebhookURL()})
		if serr != nil {
			return nil, nil, fmt.Errorf("failed to init Slack notification channel: %w", serr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		log.Printf("Notification Slack channel enabled")
	}
	if cfg.Notifications.Teams.Enabled {
		sink, terr := notifychan.NewChat(notifychan.ChatConfig{Kind: notifychan.ChatTeams, WebhookURL: cfg.Notifications.GetTeamsWebhookURL()})
		if terr != nil {
			return nil, nil, fmt.Errorf("failed to init Teams notification channel: %w", terr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		log.Printf("Notification Teams channel enabled")
	}
	// #221: email-only, with no email.broadcast_to configured, has no destination
	// for a deployment-wide broadcast (compliance digest, auto-rotation-failure
	// alert) to route to — it will keep no-op'ing every time one fires. Warn at
	// startup rather than let an operator discover it only from the (also newly
	// added, #221) dropped-delivery metric/log after the fact.
	if cfg.Notifications.Email.Enabled && cfg.Notifications.Email.BroadcastTo == "" &&
		!cfg.Notifications.Webhook.Enabled && !cfg.Notifications.Slack.Enabled && !cfg.Notifications.Teams.Enabled {
		log.Printf("WARNING: notifications.email is the only enabled notification channel and notifications.email.broadcast_to is not set — the compliance digest and auto-rotation-failure alerts have no destination to broadcast to and will silently no-op every time they fire; set notifications.email.broadcast_to to an admin/ops address to receive them")
	}
	if sink := notifychan.NewMulti(broadcastSinks...); sink != nil {
		coreService.SetNotificationSink(sink)
	}
	if sink := notifychan.NewMulti(recipientSinks...); sink != nil {
		coreService.SetRecipientNotificationSink(sink)
	}

	// Wire any off-box evidence targets (webhook and/or S3-compatible object store),
	// so the scheduled evidence pack is delivered off-box in addition to (or instead
	// of) a local dir. When both are configured the pack fans out to both.
	var evidenceTargets []evidencesink.Forwarder
	if ew := cfg.EvidenceDelivery.Webhook; ew.Enabled {
		fwd, ferr := evidencesink.NewWebhook(evidencesink.WebhookConfig{
			Endpoint:                  ew.Endpoint,
			Token:                     ew.GetToken(),
			InsecureSkipVerify:        ew.InsecureSkipVerify,
			AllowPrivateNetworkTarget: ew.AllowPrivateNetworkTarget,
			AllowInsecureTransport:    ew.AllowInsecureTransport,
		})
		if ferr != nil {
			return nil, nil, fmt.Errorf("failed to init evidence webhook target: %w", ferr)
		}
		evidenceTargets = append(evidenceTargets, fwd)
		log.Printf("Evidence webhook target enabled (endpoint=%s)", ew.Endpoint)
	}
	if os := cfg.EvidenceDelivery.ObjectStore; os.Enabled {
		sink, oerr := evidencesink.NewObjectStore(context.Background(), evidencesink.ObjectStoreConfig{
			Bucket:         os.Bucket,
			Prefix:         os.Prefix,
			Region:         os.Region,
			Endpoint:       os.Endpoint,
			UsePathStyle:   os.UsePathStyle,
			LockMode:       os.LockMode,
			LockRetainDays: os.LockRetainDays,
			LegalHold:      os.LegalHold,
		})
		if oerr != nil {
			return nil, nil, fmt.Errorf("failed to init evidence object-store target: %w", oerr)
		}
		evidenceTargets = append(evidenceTargets, sink)
		log.Printf("Evidence object-store target enabled (bucket=%s, prefix=%q)", os.Bucket, os.Prefix)
	}
	switch len(evidenceTargets) {
	case 0:
	case 1:
		coreService.SetEvidenceForwarder(evidenceTargets[0])
	default:
		coreService.SetEvidenceForwarder(evidencesink.NewMulti(evidenceTargets...))
	}

	// Apply the project membership validation mode (ADR-022). Empty = allowlist.
	if vm := cfg.Membership.ValidationMode; vm != "" {
		coreService.SetMembershipValidationMode(vm)
	}
	// Apply the invitation domain allowlist (ADR-022). Empty = no restriction.
	if len(cfg.Membership.DomainAllowlist) > 0 {
		coreService.SetMembershipDomainAllowlist(cfg.Membership.DomainAllowlist)
	}

	// Apply the credential-delivery setup-token TTL (ADR-028). GetSetupTokenTTL
	// falls back to 24h when the block is absent or invalid.
	coreService.SetSetupTokenTTL(cfg.CredentialDelivery.GetSetupTokenTTL())

	// Apply session-token lifetimes (short-lived tokens with silent auto-refresh).
	// Defaults preserve the historic 24h access window with no absolute ceiling, so
	// an install without a session block behaves exactly as before.
	coreService.SetSessionTTLs(cfg.Session.GetAccessTTL(), cfg.Session.GetAbsoluteTTL())

	wireDynamicSecrets(cfg, coreService)

	// Wire self-service emergency access (break-glass); zero value = disabled.
	coreService.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled:       cfg.BreakGlass.Enabled,
		EmergencyRole: cfg.BreakGlass.EmergencyRole,
		DefaultTTL:    cfg.BreakGlass.GetDefaultTTL(),
		MaxTTL:        cfg.BreakGlass.GetMaxTTL(),
		// #2461: GetReviewWindow had no non-test caller, so ADR-112's
		// post-activation-review deviation was computed against nothing. Wired
		// unconditionally, NOT behind cfg.BreakGlass.Enabled: an install that
		// has since turned break-glass off can still hold unreviewed
		// activations from when it was on, and those are exactly the ones that
		// must not drop off the posture report.
		ReviewWindow: cfg.BreakGlass.GetReviewWindow(),
	})

	// Wire N-of-M dual-control approval for access requests (1 = disabled).
	coreService.SetDualControlPolicy(cfg.DualControl.GetRequiredApprovals())
	if n := cfg.DualControl.GetRequiredApprovals(); n > 1 {
		log.Printf("Dual-control approval enabled: %d approvals required per access request", n)
	}

	// Wire the "restricted" classification read-time gate (#128's product
	// decision); false (the default) leaves the label purely informational,
	// identical to every deployment's behaviour today.
	coreService.SetClassificationRestrictedRequiresApproval(cfg.Classification.RestrictedRequiresApproval)
	if cfg.Classification.RestrictedRequiresApproval {
		log.Printf("Classification enforcement enabled: reading a \"restricted\" secret's value now requires an approved, secret-scoped access request")
	}
	coreService.SetClassificationRestrictedRequiresPermission(cfg.Classification.RestrictedRequiresPermission)
	if cfg.Classification.RestrictedRequiresPermission {
		log.Printf("Classification enforcement enabled: reading a \"restricted\" secret's value now requires the %q permission at the project scope", core.PermSecretReadRestricted)
	}
	coreService.SetClassificationRestrictedRequiresMFAStepUp(cfg.Classification.RestrictedRequiresMFAStepUp, cfg.Classification.RestrictedMFAStepUpWindowMinutes)
	if cfg.Classification.RestrictedRequiresMFAStepUp {
		window := cfg.Classification.RestrictedMFAStepUpWindowMinutes
		if window == 0 {
			window = 15
		}
		log.Printf("Classification enforcement enabled: reading a \"restricted\" secret's value now requires a recent MFA verification (window: %d min)", window)
	}

	// Wire the configured data-retention windows (A.5.33) so the compliance posture
	// reports them; the scheduler below drives the actual purge. Audited (#160) so a
	// shortened window is on the record, not just its eventual purge counts.
	coreService.SetRetentionPolicy(context.Background(), core.RetentionPolicy{
		AnomalyAlertsDays:               cfg.DataRetention.AnomalyAlertsDays,
		AnomalyAlertsUnackedCeilingDays: cfg.DataRetention.AnomalyAlertsUnackedCeilingDays,
		ClosedAccessReviewsDays:         cfg.DataRetention.ClosedAccessReviewsDays,
		BreakGlassDays:                  cfg.DataRetention.BreakGlassDays,
		ResolvedAccessRequestsDays:      cfg.DataRetention.ResolvedAccessRequestsDays,
	})

	// Wire the access-recertification cadence (A.5.18) so the posture flags overdue
	// projects; the scheduler below acts on it when enabled.
	coreService.SetRecertificationCadence(cfg.Recertification.CadenceDays)

	// Wire the credential-delivery channel (ADR-028). New selects out-of-band/SMTP/
	// log from the configured mode and fails loud on a bad mode (e.g. smtp with no
	// host), so a misconfigured install does not silently drop setup links.
	cd := cfg.CredentialDelivery
	deliverer, derr := delivery.New(cd.DeliveryConfig())
	if derr != nil {
		return nil, nil, fmt.Errorf("failed to init credential delivery: %w", derr)
	}
	coreService.SetCredentialDelivery(deliverer, cd.BaseURL)

	// Wire OIDC / Kubernetes-JWT federation (ADR-031) when configured. A bad
	// issuer config (e.g. missing audiences) fails loud rather than silently
	// disabling federation.
	if oidc := cfg.OIDC; oidc.Enabled && len(oidc.Issuers) > 0 {
		trusted := make([]core.OIDCTrustedIssuer, 0, len(oidc.Issuers))
		jwksURIs := make(map[string]string, len(oidc.Issuers))
		for _, iss := range oidc.Issuers {
			trusted = append(trusted, core.OIDCTrustedIssuer{
				Issuer: iss.Issuer, Audiences: iss.Audiences,
				MaxTokenAge: time.Duration(iss.MaxTokenAgeSeconds) * time.Second,
			})
			jwksURIs[iss.Issuer] = iss.JWKSURI
		}
		resolver, rerr := core.NewHTTPJWKSResolver(jwksURIs)
		if rerr != nil {
			return nil, nil, fmt.Errorf("invalid OIDC jwks_uri: %w", rerr)
		}
		verifier, verr := core.NewOIDCVerifier(trusted, resolver)
		if verr != nil {
			return nil, nil, fmt.Errorf("failed to init OIDC federation: %w", verr)
		}
		coreService.SetOIDCVerifier(verifier)
		log.Printf("OIDC federation enabled for %d issuer(s)", len(oidc.Issuers))
	}

	// Wire the audit high-water rollback-protection witness file
	// (design-b3-backup-v2.md §6.3) for local/sqlite deployments -- the only
	// backend `admin backup`/`admin restore` support, and therefore the only
	// one a stale-backup restore is even possible against. Postgres
	// deployments back up manually (pg_dump, docs/SELF_HOSTING.md §5) and
	// have no `admin restore` path this witness would ever be compared
	// against, so leaving it unset there is correct, not an oversight.
	if cfg.Storage.Type == "local" || cfg.Storage.Type == "sqlite" {
		dbPath := cfg.Storage.Database.Path
		if dbPath == "" {
			dbPath = "./secrets.db"
		}
		coreService.SetAuditHighWaterWitnessPath(auditverify.WitnessPath(dbPath))
	}

	// Wire WebAuthn / passkeys (ADR-036) when configured. A bad RP config (no
	// origins / invalid RP ID) fails loud rather than silently disabling passkeys.
	if wa := cfg.WebAuthn; wa.Enabled {
		rp, werr := webauthn.New(&webauthn.Config{
			RPID:          wa.RPID,
			RPDisplayName: cmpOr(wa.RPDisplayName, "Keyorix"),
			RPOrigins:     wa.RPOrigins,
		})
		if werr != nil {
			return nil, nil, fmt.Errorf("failed to init WebAuthn: %w", werr)
		}
		coreService.SetWebAuthn(rp)
		log.Printf("WebAuthn enabled (RP ID %q, %d origin(s))", wa.RPID, len(wa.RPOrigins))
	}

	// Wire the offline-license feature gate (ADR-065). Fail-safe throughout: a missing,
	// unreadable, or invalid license never blocks startup — the gate degrades to the
	// community baseline. A non-release build embeds no license key, so any token evaluates
	// to the baseline anyway. The gate evaluates the token freshly on every call.
	reg, terr := trust.DefaultRegistry()
	if terr != nil {
		// A malformed embedded key spec is a build/release misconfiguration; surface it,
		// but still run (no trusted keys → baseline).
		log.Printf("WARNING: trusted-key registry: %v (running community baseline)", terr)
		reg = nil
	}
	token := loadLicenseToken(cfg.License.Path)
	gate := license.NewGate(token, reg, cfg.License.DeploymentID, cfg.LicenseGrace())
	coreService.SetLicenseGate(gate)
	st := gate.Status()
	if st.Grants() {
		log.Printf("License: %s (%s) — state %s", st.Licensee, st.Plan, st.State)
	} else {
		log.Printf("License: community baseline (state %s)", st.State)
	}

	return coreService, encSvc, nil
}

// isNotFoundStorageErr reports whether err is a "not found"-substring error, the
// convention every LocalStorage Get* method in this codebase uses (see
// local_secrets.go's GetProject).
func isNotFoundStorageErr(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

// resolveConnectorOwnership resolves each connector's tenant-scoping data
// (ADR-082 §A/§E) from its config entry. A "platform"-scoped connector needs no
// resolution. A "project"-scoped connector's project: name is pinned to a real
// Keyorix project ID via ConnectorProjectBinding, never re-resolved by name on a
// later boot — see that model's own doc comment for why (project names are
// mutable and a soft-deleted project's name is freed for reuse, so re-resolving
// by name every boot would let an ordinary rename silently reassign ownership):
//
//   - First boot for a connector (no binding row yet): resolve config's project:
//     name to a project via storage.GetProjectByName, persist the binding.
//   - A later boot (binding row exists): resolve the project by the STORED ID
//     (storage.GetProject), never by name. If that project no longer exists
//     (deleted), or its CURRENT name no longer matches the name recorded in the
//     binding at first-boot time, this fails boot — a rename or delete is
//     something server/main.go treats as requiring deliberate operator action,
//     not something to silently follow or silently ignore.
//
// Every problem across every connector is collected into ONE aggregated error
// (branch 1's validateConnectScopes style), naming each offending connector and
// its specific reason, rather than failing on the first one found.
func resolveConnectorOwnership(ctx context.Context, st corestorage.Storage, connectors []config.ConnectorConfig) (map[string]core.ConnectOwnership, error) {
	ownership := make(map[string]core.ConnectOwnership, len(connectors))
	var problems []string
	for _, cn := range connectors {
		if cn.Scope == "platform" {
			ownership[cn.Name] = core.ConnectOwnership{Scope: "platform"}
			continue
		}
		// cn.Scope == "project" here: internal/config.validateConnectScopes already
		// guaranteed no other value reached boot (amended — there is no longer an
		// allow_unscoped bypass; a missing or unrecognized scope always fails boot
		// before this function is ever reached).
		binding, err := st.GetConnectorProjectBinding(ctx, cn.Name)
		switch {
		case err != nil && isNotFoundStorageErr(err):
			// First boot for this connector: resolve name -> ID, persist.
			project, perr := st.GetProjectByName(ctx, cn.Project)
			if perr != nil {
				problems = append(problems, fmt.Sprintf("%s: project %q not found: %v", cn.Name, cn.Project, perr))
				continue
			}
			created, cerr := st.CreateConnectorProjectBinding(ctx, &models.ConnectorProjectBinding{
				Connector:   cn.Name,
				ProjectID:   project.ID,
				ProjectName: project.Name,
			})
			if cerr != nil {
				problems = append(problems, fmt.Sprintf("%s: failed to persist project binding: %v", cn.Name, cerr))
				continue
			}
			auditConnectorProjectBindingCreate(ctx, st, created, "boot-time first resolution")
			ownership[cn.Name] = core.ConnectOwnership{Scope: "project", ProjectID: created.ProjectID}
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", cn.Name, err))
		default:
			// Binding exists: resolve by the stored ID, never by name.
			project, perr := st.GetProject(ctx, binding.ProjectID)
			if perr != nil {
				problems = append(problems, fmt.Sprintf("%s: bound to project id %d, which no longer exists (deleted?): %v", cn.Name, binding.ProjectID, perr))
				continue
			}
			if project.Name != binding.ProjectName {
				problems = append(problems, fmt.Sprintf(
					"%s: bound project (id %d) was renamed from %q to %q since this connector was first configured — this is a deliberate boot failure (ADR-082), not a silent reassignment; if the rename was intentional, update connect.connectors[].project to %q and clear the stale connector_project_bindings row for %q before restarting",
					cn.Name, binding.ProjectID, binding.ProjectName, project.Name, project.Name, cn.Name))
				continue
			}
			ownership[cn.Name] = core.ConnectOwnership{Scope: "project", ProjectID: binding.ProjectID}
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("connector(s) with unresolvable project binding: %s", strings.Join(problems, "; "))
	}
	return ownership, nil
}

// auditConnectorProjectBindingCreate records a ConnectorProjectBinding write
// (ADR-082 branch 3, issue #1477's audit half): the binding is an
// authorization input (it feeds core.ConnectOwnership, and from there
// connectOwnershipSatisfied) regardless of which door the write comes through.
// This unattended boot-time path was originally paired with a second call site,
// the now-deleted RemoteStorage proxy's write; source distinguishes call sites
// in the Description in case a second one is reintroduced. A logging
// failure here does not fail boot — the binding itself already persisted
// successfully — but is surfaced loudly (SECURITY-prefixed, matching
// internal/core's own emitAudit convention) since a silently-dropped audit
// write for an authorization-input change is exactly the kind of gap this
// branch exists to close.
func auditConnectorProjectBindingCreate(ctx context.Context, st corestorage.Storage, b *models.ConnectorProjectBinding, source string) {
	t := true
	event := &models.AuditEvent{
		EventType:   core.EventConnectorProjectBindingCreate,
		ProjectID:   &b.ProjectID,
		Description: fmt.Sprintf("connector project binding created (%s): connector %q bound to project %q (id %d)", source, b.Connector, b.ProjectName, b.ProjectID),
		Success:     &t,
		EventTime:   time.Now(),
		ActorType:   core.ActorTypeSystem,
	}
	if err := st.LogAuditEvent(ctx, event); err != nil {
		log.Printf("SECURITY: failed to persist audit event %q for connector %q: %v", core.EventConnectorProjectBindingCreate, b.Connector, err)
	}
}

// connectOwnershipKeySetMismatch returns every connector name whose presence in
// connect.Manager (builtNames) and in the resolved ownership map disagree — no
// exemption of any kind (amended: the prior connect.allow_unscoped-linked
// exemption is removed along with the flag, since resolveConnectorOwnership no
// longer skips any connector). A connector present in one set but not the other
// must never happen in a correctly-booted server (e.g. an unrecognized connector
// Type, which resolves ownership successfully but never makes it into the
// manager) — every divergence is reported.
func connectOwnershipKeySetMismatch(builtNames []string, ownership map[string]core.ConnectOwnership) []string {
	built := make(map[string]bool, len(builtNames))
	for _, name := range builtNames {
		built[name] = true
	}
	var mismatch []string
	for name := range built {
		if _, ok := ownership[name]; !ok {
			mismatch = append(mismatch, name)
		}
	}
	for name := range ownership {
		if !built[name] {
			mismatch = append(mismatch, name)
		}
	}
	return mismatch
}

// warnConnectConfigDrift performs two READ-ONLY, warn-only consistency checks
// after Connect's boot-time wiring (ownership) is resolved — #1477/#1479's
// boot-time drift detection. This is the only place in the system that sees
// both config (ownership, resolved from cfg.Connect.Connectors just before
// this is called) and DB rows (ConnectRefGrant, ConnectorProjectBinding)
// together, which is why it closes what the create-time checks
// (CreateConnectRefGrant, resolveConnectorOwnership's own
// CreateConnectorProjectBinding call) structurally cannot: a config edit
// AFTER a grant/binding already exists. Neither
// condition here is a security risk — a dead ref-grant already denies
// nothing extra (ReadFederatedSecret's platform branch is a terminal deny
// regardless of any grant), and an orphaned binding is simply unused, not
// over-permissive — so this warns, aggregated in ADR-082's own established
// style (one summary line naming every offender), and never fails boot.
// Scoped to when Connect's boot-wiring actually runs (cc.Enabled with at
// least one recognized connector) — a fully-disabled Connect config with
// leftover rows from a PRIOR enabled state is not covered; that is a
// narrower, separate case than the config-edit drift this targets.
func warnConnectConfigDrift(ctx context.Context, st corestorage.Storage, ownership map[string]core.ConnectOwnership) {
	if grants, err := st.ListConnectRefGrants(ctx); err != nil {
		log.Printf("Keyorix Connect: boot-time drift check: failed to list ref-grants: %v", err)
	} else {
		var dead []string
		for _, g := range grants {
			if ownership[g.Connector].Scope == "platform" {
				dead = append(dead, fmt.Sprintf("grant %d (connector %q)", g.ID, g.Connector))
			}
		}
		if len(dead) > 0 {
			log.Printf("Keyorix Connect: WARNING: %d ConnectRefGrant(s) are dead configuration — bound to a connector that now resolves to scope: platform, a terminal deny that never consults ref-grant delegation (ADR-082): %s",
				len(dead), strings.Join(dead, ", "))
		}
	}

	if bindings, err := st.ListConnectorProjectBindings(ctx); err != nil {
		log.Printf("Keyorix Connect: boot-time drift check: failed to list connector project bindings: %v", err)
	} else {
		var orphaned []string
		for _, b := range bindings {
			if _, ok := ownership[b.Connector]; !ok {
				orphaned = append(orphaned, fmt.Sprintf("%s (bound to project %q)", b.Connector, b.ProjectName))
			}
		}
		if len(orphaned) > 0 {
			log.Printf("Keyorix Connect: WARNING: %d connector project binding(s) reference a connector no longer in cfg.Connect.Connectors — orphaned by a removed or renamed connector: %s",
				len(orphaned), strings.Join(orphaned, ", "))
		}
	}
}

// cmpOr returns a if non-empty, else b (a tiny local helper to avoid a new import).
func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// flushLastUsedOnShutdown writes the last-used stamps the core has recorded
// but not yet flushed (internal/core/last_used_coalescer.go). It is bounded by
// its own 10 s context, including the wait for a background flush that is
// stuck in a slow write.
func flushLastUsedOnShutdown(coreService *core.KeyorixCore) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	coreService.FlushLastUsed(ctx)
}

// closeAuditForwarder flushes/closes the wired SIEM audit forwarder (if any) on
// shutdown. core.AuditForwarder only declares Forward (core has no dependency
// on the concrete siem package), so the Close method is reached via a local
// interface rather than a direct type assertion to *siem.Forwarder.
func closeAuditForwarder(coreService *core.KeyorixCore) {
	type closer interface{ Close() }
	if cl, ok := coreService.AuditForwarder().(closer); ok {
		cl.Close()
	}
}

// startSchedulers starts every opt-in/default background scheduler exactly
// once for the process (#G12). Previously this whole block lived inside
// startHTTPServer, so a gRPC-only deployment (HTTP disabled) never ran ANY of
// these — most visibly, SetDynamicSweepEnabled(cfg.DynamicSecrets.SweepEnabled)
// (set unconditionally from static config in initializeCoreService) told the
// dynamic-secrets engine a sweeper was active when, for that deployment shape,
// no process actually ran one. Each job is already single-replica-gated via a
// Postgres advisory lock (ADR-039), so starting the loop in every process
// (regardless of which transport it serves) is the existing, intended
// coordination model — not a new behavior.
//
// The returned wait blocks until every scheduler goroutine started here has
// exited, which happens once ctx is cancelled and any in-flight tick returns.
// The server process never needs it (it exits); tests do, so a tick cannot
// outlive the test that started it and run against the next test's process
// state (log output, i18n, config) -- see startSchedulersForTest.
func startSchedulers(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) (wait func()) { // NOSONAR -- cognitive complexity 188, suppress go:S3776
	var schedulers sync.WaitGroup
	ctx = withSchedulerTracking(ctx, &schedulers)

	// Start anomaly detection scheduler. Single-replica-gated (ADR-039) so N
	// replicas don't emit N copies of each alert. When anomaly_alerts is enabled,
	// each detection pass is followed by an alerting pass that pushes newly detected
	// anomalies to project admins + the audit/SIEM pipeline.
	{
		detector := core.NewAnomalyDetector(coreService.Storage())
		if bh := cfg.AnomalyAlerts.BusinessHours; bh.Timezone != "" || bh.OffHoursStart != 0 || bh.OffHoursEnd != 0 {
			tzLabel := bh.Timezone
			if tzLabel == "" {
				tzLabel = "UTC"
			}
			if err := detector.SetBusinessHours(ctx, bh.Timezone, bh.OffHoursStart, bh.OffHoursEnd); err != nil {
				// Misconfigured timezone: keep the safe UTC default rather than fail startup.
				log.Printf("Anomaly off-hours config ignored (%v); using UTC 22:00–06:00", err)
			} else {
				log.Printf("Anomaly off-hours rule configured (timezone %s)", tzLabel)
			}
		}
		if mlc := cfg.AnomalyAlerts.ML; mlc.Enabled {
			detector.SetMLConfig(core.MLConfig{
				Enabled:    true,
				Threshold:  mlc.Threshold,
				NumTrees:   mlc.NumTrees,
				SampleSize: mlc.SampleSize,
				Seed:       mlc.Seed,
			})
			log.Printf("Anomaly ML (Isolation Forest) detection enabled")
		}
		alertsEnabled := cfg.AnomalyAlerts.Enabled
		interval := cfg.AnomalyAlerts.GetInterval()
		// Scan a window at least as long as the cadence, so a longer schedule doesn't
		// leave the time between passes unexamined (floored at 1h inside SetLookback).
		detector.SetLookback(interval)
		detector.SetBaselineQuarantine(cfg.AnomalyAlerts.GetBaselineQuarantine())
		// Overlay the DB-persisted anomaly config on top of the file-based defaults.
		// Best-effort at startup: a storage error keeps the file-based settings rather
		// than aborting startup or leaving the detector unconfigured.
		if err := coreService.ApplyAnomalyConfig(ctx, detector); err != nil {
			log.Printf("Anomaly: could not load persisted config (%v); using file-based defaults", err)
		} else {
			log.Printf("Anomaly: persisted runtime config applied")
		}
		if alertsEnabled {
			log.Printf("Anomaly alerting enabled: scan + alert every %s", interval)
		}
		// First pass deferred + jittered, not run at startup — see anomalyFirstPassDelay.
		firstDelay := anomalyFirstPassDelay(interval, defaultRandN)
		log.Printf("Anomaly detection: first pass in %s, then every %s", firstDelay.Round(time.Second), interval)
		runSchedulerAfter(ctx, "anomaly_detection", interval, firstDelay, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockAnomaly, "Anomaly detection", func(ctx context.Context) error {
				// Hotload: re-apply the persisted config before each pass so an operator's
				// runtime change takes effect without a restart. Best-effort: a transient
				// storage failure here is logged but does not skip the detection pass.
				if err := coreService.ApplyAnomalyConfig(ctx, detector); err != nil {
					log.Printf("Anomaly: failed to reload persisted config (%v); running with prior settings", err)
				}
				if derr := detector.RunDetection(ctx, coreService.ListActiveSecrets(ctx)); derr != nil {
					return derr
				}
				if alertsEnabled {
					if n, aerr := coreService.AlertNewAnomalies(ctx); aerr != nil {
						return aerr
					} else if n > 0 {
						log.Printf("Anomaly alerting: announced %d new anomaly alert(s)", n)
					}
				}
				return nil
			})
		})
	}

	// legalHoldBlocks reports whether a deployment-wide legal hold (ISO A.5.34)
	// should block a hard-delete purge job this tick. Fails SAFE: if the hold status
	// can't be read it returns true (skip the purge), so records that may be under
	// hold are never destroyed on a transient lookup error.
	legalHoldBlocks := func(job string) bool {
		active, err := coreService.IsLegalHoldActive(ctx)
		if err != nil {
			log.Printf("%s skipped: could not check legal-hold status: %v", job, err)
			return true
		}
		if active {
			log.Printf("%s skipped: a legal hold is active", job)
			return true
		}
		return false
	}

	// Start the retention purge scheduler (ADR-032) — opt-in. Hard-deletes
	// soft-deleted users/projects/environments older than the retention window.
	if cfg.Purge.Enabled {
		retentionDays := cfg.SoftDelete.GetRetentionDays()
		interval := cfg.Purge.GetInterval()
		log.Printf("Retention purge scheduler enabled: every %s, %d-day retention", interval, retentionDays)
		runScheduler(ctx, "retention_purge", interval, func() middleware.SchedulerOutcome {
			if legalHoldBlocks("Retention purge") {
				return middleware.SchedulerSkipped
			}
			// Single-replica-gated (ADR-039): only one replica runs the purge.
			return lockedRun(ctx, coreService.Storage(), schedLockPurge, "Retention purge", func(ctx context.Context) error {
				// UTC so the cutoff is exactly the inverse of models.PurgeAtFor
				// (deleted_at + N days in UTC): a local zone with DST would let a
				// legacy (un-stamped) secret go an hour before its displayed purge date.
				cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
				res, err := coreService.PurgeExpiredSoftDeletes(ctx, cutoff)
				if err != nil {
					log.Printf("Retention purge error: %v", err)
					return err
				}
				if res.Total() > 0 {
					log.Printf("Retention purge removed %d soft-deleted records (users=%d, projects=%d, environments=%d, secrets=%d)",
						res.Total(), res.Users, res.Projects, res.Environments, res.Secrets)
				}
				return nil
			})
		})
	}

	// Start the data-retention scheduler (ISO A.5.33 / GDPR / DORA) — opt-in.
	// Hard-deletes compliance records (anomaly alerts, closed campaigns, the
	// break-glass register, resolved access requests) past their per-type window.
	// Legal-hold-gated and single-replica-gated (ADR-039); audit events are never
	// touched (append-only). Runs only when at least one window is configured.
	if cfg.DataRetention.Enabled {
		policy := core.RetentionPolicy{
			AnomalyAlertsDays:               cfg.DataRetention.AnomalyAlertsDays,
			AnomalyAlertsUnackedCeilingDays: cfg.DataRetention.AnomalyAlertsUnackedCeilingDays,
			ClosedAccessReviewsDays:         cfg.DataRetention.ClosedAccessReviewsDays,
			BreakGlassDays:                  cfg.DataRetention.BreakGlassDays,
			ResolvedAccessRequestsDays:      cfg.DataRetention.ResolvedAccessRequestsDays,
		}
		if !policy.Configured() {
			log.Printf("Data-retention scheduler enabled but no retention windows are set; nothing to purge")
		} else {
			interval := cfg.DataRetention.GetInterval()
			log.Printf("Data-retention scheduler enabled: every %s (anomaly_alerts=%dd, anomaly_alerts_unacked_ceiling=%dd, closed_reviews=%dd, break_glass=%dd, access_requests=%dd; 0=keep)",
				interval, policy.AnomalyAlertsDays, policy.AnomalyAlertsUnackedCeilingDays, policy.ClosedAccessReviewsDays, policy.BreakGlassDays, policy.ResolvedAccessRequestsDays)
			runScheduler(ctx, "data_retention", interval, func() middleware.SchedulerOutcome {
				if legalHoldBlocks("Data-retention purge") {
					return middleware.SchedulerSkipped
				}
				return lockedRun(ctx, coreService.Storage(), schedLockRetention, "Data-retention", func(ctx context.Context) error {
					res, err := coreService.PurgeExpiredComplianceRecords(ctx, time.Now(), policy)
					if err != nil {
						log.Printf("Data-retention purge error: %v", err)
						return err
					}
					if res.Total() > 0 {
						log.Printf("Data-retention purge removed %d records (anomaly_alerts=%d, closed_campaigns=%d, review_items=%d, break_glass=%d, access_requests=%d, approvals=%d)",
							res.Total(), res.AnomalyAlerts, res.ClosedAccessReviews, res.AccessReviewItems,
							res.BreakGlass, res.ResolvedAccessRequests, res.AccessRequestApprovals)
					}
					return nil
				})
			})
		}
	}

	// Start the rotation-reminder scheduler — opt-in. Notifies project admins of
	// secrets overdue/approaching their rotation deadline (proactive rotation
	// hygiene; a NIS2/ISO control). Single-replica-gated (ADR-039) so admins aren't
	// notified N times in an HA deployment.
	if cfg.RotationReminders.Enabled {
		interval := cfg.RotationReminders.GetInterval()
		log.Printf("Rotation-reminder scheduler enabled: every %s", interval)
		runScheduler(ctx, "rotation_reminder", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockRotationRmdr, "Rotation-reminder", func(ctx context.Context) error {
				n, rerr := coreService.SendRotationReminders(ctx)
				if rerr != nil {
					log.Printf("Rotation-reminder error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Rotation reminders: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}

	// Start the secret-expiry reminder scheduler — opt-in. Notifies project admins of
	// secrets that have expired or are approaching expiration, so a secret never silently
	// lapses. Single-replica-gated (ADR-039) so admins aren't notified N times in HA.
	if cfg.ExpiryReminders.Enabled {
		interval := cfg.ExpiryReminders.GetInterval()
		leadDays := cfg.ExpiryReminders.LeadDays
		log.Printf("Expiry-reminder scheduler enabled: every %s (lead %dd)", interval, leadDays)
		runScheduler(ctx, "expiry_reminder", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockExpiryRmdr, "Expiry-reminder", func(ctx context.Context) error {
				n, rerr := coreService.SendExpiryReminders(ctx, leadDays)
				if rerr != nil {
					log.Printf("Expiry-reminder error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Expiry reminders: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}

	// Start the certificate-expiry scan — opt-in (ADR-055). Parses certificate-typed
	// secrets and notifies project admins of certs expired/expiring within the window.
	// Single-replica-gated (ADR-039).
	if cfg.CertificateExpiry.Enabled {
		interval := cfg.CertificateExpiry.GetInterval()
		leadDays := cfg.CertificateExpiry.LeadDays
		log.Printf("Certificate-expiry scan enabled: every %s (lead %dd)", interval, leadDays)
		runScheduler(ctx, "certificate_expiry", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockCertExpiry, "Certificate-expiry", func(ctx context.Context) error {
				n, rerr := coreService.ScanCertificateExpiry(ctx, leadDays)
				if rerr != nil {
					log.Printf("Certificate-expiry scan error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Certificate-expiry scan: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}

	// Start the license-expiry reminder — opt-in (ADR-065 Phase 2c). Notifies install-wide
	// admins when the offline commercial license is approaching or past expiry, so a lapse
	// (which silently disables commercial features) doesn't go unnoticed. Single-replica-
	// gated (ADR-039) so N replicas don't each notify.
	if cfg.LicenseExpiry.Enabled {
		interval := cfg.LicenseExpiry.GetInterval()
		leadDays := cfg.LicenseExpiry.LeadDays
		log.Printf("License-expiry reminder enabled: every %s (lead %dd)", interval, leadDays)
		runScheduler(ctx, "license_expiry", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockLicenseExp, "License-expiry", func(ctx context.Context) error {
				n, rerr := coreService.ScanLicenseExpiry(ctx, leadDays)
				if rerr != nil {
					log.Printf("License-expiry reminder error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("License-expiry reminder: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}

	// Start the automated-rotation scheduler — opt-in (ADR-046). Rotates auto-rotate-
	// enabled secrets that are overdue under an active policy, regenerating their value.
	// Single-replica-gated (ADR-039) so a secret rotates once per tick in an HA
	// deployment.
	if cfg.AutoRotation.Enabled {
		interval := cfg.AutoRotation.GetInterval()
		log.Printf("Auto-rotation scheduler enabled: every %s", interval)
		runScheduler(ctx, "auto_rotation", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockAutoRotate, "Auto-rotation", func(ctx context.Context) error {
				n, rerr := coreService.RunAutoRotation(ctx)
				if rerr != nil {
					log.Printf("Auto-rotation error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Auto-rotation: rotated %d secret(s)", n)
				}
				return nil
			})
		})
	}

	// Start the compliance-digest scheduler — opt-in. Periodically broadcasts a
	// posture + control-matrix summary to the configured notification channels
	// (Slack/Teams/webhook). Single-replica-gated (ADR-039) so the channel gets one
	// digest per tick. A no-op (logged) when no notification channel is configured.
	if cfg.ComplianceDigest.Enabled {
		interval := cfg.ComplianceDigest.GetInterval()
		log.Printf("Compliance-digest scheduler enabled: every %s", interval)
		runScheduler(ctx, "compliance_digest", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockDigest, "Compliance-digest", func(ctx context.Context) error {
				sent, derr := coreService.SendComplianceDigest(ctx, 0)
				if derr != nil {
					log.Printf("Compliance-digest error: %v", derr)
					return derr
				}
				if !sent {
					log.Printf("Compliance digest: no notification channel configured; nothing sent")
				}
				return nil
			})
		})
	}

	// Start the scheduled access-recertification scheduler (ISO 27001 A.5.18) —
	// opt-in. Finds projects overdue for review and either auto-opens a recert
	// campaign (when auto_open) or reminds the project's admins to; also nudges
	// admins of in-flight campaigns with pending items. A create/notify, not a
	// delete, so NOT legal-hold-gated. Single-replica-gated (ADR-039) so a campaign
	// is opened once per project per tick in HA.
	if cfg.Recertification.Enabled {
		interval := cfg.Recertification.GetInterval()
		cadence := cfg.Recertification.CadenceDays
		autoOpen := cfg.Recertification.AutoOpen
		log.Printf("Recertification scheduler enabled: every %s (cadence %dd, auto_open=%t)", interval, cadence, autoOpen)
		runScheduler(ctx, "recertification", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockRecertify, "Recertification", func(ctx context.Context) error {
				res, rerr := coreService.RunScheduledRecertification(ctx, cadence, autoOpen)
				if rerr != nil {
					log.Printf("Recertification error: %v", rerr)
					return rerr
				}
				if res.Opened > 0 || res.Reminded > 0 {
					log.Printf("Recertification: opened %d campaign(s), sent %d reminder(s)", res.Opened, res.Reminded)
				}
				return nil
			})
		})
	}

	// Start the scheduled compliance-evidence delivery (ISO 27001 / SOC 2) — opt-in.
	// Periodically generates the auditor evidence pack and delivers it to the
	// configured targets (a local directory and/or a webhook); each export emits an
	// audit event (forwarded to a SIEM if configured). Single-replica-gated (ADR-039)
	// so one pack is delivered per tick. Not legal-hold-gated (it only reads).
	if cfg.EvidenceDelivery.Enabled {
		if !cfg.EvidenceDelivery.HasTarget() {
			log.Printf("Evidence-delivery scheduler enabled but no target (output_dir or webhook) is configured; skipping")
		} else {
			outputDir := cfg.EvidenceDelivery.OutputDir
			interval := cfg.EvidenceDelivery.GetInterval()
			log.Printf("Evidence-delivery scheduler enabled: every %s (dir=%q, webhook=%t)", interval, outputDir, cfg.EvidenceDelivery.Webhook.Enabled)
			runScheduler(ctx, "evidence_delivery", interval, func() middleware.SchedulerOutcome {
				return lockedRun(ctx, coreService.Storage(), schedLockEvidence, "Evidence-delivery", func(ctx context.Context) error {
					res, err := coreService.ExportComplianceEvidence(ctx, outputDir)
					if err != nil {
						log.Printf("Evidence-delivery error: %v", err)
						return err
					}
					if res.Degraded {
						// #136: a degraded pack must be loud in the operator-facing log, not
						// just embedded in the archived JSON — a collection failure means
						// this export is incomplete, not a clean point-in-time snapshot.
						log.Printf("Evidence pack exported DEGRADED (%d collection failure(s)): %d bytes -> %v; reasons: %s",
							len(res.DegradedReasons), res.Bytes, res.Targets, strings.Join(res.DegradedReasons, "; "))
					} else {
						log.Printf("Evidence pack exported: %d bytes -> %v", res.Bytes, res.Targets)
					}
					return nil
				})
			})
		}
	}

	// Start the audit-checkpoint scheduler (ADR-029). Periodically signs the verified
	// audit-chain head so tampering, tail-truncation, and genesis re-seed are
	// detectable. This is the trail's FORGERY-RESISTANCE layer: the per-row hash chain
	// is unkeyed, so a database-write attacker could otherwise edit/delete/reorder rows
	// and recompute a self-consistent chain undetected. It is therefore enabled BY
	// DEFAULT whenever a signing key is available (the key is DEK-derived → encryption
	// must be configured). HA-gated so one replica writes per tick.
	switch {
	case cfg.AuditCheckpoints.Disabled:
		log.Printf("WARNING: audit-checkpoint forgery-resistance is explicitly DISABLED; the audit trail is tamper-evident but a database-write attacker can recompute the hash chain undetected")
	case !coreService.AuditCheckpointsAvailable():
		log.Printf("WARNING: audit checkpointing is UNAVAILABLE (encryption/signing key not configured) — the audit trail is tamper-EVIDENT only, NOT forgery-resistant: a database-write attacker can edit/delete/reorder audit rows and recompute the chain. Enable encryption to activate forgery resistance.")
	default:
		interval := cfg.AuditCheckpoints.GetInterval()
		segments := core.DefaultAuditFullVerificationSegments
		// Incremental verification (docs/specs/audit-incremental-verification.md):
		// each tick checks only the tail since the latest checkpoint and re-walks
		// 1/segments of the chain, so the whole chain is re-hashed every
		// interval × segments; requests and posture read the persisted result.
		coreService.SetAuditIncrementalVerification(interval, segments)
		// A fresh checkpoint defers the first tick (spec §6): a restart does not
		// re-verify what the last tick already covered.
		firstDelay := coreService.AuditCheckpointFirstTickDelay(ctx, interval)
		log.Printf("Audit-checkpoint scheduler enabled (forgery resistance active): every %s, full re-walk every %s, first tick in %s",
			interval, interval*time.Duration(segments), firstDelay.Round(time.Second))
		runSchedulerAfter(ctx, "audit_checkpoint", interval, firstDelay, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockAuditCkpt, "Audit-checkpoint", func(ctx context.Context) error {
				res, werr := coreService.RunAuditVerificationTick(ctx)
				if res != nil && res.Written {
					log.Printf("Audit checkpoint written: #%d head=%d events=%d", res.Checkpoint.ID, res.Checkpoint.HeadID, res.Checkpoint.ChainedEvents)
				}
				if res != nil && res.SegmentWalked {
					log.Printf("Audit rolling verification: verified through #%d of #%d (cycle complete: %t)", res.VerifiedThrough, res.CycleTarget, res.CycleCompleted)
				}
				if werr != nil {
					log.Printf("Audit-checkpoint error: %v", werr)
					return werr
				}
				return nil
			})
		})
	}

	// Start the JIT access-expiry sweeper — opt-in. Removes time-bound role grants
	// whose expiry has passed (auditing each as role.expired) and reclaims the rows.
	// Expired grants already stop authorizing immediately (the auth queries filter
	// on expiry); this just keeps the tables clean and writes the expiry audit trail.
	if cfg.JITAccessExpiry.Enabled {
		interval := cfg.JITAccessExpiry.GetInterval()
		log.Printf("JIT access-expiry sweeper enabled: every %s", interval)
		runScheduler(ctx, "jit_access_expiry", interval, func() middleware.SchedulerOutcome {
			// A legal hold preserves the grant rows (the auth queries still deny
			// expired grants immediately, so blocking the sweep loses no security).
			if legalHoldBlocks("JIT access-expiry sweep") {
				return middleware.SchedulerSkipped
			}
			// Single-replica-gated (ADR-039): one replica sweeps per tick.
			return lockedRun(ctx, coreService.Storage(), schedLockJITExpiry, "JIT access-expiry", func(ctx context.Context) error {
				now := time.Now()
				n, rerr := coreService.RemoveExpiredRoleGrants(ctx, now)
				if rerr != nil {
					log.Printf("JIT access-expiry sweep error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("JIT access-expiry sweep removed %d expired grant(s)", n)
				}
				// The same sweep reclaims expired time-bound secret shares (both already
				// stop authorizing immediately; this keeps the tables clean + audited).
				// ShareEffectiveNow, not the bare `now` above: sources this sweep's cutoff
				// from the SAME watermarked clock every other share-active check in this
				// process already uses, instead of an independent real-wall-clock read
				// (#1983 investigation finding).
				sn, serr := coreService.RemoveExpiredShares(ctx, coreService.ShareEffectiveNow())
				if serr != nil {
					log.Printf("JIT access-expiry share-sweep error: %v", serr)
					return serr
				}
				if sn > 0 {
					log.Printf("JIT access-expiry sweep removed %d expired share(s)", sn)
				}
				return nil
			})
		})
	}

	// Start the dynamic-secrets auto-revoke sweeper (ADR-035) — opt-in. Revokes
	// every active lease past its expiry so credentials don't outlive their TTL.
	if cfg.DynamicSecrets.SweepEnabled {
		interval := cfg.DynamicSecrets.GetSweepInterval()
		log.Printf("Dynamic-secrets auto-revoke sweeper enabled: every %s", interval)
		runScheduler(ctx, "dynamic_secret_sweep", interval, func() middleware.SchedulerOutcome {
			// Single-replica-gated (ADR-039): one replica revokes per tick, so
			// replicas don't storm the target DBs revoking the same leases.
			return lockedRun(ctx, coreService.Storage(), schedLockDynamicSweep, "Dynamic-secrets sweep", func(ctx context.Context) error {
				// EffectiveNow, not a bare time.Now(): sources this sweep's cutoff from
				// this process's injected/testable clock (#1983 investigation finding).
				n, rerr := coreService.RevokeExpiredLeases(ctx, coreService.EffectiveNow())
				if rerr != nil {
					log.Printf("Dynamic-secrets sweep error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Dynamic-secrets sweep revoked %d expired lease(s)", n)
				}
				return nil
			})
		})
	}

	// Prune expired login-attempt records every 15 minutes (ADR-040). Single-replica-
	// gated and ALWAYS run — login_attempts are ephemeral rate-limit data (never legal
	// evidence), so this is deliberately NOT subject to legalHoldBlocks: a long-running
	// legal hold must not stop the prune, or the table grows unbounded (an attacker
	// failing logins from rotating IPs would exhaust disk). The rate-limit window is
	// 15 minutes, so a 15-minute cadence keeps the table at roughly one window of rows.
	runScheduler(ctx, "login_attempt_prune", 15*time.Minute, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockLoginPrune, "Login-attempt prune", func(ctx context.Context) error {
			// Zero `before` and a zero actorID: PruneLoginAttempts resolves the
			// cutoff itself (now - LoginWindow) and attributes the event to no
			// human/machine principal. System-actored via WithActorType so the
			// resulting data.login_attempts_pruned audit event (when anything is
			// removed) reads as "system", not the default "user".
			sysCtx := core.WithActorType(ctx, core.ActorTypeSystem)
			_, perr := coreService.PruneLoginAttempts(sysCtx, time.Time{}, 0)
			return perr
		})
	})

	// Prune expired MFA step-up grant rows every 6 hours (store-mfa-002). Each
	// successful VerifyMFAStepUp creates a new MFAStepUpGrant row, kept briefly
	// past its own expiry for audit purposes (internal/storage/store/
	// local_mfa_stepup_grant.go) — with no sweep, every legitimate
	// re-verification left a permanent row. This scheduler calls
	// PruneMFAStepUpGrants below, not DeleteMFAStepUpGrantsFor -- that older
	// method was originally only reachable via the now-deleted RemoteStorage
	// proxy and has zero callers of any kind today (interface.go's declaration
	// and the generated fault-injection wrapper aside); another follow-up
	// cleanup candidate, not removed here. Like login_attempt_prune above, this
	// ALWAYS runs — not
	// legal-hold-gated: a grant row's CREATION is already permanently,
	// independently audited (mfa.stepup_verified, never purged — ADR-029), so
	// pruning the row itself never destroys evidence, only a redundant
	// operational copy, and letting a long-running legal hold block this would
	// just grow the table unbounded for no compliance benefit. Retention
	// defaults to 30 days (config classification.mfa_stepup_grant_retention_days,
	// mirroring SoftDeleteConfig's default) — much looser than the 15-minute
	// cadence/window ratio login_attempt_prune uses, since grant rows are
	// created far less often (once per MFA step-up verification, not once per
	// rate-limit check).
	// Owed audit rows (core audit_owed.go): a plain secret suspend never waits for
	// the audit log, so a secret.suspended row the audit log refused is kept in
	// pending_audit_events and written here once the audit log accepts writes
	// again. Every minute; single-replica-gated, and exactly-once anyway (the
	// claim and the append share a transaction).
	coreService.PublishOwedAuditMetric() // keyorix_audit_owed_pending, authenticated scheduler-metrics only
	runScheduler(ctx, "audit_owed_backfill", time.Minute, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockOwedAudit, "Owed audit backfill", func(ctx context.Context) error {
			_, berr := coreService.BackfillPendingAuditEvents(ctx)
			return berr
		})
	})

	mfaGrantRetention := time.Duration(cfg.Classification.GetMFAStepUpGrantRetentionDays()) * 24 * time.Hour
	runScheduler(ctx, "mfa_stepup_grant_prune", 6*time.Hour, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockMFAGrantPrune, "MFA step-up grant prune", func(ctx context.Context) error {
			_, perr := coreService.PruneMFAStepUpGrants(ctx, mfaGrantRetention, time.Time{})
			return perr
		})
	})

	// Alert on recover-admin use (F7, Akeyless-style) — ALWAYS runs, not
	// opt-in: `recover-admin` bypasses RBAC by design (host access + the
	// recovery key alone), so an install must not be able to silently turn
	// off being notified when it's used. Runs once immediately on startup
	// (the primary trigger — recover-admin is an offline CLI command, so
	// the next server start after it ran is normally the first chance to
	// alert) and every 10 minutes thereafter as a safety net (e.g. an HA
	// replica whose own process never restarted). Single-replica-gated
	// (ADR-039) so admins aren't notified N times in an HA deployment.
	runScheduler(ctx, "recover_admin_alert", 10*time.Minute, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockRecoverAdminAlert, "Recover-admin alert", func(ctx context.Context) error {
			n, aerr := coreService.RunRecoverAdminAlerting(ctx)
			if aerr != nil {
				return aerr
			}
			if n > 0 {
				log.Printf("Recover-admin alert: notified %d recover-admin use(s)", n)
			}
			return nil
		})
	})

	// Warn about break-glass activations that have gone unreviewed past the
	// configured review window (ADR-112 §3, item 4/5; #2461) — ALWAYS runs,
	// deliberately not gated on cfg.BreakGlass.Enabled, for the same reason the
	// recover-admin alert above isn't opt-in: an install that has since turned
	// break-glass OFF can still be holding unreviewed activations from when it
	// was on, and those are precisely the ones that must not quietly drop off
	// the report. Runs once immediately on startup (the "startup warning" half)
	// and every 6h thereafter. Single-replica-gated (ADR-039) so an HA
	// deployment logs and audits this once per pass, not once per replica.
	//
	// Visibility only — see RunBreakGlassReviewReminder's own doc comment for
	// why ADR-112's "enforced" is a posture deviation plus this warning, and
	// explicitly NOT a lockout.
	runScheduler(ctx, "break_glass_review_reminder", 6*time.Hour, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockBreakGlassReview, "Break-glass review reminder", func(ctx context.Context) error {
			_, rerr := coreService.RunBreakGlassReviewReminder(ctx)
			return rerr
		})
	})

	// Start the read-quota alert scheduler — opt-in. Scans all secrets with MaxReads > 0
	// and sends in-app notifications to their owners when usage reaches 80 % (Warning)
	// or 95 % / 100 % (Critical / Exhausted). Single-replica-gated (ADR-039).
	if cfg.ReadQuotaAlerts.Enabled {
		interval := cfg.ReadQuotaAlerts.GetInterval()
		log.Printf("Read-quota alert scheduler enabled: every %s", interval)
		runScheduler(ctx, "read_quota_alerts", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockReadQuota, "Read-quota alerts", func(ctx context.Context) error {
				result, rerr := coreService.CheckReadQuotas(ctx)
				if rerr != nil {
					log.Printf("Read-quota alert scan error: %v", rerr)
					return rerr
				}
				if result.Warnings+result.Criticals > 0 {
					log.Printf("Read-quota alert scan: %d warning(s), %d critical(s), %d exhausted",
						result.Warnings, result.Criticals, result.Exhausted)
				}
				return nil
			})
		})
	}
	return schedulers.Wait
}

// errHTTPServerFailedToStart wraps every error startHTTPServer can return
// BEFORE it ever starts serving (router construction, TLS config, listener
// bind) — as opposed to server.Shutdown()'s own error return at the very
// bottom of the function, which only happens during an already-intentional
// shutdown. main()'s caller uses errors.Is against this to fail the process
// fatally on a genuine startup failure while leaving a slow-shutdown timeout
// logged only, as before (RELEASE-QA finding: a bind failure like "address
// already in use" left the process running indefinitely with nothing bound,
// since the only caller just log.Printf'd a non-nil return and fell through
// to waiting on a shutdown signal that would never come).
var errHTTPServerFailedToStart = errors.New("HTTP server failed to start")

func startHTTPServer(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) error { // NOSONAR -- cognitive complexity 188, suppress go:S3776
	// Create HTTP router
	router, err := httpServer.NewRouter(cfg, coreService)
	if err != nil {
		return fmt.Errorf("%w: failed to create HTTP router: %v", errHTTPServerFailedToStart, err)
	}

	server := newHTTPServer(cfg.Server.HTTP.ListenAddr(), router)

	// Configure TLS if enabled
	if cfg.Server.HTTP.TLS.Enabled {
		tlsConfig, err := createTLSConfig(cfg)
		if err != nil {
			return fmt.Errorf("%w: failed to create TLS config: %v", errHTTPServerFailedToStart, err)
		}
		server.TLSConfig = tlsConfig
	}

	// Bind the listener early so we can confirm the address before serving.
	ln, err := bindListener(cfg.Server.HTTP)
	if err != nil {
		return fmt.Errorf("%w: failed to bind HTTP listener: %v", errHTTPServerFailedToStart, err)
	}

	scheme := "http"
	if cfg.Server.HTTP.TLS.Enabled {
		scheme = "https"
	}
	log.Printf("HTTP server listening on %s://%s%s", scheme, ln.Addr().String(), bindScopeNote(cfg.Server.HTTP.BindHost()))

	// Start server
	go func() {
		var serveErr error
		if cfg.Server.HTTP.TLS.Enabled {
			if cfg.Server.HTTP.TLS.AutoCert {
				// checkTransportTLSPosture already validated tls.allowed_ciphers at boot,
				// so this should never fail in practice; handled defensively anyway.
				autoCertTLSConfig, err := buildAutoCertTLSConfig(cfg.Server.HTTP.TLS.Domains, cfg.Server.HTTP.TLS, cfg.Server.HTTP.TLSMode)
				if err != nil {
					log.Printf("HTTP server error: %v", err)
					return
				}
				server.TLSConfig = autoCertTLSConfig
				serveErr = server.ServeTLS(ln, "", "")
			} else {
				// Empty file names: the certificate comes from TLSConfig.GetCertificate
				// (tlsreload). Passing the files here would pin the pair loaded now.
				serveErr = server.ServeTLS(ln, "", "")
			}
		} else {
			serveErr = server.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", serveErr)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // NOSONAR
	defer cancel()

	log.Println("Shutting down HTTP server...")
	return server.Shutdown(shutdownCtx)
}

// resolvePasswordPolicy merges the configured password_policy block onto the core's
// built-in defaults (ADR-025), so a rule the operator didn't explicitly set keeps its
// safe default instead of collapsing to the Go zero value (#G37). config.PasswordPolicyConfig
// can't return a core.PasswordPolicy directly (internal/config can't import internal/core —
// it would cycle back through internal/encryption), so the conversion happens here instead.
//
// The conversion itself lives in admin.ResolvePasswordPolicy so that
// `admin check-admin-password` (#3201) applies the very same policy.
func resolvePasswordPolicy(pp config.PasswordPolicyConfig) core.PasswordPolicy {
	return admin.ResolvePasswordPolicy(pp)
}

// checkTransportTLSPosture guards against silently serving credentials/secret values in
// cleartext. For each enabled listener without TLS it either fails closed (when
// security.require_transport_tls is set) or logs a prominent warning.
//
// It also fails closed when tls.allowed_ciphers names a cipher suite that isn't a
// recognized, secure TLS 1.2 suite (weak/deprecated suites like RC4/3DES/CBC-mode, or a
// plain typo) — allowed_ciphers is now genuinely wired into the HTTP and gRPC TLS
// builders (#333, applyTLSHardening in server/main.go and server/grpc/server.go), so a
// bad value here would otherwise only surface as a confusing runtime TLS handshake
// failure instead of a clear startup error.
//
// protocol_versions remains a separate, still-unwired tuning field (out of scope for
// #333 — the TLS 1.2 floor stays fixed in code) — it still only warns, not fails, so an
// operator isn't misled into thinking it took effect.
//
// For HTTP specifically, a cleartext listener commonly means "TLS is terminated by a
// reverse proxy in front of this" (the topology production.yaml/web-enabled.yaml
// document) — but server.http.trusted_proxies defaults to empty, which makes
// middleware.ClientIP ignore X-Forwarded-For/X-Real-IP and use the raw TCP peer address
// (the proxy's own IP, not the real client's) for every request. That silently breaks
// per-client rate limiting and audit logging, with no error, so warn whenever both hold:
// this is deliberately a warning, not a fail-closed check — an empty trusted_proxies is
// also the correct, safe setting for a listener that has NO proxy in front of it, and
// config alone can't tell the two cases apart.
func checkTransportTLSPosture(cfg *config.Config) error {
	require := cfg.Security.RequireTransportTLS
	check := func(name string, inst config.ServerInstanceConfig) error {
		if !inst.Enabled {
			return nil
		}
		// allowed_ciphers is honored now (#333) — validate it up front so a
		// misspelled/weak/deprecated cipher name fails closed at startup instead of
		// only surfacing when a client fails to negotiate a TLS connection.
		if _, err := inst.TLS.ResolveCipherSuites(nil); err != nil {
			return fmt.Errorf("%s %w", name, err)
		}
		// protocol_versions is parsed but still not wired into the TLS builders — warn
		// whenever it's set (TLS on or off) so an operator isn't misled into thinking it
		// took effect.
		if len(inst.ProtocolVersions) > 0 {
			log.Printf("WARNING: %s protocol_versions is set but NOT honored — the TLS 1.2 minimum is fixed in code.", name)
		}
		// tls.allowed_ciphers has no effect under tls_mode: strict (TLS 1.3 negotiates
		// its own, always-AEAD suite set — see applyTLSHardening) — warn so an operator
		// isn't misled into thinking a configured allowlist is still narrowing anything.
		if inst.TLSMode == config.TLSModeStrict && len(inst.TLS.AllowedCiphers) > 0 {
			log.Printf("WARNING: %s tls.allowed_ciphers is set but has no effect under tls_mode: strict (TLS 1.3 only).", name)
		}
		if inst.TLS.Enabled {
			return nil
		}
		if require {
			return fmt.Errorf("%s listener has no TLS but security.require_transport_tls is set: refusing to serve credentials/secrets in cleartext (enable tls or front it with a TLS-terminating proxy and unset the requirement)", name)
		}
		log.Printf("WARNING: %s listener is serving CLEARTEXT (no TLS) — bearer tokens and secret values are unencrypted. Front it with a TLS-terminating proxy, enable tls, or set security.require_transport_tls to fail closed.", name)
		if name == "HTTP" && len(inst.TrustedProxies) == 0 {
			log.Printf("WARNING: HTTP listener has TLS disabled and server.http.trusted_proxies is empty. If a reverse proxy terminates TLS in front of this listener (as the cleartext warning above implies), X-Forwarded-For/X-Real-IP are being IGNORED and every client IP resolves to the proxy's address — silently breaking per-client rate limiting and audit logging. Set trusted_proxies to your proxy's address/CIDR, or ignore this if the listener truly has no proxy in front of it.")
		}
		return nil
	}
	if err := check("HTTP", cfg.Server.HTTP); err != nil {
		return err
	}
	return check("gRPC", cfg.Server.GRPC)
}

// runStartupValidation runs internal/startup.ValidateStartup — the file-permission,
// encryption-key (DEK/salt existence + size), and database-reachability checks that were
// previously reachable ONLY via the manual `keyorix system validate` CLI subcommand,
// despite that command's own help text and SYSTEM_SETUP.md/docs/CONFIGURATION.md claiming
// they run automatically on every boot (#330).
//
// Gated behind security.enable_file_permission_check — the flag these checks are
// documented under and the one production.yaml/web-enabled.yaml explicitly turn on.
// ADR-112 flips this flag's default to true (config.Load resolves an absent key to true,
// not Go's bool zero value) — enforceKeyFilePermissions below still runs unconditionally
// as the lighter-weight, always-on permission check it always was. When the flag is set,
// ValidateStartup itself decides warn-vs-fail-closed for a bad permission via
// insecure_allow_unsafe_file_permissions, and auto-fixes bad permissions when
// auto_fix_file_permissions is set (run first, before enforceKeyFilePermissions, so an
// auto-fix takes effect before that check re-inspects the same files) — any other failure
// (missing/undersized DEK or salt, unreachable local database) refuses to start, matching
// this being "the sole automated backstop for a world-readable master-key-material file."
//
// ADR-112 grace period: only an UPGRADED deployment that never explicitly set this key
// and has never yet booted clean under the check (EnableFilePermissionCheckUpgradeGrace,
// decided from the database by adr112UpgradeGraceEligible) gets a start-up warning instead
// of an instant boot-blocking regression if ValidateStartup finds a problem. A fresh
// install with the implicit default is enforced from its first start. A deployment that
// explicitly set the key is unaffected: an explicit true keeps the strict ValidateStartup
// and fails closed exactly as before (including on missing key material), an explicit
// false still skips the whole check below exactly as before.
func runStartupValidation(cfg *config.Config) error {
	if !cfg.Security.EnableFilePermissionCheck {
		// #G37: unlike checkTransportTLSPosture's cleartext warning, this opt-out was
		// previously silent — an operator relying on the docs' claim that these checks
		// "run automatically" had no signal that they hadn't opted in. enforceKeyFilePermissions
		// (called separately, right after this) still runs unconditionally as the lighter-weight
		// backstop, so this is visibility only, not a behavior change.
		log.Printf("WARNING: security.enable_file_permission_check is false — the DEK/salt existence+size and database-reachability startup checks are SKIPPED. Set it true to enable them.")
		return nil
	}
	configPath := config.ResolvedPath("")
	// Server startup has no --fix flag; remediation is governed solely by the
	// config's Security.AutoFixFilePermissions field, as before.
	//
	// The TOLERANT variant is reachable ONLY through the ADR-112 grace period —
	// never for a deployment that set security.enable_file_permission_check
	// explicitly. That gate is the whole point, not a detail: the tolerance
	// treats "KEK salt AND wrapped DEK both missing" as a fresh install, so with
	// it in force a key volume that failed to mount is explained away as first
	// boot, this function returns nil, and initializeEncryption then GENERATES A
	// FRESH SALT AND DEK — over an existing, still-encrypted database whose real
	// key material is merely unmounted. Every value in it becomes permanently
	// unreadable, and the server reports a clean start while doing it.
	//
	// So the variant follows the same explicit/implicit split the err→warn
	// softening below already follows, and for the same reason: an operator who
	// wrote the key down asked for these checks, and "an explicit true keeps
	// failing closed exactly as before" is what this function's own doc comment
	// above promises. Guarded by
	// TestRunStartupValidation_ExplicitTrue_MissingKeyMaterial_RefusesToStart.
	validate := startup.ValidateStartup
	if cfg.Security.EnableFilePermissionCheckImplicitDefault {
		validate = startup.ValidateStartupTolerant
	}
	result, err := validate(configPath, false)
	if result != nil {
		for _, w := range result.Warnings {
			log.Printf("startup validation warning: %s", w)
		}
		for _, e := range result.Errors {
			log.Printf("startup validation error: %s", e)
		}
	}
	if err != nil {
		if cfg.Security.EnableFilePermissionCheckUpgradeGrace {
			adr112GraceSoftened.Store(true)
			log.Printf("WARNING: startup validation failed (%v) — ADR-112 grace period: this is an upgraded deployment and security.enable_file_permission_check was never set explicitly, so it continues instead of refusing to start. Fix the problem above, then set security.enable_file_permission_check: true explicitly to make this fail closed like a compliant deployment.", err)
			return nil
		}
		return err
	}
	log.Printf("Startup validation passed (config, file permissions, encryption keys, database).")
	return nil
}

// enforceKeyFilePermissions refuses to start (or, by default, loudly warns) when sensitive
// key material on disk — the wrapped DEK, the KEK salt, and TLS private keys — is readable
// by group or other, or is owned by anyone but the server's own uid or root (#3410: the
// owner can replace the file whatever its mode; the rule is secretenv.CheckOwner's, the one
// the KEYORIX_*_FILE secrets follow). Key writes are already 0600, but a file restored from a
// backup with a bad umask, or one left 0644 by an operator, would otherwise expose the wrapped
// DEK / TLS key to any local user with no signal. A wrong owner follows the same
// warn-or-refuse matrix as a wrong mode. Fails closed only when
// security.enable_file_permission_check is set (and not overridden by
// insecure_allow_unsafe_file_permissions); otherwise it warns. A not-yet-created key file (first
// boot) is skipped — it is created at 0600.
//
// ADR-112 implicit default (the key absent from the config): the encryption key material,
// which the server writes itself, fails closed (a fresh install) or warns (an upgrade in the
// grace period). A TLS private key is an input the orchestrator mounts (a Kubernetes Secret
// is root-owned 0644 by default), so under the implicit default it only warns, naming the
// file, its mode and the fix; an explicit enable_file_permission_check: true refuses on it
// as before.
func enforceKeyFilePermissions(cfg *config.Config) error { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(".", p)
	}
	var keyPaths, tlsPaths []string
	if cfg.Storage.Encryption.Enabled {
		keyPaths = append(keyPaths, resolve(cfg.Storage.Encryption.DEKPath), resolve(cfg.Storage.Encryption.SaltPath))
	}
	if cfg.Server.HTTP.TLS.Enabled {
		tlsPaths = append(tlsPaths, cfg.Server.HTTP.TLS.KeyFile)
	}
	if cfg.Server.GRPC.TLS.Enabled {
		tlsPaths = append(tlsPaths, cfg.Server.GRPC.TLS.KeyFile)
	}

	insecureKeys := untrustedKeyFiles(keyPaths)
	insecureTLS := untrustedKeyFiles(tlsPaths)
	if insecureKeys.empty() && insecureTLS.empty() {
		return nil
	}
	sec := cfg.Security
	if !sec.EnableFilePermissionCheck || sec.AllowUnsafeFilePermissions {
		log.Printf("WARNING: %s — chmod 600 and chown to the server's user. Set security.enable_file_permission_check to fail closed instead of warning.", insecureKeys.merge(insecureTLS).describe())
		return nil
	}
	if sec.EnableFilePermissionCheckImplicitDefault {
		for _, f := range insecureTLS.readable {
			log.Printf("WARNING: TLS private key %s is readable beyond its owner — chmod 600 it (Kubernetes: mount the Secret with defaultMode 0400), or set security.enable_file_permission_check: true explicitly to refuse to start on this (ADR-112: on the implicit default an orchestrator-mounted TLS key only warns).", f)
		}
		for _, f := range insecureTLS.foreign {
			log.Printf("WARNING: TLS private key %s — chown it to the server's user or to root (Kubernetes Secret volumes are root-owned, which is trusted), or set security.enable_file_permission_check: true explicitly to refuse to start on this (ADR-112: on the implicit default an orchestrator-mounted TLS key only warns).", f)
		}
		insecureTLS = keyFileProblems{}
		if insecureKeys.empty() {
			return nil
		}
	}
	msg := insecureKeys.merge(insecureTLS).describe()
	if sec.EnableFilePermissionCheckUpgradeGrace {
		// ADR-112 grace period: an upgraded deployment that never explicitly opted into
		// the check — it's failing closed only because of the new secure default. Don't
		// turn a pre-existing bad-permission file (present before this upgrade, previously
		// only warned about) into a boot-blocking regression. Warn loudly instead, naming
		// exactly how to comply. A fresh install never gets here (see
		// adr112UpgradeGraceEligible).
		adr112GraceSoftened.Store(true)
		log.Printf("WARNING: %s — this now fails closed by default (ADR-112); set to warn-only, which is what the pre-upgrade behavior was, with security.insecure_allow_unsafe_file_permissions, or (preferred) chmod the files to 0600, chown them to the server's user, and set security.enable_file_permission_check: true explicitly once compliant.", msg)
		return nil
	}
	return fmt.Errorf("%s — refusing to start (chmod 600 and chown the files to the server's user, or set security.insecure_allow_unsafe_file_permissions to override)", msg)
}

// keyFileProblems is what untrustedKeyFiles found: files readable beyond their owner
// ("path (mode NNN)") and files owned by an account the server does not trust
// ("path (owned by uid N, ...)").
type keyFileProblems struct {
	readable, foreign []string
}

func (k keyFileProblems) empty() bool { return len(k.readable)+len(k.foreign) == 0 }

func (k keyFileProblems) merge(o keyFileProblems) keyFileProblems {
	return keyFileProblems{readable: append(slices.Clone(k.readable), o.readable...), foreign: append(slices.Clone(k.foreign), o.foreign...)}
}

// describe is the operator-facing sentence: one clause per kind of problem.
func (k keyFileProblems) describe() string {
	var parts []string
	if len(k.readable) > 0 {
		parts = append(parts, "key material is readable beyond its owner: "+strings.Join(k.readable, ", "))
	}
	if len(k.foreign) > 0 {
		parts = append(parts, "key material is owned by an account the server does not trust: "+strings.Join(k.foreign, ", "))
	}
	return strings.Join(parts, "; ")
}

// untrustedKeyFiles judges every existing path by mode (any group or other bit) and by
// owner (secretenv.CheckOwner, #3410: the running user or root; any other owner can
// replace the file whatever its mode). The path is stat'd through symlinks, so a
// Kubernetes Secret volume's target is what is judged. Empty and absent paths are skipped.
func untrustedKeyFiles(paths []string) keyFileProblems {
	var out keyFileProblems
	for _, p := range paths {
		if p == "" {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			continue // absent (e.g. created at 0600 on first boot) — nothing to check yet
		}
		if info.Mode().Perm()&0o077 != 0 {
			out.readable = append(out.readable, fmt.Sprintf("%s (mode %o)", p, info.Mode().Perm()))
		}
		if err := secretenv.CheckOwner(info); err != nil {
			if foe, ok := errors.AsType[*secretenv.ForeignOwnerError](err); ok {
				out.foreign = append(out.foreign, fmt.Sprintf("%s (owned by uid %d; the server runs as uid %d and trusts only that uid and root, because the owner can replace the file)", p, foe.UID, foe.ProcessUID))
			} else {
				out.foreign = append(out.foreign, fmt.Sprintf("%s (%v)", p, err))
			}
		}
	}
	return out
}

// generatedBootstrapTokenHint is the log line printed on an uninitialised install when no
// bootstrap token was configured and one was generated for this run. The generated value is
// only ever shown masked, so the line must say how to get a token the operator actually
// holds, not point back at a variable they never set (FIRST-RUN-1).
func generatedBootstrapTokenHint(masked string) string {
	return "system not initialised — no bootstrap token was configured, so this run generated one " +
		"(first 8 + last 4 chars shown; the full value is never logged and cannot be recovered):\n" +
		"    BOOTSTRAP TOKEN: " + masked + "\n" +
		"    To create the first admin, stop the server and start it again with a token you hold: " +
		"set KEYORIX_BOOTSTRAP_TOKEN_FILE to a 0600 file containing it (`keyorix-server admin generate-secrets` creates one), " +
		"then run `keyorix system init --server <url>`"
}

// resolveBootstrapToken returns the operator-pinned bootstrap token from
// KEYORIX_BOOTSTRAP_TOKEN or the file named by KEYORIX_BOOTSTRAP_TOKEN_FILE, or
// "" when neither is set (the caller then generates a one-time token). Both set,
// or an unreadable/empty file, is an error -- never a silent fall-through to a
// generated token.
func resolveBootstrapToken() (string, error) {
	v, found, err := secretenv.Lookup("KEYORIX_BOOTSTRAP_TOKEN")
	if err != nil {
		return "", err
	}
	if !found {
		return "", nil
	}
	return strings.TrimSpace(v), nil
}

// resolveVaultToken returns the Vault connector token from the env var named by
// tokenEnv (default VAULT_TOKEN) or its _FILE variant; "" when unset.
func resolveVaultToken(tokenEnv string) (string, error) {
	if tokenEnv == "" {
		tokenEnv = "VAULT_TOKEN"
	}
	v, _, err := secretenv.Lookup(tokenEnv)
	return v, err
}

// enforceSecretFilePermissions applies the key-material permission policy to the
// files named by *_FILE secret variables (secretenv.CheckPermissions: 0600/0400,
// plus group-read only for an orchestrator-owned file in a group the process
// holds). Key-material secrets (master password, KEK, Shamir shares) are refused
// unconditionally where they are read (secretenv.LookupChecked, no grace); this
// covers the rest, which follow the ADR-112 upgrade grace like the key files.
// Same warn-vs-refuse matrix as enforceKeyFilePermissions: refuse
// when security.enable_file_permission_check is on and
// allow_unsafe_file_permissions is off, otherwise warn.
//
// The policy itself lives in config.Config.EnforceSecretFilePermissions, shared
// with every `keyorix-server admin` command (admin.loadConfig); this wrapper
// only records a grace-softened boot.
func enforceSecretFilePermissions(cfg *config.Config) error {
	softened, err := cfg.EnforceSecretFilePermissions()
	if softened {
		adr112GraceSoftened.Store(true)
	}
	return err
}

// verifyKeyFileSetConsistency is the boot-time key-file-set consistency check
// (ADR-112, follow-up from #2400) — see keyfiles.VerifyKeySetConsistency's own
// doc comment for the two things it checks and why. No-op when encryption is
// disabled: there is no key material to check in the first place.
func verifyKeyFileSetConsistency(cfg *config.Config) error {
	if !cfg.Storage.Encryption.Enabled {
		return nil
	}
	return keyfiles.VerifyKeySetConsistency(&cfg.Storage.Encryption, ".")
}

// logWarnOnImplicitRequireMFADefault logs where security.require_mfa stands when the
// config file never set it (ADR-112 resolves an absent key to true;
// RequireMFAImplicitDefault is true only then).
//
// On a fresh install (or a deployment already enforced once) MFA is enforced and this is
// informational: server/middleware.EnforceAccountSetup confines a session-authenticated
// user without MFA to the enrolment endpoints (never locks the account out; PAT/machine
// credentials are exempt). On an upgraded deployment, applyADR112UpgradeGrace has put
// require_mfa in ADR-112's grace period (RequireMFAUpgradeGrace): MFA is NOT enforced yet,
// and this warns loudly on every boot until the key is set explicitly.
func logWarnOnImplicitRequireMFADefault(cfg *config.Config) {
	sec := cfg.Security
	switch {
	case sec.RequireMFAUpgradeGrace:
		log.Printf("WARNING: ADR-112 grace period: security.require_mfa now defaults to true, but %s and this config never set it, so MFA is NOT enforced yet. Have every interactive admin enrol (keyorix mfa enroll / activate, or Profile -> Security in the web UI), then set security.require_mfa: true explicitly to enforce it (or false to opt out visibly).", adr112MFAReason)
	case sec.RequireMFA && sec.RequireMFAImplicitDefault:
		reason := adr112MFAReason
		if reason == "" {
			reason = "the key is not set in this config"
		}
		log.Printf("INFO: security.require_mfa is enforcing on its ADR-112 secure-by-default value (%s). Session-authenticated users without MFA are confined to MFA enrolment until they enrol (PAT/machine credentials are unaffected). Set security.require_mfa explicitly to silence this.", reason)
	}
}

// warnDeprecatedSettingAliases logs every ADR-112 deprecated-alias key (an old
// name config.Load translated to its current insecure_ form) found in this
// config file — "deprecated alias, warns when used" (opt-out rule item 2)
// means the old key still works exactly as before, but is never silent about it.
func warnDeprecatedSettingAliases(cfg *config.Config) {
	for _, w := range cfg.DeprecatedSettingWarnings {
		log.Printf("WARNING: deprecated config key: %s", w)
	}
}

// warnHTTPOnlySettingsUnderGRPC logs a start-up warning for every security setting
// written under server.grpc that only the HTTP server implements (the two
// listeners share one config struct). The gRPC server has no client-IP rewrite and
// sends no HSTS, so these keys would otherwise be accepted and silently do nothing.
// The loader does not reject other HTTP-only keys under grpc either, so this warns
// rather than failing the boot.
func warnHTTPOnlySettingsUnderGRPC(cfg *config.Config) {
	for _, w := range config.HTTPOnlySettingsSetUnderGRPC(cfg) {
		log.Printf("WARNING: %s", w)
	}
}

// warnInsecureSettingsInEffect logs a start-up warning for every ADR-112
// registry entry currently in effect — unconditionally, on every boot, so a
// security-weakening setting can never be silently in effect (opt-out rule
// item 2's "a start-up warning for every insecure_ setting in effect").
// Looping config.InsecureSettingsRegistry here is also half of what makes
// TestInsecureSettingsRegistry_EveryEntryHasThePrefixWarningAndAuditHook's
// guarantee hold: every entry with a non-nil InEffect is warned about by
// construction, with no per-entry call site that could forget to wire one in.
func warnInsecureSettingsInEffect(cfg *config.Config) {
	for _, s := range config.InsecureSettingsRegistry {
		if s.InEffect(cfg) {
			log.Print(insecureSettingWarning(s, cfg))
		}
	}
}

// insecureSettingWarning is the start-up line for one registry entry in effect.
// Name is a stable identifier, not always a key an operator can set today:
// when it is not one of SourcePaths, the line says so and names the key that
// actually controls the state (Cause, or the SourcePaths), so nobody writes
// the registry name into keyorix.yaml and gets an unknown-key error
// (BOOT-REFUSALS-1 item 3).
func insecureSettingWarning(s config.InsecureSetting, cfg *config.Config) string {
	if slices.Contains(s.SourcePaths, s.Name) {
		return fmt.Sprintf("WARNING: %s is in effect (%s; config: %s) — %s", s.Name, s.Value(cfg), strings.Join(s.SourcePaths, ", "), s.Describe)
	}
	cause := "it follows " + strings.Join(s.SourcePaths, ", ")
	if s.Cause != nil {
		cause = s.Cause(cfg)
	}
	return fmt.Sprintf("WARNING: %s is in effect (%s) — %s. That is the setting's registry name, not a config key: %s", s.Name, s.Value(cfg), s.Describe, cause)
}

// resolveADR112BootPosture applies the ADR-112 upgrade-grace decision and THEN
// warns about every registry entry in effect. The order is the point (#2908):
// security.insecure_skip_startup_validation's grace-warn-only state is read
// from EnableFilePermissionCheckUpgradeGrace, which only
// applyADR112UpgradeGrace sets. Warning first -- main's order before #2908 --
// evaluated that entry with the flag still false, so a grace-period
// deployment that only warns on a failed startup check got no opt-out warning.
func resolveADR112BootPosture(cfg *config.Config) {
	applyADR112UpgradeGrace(cfg)
	warnInsecureSettingsInEffect(cfg)
}

// securityPostureSnapshot computes this boot's value of every ADR-112
// registry entry, keyed by its Name — the input to
// coreService.ReconcileSecurityPostureSnapshot's start-to-start diff. Looping
// config.InsecureSettingsRegistry here is the other half of
// TestInsecureSettingsRegistry_EveryEntryHasThePrefixWarningAndAuditHook's
// guarantee: every entry with a non-nil Value is audited by construction.
//
// config.TrackedSettings (settings that are never a deviation, such as
// storage.database.audit_durability) are diffed the same way, so a change of
// one between two starts is audited with its old and new value.
func securityPostureSnapshot(cfg *config.Config) map[string]string {
	snapshot := make(map[string]string, len(config.InsecureSettingsRegistry)+len(config.TrackedSettings))
	for _, s := range config.InsecureSettingsRegistry {
		snapshot[s.Name] = s.Value(cfg)
	}
	for _, s := range config.TrackedSettings {
		snapshot[s.Name] = s.Value(cfg)
	}
	return snapshot
}

// logAuditDurability logs the start-up INFO line for the effective
// storage.database.audit_durability, e.g. "audit durability: standard
// (PostgreSQL default; committed before every disclosure; ...)".
func logAuditDurability(cfg *config.Config) {
	log.Printf("INFO: %s", cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type).StartupLine())
}

func startGRPCServer(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) error {
	// Create gRPC server
	grpcServer, err := grpc.NewServer(cfg, coreService)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %w", err)
	}

	// Create listener
	lis, err := bindListener(cfg.Server.GRPC)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port: %w", err)
	}

	log.Printf("gRPC server listening on %s%s", lis.Addr().String(), bindScopeNote(cfg.Server.GRPC.BindHost()))

	// Start server
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	log.Println("Shutting down gRPC server...")
	stopGRPCServerWithTimeout(grpcServer, grpcShutdownTimeout)
	return nil
}

// grpcShutdownTimeout bounds how long startGRPCServer waits for
// grpcServer.GracefulStop() to drain in-flight RPCs before falling back to
// the forceful grpcServer.Stop(). Matches the HTTP listener's shutdownCtx
// timeout (see startHTTPServer) so neither transport can block shutdown past
// 10s on its own — main()'s outer 30s select/time.After backstop only forces
// process exit; it never calls grpcServer.Stop() or otherwise interrupts a
// goroutine still blocked inside GracefulStop(), so without this the abandoned
// goroutine (and any in-flight RPC/cleanup inside it) would just be leaked
// rather than drained deterministically.
const grpcShutdownTimeout = 10 * time.Second

// grpcGracefulStopper is the subset of *grpc.Server's shutdown surface that
// stopGRPCServerWithTimeout needs. Extracted as an interface (rather than
// depending on *grpc.Server directly) so a test can exercise the
// timeout/fallback branch with a fake whose GracefulStop() blocks
// indefinitely, without standing up a real gRPC listener or an actual
// long-lived RPC.
type grpcGracefulStopper interface {
	GracefulStop()
	Stop()
}

// stopGRPCServerWithTimeout runs gs.GracefulStop() in a goroutine and waits
// up to timeout for it to finish draining in-flight RPCs. A client that opens
// a long-lived or slow streaming RPC (e.g. StreamAuditLogs) and never closes
// it would otherwise block GracefulStop() forever; if timeout fires first,
// this calls gs.Stop() to forcibly cancel every outstanding RPC immediately
// instead of leaving that goroutine — and whatever RPC/cleanup it's still
// waiting on — abandoned mid-flight when main() eventually gives up.
func stopGRPCServerWithTimeout(gs grpcGracefulStopper, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		gs.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		log.Println("gRPC graceful shutdown timeout exceeded, forcing stop")
		gs.Stop()
	}
}

func createTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Server.HTTP.TLS.AutoCert {
		// AutoCert mode builds its tls.Config separately, from the autocert.Manager
		// (see buildAutoCertTLSConfig) — it still gets the same hardening applied.
		return nil, nil
	}

	// The certificate is served through tlsreload so a pair rotated on disk is
	// picked up without a restart; a pair that does not load still fails here.
	reloader, err := tlsreload.New(cfg.Server.HTTP.TLS.CertFile, cfg.Server.HTTP.TLS.KeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{GetCertificate: tlsmetrics.Wrap(tlsmetrics.HTTP, reloader.GetCertificate)} // nosemgrep: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion -- applyTLSHardening below sets MinVersion unconditionally on every path
	if err := applyTLSHardening(tlsConfig, cfg.Server.HTTP.TLS, cfg.Server.HTTP.TLSMode); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

// hardenedCipherSuites is the explicit AEAD-only cipher suite allowlist applied to
// every HTTP TLS listener, regardless of how its certificate is sourced, UNLESS the
// operator has explicitly configured tls.allowed_ciphers (#333) — in which case that
// configured list is honored instead (see applyTLSHardening).
var hardenedCipherSuites = config.DefaultCipherSuites

// applyTLSHardening layers the hardened MinVersion/CipherSuites onto tlsConfig in
// place. The protocol-version floor and cipher-suite allowlist are independent of how
// the certificate itself is sourced, so this must be applied uniformly whether
// tlsConfig came from a manually configured cert/key pair (createTLSConfig) or from an
// autocert.Manager (buildAutoCertTLSConfig) — AutoCert should only supply the
// certificate, not silently determine the rest of the TLS posture too (#172).
//
// CipherSuites is resolved from tlsCfg.AllowedCiphers (#333): when the operator has
// left tls.allowed_ciphers unset, the hardcoded hardenedCipherSuites default above
// applies unchanged (no regression for existing deployments); when they've set it,
// their configured suite list is honored instead — validated against
// config.SecureCipherSuiteNames, so a weak/deprecated/misspelled suite name fails
// closed at startup rather than being silently ignored (the previous behavior) or
// silently accepted. MinVersion stays fixed at TLS 1.2 UNLESS mode is
// config.TLSModeStrict (ADR-112 §3, "tls_mode: strict"), in which case Min/MaxVersion
// are both pinned to TLS 1.3 and CipherSuites is left untouched: TLS 1.3 has no
// equivalent per-suite selection (crypto/tls negotiates its own, always-AEAD suite
// set), so there is nothing for allowed_ciphers to configure under either mode.
func applyTLSHardening(tlsConfig *tls.Config, tlsCfg config.TLSConfig, mode string) error {
	if mode == config.TLSModeStrict {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
		return nil
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	suites, err := tlsCfg.ResolveCipherSuites(hardenedCipherSuites)
	if err != nil {
		return fmt.Errorf("invalid TLS configuration: %w", err)
	}
	tlsConfig.CipherSuites = suites
	return nil
}

// buildAutoCertTLSConfig builds the tls.Config for HTTP AutoCert (Let's Encrypt-style
// automatic certificate management) mode: the autocert.Manager supplies the
// certificate (via GetCertificate/NextProtos), and the same hardened
// MinVersion/CipherSuites as the non-AutoCert path (createTLSConfig) are layered on
// top instead of being silently discarded (#172), honoring tls.allowed_ciphers the
// same way createTLSConfig does (#333).
func buildAutoCertTLSConfig(domains []string, tlsCfg config.TLSConfig, mode string) (*tls.Config, error) {
	cacheDir := tlsCfg.CertCacheDir
	if cacheDir == "" {
		cacheDir = "certs"
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("autocert: cannot create cert cache dir %q: %w", cacheDir, err)
	}
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
	}
	tlsConfig := m.TLSConfig()
	if err := applyTLSHardening(tlsConfig, tlsCfg, mode); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

// bindListener is the only place the server opens a TCP listener for its HTTP
// and gRPC transports. It binds server.<transport>.host (default
// config.DefaultBindHost, loopback only) so the address in the startup log is
// the address actually bound (#2939: it used to bind ":port", all interfaces,
// while the log claimed 127.0.0.1).
func bindListener(inst config.ServerInstanceConfig) (net.Listener, error) {
	return net.Listen("tcp", inst.ListenAddr())
}

// bindScopeNote returns a log suffix saying who can reach a listener bound to
// host. Empty for loopback, a warning for any wider bind.
func bindScopeNote(host string) string {
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return ""
	}
	if ip != nil && ip.IsUnspecified() {
		return " (ALL interfaces: reachable from the network; set server.*.host to 127.0.0.1 to restrict)"
	}
	return " (non-loopback interface: reachable from the network)"
}

// oidcDiscovery is the subset of an OIDC discovery document we need.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// maxDiscoveryBytes caps the discovery document we read into memory.
const maxDiscoveryBytes = 1 << 20 // 1 MiB

// oidcDiscoveryTransport guards the SSO OIDC-discovery fetch the same way
// jwksEgressTransport guards the JWKS fetch (F2, adversarial-review 2026-09-14):
// clone http.DefaultTransport (preserving proxy-from-environment and pooling, the
// prior behaviour) and re-validate every direct-dial target against
// netutil.IsLinkLocal, so a misconfigured or compromised issuer whose
// /.well-known/openid-configuration resolves to the cloud instance-metadata
// endpoint (169.254.169.254) can never be dialed. Link-local-only by design:
// RFC-1918/on-prem and loopback issuers stay reachable (requireSecureOrLoopback
// already permits http on loopback for dev), which is keyorix's primary
// deployment shape. When an egress proxy is configured the dial targets the proxy
// rather than the issuer — accepted, same as the JWKS client.
var oidcDiscoveryTransport = func() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&netutil.Dialer{Disallow: netutil.IsLinkLocal}).DialContext
	return tr
}()

// discoverOIDC fetches an issuer's /.well-known/openid-configuration and validates
// it. The issuer must use https (http only for loopback) so the document — which
// names the jwks_uri that ultimately supplies the token-signing keys — is not
// fetched over plaintext where a MITM could redirect key fetching to attacker keys.
// Per the OIDC spec the document's own issuer must equal the configured issuer, and
// the jwks_uri it advertises must live on the issuer's host, so a tampered/hostile
// discovery doc can't point key fetching at an unrelated host.
func discoverOIDC(issuer string) (*oidcDiscovery, error) {
	iss, err := url.Parse(strings.TrimRight(issuer, "/"))
	if err != nil || iss.Host == "" {
		return nil, fmt.Errorf("invalid issuer %q", issuer)
	}
	if err := requireSecureOrLoopback(iss, "issuer"); err != nil {
		return nil, err
	}

	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     oidcDiscoveryTransport,
		CheckRedirect: noDiscoveryCrossOriginRedirect,
	}
	resp, err := client.Get(u) // #nosec G107 -- issuer is operator-configured and https-validated above
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned %s", resp.Status)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoveryBytes)).Decode(&d); err != nil {
		return nil, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document is missing required endpoints")
	}
	if d.Issuer != "" && strings.TrimRight(d.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, fmt.Errorf("discovery issuer %q does not match configured issuer %q", d.Issuer, issuer)
	}
	jwksURL, err := url.Parse(d.JWKSURI)
	if err != nil || jwksURL.Host == "" {
		return nil, fmt.Errorf("discovery jwks_uri %q is invalid", d.JWKSURI)
	}
	if !strings.EqualFold(jwksURL.Hostname(), iss.Hostname()) {
		return nil, fmt.Errorf("discovery jwks_uri host %q does not match issuer host %q", jwksURL.Hostname(), iss.Hostname())
	}
	return &d, nil
}

// requireSecureOrLoopback rejects a non-https URL unless its host is loopback.
func requireSecureOrLoopback(u *url.URL, label string) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHostname(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%s %q must use https (http is allowed only for localhost)", label, u.Redacted())
}

func isLoopbackHostname(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// noDiscoveryCrossOriginRedirect rejects a discovery redirect that changes host or
// downgrades the scheme, so a redirect can't pull the document from an unexpected host.
func noDiscoveryCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1].URL
	if !strings.EqualFold(req.URL.Hostname(), prev.Hostname()) {
		return fmt.Errorf("discovery: refusing cross-host redirect to %q", req.URL.Host)
	}
	if prev.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("discovery: refusing scheme downgrade to %q", req.URL.Scheme)
	}
	return nil
}

// DefaultIntegrations wires every ADR-109 integration that has its own
// wireXxx helper (docs/adr-109-core-depends-on-interfaces.md): TimestampNotary
// + its receipt verifier, SAMLServiceProvider (folded into human SSO wiring
// alongside OIDC), RotationExecutorResolver, DynamicBackendFactory, and
// ConnectorResolver — steps 1 through 4. Encryption (step 5,
// EncryptionProvider) is ALSO fully behind internal/core/ports as of step 5 —
// coreIntegrationDeps is empty, machine-checked by
// TestCoreIntegrationDepsAllowlistIsEmpty — but its own wiring
// (SetSecretValueEncryptor/SetAuthEncryptor, initializeCoreService, above
// this function's own call site) was deliberately NOT moved here: it feeds
// audit-checkpoint and evidence-pack signing keys that are derived and wired
// immediately after it and before DefaultIntegrations is ever called, so
// folding it in would either reorder that dependency or require threading
// the derived keys back out of DefaultIntegrations for no decoupling benefit
// — ADR-109's target is internal/core's import graph, not where each
// integration's own bootstrapping code physically lives.
//
// A nil implementation means the feature is unavailable; wiring never fails
// open (ADR-109 decision #2). A malformed config for an explicitly ENABLED
// feature returns an error and stops boot (the ADR-082 fail-closed shape); a
// feature left disabled, or a single misconfigured provider/backend within an
// enabled one, is skipped with a warning — unchanged from this wiring's
// pre-ADR-109 behavior. DynamicBackendFactory is the one exception: it is
// always wired unconditionally (there is no top-level "enabled" flag for
// dynamic secrets — each DynamicSecretConfig opts in individually), matching
// internal/core.dynamicEngine's pre-ADR-109 unconditional fallback to
// internal/dynamic.New. wireConnect calls log.Fatalf directly, rather than
// returning an error, for the same boot-time misconfigurations the pre-ADR-109
// inline block already treated as fatal (ADR-082) — unchanged behavior, only
// the call site moved.
func DefaultIntegrations(cfg *config.Config, coreService *core.KeyorixCore) error {
	if err := wireCheckpointNotary(cfg, coreService); err != nil {
		return err
	}
	wireHumanSSO(cfg, coreService)
	if err := wireBackendRotation(cfg, coreService); err != nil {
		return err
	}
	wireDynamicSecrets(cfg, coreService)
	if err := wireConnect(cfg, coreService); err != nil {
		return err
	}
	return nil
}

// wireBackendRotation wires the configured backend rotation executors (ADR-047)
// — upstream systems whose credentials the auto-rotation flow can rotate in
// place. Admin DSNs come from the environment, never the config file. A
// backend with an unknown type, or one missing its fail-closed allowed_refs
// allowlist, is skipped with a warning rather than failing startup — matching
// this wiring's pre-ADR-109 behavior. A KNOWN cloud backend type (aws-iam,
// gcp-service-account, azure-app) whose implementation this server binary
// was compiled without (a no<provider> build tag) is a different condition —
// that fails startup outright (ADR-109 step 6, S2): never fail open on a
// config the operator explicitly enabled. Returned (not log.Fatalf'd)
// specifically for that one condition so it is testable in-process — see
// server/rotation_failclosed_noaws_test.go and its nogcp sibling.
func wireBackendRotation(cfg *config.Config, coreService *core.KeyorixCore) error {
	if len(cfg.AutoRotation.Backends) == 0 {
		return nil
	}
	var execs []rotation.Executor
	for _, b := range cfg.AutoRotation.Backends {
		switch b.Type {
		case "postgresql":
			// Fail closed: a backend runs privileged DDL with an admin DSN, so an
			// explicit allow-list is required — refuse to register an unbounded one.
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			dsn := b.GetDSN()
			if dsn == "" {
				log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
			}
			execs = append(execs, rotation.NewPostgresExecutor(b.Name, dsn, b.AllowedRefs))
		case "mysql":
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			dsn := b.GetDSN()
			if dsn == "" {
				log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
			}
			execs = append(execs, rotation.NewMySQLExecutor(b.Name, dsn, b.AllowedRefs))
		case "mongodb":
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			dsn := b.GetDSN()
			if dsn == "" {
				log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
			}
			execs = append(execs, rotation.NewMongoExecutor(b.Name, dsn, b.AllowedRefs))
		case "redis":
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			dsn := b.GetDSN()
			if dsn == "" {
				log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
			}
			execs = append(execs, rotation.NewRedisExecutor(b.Name, dsn, b.AllowedRefs))
		case "aws-iam", "gcp-service-account", "azure-app":
			// Generate-upstream backends: the cloud mints the new credential;
			// credentials for the mint call itself come from the ambient cloud
			// identity chain (no DSN). Still fail-closed on allowed_refs. Routed
			// through rotation.LookupCloudExecutor (ADR-109 step 6) rather than each
			// backend's own constructor directly, because a no<x>-tagged build
			// (e.g. noaws) does not compile that constructor in at all — ok=false
			// is exactly the "not available in this build" signal, handled the
			// same as an unknown type below (S2 hardens this into a startup
			// failure for an explicitly-configured, not-compiled-in backend).
			if len(b.AllowedRefs) == 0 {
				log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
				continue
			}
			exec, ok := rotation.LookupCloudExecutor(b.Type, rotation.CloudExecutorParams{
				Name: b.Name, Region: b.Region, AllowedRefs: b.AllowedRefs,
			})
			if !ok {
				return fmt.Errorf("rotation backend %q has type %q, which this server binary was not built with (excluded by a no%s build tag) — rebuild without that tag, or remove this backend", b.Name, b.Type, cloudProviderTag(b.Type))
			}
			execs = append(execs, exec)
		default:
			log.Printf("Rotation backend %q: unknown type %q, skipping", b.Name, b.Type)
		}
	}
	if len(execs) > 0 {
		coreService.SetRotationManager(rotation.NewManager(execs))
		log.Printf("Backend rotation executors enabled (%d backend(s))", len(execs))
	}
	return nil
}

// cloudProviderTag maps a cloud backend/connector type to the no<provider>
// build tag that excludes it (ADR-109 step 6), for use in a boot-time error
// naming the build profile responsible — e.g. "rotation backend ... excluded
// by a noaws build tag".
func cloudProviderTag(backendOrConnectorType string) string {
	switch backendOrConnectorType {
	case "aws-iam", "aws-secrets-manager", "aws-sts", "aws-kms":
		return "aws"
	case "gcp-service-account", "gcp-secret-manager", "gcp", "gcp-kms":
		return "gcp"
	case "azure-app", "azure-key-vault", "azure", "azure-kms":
		return "azure"
	default:
		return "<provider>"
	}
}

// wireCheckpointNotary wires external-notary anchoring of audit checkpoints when
// enabled (ADR-029): each written checkpoint gets an independent RFC 3161
// timestamp the server cannot forge. Anchoring is best-effort and only
// meaningful when checkpoints are written (which requires encryption).
func wireCheckpointNotary(cfg *config.Config, coreService *core.KeyorixCore) error {
	cn := cfg.Audit.CheckpointNotary
	if !cn.Enabled {
		return nil
	}
	if cn.URL == "" {
		log.Printf("Audit checkpoint notary enabled but no url set; skipping external anchoring")
		return nil
	}
	// NewRFC3161 validates the URL is https (or http to a loopback host, for
	// local testing) — fail closed at startup rather than silently accepting a
	// plaintext TSA URL that would leak every anchored checkpoint hash (and any
	// rogue-response substitution) to a network attacker on the path.
	tsa, err := notary.NewRFC3161(cn.URL, cn.GetTimeout())
	if err != nil {
		return fmt.Errorf("audit.checkpoint_notary: %w", err)
	}
	coreService.SetCheckpointNotary(tsa)
	// Load the TSA trust anchor (and its verifier — internal/notary.VerifyReceipt
	// is a free function, not a TimestampNotary method, so ADR-109 wires it
	// separately; see ports.VerifyReceiptFunc) used to VERIFY stored anchors.
	// Without it, anchoring still records each checkpoint's raw RFC 3161 receipt
	// — that token remains valid, portable proof an independent party holding
	// the TSA's root cert can check out-of-box (#182) — but THIS server cannot
	// re-verify it locally, and must not present a merely-recorded anchor as
	// though it were one this server actually checked against a root of trust.
	// Deliberately not fail-closed here (unlike the URL-scheme check above):
	// anchoring-without-local-verification is a legitimate, intentional
	// configuration (see CheckpointNotaryConfig.CACertPath's doc comment) —
	// the trust root can be wired in later, or verification can be done
	// entirely off-box. Instead, the unverifiable state is surfaced explicitly
	// on every checkpoint-verification read (KeyorixCore.CheckpointAnchorVerifiable,
	// AuditChainVerification.AnchorTrustRootConfigured) so a caller/auditor can
	// always tell a recorded-but-unverifiable anchor apart from a verified one.
	if cn.CACertPath == "" {
		log.Printf("Audit checkpoint external anchoring enabled (rfc3161, url=%s) — WARNING: no ca_cert_path set, stored anchors are recorded but CANNOT be locally verified (checkpoint reads will report them as unverified)", cn.URL)
		return nil
	}
	roots, err := loadCertPool(cn.CACertPath)
	if err != nil {
		log.Printf("Audit checkpoint notary: failed to load ca_cert_path %q (%v) — anchors cannot be verified", cn.CACertPath, err)
		return nil
	}
	coreService.SetCheckpointAnchorRoots(roots, notary.VerifyReceipt)
	log.Printf("Audit checkpoint external anchoring enabled (rfc3161, url=%s, timeout=%s, trust anchor=%s)", cn.URL, cn.GetTimeout(), cn.CACertPath)
	return nil
}

// wireHumanSSO wires human SSO login (OIDC authorization-code flow, and SAML)
// when configured. Each provider's endpoints are discovered from its issuer; a
// provider whose discovery fails (or, for SAML, is misconfigured) is skipped
// with a warning rather than failing startup.
func wireHumanSSO(cfg *config.Config, coreService *core.KeyorixCore) {
	sso := cfg.SSO
	if !sso.Enabled || len(sso.Providers) == 0 {
		return
	}
	providers, jwks, n := buildSSOProviders(sso)
	if n > 0 {
		coreService.SetSSOProviders(providers, jwks)
		log.Printf("Human SSO enabled for %d provider(s)", n)
	}
}

// wireDynamicSecrets wires dynamic-secrets settings (ADR-035) and the default
// credential-engine factory (ports.DynamicBackendFactory, backed by
// internal/dynamic.New — the only place a concrete dynamic-secrets backend is
// still reached, now that internal/core itself depends only on
// ports.DynamicBackendEngine). There is no top-level "enabled" flag for
// dynamic secrets, so — unlike this file's other wireX helpers — the factory
// is always wired unconditionally; each DynamicSecretConfig opts a project
// into a specific backend individually.
func wireDynamicSecrets(cfg *config.Config, coreService *core.KeyorixCore) {
	// Tell core whether the auto-revoke sweeper runs (started below), so IssueLease
	// refuses to mint from backends whose lease TTL only the sweeper enforces
	// (MySQL/MongoDB) when it is disabled — otherwise the credential never expires.
	coreService.SetDynamicSweepEnabled(cfg.DynamicSecrets.SweepEnabled)
	// SSRF guard for admin DSNs: disabled (private targets allowed) only when the
	// operator explicitly opts in via dynamic_secrets.allow_private_network_targets.
	coreService.SetDynamicAllowPrivateTargets(cfg.DynamicSecrets.AllowPrivateNetworkTargets)
	// TLS-required-by-default guard for the mongodb/redis backends: disabled
	// (plaintext allowed) only when the operator explicitly opts in via
	// dynamic_secrets.allow_insecure_transport.
	coreService.SetDynamicAllowInsecureTransport(cfg.DynamicSecrets.AllowInsecureTransport)
	// Install-wide hard ceiling on any dynamic-secret lease's TTL (#97); enforced on
	// top of each config's own optional (default-unbounded) MaxTTLSeconds.
	coreService.SetDynamicMaxLeaseTTL(cfg.DynamicSecrets.GetMaxLeaseTTL())

	// dynamic.New itself re-checks allow-private/allow-insecure per call (an engine
	// that dials the admin DSN re-validates at dial time, G48) — capture the two
	// booleans once here rather than re-reading cfg on every resolve.
	allowPrivate := cfg.DynamicSecrets.AllowPrivateNetworkTargets
	allowInsecure := cfg.DynamicSecrets.AllowInsecureTransport
	coreService.SetDynamicEngineFactory(func(backendType string) (dynamic.CredentialEngine, error) {
		return dynamic.New(backendType, allowPrivate, allowInsecure)
	})
}

// wireConnect wires Keyorix Connect (ADR-043) read-through federation to
// external secret stores, when enabled — the fifth DefaultIntegrations
// component as of ADR-109 step 4 (connect behind ports). Uses
// coreService.Storage() for the boot-time ownership resolution and drift
// check below; core.NewKeyorixCore(store) always sets storage before
// DefaultIntegrations is ever called, so it is available here unconditionally.
func wireConnect(cfg *config.Config, coreService *core.KeyorixCore) error {
	cc := cfg.Connect
	if !cc.Enabled || len(cc.Connectors) == 0 {
		return nil
	}
	// ADR-082 §C: cfg.Validate() already refused to boot with a missing/invalid
	// connector scope — unconditionally, no deployment-wide escape hatch (amended:
	// the original connect.allow_unscoped flag let the server boot, but an unscoped
	// connector still denied on every read via connectOwnershipSatisfied's
	// missing-entry-denies rule, so it never restored actual usability — only
	// deferred the failure from "boot" to "every subsequent read," with a WARN an
	// operator could easily miss. Adding scope: to a connector takes minutes; there
	// is nothing for this migration path to bypass.
	var connectors []connect.Connector
	for _, cn := range cc.Connectors {
		switch cn.Type {
		case "aws-secrets-manager":
			// account_id is optional (unlike gcp-secret-manager's mandatory
			// project_id — see internal/connect/awssm.go's doc comment for why the
			// risk shape differs: a bare secret name never crosses AWS accounts, so
			// the confused-deputy gap only exists for ARN-shaped refs, and even then
			// requires the target account's own resource policy to separately grant
			// access). cfg.Validate()'s validateConnectAWSAccountID already rejected a
			// malformed (non-12-digit) account_id before this function is ever
			// reached; an empty account_id is a legal, if less-hardened,
			// configuration and boots fine, with a warning recommending it be set.
			if cn.AccountID == "" {
				log.Printf("Keyorix Connect: aws-secrets-manager connector %q has no account_id configured — a ref supplied as a full ARN naming a DIFFERENT AWS account will still succeed if that account's own resource policy grants cross-account access; set account_id to pin the connector to one account (a bare secret-name ref is unaffected either way -- Secrets Manager always resolves those within the caller's own account)", cn.Name)
			}
			conn, ok := connect.NewCloudConnector(cn.Type, connect.ConnectorParams{Name: cn.Name, Region: cn.Region, AccountID: cn.AccountID, AllowedRefs: cn.AllowedRefs})
			if !ok {
				return fmt.Errorf("connect: connector %q has type %q, which this server binary was not built with (excluded by the no%s build tag) — rebuild without -tags no%s, or remove this connector", cn.Name, cn.Type, cloudProviderTag(cn.Type), cloudProviderTag(cn.Type))
			}
			connectors = append(connectors, conn)
		case "gcp-secret-manager":
			// project_id is now a required field: unreachable via a config that
			// passed cfg.Validate() — validateConnectGCPProjectID
			// (internal/config/config.go) already refused to boot a
			// gcp-secret-manager connector with an unset project_id, before this
			// function is ever reached (see the cfg.Validate() call at the top of
			// initializeCoreService). Fail loud rather than silently construct an
			// unpinned connector if this is somehow reached anyway (e.g. a future
			// caller of this loop that bypasses Validate()) — the old behavior let an
			// unpinned connector boot with only a log warning, which is exactly the
			// confused-deputy gap this field now closes.
			if cn.ProjectID == "" {
				log.Fatalf("Keyorix Connect: gcp-secret-manager connector %q has no project_id — this should have been caught by cfg.Validate()", cn.Name)
			}
			conn, ok := connect.NewCloudConnector(cn.Type, connect.ConnectorParams{Name: cn.Name, ProjectID: cn.ProjectID, AllowedRefs: cn.AllowedRefs})
			if !ok {
				return fmt.Errorf("connect: connector %q has type %q, which this server binary was not built with (excluded by the no%s build tag) — rebuild without -tags no%s, or remove this connector", cn.Name, cn.Type, cloudProviderTag(cn.Type), cloudProviderTag(cn.Type))
			}
			connectors = append(connectors, conn)
		case "azure-key-vault":
			conn, ok := connect.NewCloudConnector(cn.Type, connect.ConnectorParams{Name: cn.Name, Address: cn.Address, AllowedRefs: cn.AllowedRefs})
			if !ok {
				return fmt.Errorf("connect: connector %q has type %q, which this server binary was not built with (excluded by the no%s build tag) — rebuild without -tags no%s, or remove this connector", cn.Name, cn.Type, cloudProviderTag(cn.Type), cloudProviderTag(cn.Type))
			}
			connectors = append(connectors, conn)
		case "vault":
			tokenEnv := cn.TokenEnv
			if tokenEnv == "" {
				tokenEnv = "VAULT_TOKEN"
			}
			token, terr0 := resolveVaultToken(tokenEnv)
			if terr0 != nil {
				return fmt.Errorf("connect: vault connector %q token: %w", cn.Name, terr0)
			}
			if token == "" {
				log.Printf("Keyorix Connect: vault connector %q has no token (%s unset) — reads will fail", cn.Name, tokenEnv)
			}
			vc := connect.NewVaultConnector(cn.Name, cn.Address, token, cn.AllowedRefs)
			if ttl, renewable, terr := vc.CheckTokenTTL(context.Background()); terr != nil {
				log.Printf("Keyorix Connect: vault connector %q: token TTL check failed: %v", cn.Name, terr)
			} else if ttl > 0 && ttl < 86400 && !renewable {
				log.Printf("Keyorix Connect: vault connector %q: token has %d seconds remaining and is NOT renewable — replace before expiry", cn.Name, ttl)
			} else if ttl > 0 && ttl < 86400 {
				log.Printf("Keyorix Connect: vault connector %q: token expires in %d seconds; ensure renewal is configured", cn.Name, ttl)
			}
			connectors = append(connectors, vc)
		default:
			// #1476: unreachable via a config that passed cfg.Validate() —
			// validateConnectTypes (internal/config/config.go) already refused
			// to boot with a connector Type outside connect.KnownTypes, before
			// this function is ever reached (see the cfg.Validate() call at the
			// top of initializeCoreService). Fail loud rather than silently
			// skip if this is somehow reached anyway (e.g. a future caller of
			// this loop that bypasses Validate()) — the old behavior let a
			// misconfigured connector boot invisibly, the same fail-open shape
			// ADR-082 closed for scope. See
			// server/connector_type_registry_test.go for the test keeping this
			// switch's case set and connect.KnownTypes from drifting apart.
			log.Fatalf("Keyorix Connect: connector %q has unrecognized type %q (must be one of %s) — this should have been caught by cfg.Validate()", cn.Name, cn.Type, strings.Join(connect.KnownTypes, ", "))
		}
	}
	if len(connectors) == 0 {
		return nil
	}
	mgr := connect.NewManager(connectors)

	// ADR-082 branch 2: resolve each connector's tenant-scoping data (project
	// binding for scope: project; nothing to resolve for scope: platform)
	// BEFORE wiring the manager in, so a resolution failure blocks boot
	// entirely rather than leaving Connect half-wired.
	ownership, err := resolveConnectorOwnership(context.Background(), coreService.Storage(), cc.Connectors)
	if err != nil {
		log.Fatalf("Keyorix Connect: %v", err)
	}

	// Defense-in-depth: ownership was resolved from the FULL cc.Connectors
	// config, but mgr was built only from connectors the type-switch above
	// actually recognized (an unrecognized type is skipped with a WARN, not a
	// hard failure — the `default` case above). If a connector's ownership
	// resolved successfully but it never made it into mgr (e.g. an
	// unrecognized type), or vice versa, that is a key-set mismatch this ADR
	// requires to fail boot loudly rather than silently deny (a missing
	// ownership entry, connectOwnershipSatisfied's own fallback) or silently
	// skip ownership entirely (a connector with no check at all). No exemption
	// of any kind (amended — the prior allow_unscoped-linked exemption is
	// removed along with the flag): every divergence between the two sets is
	// reported.
	if mismatch := connectOwnershipKeySetMismatch(mgr.Names(), ownership); len(mismatch) > 0 {
		log.Fatalf("Keyorix Connect: connector(s) present in config but whose manager/ownership resolution disagree on which connectors exist — this must never happen in a correctly-booted server; investigate before proceeding (ADR-082): %s", strings.Join(mismatch, ", "))
	}

	coreService.SetConnectManager(mgr)
	coreService.SetConnectOwnership(ownership)
	log.Printf("Keyorix Connect enabled (%d connector(s))", len(connectors))

	// #1477/#1479: warn-only consistency check, run here because this is the
	// only place in the system that sees both config (ownership, resolved
	// just above) and DB rows (ConnectRefGrant, ConnectorProjectBinding)
	// together — the create-time checks (CreateConnectRefGrant,
	// resolveConnectorOwnership's own CreateConnectorProjectBinding call
	// above) each structurally cannot see this:
	// a grant/binding valid when created can still drift out of sync with a
	// LATER config edit. Neither condition this checks is a security risk —
	// a dead ref-grant or an orphaned binding both already fail closed/are
	// simply unused, no over-permission — so this warns, never fails boot.
	warnConnectConfigDrift(context.Background(), coreService.Storage(), ownership)
	return nil
}

// ssoCompleteURL derives the SPA completion URL (<redirect origin>/auth/sso/complete)
// from a provider's redirect_url.
func ssoCompleteURL(redirectURL string) (string, error) {
	u, err := url.Parse(redirectURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid redirect_url %q", redirectURL)
	}
	return u.Scheme + "://" + u.Host + "/auth/sso/complete", nil
}

// buildSSOProviders discovers each configured provider and builds the resolved
// providers + a JWKS resolver over their issuers. A provider that is misconfigured
// or whose discovery fails is skipped with a warning (it must not block startup).
func buildSSOProviders(sso config.SSOConfig) (map[string]*core.SSOProvider, core.JWKSResolver, int) { // NOSONAR -- cognitive complexity 23, suppress go:S3776
	providers := map[string]*core.SSOProvider{}
	jwksURIs := map[string]string{}
	for i := range sso.Providers {
		pc := sso.Providers[i]
		if pc.Name == "" {
			log.Printf("SSO provider with no name; skipping")
			continue
		}
		// SAML providers are built from their own block (no OIDC discovery).
		if strings.EqualFold(pc.Type, "saml") {
			sp, err := buildSAMLProvider(pc)
			if err != nil {
				log.Printf("SSO provider %q (saml) misconfigured: %v; skipping", pc.Name, err)
				continue
			}
			completeURL, err := ssoCompleteURL(pc.SAML.ACSURL)
			if err != nil {
				log.Printf("SSO provider %q (saml): %v; skipping", pc.Name, err)
				continue
			}
			providers[pc.Name] = &core.SSOProvider{
				Name: pc.Name, Type: "saml", SAML: sp, CompleteURL: completeURL,
				AutoProvision: pc.AutoProvision, DefaultRole: pc.DefaultRole,
				TrustAssertedEmail: pc.TrustAssertedEmail,
				GroupSync:          pc.GroupSync, GroupRoleMap: pc.GroupRoleMap,
			}
			continue
		}
		if pc.Issuer == "" || pc.ClientID == "" || pc.RedirectURL == "" {
			log.Printf("SSO provider %q misconfigured (issuer/client_id/redirect_url required); skipping", pc.Name)
			continue
		}
		disc, err := discoverOIDC(pc.Issuer)
		if err != nil {
			log.Printf("SSO provider %q discovery failed: %v; skipping", pc.Name, err)
			continue
		}
		completeURL, err := ssoCompleteURL(pc.RedirectURL)
		if err != nil {
			log.Printf("SSO provider %q: %v; skipping", pc.Name, err)
			continue
		}
		scopes := pc.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}
		providers[pc.Name] = &core.SSOProvider{
			Name:     pc.Name,
			Issuer:   pc.Issuer,
			ClientID: pc.ClientID,
			OAuth: &oauth2.Config{
				ClientID:     pc.ClientID,
				ClientSecret: pc.GetClientSecret(),
				Endpoint:     oauth2.Endpoint{AuthURL: disc.AuthorizationEndpoint, TokenURL: disc.TokenEndpoint},
				RedirectURL:  pc.RedirectURL,
				Scopes:       scopes,
			},
			CompleteURL:   completeURL,
			AutoProvision: pc.AutoProvision,
			DefaultRole:   pc.DefaultRole,
			GroupSync:     pc.GroupSync,
			GroupsClaim:   pc.GroupsClaim,
			GroupRoleMap:  pc.GroupRoleMap,
		}
		jwksURIs[pc.Issuer] = disc.JWKSURI
	}
	if len(providers) == 0 {
		return nil, nil, 0
	}
	// A JWKS resolver is only needed for OIDC providers; a SAML-only deployment has none.
	if len(jwksURIs) == 0 {
		return providers, nil, len(providers)
	}
	resolver, err := core.NewHTTPJWKSResolver(jwksURIs)
	if err != nil {
		log.Printf("SSO disabled: jwks resolver init failed: %v", err)
		return nil, nil, 0
	}
	return providers, resolver, len(providers)
}

// buildSAMLProvider constructs a SAML Service Provider from its config block, reading
// the IdP metadata inline or from a file.
func buildSAMLProvider(pc config.SSOProviderConfig) (*samlpkg.Provider, error) {
	if pc.SAML == nil {
		return nil, fmt.Errorf("missing saml config block")
	}
	metaXML := []byte(pc.SAML.IDPMetadataXML)
	if len(metaXML) == 0 && pc.SAML.IDPMetadataFile != "" {
		b, err := secretenv.ReadRegularFile("idp_metadata_file", pc.SAML.IDPMetadataFile) // operator-provided metadata path; a FIFO is refused, not waited on
		if err != nil {
			return nil, fmt.Errorf("read idp_metadata_file: %w", err)
		}
		metaXML = b
	}
	return samlpkg.NewProvider(samlpkg.Config{
		Name:              pc.Name,
		IDPMetadataXML:    metaXML,
		SPEntityID:        pc.SAML.SPEntityID,
		ACSURL:            pc.SAML.ACSURL,
		AllowIDPInitiated: pc.SAML.AllowIDPInitiated,
		EmailAttr:         pc.SAML.EmailAttribute,
		NameAttr:          pc.SAML.NameAttribute,
		GroupsAttr:        pc.SAML.GroupsAttribute,
	})
}

// warnIfRecoveryKeyMissing logs a prominent WARN on EVERY boot (not just the
// first) while security.recover_admin.insecure_keyless_admin_recovery is off and no recovery
// key has ever been generated -- `recover-admin` is unusable in that state
// (F6, recovery-key visibility) and, unlike keyless mode, there is no other
// startup-time signal an operator would see. Best-effort: a lookup failure
// is logged but never blocks startup, matching every other best-effort
// startup diagnostic in this function.
func warnIfRecoveryKeyMissing(store corestorage.Storage) {
	_, found, err := store.GetRecoveryKeyRecord(context.Background())
	if err != nil {
		log.Printf("note: could not check recovery-key configuration (%v)", err)
		return
	}
	if !found {
		log.Printf("WARNING: no recovery key is configured -- `keyorix-server admin recover-admin` is unusable " +
			"until one is generated. Run `keyorix-server admin recovery-key rotate` (see docs/SELF_HOSTING.md, " +
			"\"Generate your admin recovery key now\"). This warning repeats on every startup until a key is generated.")
	}
}

// auditKeylessModeStartup records, at every boot while security.recover_admin.insecure_keyless_admin_recovery is
// enabled, a system-actor audit event (no UserID, never machine-identity-typed), so the
// tamper-evident chain itself carries a repeated record of the weaker mode. Direct
// LogAuditEvent: this runs before any request context exists, the same shape as
// auditConnectorProjectBindingCreate (listed in core's auditAttributionAllowlist).
func auditKeylessModeStartup(store corestorage.Storage) {
	ok := true
	if err := store.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType:   "admin.keyless_mode_enabled_at_startup",
		Description: "server started with security.recover_admin.insecure_keyless_admin_recovery enabled -- recover-admin can restore any admin account on host access alone",
		Success:     &ok,
		ActorType:   core.ActorTypeSystem,
		EventTime:   time.Now(),
	}); err != nil {
		log.Printf("note: could not record the keyless-mode startup event to the audit chain (%v)", err)
	}
}

// auditReadsSkippedStartupEventType is written at every boot while
// storage.database.insecure_audit_skip_reads is enabled (ADR-112 Amendment 4).
const auditReadsSkippedStartupEventType = "admin.audit_reads_skipped_at_startup"

// auditReadsSkippedStartup records, at every boot while
// storage.database.insecure_audit_skip_reads is enabled, a system-actor audit
// event, the same shape and reason as auditKeylessModeStartup: the
// tamper-evident chain carries its own repeated record that successful secret
// reads were not being audited from this start on.
func auditReadsSkippedStartup(store corestorage.Storage) {
	ok := true
	if err := store.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType: auditReadsSkippedStartupEventType,
		Description: "server started with storage.database.insecure_audit_skip_reads enabled -- successful " +
			"secret-value reads are NOT audited; writes, permission changes, authentication, denied reads and " +
			"admin actions still are",
		Success:   &ok,
		ActorType: core.ActorTypeSystem,
		EventTime: time.Now(),
	}); err != nil {
		log.Printf("note: could not record the audit-reads-skipped startup event to the audit chain (%v)", err)
	}
}
