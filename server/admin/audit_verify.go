// audit_verify.go implements `keyorix-server admin verify-audit` (ADR-108
// §B4, docs/design-b4-offline-audit-verify.md): offline verification of the
// ADR-029 audit tamper-evidence hash chain directly against a database
// artifact, without trusting or needing a running Keyorix server.
//
// This file is deliberately thin: it resolves flags to an
// internal/auditverify.DB and internal/auditverify.Options and calls
// auditverify.Verify — no chain-walk, hash, or checkpoint logic lives here
// (design's own task requirement; see internal/auditverify's own doc.go for
// why that independence matters).
package admin

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/spf13/cobra"
)

// anchorSourceFlag/Config/None are the values reported as
// Result.AnchorSource (design §10 Q5 addendum) — the exact strings the
// review on #2084 asked for.
const (
	anchorSourceFlag   = "flag"
	anchorSourceConfig = "config (audit.offline_anchor_path)"
	anchorSourceNone   = "none"
)

var (
	verifyAuditDBPath      string
	verifyAuditPGDSN       string
	verifyAuditKeyFile     string
	verifyAuditAnchorFile  string
	verifyAuditTSARootFile string
	verifyAuditJSON        bool
)

var verifyAuditCmd = &cobra.Command{
	Use:   "verify-audit",
	Short: "Offline-verify the audit tamper-evidence hash chain against a database artifact",
	Long: `verify-audit re-walks the ADR-029 audit hash chain directly from a database
artifact -- a detached copy (--db/--pg-dsn) or, by default, this host's own
configured database -- WITHOUT trusting or needing a running Keyorix server
process to be honest, or even running. Read-only: never writes to the
database it verifies.

WHAT THIS PROVES: a bare re-walk detects any modification, deletion,
insertion, or reordering of a row still present in the table. With
--checkpoint-key-file (the KEK-derived checkpoint signing key, written by
'admin audit export-checkpoint-key' -- never the KEK or passphrase itself), it
additionally detects tail-truncation and genesis re-seed against the
certified high-water mark. With --anchor (or, if not passed, audit.
offline_anchor_path from config -- an offline anchor source: a checkpoint
export written to write-once media by 'admin audit export-checkpoint', see
docs/design-b4-offline-audit-verify.md §10 Q5), it cross-checks the live
chain against a signed checkpoint snapshot held OUTSIDE this host -- catching
a truncation or re-seed even if the local checkpoint/high-water rows were
themselves deleted. With --tsa-roots (a PEM bundle of trusted RFC 3161 TSA
root certs), it independently re-verifies a checkpoint's or --anchor's
timestamp token against a third-party time-stamping authority -- the one
check that needs NO shared secret at all (no --checkpoint-key-file, no trust
in this host), and the strongest guarantee this tool can offer.

WHAT THIS DOES NOT PROVE: a host admin who holds BOTH this database and its
checkpoint signing key can fabricate a fully self-consistent, validly-
checkpointed history -- this tool proves only that a DB-only actor (without
that key) could not have tampered undetectably. Without
--checkpoint-key-file, tail-truncation and genesis re-seed are not detected
at all -- a shorter, self-consistent chain still verifies, by design (ADR-029
documents this as the bare re-walk's known limit). A retention gap left by a
sanctioned purge that cannot be authenticated is reported INDETERMINATE,
never silently VALID (which would hide a real gap) and never BROKEN (which
would false-alarm on every purged deployment). Every run's report includes a
"what this does not prove" section stating these limits given the inputs it
was actually handed -- read it, not just the top-line verdict.

Lock: with --db or --pg-dsn, this command never touches the database a
running server might be attached to, so it takes no lock. Without either
flag, it verifies the CONFIGURED live database and acquires the same
exclusive lock every other admin command does (internal/serverguard) for its
entire run, refusing (unless --force) if a server or another admin command
already holds it.

If --anchor is not passed and a config file EXISTS but fails to load (bad
YAML, a permissions problem), this is a hard error (exit 3), not a silent
"no anchor" -- an operator who configured audit.offline_anchor_path must
never have that setting silently dropped because their config also happened
to break. Every report (human and --json) states which source actually
served the anchor: "flag", "config (audit.offline_anchor_path)", or "none".

Exit codes: 0 VALID, 1 BROKEN (tamper detected), 2 INDETERMINATE (could not
fully verify -- e.g. an unauthenticated retention gap, or no key to check a
real truncation), 3 usage/input error (bad DSN, unreadable file, malformed
key or anchor, or an unloadable config file that could have configured one).
Never 0 when something was silently left unverified.`,
	RunE: runVerifyAudit,
}

func init() {
	verifyAuditCmd.Flags().StringVar(&verifyAuditDBPath, "db", "",
		"Verify this SQLite file directly (opened read-only), instead of the configured database")
	verifyAuditCmd.Flags().StringVar(&verifyAuditPGDSN, "pg-dsn", "",
		"Verify this Postgres DSN directly, instead of the configured database")
	verifyAuditCmd.Flags().StringVar(&verifyAuditKeyFile, "checkpoint-key-file", "",
		"Path to the derived audit-checkpoint signing key (hex or base64) -- enables checkpoint/high-water/truncation checks")
	verifyAuditCmd.Flags().StringVar(&verifyAuditAnchorFile, "anchor", "",
		"Path to a JSON checkpoint snapshot held externally (e.g. an 'export-checkpoint' export) -- cross-checks the live chain against a copy this host does not control. Defaults to audit.offline_anchor_path from config when not passed")
	verifyAuditCmd.Flags().StringVar(&verifyAuditTSARootFile, "tsa-roots", "",
		"Path to a PEM bundle of trusted RFC 3161 TSA root certs -- independently re-verifies a checkpoint's or --anchor's timestamp token against them, without needing --checkpoint-key-file or any other shared secret")
	verifyAuditCmd.Flags().BoolVar(&verifyAuditJSON, "json", false,
		"Emit the verification result as JSON instead of a human report")
	rootCmd.AddCommand(verifyAuditCmd)
}

// exitCodeError carries a specific process exit code, read by Execute (see
// admin.go) instead of its default "any error is exit 1" mapping.
// verify-audit's exit code is part of its documented contract (0/1/2/3,
// design §6) — a verdict, not merely success/failure — so it cannot use
// Execute's default.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string { return e.err.Error() }
func (e *exitCodeError) Unwrap() error { return e.err }

func newExitCodeError(code int, err error) error {
	return &exitCodeError{code: code, err: err}
}

func runVerifyAudit(cmd *cobra.Command, args []string) error {
	// Loaded once: cs distinguishes "no config file at all" (design §10 Q2's
	// deliberately-supported --db/--pg-dsn-without-config case) from "a config
	// file exists but failed to load" (a real misconfiguration -- see
	// resolveOfflineAnchor, which is the only place this distinction matters).
	cs := loadConfigForVerifyAudit()

	opts, anchorSource, err := buildVerifyAuditOptions(cs)
	if err != nil {
		return newExitCodeError(3, err)
	}

	db, lock, err := openVerifyAuditTarget(cs.cfg, cs.err)
	if err != nil {
		return newExitCodeError(3, err)
	}
	defer func() {
		_ = db.Close()
		if lock != nil {
			_ = lock.Release()
		}
	}()

	result, err := auditverify.Verify(context.Background(), db, opts)
	if err != nil {
		return newExitCodeError(3, fmt.Errorf("verification failed to run: %w", err))
	}
	result.AnchorSource = anchorSource

	printVerifyAuditReport(result)

	if result.Verdict != auditverify.VerdictValid {
		return newExitCodeError(result.ExitCode(), fmt.Errorf("audit chain verification: %s", result.Verdict))
	}
	return nil
}

// configLoadState is loadConfig's raw (cfg, err) result PLUS whether the
// config file exists at all. openVerifyAuditTarget only ever needs the raw
// pair (it already tolerates a missing file when --db/--pg-dsn is given, and
// requires cfg regardless of why loading failed otherwise); resolveOfflineAnchor
// is the one place that needs to tell "nothing to load" apart from "loading
// failed" (see its own doc comment).
type configLoadState struct {
	cfg         *config.Config
	err         error
	fileMissing bool
}

// loadConfigForVerifyAudit wraps loadConfig with an independent check of
// whether the resolved config path exists, resolved the same way
// config.Load itself resolves it (mirrors server/admin/audit.go's own
// runAdminAudit, which needs the identical resolved path for its own
// purposes).
func loadConfigForVerifyAudit() configLoadState {
	configPath := filepath.Clean(config.ResolvedPath(configPathFlag))
	_, statErr := os.Stat(configPath)
	cfg, err := loadConfig()
	return configLoadState{cfg: cfg, err: err, fileMissing: os.IsNotExist(statErr)}
}

// buildVerifyAuditOptions resolves --checkpoint-key-file/--anchor/--tsa-roots
// into an auditverify.Options, plus the anchor source string for the report
// (design §10 Q5 addendum). All interpretation of the anchor bundle's JSON
// lives in auditverify.ParseExternalAnchorBundle, not here.
func buildVerifyAuditOptions(cs configLoadState) (auditverify.Options, string, error) {
	var opts auditverify.Options
	if verifyAuditKeyFile != "" {
		key, err := readCheckpointKeyFile(verifyAuditKeyFile)
		if err != nil {
			return opts, "", fmt.Errorf("--checkpoint-key-file: %w", err)
		}
		opts.CheckpointKey = key
	}

	anchorPath, anchorSource, err := resolveOfflineAnchor(cs)
	if err != nil {
		return opts, "", err
	}
	if anchorPath != "" {
		data, err := os.ReadFile(anchorPath) // #nosec G304 -- operator-supplied path (flag or config), the whole point of this setting
		if err != nil {
			return opts, anchorSource, fmt.Errorf("--anchor: read %q: %w", anchorPath, err)
		}
		bundle, err := auditverify.ParseExternalAnchorBundle(data)
		if err != nil {
			return opts, anchorSource, fmt.Errorf("--anchor: %w", err)
		}
		opts.ExternalAnchor = bundle
	}
	if verifyAuditTSARootFile != "" {
		roots, err := readTSARootsFile(verifyAuditTSARootFile)
		if err != nil {
			return opts, anchorSource, fmt.Errorf("--tsa-roots: %w", err)
		}
		opts.TSARoots = roots
	}
	return opts, anchorSource, nil
}

// resolveOfflineAnchor resolves design §10 Q5's --anchor precedence AND
// classifies which source served it, for Result.AnchorSource: "flag",
// "config (audit.offline_anchor_path)", or "none".
//
// A config file that EXISTS but fails to load/parse is deliberately NOT
// treated the same as no config file at all. Before this function existed,
// buildVerifyAuditOptions took a bare *config.Config that was already nil in
// both cases -- so an operator who genuinely configured
// audit.offline_anchor_path, but whose config had since developed a typo or
// permissions problem, got a SILENT downgrade to a bare re-walk with no
// anchor and no indication why (found in review of #2084). When --anchor was
// not passed explicitly and cs reports a present-but-unloadable config file,
// this returns a hard error instead. An explicit --anchor always resolves
// regardless of cs, since it does not depend on config at all.
func resolveOfflineAnchor(cs configLoadState) (path, source string, err error) {
	if verifyAuditAnchorFile != "" {
		return verifyAuditAnchorFile, anchorSourceFlag, nil
	}
	if cs.cfg != nil && cs.cfg.Audit.OfflineAnchorPath != "" {
		return cs.cfg.Audit.OfflineAnchorPath, anchorSourceConfig, nil
	}
	if cs.err != nil && !cs.fileMissing {
		return "", "", fmt.Errorf(
			"--anchor was not passed, and audit.offline_anchor_path could not be checked because the config file "+
				"failed to load -- refusing to silently verify without a possibly-configured anchor: %w", cs.err)
	}
	return "", anchorSourceNone, nil
}

// readCheckpointKeyFile reads the derived audit-checkpoint signing key
// (design Q1: the derived key itself, never the KEK or passphrase), accepted
// as hex or base64 per the design's own documented flag contract.
func readCheckpointKeyFile(path string) ([]byte, error) {
	raw, err := readKeyFile(path) // secret: non-blocking open, FIFO refused (secretenv.OpenRegular)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("%q is empty", path)
	}
	if key, err := hex.DecodeString(trimmed); err == nil && len(key) > 0 {
		return key, nil
	}
	if key, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(key) > 0 {
		return key, nil
	}
	return nil, fmt.Errorf("%q is neither valid hex nor valid base64 (the derived checkpoint key must be one of those two encodings)", path)
}

// readTSARootsFile parses the PEM bundle of trusted RFC 3161 TSA root certs
// design §3's `--tsa-roots` flag takes -- the one check this design calls
// out as needing no shared secret at all (a public-key proof-of-existence),
// so it is deliberately independent of --checkpoint-key-file.
func readTSARootsFile(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path, the whole point of this flag
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%q contains no valid PEM certificates", path)
	}
	return pool, nil
}

// openVerifyAuditTarget resolves --db/--pg-dsn/config precedence into an
// auditverify.DB. The returned lock is non-nil ONLY when this run fell back
// to the config's own live database (design Q2) — an explicit --db/--pg-dsn
// copy never touches that path, so it is never guarded. cfg/cfgErr are the
// single loadConfig() call runVerifyAudit already made: --db/--pg-dsn mode
// never needs cfg to have loaded (design §10 Q2), so cfgErr is surfaced only
// in the fallback branch below, where a live config-referenced database is
// genuinely required.
func openVerifyAuditTarget(cfg *config.Config, cfgErr error) (*auditverify.DB, *serverguard.Exclusive, error) {
	if verifyAuditDBPath != "" {
		db, err := auditverify.OpenSQLiteReadOnly(verifyAuditDBPath)
		if err != nil {
			return nil, nil, fmt.Errorf("open --db %q: %w", verifyAuditDBPath, err)
		}
		return db, nil, nil
	}
	if verifyAuditPGDSN != "" {
		db, err := auditverify.OpenPostgres(verifyAuditPGDSN)
		if err != nil {
			return nil, nil, fmt.Errorf("open --pg-dsn: %w", err)
		}
		return db, nil, nil
	}

	if cfgErr != nil {
		return nil, nil, cfgErr
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return nil, nil, err
	}

	switch cfg.Storage.Type {
	case "postgres", "postgresql":
		dsn, dsnErr := config.ResolvePostgresDSN(&cfg.Storage.Database)
		if dsnErr != nil {
			_ = lock.Release()
			return nil, nil, dsnErr
		}
		if dsn == "" {
			_ = lock.Release()
			return nil, nil, fmt.Errorf("postgres storage requires a DSN or host/name/user fields")
		}
		db, err := auditverify.OpenPostgres(dsn)
		if err != nil {
			_ = lock.Release()
			return nil, nil, fmt.Errorf("open configured postgres database: %w", err)
		}
		return db, lock, nil
	case "remote":
		_ = lock.Release()
		return nil, nil, fmt.Errorf("storage.type is \"remote\" -- this host has no local database to verify; " +
			"run verify-audit against the hub's own database, or point --db/--pg-dsn at a copy of it")
	default: // "local", "sqlite", ""
		dbPath := cfg.Storage.Database.Path
		if dbPath == "" {
			dbPath = "./secrets.db"
		}
		db, err := auditverify.OpenSQLiteReadOnly(dbPath)
		if err != nil {
			_ = lock.Release()
			return nil, nil, fmt.Errorf("open configured database %q: %w", dbPath, err)
		}
		return db, lock, nil
	}
}

// printVerifyAuditReport prints the human report (design §6) or, with
// --json, the raw Result as JSON. Both forms carry the "what this does not
// prove" section — a compliance tool that only states its limits in --help
// and drops them from the actual report output overstates what it proves.
func printVerifyAuditReport(r *auditverify.Result) {
	if verifyAuditJSON {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to marshal result:", err)
			return
		}
		fmt.Println(string(b))
		return
	}

	fmt.Println("Offline audit-chain verification")
	fmt.Println("=================================")
	fmt.Printf("Verdict: %s\n", r.Verdict)
	if r.Reason != "" {
		fmt.Printf("  reason:           %s\n", r.Reason)
	}
	if r.FirstBrokenID != nil {
		fmt.Printf("  first broken id:  %d\n", *r.FirstBrokenID)
	}
	fmt.Printf("  range:            id %d..%d\n", r.Range.FromID, r.Range.ToID)
	fmt.Printf("  chained events:   %d\n", r.ChainedEvents)
	fmt.Printf("  unchained legacy: %d\n", r.UnchainedLegacyEvents)

	fmt.Println("\nCheckpoint:")
	switch {
	case !r.Checkpoint.Present:
		fmt.Println("  none found -- no checkpoint has ever been written for this trail")
	case r.Checkpoint.Authenticated:
		fmt.Printf("  authenticated, key version %q, certifies %d chained events\n",
			r.Checkpoint.KeyVersion, r.Checkpoint.ChainedEventsCertified)
	default:
		fmt.Println("  present but UNAUTHENTICATED -- no --checkpoint-key-file was supplied, or it did not verify")
	}

	fmt.Println("\nRetention gap:")
	switch {
	case !r.RetentionGap.Present:
		fmt.Println("  none -- the chain reaches genesis")
	case r.RetentionGap.Sanctioned:
		fmt.Printf("  present before event #%d, SANCTIONED by an authenticated retention anchor\n", r.RetentionGap.RowID)
	default:
		fmt.Printf("  present before event #%d, UNAUTHENTICATED\n", r.RetentionGap.RowID)
	}

	if r.Anchor.Present {
		fmt.Println("\nCheckpoint external anchor (RFC 3161):")
		if r.Anchor.Verified {
			fmt.Printf("  verified against the configured trust root, provider %q, anchored at %s\n",
				r.Anchor.Provider, r.Anchor.AnchoredAt.Format(time.RFC3339))
		} else {
			fmt.Println("  present but not independently re-verified against a TSA trust root")
		}
	}

	fmt.Printf("\nAnchor source: %s\n", r.AnchorSource)

	if r.ExternalAnchor.Supplied {
		fmt.Println("\nExternal anchor bundle (--anchor):")
		if r.ExternalAnchor.Authenticated {
			fmt.Println("  authenticated and cross-checked against the live chain")
		} else {
			fmt.Println("  present but UNAUTHENTICATED -- its claims were not cross-checked against this database")
		}
	}

	fmt.Println("\nWhat this run does NOT prove:")
	for _, np := range r.NotProven {
		fmt.Printf("  - %s\n", np)
	}

	fmt.Printf("\nGenerated at %s by %s.\n", r.GeneratedAt.Format(time.RFC3339), r.VerifierVersion)
}
