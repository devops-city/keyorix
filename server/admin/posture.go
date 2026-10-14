package admin

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/solewriter"
	"github.com/keyorixhq/keyorix/internal/startup"
)

// postureFlag is `admin validate --posture` — reports every ADR-112 secure-
// baseline deviation and exits non-zero if any is found, instead of running
// the ordinary config/permissions/encryption/database validation above.
var postureFlag bool

func init() {
	validateCmd.Flags().BoolVar(&postureFlag, "posture", false, "Report every ADR-112 secure-baseline deviation and exit non-zero if any is found, instead of the ordinary validation")
}

// deviationOrigin says WHY a deviation is present, so an operator can tell
// "this install has not been hardened yet" from "someone turned this off".
// It changes how a deviation READS, never whether it counts: both values are
// counted toward the exit code. Keeping the distinction in the output rather
// than in the exit code is the whole correction to this report's first shape,
// which excluded a class of settings from counting at all.
type deviationOrigin string

const (
	// originExplicit: the config file asked for this state.
	originExplicit deviationOrigin = "explicit"
	// originShippedDefault: the weak state is what a config file that says
	// nothing gets. Still a deviation from the secure baseline -- the fix is to
	// change the default, not to stop reporting it.
	originShippedDefault deviationOrigin = "shipped-default"
)

// postureDeviation is one line of `admin validate --posture` output: a
// concrete, named reason the install does not match the ADR-112 secure
// baseline. EVERY deviation counts toward the command's exit code; only
// report.info lines do not.
type postureDeviation struct {
	category string
	detail   string
	origin   deviationOrigin
}

// postureReport is the full output of one `admin validate --posture` run.
type postureReport struct {
	deviations    []postureDeviation
	informational []string
}

// deviate records a deviation whose cause is an explicit config choice.
func (r *postureReport) deviate(category, detail string) {
	r.deviations = append(r.deviations, postureDeviation{category: category, detail: detail, origin: originExplicit})
}

// deviateShippedDefault records a deviation the install gets without asking
// for it. Counted identically to deviate -- see deviationOrigin.
func (r *postureReport) deviateShippedDefault(category, detail string) {
	r.deviations = append(r.deviations, postureDeviation{category: category, detail: detail, origin: originShippedDefault})
}

func (r *postureReport) info(line string) {
	r.informational = append(r.informational, line)
}

func runAdminValidatePosture(cfg *config.Config, configPath string) error {
	report := &postureReport{}

	explicit, err := config.ExplicitlySetPaths(configPath)
	if err != nil {
		return fmt.Errorf("posture check could not read the config file: %w", err)
	}
	// ValidateStartup (inside collectFilePermissionPosture) runs BEFORE
	// withUsableStorage below opens -- and may create -- the database, so a
	// missing database file is still reported as the problem it is.
	collectFilePermissionPosture(cfg, configPath, report)
	collectKeyFileSetPosture(cfg, report)
	collectTLSPosture(cfg, report)
	collectDatabaseTLSPosture(cfg, report)
	collectKEKAgePosture(cfg, report)
	collectSingleWriterPosture(cfg, report)

	// A database that cannot be queried is reported as a deviation of its own
	// and the report is still printed: everything collected above is real, and
	// discarding it would leave the operator with one error line instead of the
	// report (withUsableStorage's contract is to report the database distinctly,
	// not to fail the whole command over it). The command still fails.
	var fileGraceKnown bool
	var fileEnforcedSince string
	dbErr := withUsableStorage(cfg, func(store corestorage.Storage) error {
		coreService := core.NewKeyorixCore(store)
		ctx := context.Background()
		// #2908: decide the enable_file_permission_check grace period from the
		// same database facts the server's boot does, BEFORE the registry is
		// read below -- its insecure_skip_startup_validation entry reads the
		// grace flag this sets.
		var err error
		if fileEnforcedSince, err = resolveFilePermissionUpgradeGrace(ctx, cfg, store); err != nil {
			return err
		}
		fileGraceKnown = true
		// TODO(#2461): add collectBreakGlassReviewPosture here -- see its
		// comment below for the two findings Andrei decided on and why they
		// cannot be implemented until that PR's API lands.
		inGrace, err := collectRequireMFAPosture(ctx, cfg, store, report)
		if err != nil {
			return err
		}
		return collectAdminMFAPosture(ctx, inGrace, coreService, report)
	})
	if dbErr != nil {
		report.deviate("database", fmt.Sprintf("posture check could not query the database, so the admin-MFA check and the enable_file_permission_check grace-period check were NOT evaluated: %v", dbErr))
	}
	collectInsecureSettingsPosture(cfg, explicit, report)
	collectStartupValidationStatePosture(cfg, fileGraceKnown, fileEnforcedSince, report)

	printPostureReport(report)

	if dbErr != nil {
		return fmt.Errorf("posture check could not query the database: %w", dbErr)
	}
	if len(report.deviations) > 0 {
		return fmt.Errorf("%d secure-baseline deviation(s) found", len(report.deviations))
	}
	return nil
}

// collectSingleWriterPosture reports storage.database.single_writer: always a
// visible line while it is on (with the emergency two-step), and a deviation
// when the installed write fence is incomplete or not ENABLE ALWAYS (a server
// start reinstalls it, and refuses to run without it).
func collectSingleWriterPosture(cfg *config.Config, report *postureReport) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rep, err := solewriter.InspectFence(ctx, cfg)
	if !cfg.Storage.Database.SingleWriter {
		if err == nil && rep.Triggers > 0 {
			report.info(fmt.Sprintf("single_writer: off, but %d write-fence trigger(s) from an earlier single_writer boot are still installed; the next server start removes them", rep.Triggers))
		}
		return
	}
	report.info(fmt.Sprintf("single_writer: on (storage.database.single_writer). The server is the only permitted writer of %d security tables; "+
		"direct database writes to them are refused while it runs, and revocations through the server take effect on the next request. "+
		"Emergency direct change: %s", len(solewriter.FencedTables), solewriter.EmergencySQL))
	switch {
	case err != nil:
		report.info(fmt.Sprintf("single_writer: the write fence could not be inspected: %v", err))
	case rep.Triggers == 0:
		report.info("single_writer: the write fence is not installed yet; the server installs it at start-up and refuses to start without it")
	case !rep.Complete():
		report.deviate("single_writer", fmt.Sprintf("the write fence is incomplete: %d of %d triggers present, %d ENABLE ALWAYS. Restart the server to reinstall it", rep.Triggers, rep.Expected, rep.Always))
	}
	if err == nil && rep.HolderLive {
		report.info(fmt.Sprintf("single_writer: a server holds the single-writer lock (backend pid %d)", rep.HolderPID))
	}
}

// collectInsecureSettingsPosture reports EVERY item-2 registry entry currently
// in effect as a deviation. No entry is excluded, and nothing about how a
// setting is NAMED affects whether it counts.
//
// The first shape of this function skipped any entry whose Describe contained
// the substring "NEEDS ANDREI" -- the marker the registry uses for a setting
// whose insecure_ rename needs a product decision -- and recorded it as
// uncounted informational instead. That was wrong in two separate ways, and
// the coordinator's review of this PR caught both:
//
//  1. It defeated the report. The marker covered THIRTEEN entries, including
//     encryption-at-rest disabled, database TLS disabled (ssl_mode=disable), a
//     forgeable Shamir KEK commitment, unauthenticated /metrics and
//     log-delivered setup links. An install with encryption at rest switched
//     off printed "No deviations found." and exited 0, and nothing else caught
//     it: collectKeyFileSetPosture early-returns when encryption is off, for
//     the good reason that there is then no key material to check. A report
//     whose one job is answering "does this install match the secure baseline"
//     answered yes for an install storing every secret in plaintext.
//
//  2. The mechanism was unsound regardless of which entries it hit. Keying
//     security control flow on a prose match against a human-readable
//     description string means any future entry whose Describe happens to
//     contain that phrase silently stops counting -- a reviewer editing a
//     sentence could switch off a deviation without touching a line of logic.
//
// The review suggested scoping the exclusion to the defensible shipped-template
// cases via an explicit per-entry registry field. Andrei's instruction is
// stronger, and is what is implemented: every insecure setting counts as a
// deviation, whether or not its naming is settled. So there is no exclusion
// field to key on, and no way to add one by accident.
//
// What a shipped template needs is honesty about WHY, not an exemption, so the
// origin distinction does that job instead: a weakening that is simply the
// current default reads as "shipped-default" and still counts. If a shipped
// config template exits non-zero here, the install genuinely does not match
// the secure baseline, and the fix is to change the default (which is what the
// rest of ADR-112 is for) rather than to stop reporting it.
func collectInsecureSettingsPosture(cfg *config.Config, explicit map[string]bool, report *postureReport) {
	for _, s := range config.InsecureSettingsRegistry {
		if !s.InEffect(cfg) {
			continue
		}
		// The value says WHICH weak state, where an entry has more than one
		// (#2908: insecure_skip_startup_validation is "off" or "grace-warn-only").
		detail := fmt.Sprintf("%s is in effect (%s) — %s", s.Name, s.Value(cfg), s.Describe)
		// Origin is a fact about the config FILE: explicit when it writes one
		// of the paths this entry reads, shipped-default when it is silent and
		// the weak state is what Load resolves the absent key to. Not keyed on
		// any Describe text (the first shape matched "NEEDS ANDREI", which
		// labelled production.yaml's explicit require_transport_tls: false a
		// shipped default).
		if !writesAnyOf(explicit, s.SourcePaths) {
			report.deviateShippedDefault("insecure-setting", detail)
			continue
		}
		report.deviate("insecure-setting", detail)
	}
}

// writesAnyOf reports whether the config file (explicit, from
// config.ExplicitlySetPaths) writes any of paths.
func writesAnyOf(explicit map[string]bool, paths []string) bool {
	for _, p := range paths {
		if explicit[p] {
			return true
		}
	}
	return false
}

// collectFilePermissionPosture reports the secure-baseline file-permission
// deviations: the check turned off outright (always an explicit choice — the
// ADR-112 default never resolves to false, see config.Load), and a real
// on-disk permission/encryption/database problem ValidateStartup finds. The
// grace-period case (ImplicitDefault true, relying on the new secure default
// without having explicitly reviewed it, AND a real problem exists) is
// reported as its own deviation category so an operator sees both "there is a
// real problem" and "the grace period covering it is not yet closed out" --
// server/main.go's runStartupValidation/enforceKeyFilePermissions soften this
// exact case from a boot-time failure into a warning, so this command, not
// the boot path, is where it must surface as something that needs fixing.
func collectFilePermissionPosture(cfg *config.Config, configPath string, report *postureReport) {
	// No early return when the check is off (coordinator review #1): the
	// encryption and database checks do not depend on it, and an install with
	// the permission check switched off is the one most likely to have a real
	// problem -- it must not get the thinnest report.
	// The implicit-default states (grace-warn-only / enforcing-implicit) need
	// the database to tell apart; collectStartupValidationStatePosture reports
	// them once it has been read.
	if !cfg.Security.EnableFilePermissionCheck {
		report.deviate("file-permissions", "security.enable_file_permission_check is disabled (ADR-112 requires it enabled by default)")
	}

	// configPath, not ResolvedPath(""): --config must be the file validated
	// (coordinator review #3), same as the sibling admin commands.
	result, err := startup.ValidateStartup(config.ResolvedPath(configPath), false)
	if !result.ConfigValid {
		report.deviate("startup-validation", fmt.Sprintf("configuration did not load/validate, so no other startup check ran: %v", err))
		return
	}

	// ValidateStartup stops at its FIRST hard failure. A check is a deviation
	// only if it RAN and failed (coordinator review #2): one bad file
	// permission used to read as three deviations, two of them for checks
	// that never ran. A check that was reached by nobody is said to be
	// unevaluated -- informational, because the check that stopped validation
	// is already a counted deviation.
	if result.PermissionsChecked && result.PermissionsIssue != "" {
		detail := "file permission validation found: " + result.PermissionsIssue
		if cfg.Security.AllowUnsafeFilePermissions {
			detail += " (tolerated at boot only because security.insecure_allow_unsafe_file_permissions is set)"
		}
		report.deviate("file-permissions", detail)
	}
	for _, c := range []struct {
		applies, checked, ok bool
		what                 string
	}{
		{cfg.Storage.Encryption.Enabled, result.EncryptionChecked, result.EncryptionOK, "encryption validation"},
		{true, result.DatabaseChecked, result.DatabaseOK, "database validation"},
	} {
		switch {
		case !c.applies || (c.checked && c.ok):
		case !c.checked:
			report.info(c.what + " not evaluated: startup validation stopped at an earlier failed check (counted above)")
		default:
			// It ran and failed, so it is where validation stopped: err is its error.
			report.deviate("startup-validation", fmt.Sprintf("%s did not pass: %v", c.what, err))
		}
	}

	if result.PermissionsIssue != "" && cfg.Security.EnableFilePermissionCheckImplicitDefault {
		report.deviate("grace-period", "security.enable_file_permission_check's grace period is not yet complied with — the file-permissions deviation above would hard-fail startup once the setting is reviewed and set explicitly")
	}
}

// collectStartupValidationStatePosture reports where
// security.enable_file_permission_check stands when the config file never set
// it (#2908). The registry entry (security.insecure_skip_startup_validation)
// already counts the grace-warn-only state; this adds the operator-facing
// explanation and the way out, the same pairing the explicit-false case gets
// (a registry deviation plus collectFilePermissionPosture's own line).
//
// graceKnown is false when the database could not be read: then the report
// cannot tell an upgrade in the grace period (the server only warns) from an
// enforced deployment, and it counts that as a deviation rather than vouching
// for enforcement it did not verify.
func collectStartupValidationStatePosture(cfg *config.Config, graceKnown bool, enforcedSince string, report *postureReport) {
	sec := cfg.Security
	if !sec.EnableFilePermissionCheck || !sec.EnableFilePermissionCheckImplicitDefault {
		return // off is reported by collectFilePermissionPosture; explicit true needs no line
	}
	switch {
	case !graceKnown:
		report.deviateShippedDefault("grace-period", "security.enable_file_permission_check is on its ADR-112 implicit default and the database could not be read, so whether this deployment is in the upgrade grace period (a failed startup check only WARNS) is unknown — counted until it can be checked")
	case sec.StartupValidationState() == config.StartupValidationGraceWarnOnly:
		report.deviateShippedDefault("grace-period", "security.enable_file_permission_check is in its ADR-112 upgrade grace period: this upgraded deployment never set it, so a failed startup check only WARNS and the server starts anyway. Fix anything the startup checks report; the first clean boot then ends the grace period for good (adr112.file_permission_check.enforced), or set security.enable_file_permission_check: true explicitly")
	case enforcedSince != "":
		report.info("security.enable_file_permission_check is enforcing on its ADR-112 secure-by-default value (never set explicitly; enforced since " + enforcedSince + ")")
	default:
		report.info("security.enable_file_permission_check is enforcing on its ADR-112 secure-by-default value (never set explicitly; fresh install)")
	}
}

// resolveFilePermissionUpgradeGrace sets
// cfg.Security.EnableFilePermissionCheckUpgradeGrace from the database, exactly
// as server/adr112_grace.go's applyADR112UpgradeGrace does at boot: the key is
// absent, users exist, and no config.ADR112FilePermEnforcedMarker row. Returns
// the marker's value when one is recorded.
func resolveFilePermissionUpgradeGrace(ctx context.Context, cfg *config.Config, store corestorage.Storage) (enforcedSince string, err error) {
	sec := &cfg.Security
	if !sec.EnableFilePermissionCheck || !sec.EnableFilePermissionCheckImplicitDefault {
		return "", nil
	}
	inGrace, since, err := adr112UpgradeGraceFromStore(ctx, store, config.ADR112FilePermEnforcedMarker, "enable_file_permission_check")
	if err != nil {
		return "", err
	}
	sec.EnableFilePermissionCheckUpgradeGrace = inGrace
	return since, nil
}

// adr112UpgradeGraceFromStore reads the facts server/adr112_grace.go decides
// an ADR-112 upgrade grace period from: a deployment with users and no
// enforcement marker is an upgrade in the grace period; no users is a fresh
// install (enforced); a marker means already enforced (since its value).
func adr112UpgradeGraceFromStore(ctx context.Context, store corestorage.Storage, marker, key string) (inGrace bool, enforcedSince string, err error) {
	_, users, err := store.ListUsers(ctx, &corestorage.UserFilter{IncludeDeleted: true, PageSize: 1})
	if err != nil {
		return false, "", fmt.Errorf("failed to count users for the %s grace check: %w", key, err)
	}
	if users == 0 {
		return false, "", nil
	}
	since, found, err := store.GetSystemMetadata(ctx, marker)
	if err != nil {
		return false, "", fmt.Errorf("failed to read the %s enforcement marker: %w", key, err)
	}
	if found {
		return false, since, nil
	}
	return true, "", nil
}

// collectKeyFileSetPosture reports item 6's boot-time key-file-set
// consistency check as a deviation when it would refuse to boot.
func collectKeyFileSetPosture(cfg *config.Config, report *postureReport) {
	if !cfg.Storage.Encryption.Enabled {
		return
	}
	if err := keyfiles.VerifyKeySetConsistency(&cfg.Storage.Encryption, "."); err != nil {
		report.deviate("key-file-set-consistency", err.Error())
	}
}

// collectTLSPosture mirrors checkTransportTLSPosture's own boot-time
// judgment call exactly, rather than tightening it: a cleartext-serving
// listener is a deviation only when security.require_transport_tls is set
// but TLS is nonetheless disabled (a contradiction checkTransportTLSPosture
// already refuses to boot over, so this is unreachable for a running
// install — kept here for defense in depth). Cleartext with
// require_transport_tls left false is informational only, same as the boot
// path's own warning: server/config/production.yaml deliberately ships this
// shape (TLS terminated by a fronting reverse proxy), and a deployment
// making that documented, deliberate choice is not a secure-baseline
// deviation. TLS mode itself (default vs strict) is informational only:
// ADR-112's recorded decision keeps TLS 1.2 compliant, so neither mode is,
// by itself, a deviation.
func collectTLSPosture(cfg *config.Config, report *postureReport) {
	check := func(name string, inst config.ServerInstanceConfig) {
		if !inst.Enabled {
			return
		}
		// TODO(FIX-4): report inst.TLSMode here (informational only -- ADR-112's
		// recorded decision keeps TLS 1.2 compliant, so neither mode is a
		// deviation by itself). The field arrived on main with the tls_mode:
		// strict PR, which is NOT in this PR's base chain
		// (#2446 -> #2454 -> #2462), so referencing it here would not compile.
		// Re-add in one line once this stack is rebased onto a main that has it.
		if inst.TLS.Enabled {
			return
		}
		if cfg.Security.RequireTransportTLS {
			report.deviate("tls", fmt.Sprintf("%s listener has no TLS but security.require_transport_tls is set", name))
			return
		}
		report.info(fmt.Sprintf("%s listener is serving cleartext (no TLS) — counted above as security.insecure_allow_cleartext_transport; safe only if a TLS-terminating reverse proxy fronts it", name))
	}
	check("HTTP", cfg.Server.HTTP)
	check("gRPC", cfg.Server.GRPC)
}

// collectDatabaseTLSPosture reports how the PostgreSQL connection is
// protected (PG-VERIFYFULL-1): one informational line saying what is
// encrypted and what is verified against which CA. A TLS trust setting the
// server would refuse to boot on (verify-full with no ssl_root_cert, an
// unusable CA file) is a deviation carrying the same message as the boot
// refusal. Through the real command that branch is defense in depth, like
// collectTLSPosture's: runAdminValidate's server-presence check
// (acquireDatabaseLock -> serverguard -> config.ResolvePostgresConnConfig) already
// fails the command with that same message before this runs (verified on the
// e2e VM against a TLS PostgreSQL). ssl_mode: disable itself is already
// counted by the insecure-settings registry
// (storage.database.insecure_disable_database_tls), and require without a CA
// is the Helm secure baseline's bundled-database shape, so neither is a
// second deviation here.
func collectDatabaseTLSPosture(cfg *config.Config, report *postureReport) {
	switch cfg.Storage.Type {
	case "postgres", "postgresql":
	default:
		return
	}
	line, err := config.DatabaseTLSPosture(&cfg.Storage.Database)
	if err != nil {
		report.deviate("database-tls", err.Error())
		return
	}
	report.info(line)
}

// collectKEKAgePosture reports the KEK salt file's age, informationally only
// -- no rotation-age threshold exists anywhere in this codebase or ADR-112
// itself, and scheduled KEK rotation is explicitly out of scope for this
// work; inventing a threshold here would be a guess, not a derived fact.
func collectKEKAgePosture(cfg *config.Config, report *postureReport) {
	if !cfg.Storage.Encryption.Enabled || cfg.Storage.Encryption.SaltPath == "" {
		return
	}
	info, err := os.Stat(cfg.Storage.Encryption.SaltPath)
	if err != nil {
		return // key-file-set-consistency above already reports a missing/partial set
	}
	age := time.Since(info.ModTime()).Round(time.Hour)
	report.info(fmt.Sprintf("KEK salt file age: %s (no rotation-age threshold is defined — informational only)", age))
}

// collectAdminMFAPosture reports every active global admin-tier holder with
// no second factor enrolled (item 1's require_mfa grace period, finally made
// visible as a concrete, named list rather than a boot-time warning with no
// way to see who still needs to comply).
func collectAdminMFAPosture(ctx context.Context, requireMFAInGrace bool, coreService *core.KeyorixCore, report *postureReport) error {
	admins, err := coreService.ListAdminsWithoutMFA(ctx)
	if err != nil {
		return fmt.Errorf("failed to list admins without MFA: %w", err)
	}
	if len(admins) == 0 {
		return nil
	}
	names := make([]string, 0, len(admins))
	for _, u := range admins {
		names = append(names, fmt.Sprintf("%s (%s)", u.Username, u.Email))
	}
	report.deviate("admin-mfa", fmt.Sprintf("%d admin(s) without MFA or a passkey enrolled: %s", len(admins), strings.Join(names, ", ")))
	if requireMFAInGrace {
		report.deviate("grace-period", "security.require_mfa's grace period is not yet complied with — the admin-mfa deviation above lists who still needs to enrol")
	}
	return nil
}

// collectRequireMFAPosture reports security.require_mfa itself, and whether it
// is in ADR-112's upgrade grace period. Same facts the server uses at boot
// (server/adr112_grace.go): the key is absent from the config, the database
// already has users, and the config.ADR112RequireMFAEnforcedMarker row is
// absent. In that state the server does NOT enforce MFA, whatever Load()
// resolved the field to, so it is a deviation even when every admin happens to
// be enrolled. An explicit false is a deviation of its own.
func collectRequireMFAPosture(ctx context.Context, cfg *config.Config, store corestorage.Storage, report *postureReport) (inGrace bool, err error) {
	sec := cfg.Security
	if !sec.RequireMFA {
		report.deviate("admin-mfa", "security.require_mfa is false: interactive logins do not require a second factor (ADR-112 requires it on)")
		return false, nil
	}
	if !sec.RequireMFAImplicitDefault {
		return false, nil
	}
	inGrace, since, err := adr112UpgradeGraceFromStore(ctx, store, config.ADR112RequireMFAEnforcedMarker, "require_mfa")
	if err != nil {
		return false, err
	}
	if since != "" {
		report.info("security.require_mfa is enforcing on its ADR-112 default (enforced since " + since + ")")
		return false, nil
	}
	if !inGrace {
		return false, nil // fresh install: the server enforces require_mfa from its first start
	}
	// #2986: the registry entry security.insecure_disable_mfa_requirement reads
	// this flag (collectInsecureSettingsPosture runs after this), the same way
	// the server's boot sets it in applyADR112UpgradeGrace.
	cfg.Security.RequireMFAUpgradeGrace = true
	report.deviateShippedDefault("grace-period", "security.require_mfa is in its ADR-112 upgrade grace period: this upgraded deployment never set it, so the server does NOT enforce MFA yet. Have every interactive admin enrol, then set security.require_mfa: true explicitly (#2923 tracks an automatic end condition)")
	return true, nil
}

// collectBreakGlassReviewPosture is the two findings Andrei decided on #2461:
// an unreviewed break-glass activation past its review window is a FAILING
// finding, and a single-admin deployment reports "independent review
// impossible" as a finding of its own.
//
// Both are TODOs rather than code, because #2461 is still OPEN and its API is
// not on main or anywhere in this PR's base chain
// (#2446 -> #2454 -> #2462): core.ListUnreviewedBreakGlassActivations,
// BreakGlassConfig.GetReviewWindow and the review endpoint all arrive with it.
// An earlier revision of this branch was stacked on #2461 and had the first
// finding implemented; that stack is gone now that this PR sits on #2462, and
// reimplementing the API here would fork it.
//
// TODO(#2461): when #2461 merges, restore both findings:
//
//  1. report.deviate("break-glass-review", ...) for every activation older
//     than cfg.BreakGlass.GetReviewWindow() with no review, listing each
//     activation id, project and activation time. The implementation is in
//     this branch's history (the commit before the rebase onto #2462) and was
//     working; it needs no redesign, only the API back.
//  2. report.deviate("break-glass-review", "independent review impossible")
//     when the install has exactly ONE admin-tier holder. This one is a
//     SEPARATE finding, not a detail of the first: with a single admin, every
//     activation is reviewed by the person who activated it, so a clean
//     review record carries no independent assurance at all. It must fire even
//     when every activation HAS been reviewed -- otherwise the install with
//     the weakest possible review process is the one that looks compliant.
//     collectAdminMFAPosture already resolves the admin-tier holder set, so
//     the count is available without new storage work; it is left out here
//     only because "independent review impossible" is meaningless to report
//     before the review requirement it refers to exists.
//
// Deliberately not approximated in the meantime. A finding that said
// "break-glass review status unknown" would be a third thing to maintain and
// would read, in a report whose entire purpose is a trustworthy yes/no, as if
// the check existed.

func printPostureReport(report *postureReport) {
	fmt.Println("ADR-112 Secure Baseline Posture")
	fmt.Println("===============================")
	if len(report.deviations) == 0 {
		fmt.Println("No deviations found.")
	} else {
		// The origin is printed per line, and the counts are summarised, so an
		// operator reading a non-zero exit can immediately see how much of it is
		// "not hardened yet" versus "deliberately turned off". Both are counted:
		// see deviationOrigin.
		var shipped int
		for _, d := range report.deviations {
			if d.origin == originShippedDefault {
				shipped++
			}
		}
		fmt.Printf("%d deviation(s) found (%d from shipped defaults, %d explicitly configured) — all counted:\n",
			len(report.deviations), shipped, len(report.deviations)-shipped)
		for _, d := range report.deviations {
			fmt.Printf("  [%s/%s] %s\n", d.category, d.origin, d.detail)
		}
	}
	if len(report.informational) > 0 {
		fmt.Println("\nInformational (not counted toward the exit code):")
		for _, line := range report.informational {
			fmt.Printf("  - %s\n", line)
		}
	}
}
