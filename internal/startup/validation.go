package startup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

const (
	statusFail = "❌"
	statusPass = "✅"
)

// ValidationResult contains the results of startup validation
type ValidationResult struct {
	ConfigValid   bool
	PermissionsOK bool
	EncryptionOK  bool
	DatabaseOK    bool
	Warnings      []string
	Errors        []string

	// Which checks actually RAN. validateStartup stops at its first hard
	// failure, so a false *OK field alone cannot tell "ran and failed" from
	// "never reached"; a caller reporting per-check outcomes (the posture
	// report, server/admin/posture.go) needs both. A check that is switched
	// off (file-permission check disabled, encryption disabled) did not run
	// either, and its *OK is true by convention.
	PermissionsChecked bool
	EncryptionChecked  bool
	DatabaseChecked    bool
	// PermissionsIssue is what the file-permission check found, whether it
	// then failed validation or was tolerated by
	// security.allow_unsafe_file_permissions (in which case validation carries
	// on and the issue is otherwise only in Warnings). "" when it found none or
	// did not run.
	PermissionsIssue string
	// InsecureSettings is the STRUCTURED posture view of every ADR-112
	// `insecure_` opt-out this validator knows about, alongside the
	// human-readable Warnings above. Structured on purpose (Andrei's decision,
	// 2026-10-05): "configured but not in effect, and here is why" is a
	// distinct state from both "off" and "weakening your durability", and a
	// consumer — the posture report, a dashboard, an auditor's script — has to
	// be able to tell them apart from a field rather than by parsing log text.
	//
	// Today it carries the access-log drop mode only. When ADR-112's registry
	// (#2454) lands, this slice should be populated by iterating that registry
	// instead of being hand-built here.
	InsecureSettings []InsecureSettingStatus
	// EffectiveAuditDurability is the effective storage.database.audit_durability
	// (ADR-112 Amendment 3). Informational: both levels are baseline, so it
	// is never a Warning or an InsecureSettings entry. Zero when validation
	// stopped before the database check.
	EffectiveAuditDurability config.AuditDurabilityStatus
}

// InsecureSettingStatus is one ADR-112 `insecure_` opt-out's posture state.
type InsecureSettingStatus struct {
	// Name is the canonical dotted config path, insecure_-prefixed leaf.
	Name string
	// Configured is true when the operator wrote the key into the config file,
	// whether or not it does anything on this backend.
	Configured bool
	// InEffect is true only when the setting is configured AND actually
	// weakening something right now.
	InEffect bool
	// NotInEffectReason is non-empty ONLY when Configured is true and InEffect
	// is false — so a non-empty value always means "you wrote this and it is
	// doing nothing", and never means anything else.
	NotInEffectReason string
	// Describe is a one-line explanation of what being in effect weakens.
	Describe string
}

// ValidateStartup performs comprehensive startup validation. forceAutoFix, when
// true, remediates file-permission issues regardless of the loaded config's
// Security.AutoFixFilePermissions setting — this is how a caller-supplied
// intent (e.g. an explicit CLI flag) takes effect without silently depending
// on a field read from the very config file being validated.
func ValidateStartup(configPath string, forceAutoFix bool) (*ValidationResult, error) {
	return validateStartup(configPath, forceAutoFix, false)
}

// ValidateStartupTolerant is ValidateStartup, except a KEK salt/wrapped-DEK pair
// that BOTH don't exist yet is a warning, not an error, from validateEncryption.
//
// server/main.go's runStartupValidation is the sole caller: it runs BEFORE
// initializeCoreService's encryption.Service.Initialize, which performs
// first-boot key generation (ensureSaltExists/ensureWrappedDEKExists) when
// they're missing — so on an actual fresh install, "missing" here means
// "about to be generated in a few hundred milliseconds," not "broken."
// ADR-112 flips security.enable_file_permission_check's default to true,
// which is what makes this server-boot path reach ValidateStartup at all for
// a deployment that never explicitly asked for it — this tolerance is what
// keeps that flip from refusing to complete a fresh install's first boot.
//
// `keyorix-server admin ... validate` (server/admin/validate.go) and
// examples/system_init deliberately keep calling the strict ValidateStartup
// above, unchanged: an operator invoking validate (or the init example)
// explicitly, as a diagnostic, wants "encryption is enabled but no key
// material exists" reported as the real problem it is, not silently
// explained away as "first boot" — they are not mid-boot-sequence the moment
// before auto-generation runs the way the server's own call is.
//
// It also applies only while the loaded config leaves enable_file_permission_check
// to ADR-112's implicit default, and under that default an orchestrator-mounted
// input (the config file, a TLS cert/key) with the wrong mode or owner is a
// warning naming the file and the fix rather than an error (see
// validateFilePermissions). Key material and the database stay strict.
func ValidateStartupTolerant(configPath string, forceAutoFix bool) (*ValidationResult, error) {
	return validateStartup(configPath, forceAutoFix, true)
}

func validateStartup(configPath string, forceAutoFix bool, tolerateUnprovisionedKeys bool) (*ValidationResult, error) {
	result := &ValidationResult{
		ConfigValid:   false,
		PermissionsOK: false,
		EncryptionOK:  false,
		DatabaseOK:    false,
		Warnings:      []string{},
		Errors:        []string{},
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to load config: %v", err))
		return result, fmt.Errorf("configuration validation failed: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Config schema validation failed: %v", err))
		return result, fmt.Errorf("configuration validation failed: %w", err)
	}
	result.ConfigValid = true
	// The tolerant variant's relaxations exist only for ADR-112's implicit default;
	// a config that writes the key itself is audited strictly whoever the caller is.
	tolerateUnprovisionedKeys = tolerateUnprovisionedKeys && cfg.Security.EnableFilePermissionCheckImplicitDefault

	if cfg.Security.EnableFilePermissionCheck {
		result.PermissionsChecked = true
		if err := validateFilePermissions(cfg, configPath, forceAutoFix, tolerateUnprovisionedKeys, result); err != nil {
			result.PermissionsIssue = err.Error()
			if !cfg.Security.AllowUnsafeFilePermissions {
				return result, fmt.Errorf("file permission validation failed: %w", err)
			}
			result.Warnings = append(result.Warnings, fmt.Sprintf("File permission issues detected but allowed: %v", err))
		} else {
			result.PermissionsOK = true
		}
	} else {
		result.PermissionsOK = true
		result.Warnings = append(result.Warnings, "File permission checks are disabled")
	}

	if cfg.Storage.Encryption.Enabled {
		result.EncryptionChecked = true
		if err := validateEncryption(cfg, result, tolerateUnprovisionedKeys); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Encryption validation failed: %v", err))
			return result, fmt.Errorf("encryption validation failed: %w", err)
		}
		result.EncryptionOK = true
	} else {
		result.EncryptionOK = true
		result.Warnings = append(result.Warnings, "Encryption is disabled")
	}

	result.DatabaseChecked = true
	if err := validateDatabase(cfg, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Database validation failed: %v", err))
		return result, fmt.Errorf("database validation failed: %w", err)
	}
	result.DatabaseOK = true

	// ADR-112 Amendment 3: admin validate reports the effective audit
	// durability level. Both levels are baseline, so it is never a warning.
	result.EffectiveAuditDurability = cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type)
	appendAccessLogPosture(cfg, result)

	return result, nil
}

// AccessLogOnSinkStallSettingName is the dotted config path of the access-log
// stall mode.
const AccessLogOnSinkStallSettingName = "server.access_log.on_sink_stall"

const accessLogDropDescribe = "when the log sink stalls, access-log lines past the 1 MiB queue are " +
	"dropped (counted in /api/v1/system/info access_log_dropped) instead of making requests wait"

// AccessLogDropModeWarning is the startup and posture line when
// server.access_log.on_sink_stall is "drop". The default "block" is not a
// deviation and records nothing, so a default install still shows zero.
const AccessLogDropModeWarning = "Access log stall mode is DROP (server.access_log.on_sink_stall): " +
	"keeps serving secrets when the log sink stalls; access-log lines past the 1 MiB queue are dropped " +
	"and reported; the audit trail is unaffected"

// appendAccessLogPosture records the drop mode in result, as a Warnings line
// and a structured InsecureSettings entry. It is always in effect when
// configured.
func appendAccessLogPosture(cfg *config.Config, result *ValidationResult) {
	if cfg.Server.AccessLog.EffectiveOnSinkStall() != config.AccessLogOnSinkStallDrop {
		return
	}
	result.InsecureSettings = append(result.InsecureSettings, InsecureSettingStatus{
		Name:       AccessLogOnSinkStallSettingName,
		Configured: true,
		InEffect:   true,
		Describe:   accessLogDropDescribe,
	})
	result.Warnings = append(result.Warnings, AccessLogDropModeWarning)
}

// SafeFilePermPath cleans path and rejects it if the cleaned form still
// contains a ".." segment. Unlike validateEncryption/validateDatabase (whose
// paths come from a small, fixed set of config fields dedicated to a single
// key/db file), the paths collected here span several independently-authored
// config fields (config path, key paths, TLS cert/key paths, db path) that
// FixFilePerms below will Lstat/Chmod/Chown — so every one of them is
// sanitized the same way before it is ever added to that list, closing off a
// config-driven path-traversal into chmod/chown of an unintended file.
func SafeFilePermPath(label, path string) (string, error) {
	// Single source of truth for the path-safety rule. This used to be a
	// byte-identical copy of keyfiles.SafePath; two independent copies of a
	// traversal guard drift, and then one gets a fix the other doesn't, so it
	// delegates. Behaviour (cleaned path, ".."-substring rejection, identical
	// error text) is unchanged.
	return keyfiles.SafePath(label, path)
}

// implicitDefault (ValidateStartupTolerant only: security.enable_file_permission_check is
// on through ADR-112's default, not written in the config) changes two things:
//
//   - It leaves out of the audit the files the server itself creates at 0600 later in
//     the same first boot: the key material when EVERY key file is absent (the same
//     both-missing rule as validateEncryption; a partial set is audited, and refused by
//     the key-set consistency check), and a local database file that does not exist yet.
//   - The config file and the TLS cert/key are inputs an orchestrator mounts (a
//     Kubernetes ConfigMap/Secret is root-owned 0644 by default, a docker-compose bind
//     mount keeps the host owner), so a mode/owner mismatch on them is a warning naming
//     the file, the mismatch and the fix, not a refusal. Key material and the database
//     stay strict. An explicit enable_file_permission_check: true audits everything
//     strictly, as before ADR-112.
func validateFilePermissions(cfg *config.Config, configPath string, forceAutoFix, implicitDefault bool, result *ValidationResult) error { // NOSONAR -- cognitive complexity 27, suppress go:S3776
	var files []securefiles.FilePermSpec
	// mounted holds the orchestrator-mounted inputs (config file, TLS cert/key); they
	// join files (strict) unless implicitDefault, see the doc comment above.
	var mounted []mountedInput

	// Check the config file that was actually loaded, not a hardcoded "keyorix.yaml":
	// the loader resolves KEYORIX_CONFIG_PATH / an absolute path, so a fixed relative
	// name would silently stat a non-existent file and pass. Skip only when truly unknown.
	if cfgFile := strings.TrimSpace(configPath); cfgFile != "" {
		clean, err := SafeFilePermPath("config file", cfgFile)
		if err != nil {
			return err
		}
		mounted = append(mounted, mountedInput{"config file", securefiles.FilePermSpec{Path: clean, Mode: 0600}})
	}

	if cfg.Storage.Encryption.Enabled {
		// The KEK salt and wrapped DEK (ADR-004) are always present; a TPM/cloud-KMS
		// key_provider (ADR-038/ADR-041) adds a separate wrapped-KEK blob, and a
		// shamir key_provider's share files are also key material -- see
		// internal/keyfiles.Registry, the single enumeration every key-permission
		// checker in this repo shares (this function used to hand-build a
		// salt+DEK-only list here, which is exactly how the wrapped-KEK blob went
		// unchecked for every TPM/KMS deployment).
		specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
		if err != nil {
			return err
		}
		if implicitDefault && noneExist(specs) {
			result.Warnings = append(result.Warnings, "Key material does not exist yet — treating as first boot; its permissions are checked once it is generated")
		} else {
			files = append(files, specs...)
		}
	}

	// Mirror Config.Validate()'s switch on Storage.Type: only "local"/"" storage has a
	// local database FILE to lock down. postgres/remote connect over the network (DSN or
	// host/name/user, or the remote client's own auth) and legitimately have an empty
	// Database.Path — appending it unconditionally would stat/chmod the current directory
	// (filepath.Clean("") == ".") instead of skipping the check.
	switch cfg.Storage.Type {
	case "remote", "postgres", "postgresql":
		// no local database file to check
	default: // "local", ""
		if cfg.Storage.Database.Path != "" {
			dbPath, err := SafeFilePermPath("database", cfg.Storage.Database.Path)
			if err != nil {
				return err
			}
			if implicitDefault && noneExist([]securefiles.FilePermSpec{{Path: dbPath}}) {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Database file %s does not exist yet — treating as first boot; it is created at 0600", dbPath))
			} else {
				files = append(files, securefiles.FilePermSpec{
					Path: dbPath,
					Mode: 0600,
				})
			}
		}
	}

	if cfg.Server.HTTP.TLS.Enabled {
		certPath, err := SafeFilePermPath("HTTP TLS cert", cfg.Server.HTTP.TLS.CertFile)
		if err != nil {
			return err
		}
		keyPath, err := SafeFilePermPath("HTTP TLS key", cfg.Server.HTTP.TLS.KeyFile)
		if err != nil {
			return err
		}
		mounted = append(mounted,
			mountedInput{"HTTP TLS cert", securefiles.FilePermSpec{Path: certPath, Mode: 0600}},
			mountedInput{"HTTP TLS key", securefiles.FilePermSpec{Path: keyPath, Mode: 0600}},
		)
	}
	if cfg.Server.GRPC.TLS.Enabled {
		certPath, err := SafeFilePermPath("gRPC TLS cert", cfg.Server.GRPC.TLS.CertFile)
		if err != nil {
			return err
		}
		keyPath, err := SafeFilePermPath("gRPC TLS key", cfg.Server.GRPC.TLS.KeyFile)
		if err != nil {
			return err
		}
		mounted = append(mounted,
			mountedInput{"gRPC TLS cert", securefiles.FilePermSpec{Path: certPath, Mode: 0600}},
			mountedInput{"gRPC TLS key", securefiles.FilePermSpec{Path: keyPath, Mode: 0600}},
		)
	}

	autoFix := cfg.Security.AutoFixFilePermissions || forceAutoFix
	for _, m := range mounted {
		if !implicitDefault {
			files = append(files, m.spec)
			continue
		}
		if err := securefiles.FixFilePerms([]securefiles.FilePermSpec{m.spec}, autoFix); err != nil {
			result.Warnings = append(result.Warnings, describeMountedInputMismatch(m))
		}
	}
	if err := securefiles.FixFilePerms(files, autoFix); err != nil {
		return fmt.Errorf("file permission validation failed: %w", err)
	}

	if autoFix {
		result.Warnings = append(result.Warnings, autoFixPermsNotice)
	}

	return nil
}

// mountedInput is a file an orchestrator typically provides read-only (config, TLS).
type mountedInput struct {
	label string
	spec  securefiles.FilePermSpec
}

// describeMountedInputMismatch is the warning for a mounted input that failed the
// audit under the ADR-112 implicit default: the file, what is wrong with it, and how
// to fix it.
func describeMountedInputMismatch(m mountedInput) string {
	var problems []string
	info, err := os.Lstat(m.spec.Path)
	switch {
	case err != nil:
		problems = append(problems, fmt.Sprintf("cannot be inspected (%v)", err))
	case info.Mode()&os.ModeSymlink != 0:
		problems = append(problems, "is a symlink")
	default:
		if perm := info.Mode().Perm(); perm != m.spec.Mode {
			problems = append(problems, fmt.Sprintf("has mode %04o, expected %04o", perm, m.spec.Mode))
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
			problems = append(problems, fmt.Sprintf("is owned by uid %d, expected the server's uid %d", st.Uid, os.Getuid()))
		}
	}
	if len(problems) == 0 {
		problems = append(problems, "failed the permission audit")
	}
	return fmt.Sprintf("ADR-112: %s %s %s. Fix: chmod %o and chown it to the server's user (Kubernetes: mount it with defaultMode 0400 and the pod's fsGroup, or copy it into an emptyDir in an initContainer running as the server's uid; docker-compose: chown/chmod the host file to match the container user). On the implicit security.enable_file_permission_check default this only warns; set the key to true explicitly to refuse to start on it.",
		m.label, m.spec.Path, strings.Join(problems, " and "), m.spec.Mode)
}

// noneExist reports whether every spec's path is absent (os.ErrNotExist). Any
// other stat result, including an error, counts as existing, so the file stays
// in the audit.
func noneExist(specs []securefiles.FilePermSpec) bool {
	for _, sp := range specs {
		if _, err := os.Stat(sp.Path); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

// autoFixPermsNotice is shown whenever automatic permission fixing is ON (config
// security.auto_fix_file_permissions, or admin validate --fix), not only when
// something was changed. FixFilePerms prints one "[FIXED] <path>: <old> -> <new>"
// line per file it actually changed, so say that, and say what to do (#2940: the
// old text, "File permissions were automatically fixed", appeared on every start
// and read like a fault).
const autoFixPermsNotice = "Automatic file-permission fixing is on (security.auto_fix_file_permissions in keyorix.yaml): " +
	"wrong modes on key, config and database files are reset at every start, and each change is logged as \"[FIXED] <path>\". " +
	"If no [FIXED] line appears, nothing needed changing. Set it to false to turn this off."

// validateEncryption verifies the on-disk key material required by the ADR-004
// envelope scheme: the 32-byte KEK salt and the wrapped DEK. The KEK itself is
// derived from the master passphrase at runtime and never touches disk, so there
// is no KEK file to check. The DEK on disk is wrapped (AES-256-GCM: 12-byte nonce
// + 32-byte key + 16-byte tag = 60 bytes), not a bare 32-byte key.
//
// tolerateUnprovisionedKeys, when true (ValidateStartupTolerant), treats BOTH
// files missing as "not yet provisioned" (a warning) rather than an error — see
// ValidateStartupTolerant's doc comment for why the server's own boot path needs
// this and the CLI `admin validate` diagnostic path (tolerateUnprovisionedKeys
// false, via the plain ValidateStartup) does not. Exactly one of the two missing
// (as opposed to both) is NEVER given this pass, even when tolerant: that is a
// broken partial state no ordinary boot sequence produces, not a fresh install,
// and stays a hard error below regardless of the caller.
func validateEncryption(cfg *config.Config, result *ValidationResult, tolerateUnprovisionedKeys bool) error {
	enc := cfg.Storage.Encryption

	saltPath := resolveKeyPath(enc.SaltPath)
	if strings.Contains(saltPath, "..") {
		return fmt.Errorf("KEK salt path is unsafe: %s", saltPath)
	}
	dekPath := resolveKeyPath(enc.DEKPath)
	if strings.Contains(dekPath, "..") {
		return fmt.Errorf("DEK path is unsafe: %s", dekPath)
	}

	saltInfo, saltErr := os.Stat(saltPath)
	dekInfo, dekErr := os.Stat(dekPath)
	if tolerateUnprovisionedKeys && os.IsNotExist(saltErr) && os.IsNotExist(dekErr) {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"KEK salt (%s) and wrapped DEK (%s) do not exist yet — treating as first boot; they will be generated before this check runs again",
			saltPath, dekPath))
		return nil
	}

	if saltErr != nil {
		return fmt.Errorf("KEK salt file not found: %s", saltPath)
	}
	if saltInfo.Size() != 32 {
		return fmt.Errorf("KEK salt file %s has invalid size %d bytes (expected 32)", saltPath, saltInfo.Size())
	}

	if dekErr != nil {
		return fmt.Errorf("wrapped DEK file not found: %s", dekPath)
	}
	const minWrappedDEKSize = 60 // 12-byte GCM nonce + 32-byte key + 16-byte tag
	if dekInfo.Size() < minWrappedDEKSize {
		return fmt.Errorf("wrapped DEK file %s is too small (%d bytes) to be a valid wrapped key", dekPath, dekInfo.Size())
	}
	return nil
}

// resolveKeyPath maps a configured key path to its on-disk location, mirroring
// the baseDir resolution the server uses at startup: absolute paths are used
// as-is, relative paths are resolved against the working directory.
func resolveKeyPath(p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(".", p))
}

func validateDatabase(cfg *config.Config, result *ValidationResult) error {
	// Mirror Config.Validate()'s switch on Storage.Type: only "local"/"" storage is a
	// local SQLite file reachable by stat/open. postgres/remote reach their backing store
	// over the network and are out of scope for a local-file reachability check here.
	switch cfg.Storage.Type {
	case "remote":
		result.Warnings = append(result.Warnings, "Database reachability check skipped: storage.type is \"remote\" (network client, not a local file)")
		return nil
	case "postgres", "postgresql":
		result.Warnings = append(result.Warnings, "Database reachability check skipped: storage.type is \"postgres\" (network connection, not a local file)")
		return nil
	}

	dbPath := filepath.Clean(cfg.Storage.Database.Path)

	if strings.Contains(dbPath, "..") || !filepath.IsAbs(dbPath) {
		return fmt.Errorf("unsafe or relative database path: %s", dbPath)
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Database file does not exist: %s (will be created on first use)", dbPath))
		return nil
	}

	file, err := secretenv.OpenRegularNamed("database file", dbPath) // a FIFO is refused, not waited on
	if err != nil {
		return fmt.Errorf("cannot open database file %s: %w", dbPath, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close database file: %w", err)
	}

	return nil
}

func PrintValidationResult(result *ValidationResult) {
	fmt.Println("🔍 Startup Validation Results")
	fmt.Println("============================")

	printStatus := func(name string, ok bool) {
		if ok {
			fmt.Printf("%-13s: %s\n", name, statusPass)
		} else {
			fmt.Printf("%-13s: %s\n", name, statusFail)
		}
	}

	printStatus("Configuration", result.ConfigValid)
	printStatus("Permissions", result.PermissionsOK)
	printStatus("Encryption", result.EncryptionOK)
	printStatus("Database", result.DatabaseOK)
	if result.EffectiveAuditDurability.Level != "" {
		fmt.Printf("%-13s: %s (%s)\n", "Audit durability", result.EffectiveAuditDurability.Level, result.EffectiveAuditDurability.Level.Meaning())
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\n⚠️  Warnings:")
		for _, w := range result.Warnings {
			fmt.Printf("   • %s\n", w)
		}
	}
	if len(result.Errors) > 0 {
		fmt.Println("\n❌ Errors:")
		for _, e := range result.Errors {
			fmt.Printf("   • %s\n", e)
		}
	}

	if result.ConfigValid && result.PermissionsOK && result.EncryptionOK && result.DatabaseOK {
		fmt.Println("\n🎉 All validations passed!")
	} else {
		fmt.Println("\n⚠️  Some validations failed. Please review the output above.")
	}
}
