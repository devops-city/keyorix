package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/startup"
)

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
// previously reachable ONLY via the manual `keyorix-server admin validate` CLI subcommand,
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
