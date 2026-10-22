package config

import (
	"fmt"
	"time"
)

type StorageConfig struct {
	Type string `yaml:"type"` // "local" (alias "sqlite"), "postgres", "postgresql", "remote"
	// "remote" is rejected unconditionally by Validate (validateRemoteStorageNotServer,
	// ADR-083) -- this Config type is only ever used to configure a server process, and
	// remote storage is a CLI/client mode only. There is deliberately no Remote field
	// here: a "remote" storage.type config carries no server-side settings to parse.
	Database   DatabaseConfig   `yaml:"database"`
	Encryption EncryptionConfig `yaml:"encryption"`
}

type DatabaseConfig struct {
	// SQLite
	Path string `yaml:"path"`

	// RequireExistingPath (INV-STORAGE-22, ADR-095 "Task 3", #2504) makes the
	// server REFUSE to boot when the SQLite file at Path does not already
	// exist, instead of letting gorm.Open silently vivify a fresh, empty,
	// healthy-looking store. A mistyped path or a volume mount that failed to
	// attach otherwise produces a working server with zero secrets in it and
	// no error anywhere — the operator's own data is still on disk, untouched,
	// at the path they meant.
	//
	// Default false, i.e. today's create-if-missing behaviour, DELIBERATELY:
	// nothing in the supported first-boot paths creates the database file
	// before the server starts (server/entrypoint.sh and docker-compose.yml
	// both boot the server directly; `keyorix-server admin init`, the
	// explicit "yes, a fresh install belongs here" marker ADR-095 names, is
	// optional), so defaulting this to true would break every containerized
	// first boot. ADR-095 Task 3 says the flip "deserves a deliberate
	// sign-off rather than landing inside a same-day investigation" — this
	// field is that sign-off's prerequisite, not the flip itself.
	//
	// Does not apply to an in-memory DSN (":memory:", "mode=memory"), which
	// has no file to pre-exist, nor to the Postgres backend.
	RequireExistingPath bool `yaml:"require_existing_path"`

	// PostgreSQL — use DSN directly or set individual fields
	DSN      string `yaml:"dsn"` // e.g. "host=localhost user=keyorix dbname=keyorix port=5432 sslmode=require"
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Name     string `yaml:"name"`
	User     string `yaml:"user"`
	Password string `yaml:"password"` // use KEYORIX_DB_PASSWORD env var instead
	SSLMode  string `yaml:"ssl_mode"` // disable, require, verify-ca, verify-full
	// SSLRootCert is the PEM file of the CA that signed the PostgreSQL
	// server's certificate, passed to the driver as sslrootcert (or "system"
	// for the OS CA store). REQUIRED when ssl_mode is verify-full/verify-ca:
	// without it the server refuses to start rather than verify against a
	// trust store the config does not name. A relative path is anchored to
	// the config file's directory, like database.path. See database_tls.go.
	SSLRootCert string `yaml:"ssl_root_cert"`

	// Shared pool settings
	MaxOpenConns           int `yaml:"max_open_conns"`
	MaxIdleConns           int `yaml:"max_idle_conns"`
	ConnMaxLifetimeMinutes int `yaml:"conn_max_lifetime_minutes"`

	// NativeReadPoolMax caps the Postgres pool the hottest read-path statements
	// run on (the machine credential lookup and the node-stamp read; see
	// storage.NativeReadPoolMaxSize). 0 or unset is DefaultNativeReadPoolMax.
	// Never more than the request pool's own cap. Postgres only.
	NativeReadPoolMax int `yaml:"native_read_pool_max"`

	// AuditFlusherLingerWindow (SESSION-PERF, #2420 follow-up) is how long the
	// audit-chain batching flusher deliberately waits, after its first queued
	// item, for more items to arrive before committing — a Go duration string
	// (e.g. "1ms"), or empty/unset for the default. Default is "0" (no
	// deliberate wait — drain whatever's already queued and commit
	// immediately), NOT a tuned nonzero value: measurement across 0/0.5/1/2ms
	// found every nonzero window pays a fixed ~5.5-7ms tax on a single-client
	// read regardless of its nominal size, and on Postgres specifically any
	// nonzero window regresses c=10 throughput even though it roughly doubles
	// c=50 throughput (see PR #2420's body for the full data). Left
	// configurable, rather than removed, so a deployment with real production
	// batch-size telemetry (keyorix_audit_flusher_batch_size,
	// keyorix_audit_flusher_flushes_total) justifying a nonzero value can set
	// one without a code change.
	AuditFlusherLingerWindow string `yaml:"audit_flusher_linger_window"`

	// AuditDurability (ADR-112 Amendment 3, docs/specs/fast-audit-mode.md)
	// chooses whether the audit commit waits for the disk sync. Config file
	// only; no HTTP handler, gRPC RPC, env var or CLI flag can set it (the
	// guards are TestAuditDurability_NoWriteAssignment and
	// TestAuditDurability_NotSettableFromTheEnvironment). Read it through
	// EffectiveAuditDurability, never directly: the default depends on the
	// backend and on the deprecated alias below.
	//
	//   - "strict": the audit commit waits for the disk sync. No audit entry
	//     is lost to any crash or power loss. The only level on SQLite.
	//   - "standard": the audit row is still INSERTed and COMMITted before the
	//     secret is returned, and a failed audit write still fails the
	//     request; only the wait for the disk sync is skipped (`SET LOCAL
	//     synchronous_commit = off` on the audit transaction, and only that
	//     transaction). A Keyorix process crash loses nothing; an OS crash,
	//     power loss or PostgreSQL crash can lose up to ~600 ms (3 ×
	//     wal_writer_delay) of audit entries as a TAIL, never a gap or a fork.
	//     PostgreSQL only, and the PostgreSQL default.
	//   - "" (unset): the backend default -- standard on PostgreSQL, strict on
	//     SQLite.
	//
	// Non-audit writes (secret writes, revocations, rotations) commit durably
	// at both levels. SQLite refuses standard at start-up
	// (auditDurabilityStandardSQLiteUnsupportedError): its synchronous pragma
	// is per-connection and the pool is shared, so relaxing it would relax
	// every table, not only audit (Amendment 1's rejection, which stands).
	AuditDurability string `yaml:"audit_durability"`

	// InsecureAuditSkipDurableSync is the DEPRECATED alias of AuditDurability,
	// kept for one minor release (ADR-112 Amendment 3): true means standard,
	// an explicit false means strict, absent means "not set". A pointer so an
	// explicit false is distinguishable from an absent key. Setting both keys
	// to conflicting levels refuses to start (Validate); Load adds a
	// deprecation line to DeprecatedSettingWarnings whenever it is present.
	InsecureAuditSkipDurableSync *bool `yaml:"insecure_audit_skip_durable_sync"`

	// InsecureAuditSkipReads (ADR-112 Amendment 4) stops SUCCESSFUL secret-value
	// reads from writing an audit row (and their secret_access_logs row): every
	// path that discloses a value -- REST, gRPC, render, copy, federated
	// connect reads, and the CLI, sync and operator clients through the API.
	// Everything else stays audited: secret create/update/delete/version
	// changes, permission/role/share/policy changes, authentication events and
	// failures, denied reads, admin and break-glass actions, configuration and
	// key operations. Default false; config file only (the guards are
	// TestInsecureAuditSkipReads_NoWriteAssignment and
	// TestInsecureAuditSkipReads_NotSettableFromTheEnvironment). Independent of
	// AuditDurability, which governs every row still written. A compliance
	// profile refuses it (complianceProfileRefusals).
	InsecureAuditSkipReads bool `yaml:"insecure_audit_skip_reads"`

	// Pooler names the connection pooler between Keyorix and PostgreSQL:
	// "none" (the default, also when empty), "pgbouncer-session" or
	// "pgbouncer-transaction". Only pgbouncer-transaction changes behaviour;
	// see TransactionPooling and docs/postgresql-poolers.md.
	Pooler string `yaml:"pooler"`

	// SingleWriter (docs/specs/single-writer-cache.md) declares this server the
	// ONLY writer of its PostgreSQL database. Default false; false changes
	// nothing. When true the server takes a per-schema advisory lock at boot
	// and refuses to start if another server holds it, installs a write fence
	// that refuses every write to the security tables from any other session
	// while it runs, and keeps a write epoch it polls (internal/solewriter). If
	// the fence cannot be installed and verified, the server refuses to start:
	// the setting is never in effect without it.
	//
	// PostgreSQL only: a SQLite or remote backend refuses to start with it set,
	// as do auth_rate_limit_fallback.replicas > 1 (a declared multi-replica
	// deployment) and pooler pgbouncer-transaction (the lock and the session
	// tag are session-scoped).
	SingleWriter bool `yaml:"single_writer"`
}

// GetPassword returns the resolved DB password, preferring the environment variable.
func (d *DatabaseConfig) GetPassword() string {
	return resolveSecret("KEYORIX_DB_PASSWORD", d.Password)
}

// GetAuditFlusherLingerWindow returns the configured audit-flusher linger
// window, defaulting to 0 (no deliberate wait) when unset or unparseable.
// See AuditFlusherLingerWindow's doc comment for why 0, not a tuned nonzero
// value, is the default.
func (d *DatabaseConfig) GetAuditFlusherLingerWindow() time.Duration {
	return parseDurationDefault(d.AuditFlusherLingerWindow, 0)
}

// singleWriterUnsupportedBackendError / singleWriterMultiReplicaError are the
// start-up refusals for storage.database.single_writer outside its one
// supported topology (one server, PostgreSQL).
const (
	singleWriterUnsupportedBackendError = "storage.database.single_writer is only supported with storage.type postgres: " +
		"it relies on PostgreSQL session advisory locks and triggers; remove the setting"
	singleWriterMultiReplicaError = "storage.database.single_writer allows exactly one server, but " +
		"security.auth_rate_limit_fallback.replicas declares more than one; remove one of the two settings"
	singleWriterTransactionPoolingError = "storage.database.single_writer is not supported with storage.database.pooler " +
		"pgbouncer-transaction: its holder lock and session tag are session-scoped; use pgbouncer-session or connect directly"
)

// AuditDurabilityLevel is one value of storage.database.audit_durability.
type AuditDurabilityLevel string

const (
	// AuditDurabilityStrict: the audit commit waits for the disk sync.
	AuditDurabilityStrict AuditDurabilityLevel = "strict"
	// AuditDurabilityStandard: the audit row is committed before every
	// disclosure, without waiting for the disk sync. PostgreSQL only.
	AuditDurabilityStandard AuditDurabilityLevel = "standard"
)

// AuditDurabilitySettingName is the canonical dotted path of the setting.
const AuditDurabilitySettingName = "storage.database.audit_durability"

// auditDurabilityDeprecatedAliasName is the dotted path of the deprecated alias.
const auditDurabilityDeprecatedAliasName = "storage.database.insecure_audit_skip_durable_sync"

// auditDurabilityStandardSQLiteUnsupportedError is the exact start-up refusal
// for standard on a SQLite backend (ADR-112 Amendment 1's rejection, kept by
// Amendment 3). A constant so Validate and its tests cannot drift apart.
const auditDurabilityStandardSQLiteUnsupportedError = "storage.database.audit_durability: standard is only " +
	"supported with PostgreSQL; SQLite runs strict only -- remove the setting or set it to strict"

// Meaning returns the one-line, operator-facing meaning of the level, used by
// the start-up INFO line, admin validate and the posture report.
func (l AuditDurabilityLevel) Meaning() string {
	switch l {
	case AuditDurabilityStandard:
		return "committed before every disclosure; up to ~600 ms of entries can be lost to an OS crash or power loss; " +
			"set audit_durability: strict to wait for the disk sync"
	case AuditDurabilityStrict:
		return "committed and synced to disk before every disclosure; no audit entry is lost to any crash or power loss"
	default:
		return "unknown level"
	}
}

// parseAuditDurability validates an explicit audit_durability value. "" means
// unset and is valid.
func parseAuditDurability(v string) (AuditDurabilityLevel, error) {
	switch AuditDurabilityLevel(v) {
	case "", AuditDurabilityStrict, AuditDurabilityStandard:
		return AuditDurabilityLevel(v), nil
	default:
		return "", fmt.Errorf("storage.database.audit_durability: unknown value %q (allowed: strict, standard)", v)
	}
}

// explicitAuditDurability resolves the two config keys into the level the
// operator asked for, "" when neither is set. Both set with conflicting levels
// is an error: neither key may silently win over the other.
func (d *DatabaseConfig) explicitAuditDurability() (AuditDurabilityLevel, error) {
	level, err := parseAuditDurability(d.AuditDurability)
	if err != nil {
		return "", err
	}
	if d.InsecureAuditSkipDurableSync == nil {
		return level, nil
	}
	alias := AuditDurabilityStrict
	if *d.InsecureAuditSkipDurableSync {
		alias = AuditDurabilityStandard
	}
	if level != "" && level != alias {
		return "", fmt.Errorf("storage.database.audit_durability is %q but the deprecated "+
			"storage.database.insecure_audit_skip_durable_sync: %t means %q; remove the deprecated key",
			level, *d.InsecureAuditSkipDurableSync, alias)
	}
	return alias, nil
}

// validateAuditDurability is Validate's check: a known value, no conflict
// between the key and its deprecated alias, and standard only on PostgreSQL.
func (d *DatabaseConfig) validateAuditDurability(storageType string) error {
	level, err := d.explicitAuditDurability()
	if err != nil {
		return err
	}
	if level == AuditDurabilityStandard && (storageType == "local" || storageType == "sqlite") {
		return fmt.Errorf("%s", auditDurabilityStandardSQLiteUnsupportedError)
	}
	return nil
}

// AuditDurabilityStatus is the effective audit durability of one loaded
// config, the single source of truth the storage factory, the start-up line,
// admin validate, the posture report, the settings diff and GET /system/info
// all read, so they cannot disagree.
type AuditDurabilityStatus struct {
	// Level is the level the audit commit actually runs at.
	Level AuditDurabilityLevel
	// Explicit is true when the config file chose the level (audit_durability
	// or its deprecated alias), false when it is the backend default.
	Explicit bool
}

// EffectiveAuditDurability computes the effective level for storageType:
// the explicit setting when there is one, otherwise standard on PostgreSQL
// and strict everywhere else.
//
// Only postgres/postgresql can ever be standard. An allowlist on purpose: a
// backend that does not implement the SET LOCAL mechanism (SQLite, remote, an
// unknown type in a config that skipped Validate) reports strict, which is
// what it actually does, rather than claiming a relaxation nothing performs.
// An invalid or conflicting setting (refused by Validate) also reports strict.
func (d *DatabaseConfig) EffectiveAuditDurability(storageType string) AuditDurabilityStatus {
	level, err := d.explicitAuditDurability()
	explicit := err == nil && level != ""
	if storageType != "postgres" && storageType != "postgresql" {
		return AuditDurabilityStatus{Level: AuditDurabilityStrict, Explicit: explicit}
	}
	if err != nil {
		return AuditDurabilityStatus{Level: AuditDurabilityStrict}
	}
	if level == "" {
		return AuditDurabilityStatus{Level: AuditDurabilityStandard}
	}
	return AuditDurabilityStatus{Level: level, Explicit: true}
}

// StartupLine is the one INFO line every start logs for the effective level,
// e.g. "audit durability: standard (PostgreSQL default; committed before every
// disclosure; ...)".
func (s AuditDurabilityStatus) StartupLine() string {
	source := ""
	if !s.Explicit && s.Level == AuditDurabilityStandard {
		source = "PostgreSQL default; "
	}
	return fmt.Sprintf("audit durability: %s (%s%s)", s.Level, source, s.Level.Meaning())
}

// validateRemoteStorageNotServer enforces ADR-083: storage.type: remote is a
// CLI/client mode only — it delegates the ENTIRE storage backend to an upstream
// server over HTTP, and RemoteStorage never implements the primitives
// AuthorizePrincipal needs to resolve a permission for ANY caller (GetUserRoleIDsAt,
// GetUserGroupRoleIDsAt, RoleSetHasPermission are all hard "not supported in
// remote storage" stubs). A process with server.http.enabled or
// server.grpc.enabled registers the full RequirePermission-gated route set
// regardless of storage backend — on storage.type: remote, every one of those
// checks would fail closed, for every permission, for every caller, making the
// combination a broken feature, not a smaller one. See ADR-083 for the full
// investigation (which supersedes ADR-049's "downstream Keyorix server" framing)
// before ever considering lifting this gate.
//
// G80 follow-up (2026-08-24): rejects unconditionally now, not just when
// server.http.enabled or server.grpc.enabled. server/main.go's startSchedulers
// (main.go:157) runs EVERY time this process's main() executes, independent of
// both of those flags — #G12 deliberately unified scheduler startup so a
// gRPC-only (HTTP disabled) or even an HTTP-and-gRPC-both-disabled "worker-only"
// deployment still runs its background jobs. Three of the 17 schedulers
// (anomaly_detection, login_attempt_prune, mfa_stepup_grant_prune) have no
// enable flag at all -- they always run -- so no finite enumeration of
// `cfg.X.Enabled` checks can fully close this gap; a new scheduler added later
// would silently reopen it again. This function is safe to make unconditional
// because it is ONLY ever reached from server/main.go's own cfg.Validate() call
// (verified: internal/config.Config.Validate has no caller anywhere in the CLI --
// the old internal/cli tree and the internal/storage/remote package it used are
// both fully deleted now, and the current thin CLI, cli/, never imports this
// package at all -- ADR-108 Decision A's depguard forbids it) -- there is no
// legitimate caller this change could break.
//
// #1480: this function is enforcement, not the dead topology it forbids —
// do NOT delete it (or its test) as part of any future cleanup pass that
// removes the storage.type:-remote-as-server route registrations/proxy
// plumbing this gate makes unreachable. Deleting it would silently
// RE-ENABLE the topology, with no code left to make it work correctly —
// worse than leaving it, since a server would then boot successfully on
// storage.type: remote and 403/error on every request instead of failing
// loud at startup. The #1480 cleanup pass (docs/adr-083-remote-storage-cli-only.md's
// "Deferred work" section) removed the now-dead client/server plumbing
// this gate makes unreachable, but explicitly did NOT touch this function.
func validateRemoteStorageNotServer(c *Config) error {
	return fmt.Errorf("storage.type: remote cannot back a server process: " +
		"remote storage is a CLI/client mode only, not a deployable server backend " +
		"(this includes a scheduler-only process with server.http.enabled and " +
		"server.grpc.enabled both false -- server/main.go always starts its " +
		"background schedulers regardless of either flag) — see ADR-083")
}

// validatePostgresConnConfig resolves the PostgreSQL connection settings (Validate step).
func validatePostgresConnConfig(c *Config) error {
	if st := c.Storage.Type; st == "postgres" || st == "postgresql" {
		if _, err := ResolvePostgresConnConfig(&c.Storage.Database); err != nil {
			return err
		}
	}
	return nil
}

// validateStorageSection checks storage.*: pooling, read pool, audit durability, key_dir_lock and the
// storage.type switch (Validate step). storage.type remote always returns an error.
func validateStorageSection(c *Config) error {
	if err := validatePooler(c.Storage.Type, &c.Storage.Database); err != nil {
		return err
	}
	if err := validateNativeReadPoolMax(c.Storage.Type, &c.Storage.Database); err != nil {
		return err
	}
	// ADR-112 Amendment 3: a known level, no conflict with the deprecated
	// alias, and standard only on PostgreSQL (a SQLite backend refuses it).
	if err := c.Storage.Database.validateAuditDurability(c.Storage.Type); err != nil {
		return err
	}
	// ADR-112 Amendment 4: a compliance profile refuses insecure_audit_skip_reads.
	if err := validateInsecureAuditSkipReads(c); err != nil {
		return err
	}

	if err := validateKeyDirLock(c); err != nil {
		return err
	}

	switch c.Storage.Type {
	case "remote":
		// remote storage uses its own connection — no local DB config required.
		// validateRemoteStorageNotServer always returns a non-nil error here (see
		// its own doc comment); return it directly rather than an if-err wrapper
		// staticcheck (correctly) flags as a tautological comparison.
		return validateRemoteStorageNotServer(c)
	case "postgres", "postgresql":
		db := c.Storage.Database
		if db.DSN == "" && (db.Host == "" || db.Name == "" || db.User == "") {
			return fmt.Errorf("postgres storage requires either database.dsn or all of host, name, and user to be set")
		}
		// PG-VERIFYFULL-1: verify-full with no CA, or an unusable CA file,
		// refuses to start here rather than at the first connection.
		if err := ValidateDatabaseTLS(&db); err != nil {
			return err
		}
		if db.SingleWriter && c.Security.AuthRateLimitFallback.GetReplicas() > 1 {
			return fmt.Errorf("%s", singleWriterMultiReplicaError)
		}
		if db.SingleWriter && db.TransactionPooling() {
			return fmt.Errorf("%s", singleWriterTransactionPoolingError)
		}
	// #1640: "sqlite" is an accepted alias for "local" -- see the matching
	// comment in internal/storage/factory.go's CreateStorage switch.
	case "local", "sqlite":
		if c.Storage.Database.Path == "" {
			return fmt.Errorf("database path is not specified")
		}
		if c.Storage.Database.SingleWriter {
			return fmt.Errorf("%s", singleWriterUnsupportedBackendError)
		}
	case "":
		// #G-blank-storage-default: a blank storage.type used to be bucketed
		// with "local"/"sqlite" here, so a config file with no storage: block
		// (or one that set database.path without type) passed validation
		// silently and then hit the storage factory's identical blank-type
		// tolerance -- two independent layers both treating "unset" as
		// "local", with no operator-visible signal either way. See
		// internal/storage/factory.go's CreateStorage (#G-blank-storage-default)
		// for the full rationale; this is that same fix's validation-layer
		// half. The ONE legitimate "no storage: block = local SQLite" shape
		// (an existing on-prem single-node server) is preserved by
		// server/main.go explicitly setting cfg.Storage.Type = "local" in the
		// server's own boot sequence BEFORE this Validate() call ever runs --
		// not here, since this function is shared by the CLI, which must NOT
		// get that default applied on its behalf.
		return fmt.Errorf("storage.type is not set: no storage configuration found -- specify \"local\", \"postgres\", \"postgresql\", or \"remote\" explicitly")
	default:
		// #463: an unrecognized storage.type (e.g. a typo like "postgress" or
		// "remot") used to fall through silently to the SQLite default in both
		// this validator and the storage factory — in a multi-replica HA
		// deployment intending shared Postgres/remote storage, that produced
		// per-replica split-brain SQLite instances with no operator-visible
		// signal. Fail fast at config-validation time instead.
		return fmt.Errorf("invalid storage.type %q: must be one of \"local\", \"sqlite\", \"postgres\", \"postgresql\", or \"remote\"", c.Storage.Type)
	}
	return nil
}
