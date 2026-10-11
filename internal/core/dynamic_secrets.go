// dynamic_secrets.go — on-demand database credentials (ADR-035): an operator
// registers a target (DynamicSecretConfig); callers issue short-lived leases that
// mint a role on the target; an auto-revoke sweep drops them at expiry. The admin
// DSN and each issued credential are encrypted at rest.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/netutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const defaultDynamicTTL = 1 * time.Hour

// defaultMaxLeaseTTL is the install-wide lease TTL ceiling used when
// KeyorixCore.dynamicMaxLeaseTTL is unset (mirrors config.DynamicSecretsConfig's
// own default so behaviour is identical whether or not the server wired
// SetDynamicMaxLeaseTTL, e.g. in tests that construct KeyorixCore directly).
const defaultMaxLeaseTTL = 90 * 24 * time.Hour

// maxDynamicTTLSeconds bounds a raw seconds value (ttl_seconds override) before it's
// multiplied into a time.Duration (mirrors MaxInactiveDays' overflow guard in
// inactivity_suspend.go). time.Duration is an int64 count of nanoseconds, so
// time.Duration(seconds) * time.Second overflows for seconds beyond roughly 2^63/1e9
// (~9.22e9s); a caller-supplied ttl_seconds above that wraps around to an arbitrary —
// possibly NEGATIVE — Duration that neither the per-config MaxTTLSeconds nor the
// install-wide ceiling clamp below can catch (both are plain ">" comparisons against a
// positive max, so a negative wrapped value sails through both). 100 years in seconds
// is comfortably below the overflow threshold while still far beyond any legitimate
// lease TTL, matching the generous-headroom style of MaxInactiveDays.
const maxDynamicTTLSeconds = 100 * 365 * 24 * 3600

// isPrivateIP reports whether ip is disallowed as an admin-DSN target — the
// canonical private/loopback/link-local/IMDS/CGNAT check, shared (via
// netutil.IsPrivateOrLinkLocal) with every other backend-infrastructure dial
// site in this codebase (currently also azurekms's kms_key_id), so there is
// exactly one definition of "private" for these strictly-backend-service
// targets rather than a per-package reimplementation.
func isPrivateIP(ip net.IP) bool {
	return netutil.IsPrivateOrLinkLocal(ip)
}

// parseDSNHost extracts the FIRST host (without port) from an admin DSN in any
// of the supported formats -- see parseDSNHosts, which this delegates to. Kept
// for callers (and existing tests) that only ever dealt with a single-host DSN;
// validateAdminDSNHost itself uses parseDSNHosts directly so a multi-host DSN
// gets every host checked, not just this first one.
//
// Returns "" when the format is unrecognised or no host can be extracted.
func parseDSNHost(dsn string) string {
	hosts := parseDSNHosts(dsn)
	if len(hosts) == 0 {
		return ""
	}
	return hosts[0]
}

// parseDSNHosts extracts every host named in an admin DSN, in any of the
// supported formats:
//   - URL-form: postgres://user:pass@host:port/db, mysql://…, mongodb://…, redis://…
//   - PostgreSQL key-value: host=xxx port=yyy user=zzz dbname=www
//   - MySQL tcp-wrapper: user:pass@tcp(host:port)/db or user:pass@(host:port)/db
//
// PostgreSQL supports a MULTI-HOST DSN for client-side failover, in both forms
// this function recognises: key-value (host=h1,h2,h3 port=p1,p2,p3 ...) and URL
// (postgres://user@h1:5432,h2:5432,h3:5432/db) -- pgconn.ParseConfig accepts
// both and tries each host in order (see internal/dynamic/postgres.go's
// dialPostgres). A guard that extracts only DSN.Host, or naively runs
// net.SplitHostPort/net.LookupHost against the whole comma-joined string
// (which fails with "too many colons in address" for the URL form, or a bogus
// hostname lookup for the key-value form), silently skips validation for EVERY
// host in the list -- not just the ones after the first. Every returned host is
// checked by validateAdminDSNHost, in list order, so a private/IMDS address
// anywhere in a multi-host DSN is still caught before the failover behavior
// ever gets a chance to dial it.
//
// Returns nil when the format is unrecognised or no host can be extracted.
// Thin wrapper over dsn.ParseDSNHosts (internal/core/dsn), moved there so this
// logic can be fuzzed cheaply as a leaf package — see that package's doc.go.
func parseDSNHosts(dsnStr string) []string { return dsn.ParseDSNHosts(dsnStr) }

// validateAdminDSNHost rejects an admin DSN whose host is a private or
// link-local address. This prevents an internal operator from using Keyorix
// as an SSRF proxy against other services on the same private network
// (including the cloud IMDS endpoint).
//
// PostgreSQL's multi-host DSN syntax (host=h1,h2,h3 in key-value form, or
// h1:5432,h2:5432,h3:5432 in URL form) names several failover hosts, any of
// which pgconn may actually dial (internal/dynamic/postgres.go's
// dialPostgres); every one of them is checked here via parseDSNHosts, not
// just the first.
func validateAdminDSNHost(adminDSN string) error {
	hosts := parseDSNHosts(adminDSN)
	if len(hosts) == 0 {
		return nil // unrecognised format — can't extract host
	}
	for _, host := range hosts {
		if err := validateAdminDSNSingleHost(host); err != nil {
			return err
		}
	}
	return nil
}

// validateAdminDSNSingleHost applies validateAdminDSNHost's check to one
// already-extracted host. Literal IPs are checked directly; hostnames are
// resolved and each returned address is checked. If the hostname cannot be
// resolved (e.g. the target is in a network segment not reachable from
// Keyorix at config-register time), the check is skipped for THIS host only —
// the connection will fail at issue time regardless.
func validateAdminDSNSingleHost(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("admin_dsn host %q is a private or link-local address; "+
				"set dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets: true to allow private-network backends", host)
		}
		return nil
	}
	// net.ParseIP does not accept RFC 4007 zone-ID syntax (e.g. "fe80::1%eth0"), so a
	// zone-qualified link-local IPv6 literal isn't recognised as a literal IP above and
	// would otherwise fall straight through to net.LookupHost — which errors on a
	// zone-qualified address (it isn't a valid DNS query), landing in the "unresolvable,
	// skip validation" branch below and silently bypassing the blocklist for exactly the
	// fe80::/10 addresses it names. Strip the zone and retry as a literal IP first.
	if zoneHost, _, hasZone := strings.Cut(host, "%"); hasZone {
		if ip := net.ParseIP(zoneHost); ip != nil {
			if isPrivateIP(ip) {
				return fmt.Errorf("admin_dsn host %q is a private or link-local address; "+
					"set dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets: true to allow private-network backends", host)
			}
			return nil
		}
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil // unresolvable at register time — actual connection fails at issue time
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && isPrivateIP(ip) {
			return fmt.Errorf("admin_dsn host %q resolves to private or link-local address %s; "+
				"set dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets: true to allow private-network backends", host, addr)
		}
	}
	return nil
}

// CreateDynamicSecretConfigRequest registers a dynamic-secrets target.
type CreateDynamicSecretConfigRequest struct {
	Name              string
	ProjectID         uint
	EnvironmentID     uint
	BackendType       string
	AdminDSN          string
	CreationTemplate  string
	DefaultTTLSeconds int
	MaxTTLSeconds     int
	MaxActiveLeases   int
	CreatedBy         string
	// ActorID is the authenticated caller, used for the admin-authority check on
	// binding a backend (#162) — CreatedBy is a display username, not a resolvable
	// principal ID.
	ActorID uint
	// Classification is an optional data-sensitivity label (A.5.12) for the
	// credentials this config mints: "" or one of public|internal|confidential|restricted.
	Classification string
}

// IssuedLease is the credential returned to the caller once, on issue. Database
// backends populate Username/Password; cloud-IAM backends (AWS STS) leave those
// empty and populate Fields (access_key_id, secret_access_key, session_token, …).
type IssuedLease struct {
	LeaseID   string            `json:"lease_id"`
	Username  string            `json:"username,omitempty"`
	Password  string            `json:"password,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// CreateDynamicSecretConfig validates the backend, encrypts the admin DSN, and
// stores the config.
func (c *KeyorixCore) CreateDynamicSecretConfig(ctx context.Context, req *CreateDynamicSecretConfigRequest) (*models.DynamicSecretConfig, error) {
	if err := validateCreateDynamicSecretConfigRequest(req); err != nil {
		return nil, err
	}
	// Verify the environment belongs to the stated project — same cross-reference
	// check CreateSecret already applies (secrets.go), and for the same reason:
	// without it, a project-admin on project A could bind a dynamic-secret config
	// whose EnvironmentID points at project B's environment. Downstream reads/leases
	// stay keyed off the config's own stored ProjectID (not the environment's), so
	// this wasn't a cross-project value leak, but it's real reference confusion — a
	// config an operator believes is scoped to (A, envX) is actually associated with
	// an environment that belongs to a project the creator may have no visibility
	// into at all.
	//
	// EnvironmentID == 0 is the documented project-wide sentinel (CLI's own
	// --environment-id help: "0 = project-wide") and must skip this lookup
	// entirely — GetEnvironment(ctx, 0) always fails (no environment has
	// primary key 0), so without this guard every project-wide config create
	// unconditionally failed with "environment 0 not found", regardless of
	// actor or project. Found while writing scripts/e2e/journeys/journey7.
	if req.EnvironmentID != 0 {
		if env, err := c.storage.GetEnvironment(ctx, req.EnvironmentID); err != nil {
			return nil, fmt.Errorf("environment %d not found", req.EnvironmentID)
		} else if env.ProjectID != req.ProjectID {
			return nil, fmt.Errorf("environment %d does not belong to project %d", req.EnvironmentID, req.ProjectID)
		}
	}
	if _, err := c.dynamicEngine(req.BackendType); err != nil {
		return nil, err
	}
	// #162: binding a backend hands out standing access to mint live credentials
	// against it (a DB admin DSN or a cloud-IAM role) — the route only requires
	// secrets.write at the project/environment scope, which is too weak a gate for
	// that authority on its own (exact sibling of #90's rotation-backend check).
	if err := c.requireDynamicSecretAdminAuthority(ctx, req.ActorID, req.ProjectID, req.EnvironmentID); err != nil {
		return nil, err
	}
	if err := validateCreationTemplate(req.BackendType, req.CreationTemplate); err != nil {
		return nil, err
	}
	// SSRF guard: reject an admin_dsn whose host is a private or link-local address
	// unless the operator has explicitly opted in (allow_private_network_targets).
	// Prevents an internal operator from using Keyorix as a proxy to scan/reach
	// other services at its network position, including cloud IMDS.
	if err := c.enforceDynamicSecretSSRFGuard(req.AdminDSN); err != nil {
		return nil, err
	}
	// #94: the admin DSN is encrypted bound to DynamicSecretConfigAAD(cfg.ID, ...), so
	// it must be encrypted AFTER the row exists (cfg.ID is an auto-increment PK, not
	// known beforehand) — insert first with the DSN columns empty, then encrypt and
	// persist them in a second write. The inserted row IS visible between the two
	// writes: the insert commits on its own, and DeleteProject's #369 cascade disables
	// it by project, not by ID. So the second write touches ONLY the DSN columns
	// (SetDynamicSecretConfigAdminDSN, #2651); a full-row Save here wrote
	// disabled=false back over a concurrent DeleteProject.
	cfg, err := c.insertDynamicSecretConfigRow(ctx, req)
	if err != nil {
		return nil, err
	}
	dsnEnc, dsnMeta, err := c.encryptAuthSecret(req.AdminDSN, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt admin DSN: %w", err)
	}
	cfg.AdminDSNEnc = dsnEnc
	cfg.AdminDSNMeta = dsnMeta
	// A direct read of cfg.AdminDSNEnc (the field every issue/renew-time decrypt
	// site later reads) passed to a validator-named call, distinct from
	// enforceDynamicSecretSSRFGuard(req.AdminDSN) above which validates the
	// pre-encryption plaintext parameter, not this field -- a static analyzer can
	// only recognize the field itself as validated via a call shaped like this one.
	if err := validateEncryptedAdminDSNField(cfg.AdminDSNEnc); err != nil {
		return nil, fmt.Errorf("encrypted admin DSN is invalid: %w", err)
	}
	if err := c.storage.SetDynamicSecretConfigAdminDSN(ctx, cfg.ID, cfg.AdminDSNEnc, cfg.AdminDSNMeta); err != nil {
		return nil, fmt.Errorf("failed to persist encrypted admin DSN: %w", err)
	}
	pid := cfg.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_secret.config_created", nil, nil, &pid, "",
		fmt.Sprintf("dynamic-secret config %q (%s) created in project %d", cfg.Name, cfg.BackendType, cfg.ProjectID))
	return cfg, nil
}

func validateCreateDynamicSecretConfigRequest(req *CreateDynamicSecretConfigRequest) error {
	if req.Name == "" || req.ProjectID == 0 || req.AdminDSN == "" {
		return fmt.Errorf("name, project_id and admin_dsn are required")
	}
	if req.MaxTTLSeconds > 0 && req.DefaultTTLSeconds > req.MaxTTLSeconds {
		return fmt.Errorf("default_ttl_seconds (%d) cannot exceed max_ttl_seconds (%d)", req.DefaultTTLSeconds, req.MaxTTLSeconds)
	}
	// Sibling of dynamicTTL's override bound: DefaultTTLSeconds/MaxTTLSeconds are also
	// multiplied by time.Second (in dynamicTTL's clamp and RenewLease's per-lease hardCap
	// computation) with no upper bound otherwise, so an oversized value set here at
	// config-create time would overflow int64 nanoseconds just the same as an oversized
	// caller-supplied ttl_seconds override does. Reject both at the door.
	if req.DefaultTTLSeconds > maxDynamicTTLSeconds {
		return fmt.Errorf("default_ttl_seconds (%d) exceeds the maximum of %d seconds", req.DefaultTTLSeconds, maxDynamicTTLSeconds)
	}
	if req.MaxTTLSeconds > maxDynamicTTLSeconds {
		return fmt.Errorf("max_ttl_seconds (%d) exceeds the maximum of %d seconds", req.MaxTTLSeconds, maxDynamicTTLSeconds)
	}
	if !IsValidClassification(req.Classification) {
		return fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty)")
	}
	return nil
}

func (c *KeyorixCore) requireDynamicSecretAdminAuthority(ctx context.Context, actorID, projectID, environmentID uint) error {
	ids, err := c.scopedRoleIDs(ctx, actorID, Scope{ProjectID: projectID, EnvironmentID: environmentID})
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	containsAdmin, err := c.roleSetContainsAdmin(ctx, ids)
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !containsAdmin {
		return fmt.Errorf("binding a dynamic-secret backend requires admin authority on this project")
	}
	return nil
}

func (c *KeyorixCore) enforceDynamicSecretSSRFGuard(adminDSN string) error {
	if c.dynamicAllowPrivateTargets {
		return nil
	}
	return validateAdminDSNHost(adminDSN)
}

// revalidateAdminDSN re-checks a just-decrypted admin DSN against the same SSRF guard
// applied once at config-create time (enforceDynamicSecretSSRFGuard), and returns dsn
// unchanged on success. Defense-in-depth: a config created before this guard existed, or
// before an operator tightened dynamic_secrets.allow_private_network_targets, would
// otherwise be trusted forever from its original create-time check alone.
func (c *KeyorixCore) revalidateAdminDSN(dsn string) (string, error) {
	if err := c.enforceDynamicSecretSSRFGuard(dsn); err != nil {
		return "", err
	}
	return dsn, nil
}

// validateEncryptedAdminDSNField checks that a just-encrypted admin DSN ciphertext is
// non-empty before it's persisted to DynamicSecretConfig.AdminDSNEnc — a direct read of
// that exact field (see CreateDynamicSecretConfig above), distinct from
// enforceDynamicSecretSSRFGuard's validation of the pre-encryption plaintext parameter.
// The real SSRF guard already ran on the plaintext before this; this only catches a
// degenerate empty-ciphertext bug before it's ever written to storage.
func validateEncryptedAdminDSNField(dsnEnc []byte) error {
	if len(dsnEnc) == 0 {
		return fmt.Errorf("admin_dsn: encrypted value is unexpectedly empty")
	}
	return nil
}

func (c *KeyorixCore) insertDynamicSecretConfigRow(ctx context.Context, req *CreateDynamicSecretConfigRequest) (*models.DynamicSecretConfig, error) {
	cfg, err := c.storage.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name:              req.Name,
		ProjectID:         req.ProjectID,
		EnvironmentID:     req.EnvironmentID,
		BackendType:       req.BackendType,
		CreationTemplate:  req.CreationTemplate,
		DefaultTTLSeconds: req.DefaultTTLSeconds,
		MaxTTLSeconds:     req.MaxTTLSeconds,
		MaxActiveLeases:   req.MaxActiveLeases,
		Classification:    req.Classification,
		CreatedBy:         req.CreatedBy,
		CreatedAt:         c.now(),
		UpdatedAt:         c.now(),
	})
	if err != nil {
		// #462: DynamicSecretConfig's doc comment states "one per (project, env,
		// name)"; the unique index uniq_dynamic_secret_configs_project_env_name backs
		// that up at the DB layer and CreateDynamicSecretConfig wraps a violation in
		// storage.ErrDuplicateDynamicSecretConfig. Surface a clean validation error
		// instead of a raw constraint-violation message.
		if errors.Is(err, storage.ErrDuplicateDynamicSecretConfig) {
			return nil, fmt.Errorf("a dynamic-secret config named %q already exists in this project and environment", req.Name)
		}
		return nil, err
	}
	return cfg, nil
}

func (c *KeyorixCore) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	return c.storage.GetDynamicSecretConfig(ctx, id)
}

func (c *KeyorixCore) ListDynamicSecretConfigs(ctx context.Context, projectID, environmentID uint) ([]*models.DynamicSecretConfig, error) {
	return c.storage.ListDynamicSecretConfigs(ctx, projectID, environmentID)
}

// ClassifyDynamicSecretConfig sets (or clears, with "") the data-classification
// label on a dynamic-secret config and audits the change with a before/after diff.
func (c *KeyorixCore) ClassifyDynamicSecretConfig(ctx context.Context, actorID uint, configID uint, level string) (*models.DynamicSecretConfig, error) {
	if configID == 0 {
		return nil, fmt.Errorf("config id is required")
	}
	if !IsValidClassification(level) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, configID)
	if err != nil {
		return nil, fmt.Errorf("dynamic-secret config not found: %w", err)
	}
	if cfg.Classification == level {
		return cfg, nil // no-op
	}
	old := cfg.Classification
	// #2698: a column-scoped write of `classification` alone, conditional on the
	// value this function read. The previous full-row Save carried the whole
	// pre-read struct back — `disabled` included — so a SetDynamicSecretConfigEnabled(false)
	// (the incident kill switch, which also revokes the config's live leases) or a
	// DeleteProject #369 cascade committing between the read above and this write was
	// silently undone, and IssueLease could mint real database credentials again. A
	// no-match means another classifier moved the label; fail closed rather than
	// clobber it, and write no audit event (nothing of ours was persisted).
	matched, err := c.storage.SetDynamicSecretConfigClassification(ctx, cfg.ID, old, level, c.now())
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, fmt.Errorf("dynamic-secret config classification changed concurrently; re-read and retry")
	}
	cfg.Classification = level
	aid := actorID
	pid := cfg.ProjectID
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.writeAuditEventDiff(ctx, "dynamic_secret.config_classified", &aid, nil, &pid, "",
		fmt.Sprintf("dynamic-secret config %q classification set to %q", cfg.Name, level), diff)
	return cfg, nil
}

func (c *KeyorixCore) ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error) {
	return c.storage.ListDynamicSecretLeases(ctx, configID)
}

// SetDynamicSecretConfigEnabled toggles a config's Disabled flag and audits the
// change with a before/after diff (mirrors ClassifyDynamicSecretConfig). A
// disabled config refuses new IssueLease/RenewLease calls (#369). DeleteProject's
// cascade sets this automatically when the owning project is soft-deleted; this
// is also how an admin deliberately disables a config directly (e.g. incident
// response short of a full RevokeLeasesForConfig kill switch) or re-enables one
// afterward — including after restoring a project, which deliberately does NOT
// re-enable its configs on its own (see RestoreProject).
func (c *KeyorixCore) SetDynamicSecretConfigEnabled(ctx context.Context, actorID uint, configID uint, enabled bool) (*models.DynamicSecretConfig, error) {
	if configID == 0 {
		return nil, fmt.Errorf("config id is required")
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, configID)
	if err != nil {
		return nil, fmt.Errorf("dynamic-secret config not found: %w", err)
	}
	disabled := !enabled
	if cfg.Disabled == disabled {
		return cfg, nil // no-op
	}
	// #2806: ENABLING requires the parent project to be live. #369's rule is
	// that a project's configs stay disabled across a delete AND across a
	// later RestoreProject, so that re-enabling one is always a fresh,
	// deliberate, audited decision taken while the project is live. Without
	// this check that decision can be taken while the project is soft-deleted
	// — invisible in every project-scoped view — and it then takes effect
	// silently the moment someone restores the project, with no
	// re-authorization at that point and nothing in the restore's own audit
	// trail about a credential-minting config coming back. Same shape as
	// #370's "a share silently reactivates on restore".
	//
	// GetProject is soft-delete-scoped, which is what makes this a liveness
	// check and not merely an existence check.
	//
	// Checked BEFORE the write and not after, unlike the parent-liveness
	// checks #2675 adds at the storage layer (lockLiveParent, write-then-
	// re-read-under-FOR-SHARE). That asymmetry is deliberate: those guard a
	// RACE against a concurrent cascade, where checking first leaves a window
	// for the cascade to run entirely between check and write. This one
	// guards a SERIAL path — one API call, no concurrency — so a pre-check is
	// sufficient and is the readable place for it. The racing case for this
	// same column is #2651's, and it is fixed separately in #2675.
	//
	// DISABLING is deliberately NOT gated: it is the safe direction, and
	// refusing it would make a deleted project's configs un-disableable,
	// which is strictly worse than the bug. One direction narrowed, not both.
	if enabled {
		if _, perr := c.storage.GetProject(ctx, cfg.ProjectID); perr != nil {
			return nil, fmt.Errorf("cannot enable a dynamic-secret config under project %d: project not found or deleted — restore the project first", cfg.ProjectID)
		}
	}
	old := cfg.Disabled
	cfg.Disabled = disabled
	cfg.UpdatedAt = c.now()
	matched, err := c.storage.TransitionDynamicSecretConfigDisabled(ctx, cfg, old)
	if err != nil {
		return nil, err
	}
	if !matched {
		// Lost the race: the row's persisted disabled value moved away from old
		// between the GetDynamicSecretConfig read and this write (a concurrent
		// enable/disable, or an unrelated concurrent edit) — treat as a rejected
		// write, not silently applied, exactly like TransitionMachineIdentityState's
		// #388/#518 lost-race handling.
		return nil, fmt.Errorf("dynamic-secret config %d's enabled state changed concurrently; retry", configID)
	}
	aid := actorID
	pid := cfg.ProjectID
	state := "enabled"
	if disabled {
		state = "disabled"
	}
	diff := fmt.Sprintf(`{"disabled":{"before":%t,"after":%t}}`, old, disabled)
	c.writeAuditEventDiff(ctx, "dynamic_secret.config_"+state, &aid, nil, &pid, "",
		fmt.Sprintf("dynamic-secret config %q %s", cfg.Name, state), diff)
	return cfg, nil
}

func (c *KeyorixCore) GetDynamicSecretLease(ctx context.Context, leaseID string) (*models.DynamicSecretLease, error) {
	return c.storage.GetDynamicSecretLease(ctx, leaseID)
}

// IssueLease mints a short-lived credential on the target and persists the lease.
// The plaintext credential is returned ONCE; only its encrypted form is stored.
// ttlSeconds<=0 uses the config default (or 1h).
//
// LOW (#97): a genuine process crash (SIGKILL/OOM/panic bypassing defers) between
// engine.Issue minting the credential on the target and this function persisting the
// lease row leaves an orphan invisible to every list/revoke/sweep path (all keyed off
// the lease table) — cleanupOrphanedRole only covers synchronous Go-level errors
// returned by the steps AFTER Issue, not a hard crash. Fully closing this needs
// crash-safe two-phase persistence (write a pre-mint marker, reconcile it against the
// target on restart) across all 8 backend engines — out of proportion for a LOW
// finding. The log line below is a partial mitigation: it gives an operator a
// searchable breadcrumb (config, backend, target-ish role hint) to correlate against
// server logs during incident response if a mint never resulted in a lease row.
func (c *KeyorixCore) IssueLease(ctx context.Context, configID uint, ttlSeconds int, userID uint) (*IssuedLease, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, configID)
	if err != nil {
		return nil, fmt.Errorf("dynamic-secret config not found")
	}
	// #369: refuse to mint against a config DeleteProject's cascade (or an admin)
	// disabled, and refuse when the owning project/environment has since been
	// soft-deleted directly — a principal who still holds a role scoped to a
	// "deleted" project must not be able to keep minting fresh database
	// credentials against it just because the RBAC join that resolved their
	// authority doesn't itself check project liveness.
	if cfg.Disabled {
		return nil, fmt.Errorf("dynamic-secret config is disabled")
	}
	if err := c.requireLiveProjectAndEnvironment(ctx, cfg.ProjectID, cfg.EnvironmentID); err != nil {
		return nil, err
	}
	engine, err := c.dynamicEngine(cfg.BackendType)
	if err != nil {
		return nil, err
	}
	// A backend with no DB-level expiry (MySQL/MongoDB) relies entirely on the
	// auto-revoke sweeper to enforce the lease TTL. Issuing from it while the
	// sweeper is disabled would mint a credential whose advertised expiry is never
	// enforced — a false promise — so refuse and point the operator at the fix.
	if !engine.SupportsNativeExpiry() && !c.dynamicSweepEnabled {
		return nil, fmt.Errorf("cannot issue from the %s backend while the auto-revoke sweeper is disabled: its lease TTL is enforced only by the sweeper, so the credential would never expire — enable dynamic_secrets.sweep_enabled", cfg.BackendType)
	}
	// Enforce the config's active-lease ceiling so a caller can't mint unbounded real DB
	// roles/users (resource exhaustion on the target). A small race under concurrency is
	// acceptable for a soft resource cap.
	if cfg.MaxActiveLeases > 0 {
		active, cerr := c.storage.CountActiveLeases(ctx, configID)
		if cerr != nil {
			return nil, fmt.Errorf("failed to check active lease count: %w", cerr)
		}
		if active >= int64(cfg.MaxActiveLeases) {
			return nil, fmt.Errorf("active-lease limit reached for this config (%d); revoke a lease before issuing another", cfg.MaxActiveLeases)
		}
	}
	adminDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt admin DSN: %w", err)
	}
	adminDSN, err = c.revalidateAdminDSN(adminDSN)
	if err != nil {
		return nil, err
	}
	ttl, err := c.dynamicTTL(cfg, ttlSeconds)
	if err != nil {
		return nil, err
	}

	// Logged BEFORE the mint (not after) so the breadcrumb survives a crash during or
	// immediately after engine.Issue — see the crash-orphan note on IssueLease's doc
	// comment (#97).
	log.Printf("dynamic-secrets: issuing a %s credential (config=%q id=%d project=%d ttl=%s)", cfg.BackendType, cfg.Name, cfg.ID, cfg.ProjectID, ttl)
	cred, roleName, err := engine.Issue(ctx, adminDSN, cfg.CreationTemplate, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to issue credential: %w", err)
	}
	// leaseID is generated BEFORE encryption (not after, as in the pre-#94 order) so
	// DynamicSecretLeaseAAD can bind the credential's ciphertext to it — leaseID is a
	// random token assigned by us, not an auto-increment PK, so it's available without
	// a two-phase insert-then-update (contrast CreateDynamicSecretConfig above).
	leaseID, err := generateSecureToken()
	if err != nil {
		c.cleanupOrphanedRole(ctx, cfg, engine, adminDSN, roleName, userID)
		return nil, err
	}
	credJSON, _ := json.Marshal(cred) // #nosec G117 -- intentional: serialized only to be immediately encrypted at rest below, never persisted or logged in cleartext
	credEnc, credMeta, err := c.encryptAuthSecret(string(credJSON), ports.DynamicSecretLeaseAAD(leaseID, cfg.ID))
	if err != nil {
		// The role exists on the target — revoke it so we don't leak it.
		c.cleanupOrphanedRole(ctx, cfg, engine, adminDSN, roleName, userID)
		return nil, fmt.Errorf("failed to encrypt credential: %w", err)
	}
	// #97: cloud-IAM engines (AWS STS, Kubernetes) floor the REQUESTED ttl up to their
	// own provider minimum (900s/600s) when minting, so the credential returned is
	// valid for longer than a short-ttl caller asked for — but ExpiresAt computed from
	// the requested ttl alone would understate that, making Keyorix believe (and the
	// auto-revoke sweep act on) an earlier expiry than the credential's true,
	// provider-enforced one. Both engines surface the actual granted expiry in
	// cred.Fields["expiration"] (RFC3339); trust it over the requested-ttl computation
	// whenever the engine provides it.
	expiresAt := c.now().Add(ttl)
	if raw := cred.Fields["expiration"]; raw != "" {
		if actual, perr := time.Parse(time.RFC3339, raw); perr == nil {
			expiresAt = actual
		}
	}
	lease, err := c.storage.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID:       cfg.ID,
		LeaseID:        leaseID,
		ProjectID:      cfg.ProjectID,
		EnvironmentID:  cfg.EnvironmentID,
		RoleName:       roleName,
		CredentialEnc:  credEnc,
		CredentialMeta: credMeta,
		Status:         "active",
		IssuedAt:       c.now(),
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		// Also the #2652 path: storage refuses an active lease whose config a
		// concurrent DeleteProject (#369) or disable committed after the cfg.Disabled
		// check above, so the credential minted for it is revoked here, not leaked.
		c.cleanupOrphanedRole(ctx, cfg, engine, adminDSN, roleName, userID)
		if errors.Is(err, storage.ErrDynamicSecretConfigDisabled) {
			return nil, fmt.Errorf("dynamic-secret config is disabled")
		}
		return nil, fmt.Errorf("failed to persist lease: %w", err)
	}
	uid := userID
	pid := cfg.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_lease.issued", &uid, nil, &pid, "",
		fmt.Sprintf("issued dynamic credential (lease=%s, config=%q, ttl=%s)", lease.LeaseID, cfg.Name, ttl))
	return &IssuedLease{LeaseID: lease.LeaseID, Username: cred.Username, Password: cred.Password, Fields: cred.Fields, ExpiresAt: expiresAt}, nil
}

// cleanupOrphanedRole drops a just-minted role after a post-mint failure aborts the
// issue (encryption / token-gen / lease-persist failed). If the drop itself fails,
// the role would otherwise be a LIVE credential with no lease row — invisible to
// every list/sweep/revoke path (all keyed off the lease table) and therefore
// permanent and undrop-able. To keep it visible, we record a revoke_failed lease
// capturing the role name and audit it, mirroring RevokeLease's failure handling.
func (c *KeyorixCore) cleanupOrphanedRole(ctx context.Context, cfg *models.DynamicSecretConfig, engine ports.DynamicBackendEngine, adminDSN, roleName string, userID uint) {
	if err := engine.Revoke(ctx, adminDSN, roleName); err == nil {
		return // role dropped cleanly — nothing to track
	} else {
		now := c.now()
		leaseID, gerr := generateSecureToken()
		if gerr != nil {
			leaseID = "orphan-" + roleName // last-resort id so the row still persists
		}
		// No credential is stored — the issue was aborted; only the role name
		// matters so an operator can drop it. CredentialEnc is intentionally empty.
		// Through besteffort.Run: a PANIC in this write must not skip the
		// revoke_failed audit event below, which is the operator's only other
		// signal that a live, unleased role exists.
		besteffort.Run(ctx, "dynamic_secrets.cleanupOrphanedRole.CreateDynamicSecretLease", func() error {
			_, lerr := c.storage.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
				ConfigID:      cfg.ID,
				LeaseID:       leaseID,
				ProjectID:     cfg.ProjectID,
				EnvironmentID: cfg.EnvironmentID,
				RoleName:      roleName,
				Status:        "revoke_failed",
				RevokeError:   "orphaned on aborted issue: " + err.Error(),
				IssuedAt:      now,
				ExpiresAt:     now,
				RevokedAt:     &now,
			})
			return lerr
		})
		var uidPtr *uint
		if userID != 0 {
			uidPtr = &userID
		}
		var pidPtr *uint
		if cfg.ProjectID != 0 {
			pid := cfg.ProjectID
			pidPtr = &pid
		}
		c.writeAuditEventFull(ctx, "dynamic_lease.revoke_failed", uidPtr, nil, pidPtr, "",
			fmt.Sprintf("FAILED to clean up orphaned dynamic role %s after an aborted issue (config=%q): %v — drop it manually", roleName, cfg.Name, err))
	}
}

// RevokeLease revokes a lease on the target and marks it revoked (or
// revoke_failed if the target drop fails, surfacing it to an operator).
func (c *KeyorixCore) RevokeLease(ctx context.Context, leaseID string, userID uint, reason string) error {
	lease, err := c.storage.GetDynamicSecretLease(ctx, leaseID)
	if err != nil {
		return fmt.Errorf("lease not found")
	}
	// Admit revoke_failed too: a prior revoke whose target drop failed left the underlying
	// credential LIVE, so it must remain retryable (manually or via the sweep). Only an
	// already-revoked/expired lease is a no-op.
	if lease.Status != "active" && lease.Status != "revoke_failed" {
		return fmt.Errorf("lease is not active (status %s)", lease.Status)
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, lease.ConfigID)
	if err != nil {
		return fmt.Errorf("config not found")
	}
	engine, err := c.dynamicEngine(cfg.BackendType)
	if err != nil {
		return err
	}
	adminDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err != nil {
		return fmt.Errorf("failed to decrypt admin DSN: %w", err)
	}
	adminDSN, err = c.revalidateAdminDSN(adminDSN)
	if err != nil {
		return err
	}
	now := c.now()
	var uidPtr *uint
	if userID != 0 {
		uidPtr = &userID
	}
	pid := lease.ProjectID
	if rerr := engine.Revoke(ctx, adminDSN, lease.RoleName); rerr != nil {
		lease.Status = "revoke_failed"
		log.Printf("failed to revoke dynamic secret lease %s: %s", lease.LeaseID, ports.SanitizeErrorMessage(rerr))
		lease.RevokeError = "backend revoke failed — see server audit log for details"
		// Deliberately NOT stamping RevokedAt here: the target drop failed, so the
		// credential is still live. Stamping it would make the audit trail / API
		// falsely claim the role was dropped at this time, even though it wasn't —
		// and it wasn't dropped at all yet, so there is no "revoked at" moment to
		// record. RevokedAt is set only on the success path below.
		// #2698: record only the revocation columns. The former full-row Save also
		// rewrote expires_at from this call's pre-read copy.
		//
		// #2836 review: the outcome is checked rather than discarded. This branch
		// already fails closed for the caller (it returns the target-revoke error
		// below, which is the more important fact and must not be replaced), but a
		// no-match or a storage error means the `revoke_failed` marker — the thing
		// that tells an operator this credential is STILL LIVE and needs dropping
		// by hand — never reached the database. There is no row left to carry that
		// warning, so the log is the only place it can go.
		if matched, rrerr := c.storage.RecordDynamicSecretLeaseRevocation(ctx, lease.LeaseID, lease.Status, lease.RevokeReason, lease.RevokeError, lease.RevokedAt); rrerr != nil || !matched {
			log.Printf("dynamic secret lease %s: target revoke FAILED and the revoke_failed marker could not be "+
				"persisted (matched=%v, err=%s) — the credential is still live with no row recording it",
				lease.LeaseID, matched, ports.SanitizeErrorMessage(rrerr))
		}
		c.writeAuditEventFull(ctx, "dynamic_lease.revoke_failed", uidPtr, nil, &pid, "",
			fmt.Sprintf("FAILED to revoke dynamic lease %s (role %s): %v", lease.LeaseID, lease.RoleName, rerr))
		return fmt.Errorf("failed to revoke on target: %w", rerr)
	}
	lease.Status = "revoked"
	lease.RevokeReason = reason
	lease.RevokeError = "" // clear any error from a prior failed attempt — this retry succeeded
	lease.RevokedAt = &now
	// #97: for most ephemeral backends (AWS STS, Azure, GCP, and Kubernetes unless
	// opted into bound-token revocation) engine.Revoke above is a documented no-op
	// — the credential cannot be invalidated early at the provider, only marked
	// dead in Keyorix's own bookkeeping. Saying "revoked" outright would
	// misleadingly imply the credential is dead; it remains live until its own
	// provider-enforced expiry (lease.ExpiresAt, corrected to the actual granted
	// expiry at issue — see IssueLease). RevokeInvalidatesCredential tells us
	// whether THIS lease's specific adminDSN actually got a real revoke (e.g. a
	// Kubernetes config with "revocable":true), so that case is audited honestly
	// as a genuine revoke rather than lumped in with the no-op backends.
	msg := fmt.Sprintf("revoked dynamic lease %s (reason=%s)", lease.LeaseID, reason)
	if engine.IsEphemeralBackend() && !engine.RevokeInvalidatesCredential(adminDSN) {
		msg = fmt.Sprintf("marked dynamic lease %s revoked locally (reason=%s); the %s credential cannot be invalidated early and remains live until its provider-enforced expiry at %s",
			lease.LeaseID, reason, cfg.BackendType, lease.ExpiresAt.UTC().Format(time.RFC3339))
	}
	// #2406: the target credential IS already dropped (engine.Revoke above
	// succeeded) -- that cannot be undone, and must not be. But a failed audit
	// write for a security action this sensitive is itself a gap that must
	// not be swallowed the way a merely-incidental audit write would be
	// (emitAudit's normal best-effort contract, unchanged for every other
	// caller). Record the gap on the lease itself (the same RevokeError field
	// the target-revoke-failure branch above uses, so it surfaces through the
	// same existing API/UI path) and return an error, so RevokeLeasesForConfig
	// -- and the REST/gRPC bulk-revoke response, which already propagates a
	// non-nil error as a non-2xx/non-OK response -- cannot report a clean,
	// unconditional success while this lease's audit trail has a hole in it.
	auditOK := c.writeAuditEventFull(ctx, "dynamic_lease.revoked", uidPtr, nil, &pid, "", msg)
	if !auditOK {
		lease.RevokeError = "revoked on target, but the audit record failed to persist — verify manually (see server log)"
	}
	// #2698: see the revoke-failed branch above — revocation columns only.
	//
	// #2836 review: `matched` is checked and fails closed, for the same reason
	// the !auditOK branch below does. A no-match means the lease row was deleted
	// concurrently, so this revocation was never recorded anywhere. The target
	// credential IS dead (engine.Revoke succeeded above), so this is a bookkeeping
	// hole rather than a live credential — but RevokeLeasesForConfig and the
	// REST/gRPC bulk-revoke response both turn a nil return into an unconditional
	// success, and a success report that no stored row corroborates is exactly
	// what the !auditOK branch exists to prevent.
	matched, rerr := c.storage.RecordDynamicSecretLeaseRevocation(ctx, lease.LeaseID, lease.Status, lease.RevokeReason, lease.RevokeError, lease.RevokedAt)
	if rerr != nil {
		return rerr
	}
	if !matched {
		return fmt.Errorf("lease %s was revoked on target, but no lease row remained to record it (deleted concurrently) — treat as unconfirmed", lease.LeaseID)
	}
	if !auditOK {
		return fmt.Errorf("lease %s revoked on target, but failed to record the audit event — treat as unconfirmed", lease.LeaseID)
	}
	return nil
}

// leaseClockRegressionTolerance bounds how far now may read EARLIER than
// dynamicSecretsClockWatermark before checkLeaseRenewClockNotRegressed
// refuses a lease renewal. Same value and rationale as
// sessionRefreshClockRegressionTolerance/secretExpiryClockRegressionTolerance
// (auth.go/versions.go, #1632): large enough not to false-positive on
// ordinary NTP slew, small enough to still catch a deliberate/NTP-less
// manual clock reset.
const leaseClockRegressionTolerance = 30 * time.Second

// checkLeaseRenewClockNotRegressed refuses to trust now for RenewLease's
// !now.Before(lease.ExpiresAt) recheck if it looks EARLIER than a time this
// process has already legitimately observed for a lease operation
// (FUZZ-MECH M2 finding, 2026-09-27, closing the gap
// docs/findings/2026-09-27-FINDING-dynamic-secret-lease-clock-rollback.md
// documents). Reuses RenewLease's own "lease has expired" refusal text, not
// a distinct message, so a caller cannot use it as an oracle confirming
// clock manipulation had an effect -- same reasoning as
// checkSessionRefreshClockNotRegressed (auth.go, #1653), which this mirrors.
// On success, advances the watermark to now (never backward). Shares
// dynamicSecretsClockWatermark with dynamicSecretsSweepCutoff below, so a
// renewal attempt and the background sweep warm the same protection.
// .UTC() strips any monotonic clock reading now carries -- see
// authEffectiveNow's doc comment (auth.go) for why an unstripped comparison
// here would never actually detect a backward wall-clock step.
func (c *KeyorixCore) checkLeaseRenewClockNotRegressed(now time.Time) error {
	now = now.UTC()
	c.dynamicSecretsClockWatermarkMu.Lock()
	defer c.dynamicSecretsClockWatermarkMu.Unlock()
	if !c.dynamicSecretsClockWatermark.IsZero() && now.Before(c.dynamicSecretsClockWatermark.Add(-leaseClockRegressionTolerance)) {
		return fmt.Errorf("lease has expired; issue a new lease instead")
	}
	if now.After(c.dynamicSecretsClockWatermark) {
		c.dynamicSecretsClockWatermark = now
	}
	return nil
}

// dynamicSecretsSweepCutoff returns the later of before and this process's
// dynamic-secrets clock watermark, so a backward host-clock step never
// shrinks RevokeExpiredLeases' sweep window -- an already-observed-expired
// lease stays swept even while a rollback is in effect. CLAMPs rather than
// refuses (unlike checkLeaseRenewClockNotRegressed above): the sweep is a
// background maintenance action with no caller to deny, so it prefers "keep
// working" -- same shape as authEffectiveNow/rbacClockWatermark, not
// checkSessionRefreshClockNotRegressed's refuse-outright behavior. Advances
// the SAME watermark checkLeaseRenewClockNotRegressed reads/writes.
func (c *KeyorixCore) dynamicSecretsSweepCutoff(before time.Time) time.Time {
	before = before.UTC()
	c.dynamicSecretsClockWatermarkMu.Lock()
	defer c.dynamicSecretsClockWatermarkMu.Unlock()
	if before.After(c.dynamicSecretsClockWatermark) {
		c.dynamicSecretsClockWatermark = before
		return before
	}
	return c.dynamicSecretsClockWatermark
}

// RevokeExpiredLeases is the auto-revoke sweep: it revokes every active (or previously
// revoke_failed) lease past its expiry (system-actored). Returns the count revoked and a
// non-nil error if any revoke failed, so the scheduler records the partial failure rather
// than reporting a clean sweep while credentials remain live past their TTL.
func (c *KeyorixCore) RevokeExpiredLeases(ctx context.Context, before time.Time) (int, error) {
	// Clamp before FIRST: a scheduler that read a regressed host clock for
	// its own "now" must not shrink the sweep window below what this process
	// has already legitimately observed (FUZZ-MECH M2 finding, 2026-09-27).
	before = c.dynamicSecretsSweepCutoff(before)
	expired, err := c.storage.ListExpiredActiveLeases(ctx, before)
	if err != nil {
		return 0, err
	}
	revoked, failed := 0, 0
	for _, l := range expired {
		if err := c.RevokeLease(ctx, l.LeaseID, 0, "expired"); err == nil {
			revoked++
		} else {
			failed++
		}
	}
	if failed > 0 {
		return revoked, fmt.Errorf("dynamic-secrets sweep: %d of %d expired lease(s) failed to revoke — those credentials remain live past their TTL", failed, len(expired))
	}
	return revoked, nil
}

// RevokeLeasesForConfig revokes every active lease issued from a config — an
// incident-response kill switch for a config's outstanding dynamic credentials
// (e.g. a compromised target DB or config). Returns the counts revoked and failed
// (each revoke is audited per-lease as well). Best-effort: one lease's revoke
// failure does not stop the others.
func (c *KeyorixCore) RevokeLeasesForConfig(ctx context.Context, configID, userID uint, reason string) (revoked, failed int, err error) {
	leases, err := c.storage.ListDynamicSecretLeases(ctx, configID)
	if err != nil {
		return 0, 0, err
	}
	for _, l := range leases {
		// Retry a previously-failed revoke too — its credential is still live.
		if l.Status != "active" && l.Status != "revoke_failed" {
			continue
		}
		if c.RevokeLease(ctx, l.LeaseID, userID, reason) != nil {
			failed++
		} else {
			revoked++
		}
	}
	var uidPtr *uint
	if userID != 0 {
		uidPtr = &userID
	}
	pid := uint(0)
	if cfg, gerr := c.storage.GetDynamicSecretConfig(ctx, configID); gerr == nil {
		pid = cfg.ProjectID
	}
	var pidPtr *uint
	if pid != 0 {
		pidPtr = &pid
	}
	c.writeAuditEventFull(ctx, "dynamic_secret.bulk_revoke", uidPtr, nil, pidPtr, "",
		fmt.Sprintf("bulk-revoked dynamic leases for config %d (revoked=%d, failed=%d, reason=%s)", configID, revoked, failed, reason))
	// #2406: this used to always return a nil error here, regardless of
	// failed -- counts caught the per-lease outcome, but the REST/gRPC
	// callers both already propagate a non-nil error as a non-2xx/non-OK
	// response and a nil one as unconditional success (dynamic_secrets.go's
	// RevokeAllLeases handler, dynamic_secret_service.go's gRPC sibling), so
	// an incident responder's bulk kill-switch call reported a clean 200/OK
	// even when some leases weren't fully revoked (target drop failed) or
	// weren't fully CONFIRMED revoked (the target drop succeeded, but its
	// audit record didn't -- see RevokeLease's own #2406 doc comment).
	// Mirrors RevokeExpiredLeases' own identical fix above in this same file.
	if failed > 0 {
		return revoked, failed, fmt.Errorf("bulk-revoke for config %d: %d of %d attempted lease(s) did not fully complete (target revoke and/or its audit record) — see server log for which", configID, failed, revoked+failed)
	}
	return revoked, failed, nil
}

// requireLiveProjectAndEnvironment refuses when projectID or (if non-zero)
// environmentID is missing or soft-deleted — GetProject/GetEnvironment apply
// GORM's default soft-delete scope (models.Project/Environment use gorm.DeletedAt),
// so a soft-deleted row already surfaces as "not found" here without a separate
// deleted_at predicate. Shared by IssueLease and RenewLease (#369): a project's
// soft-delete does not, on its own, revoke the role grants scoped to it, so
// issuance/renewal need their own explicit liveness gate independent of RBAC.
//
// Uses GetEnvironmentInProject (not the bare GetEnvironment) so this also
// refuses when environmentID exists but belongs to a DIFFERENT project than
// projectID — both callers (IssueLease/RenewLease) already have both IDs
// available (from the config/lease row), so there's no reason to accept a
// mismatch here even though today's callers happen to pass coupled fields
// from the same row; this closes the gap defensively rather than relying on
// that coupling holding forever.
func (c *KeyorixCore) requireLiveProjectAndEnvironment(ctx context.Context, projectID, environmentID uint) error {
	if _, err := c.storage.GetProject(ctx, projectID); err != nil {
		return fmt.Errorf("cannot issue lease: project not found or deleted")
	}
	if environmentID != 0 {
		if _, err := c.GetEnvironmentInProject(ctx, projectID, environmentID); err != nil {
			return fmt.Errorf("cannot issue lease: environment not found or deleted")
		}
	}
	return nil
}

// dynamicTTL resolves the requested TTL (override, else config default, else 1h),
// clamps it to the config's MaxTTLSeconds ceiling when one is set, and always clamps
// it to the install-wide max-lease-TTL ceiling on top (#97) — the per-config ceiling
// is entirely operator-controlled and defaults to "unset = unbounded" (e.g. a config
// left with MaxTTLSeconds=0 combined with a caller-supplied override would otherwise
// mint a credential valid for however long the caller asked, with nothing to stop a
// 100-year lease).
//
// override is caller-supplied (HTTP JSON body / gRPC field ttl_seconds) with no upper
// bound applied before it reaches here, so it's checked against maxDynamicTTLSeconds
// BEFORE the multiplication below: time.Duration(override) * time.Second overflows
// int64 nanoseconds for large enough override, wrapping to an arbitrary — possibly
// NEGATIVE — Duration that the MaxTTLSeconds/install-ceiling clamps further down
// cannot catch (both are plain "ttl > max" comparisons, which a negative ttl never
// satisfies), producing an ExpiresAt in the past instead of a rejected request.
func (c *KeyorixCore) dynamicTTL(cfg *models.DynamicSecretConfig, override int) (time.Duration, error) {
	ttl := defaultDynamicTTL
	switch {
	case override > 0:
		if override > maxDynamicTTLSeconds {
			return 0, fmt.Errorf("ttl_seconds (%d) exceeds the maximum of %d seconds", override, maxDynamicTTLSeconds)
		}
		ttl = time.Duration(override) * time.Second
	case cfg.DefaultTTLSeconds > 0:
		ttl = time.Duration(cfg.DefaultTTLSeconds) * time.Second
	}
	if cfg.MaxTTLSeconds > 0 {
		if max := time.Duration(cfg.MaxTTLSeconds) * time.Second; ttl > max {
			ttl = max
		}
	}
	installMax := c.dynamicMaxLeaseTTL
	if installMax <= 0 {
		installMax = defaultMaxLeaseTTL
	}
	if ttl > installMax {
		ttl = installMax
	}
	return ttl, nil
}

// RenewLease extends an active lease's expiry by ttlSeconds (or the config
// default), capped so the lease's total lifetime from issue never exceeds the
// config's MaxTTLSeconds. On backends with a DB-level expiry (PostgreSQL) it also
// pushes the role's VALID UNTIL forward. Returns the new expiry.
func (c *KeyorixCore) RenewLease(ctx context.Context, leaseID string, ttlSeconds int, userID uint) (time.Time, error) { // NOSONAR -- cognitive complexity 21, suppress go:S3776
	lease, err := c.storage.GetDynamicSecretLease(ctx, leaseID)
	if err != nil {
		return time.Time{}, fmt.Errorf("lease not found")
	}
	if lease.Status != "active" {
		return time.Time{}, fmt.Errorf("lease is not active (status %s)", lease.Status)
	}
	// A lease whose expiry has already passed is logically dead even if the sweeper
	// has not yet flipped its status (sweep disabled, or not run yet). Renewing it
	// would push the backend credential's lifetime forward — resurrecting a
	// credential that should be gone, violating the promised TTL — and would race the
	// sweep that is about to revoke it. Refuse; the caller must issue a new lease.
	//
	// checkLeaseRenewClockNotRegressed runs FIRST: without it, a host clock
	// stepped backward to before lease.ExpiresAt after this process already
	// correctly observed the lease expired would make the check below pass
	// again, resurrecting a lease this process already knows is dead
	// (FUZZ-MECH M2 finding, 2026-09-27).
	if err := c.checkLeaseRenewClockNotRegressed(c.now()); err != nil {
		return time.Time{}, err
	}
	if !c.now().Before(lease.ExpiresAt) {
		return time.Time{}, fmt.Errorf("lease has expired; issue a new lease instead")
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, lease.ConfigID)
	if err != nil {
		return time.Time{}, fmt.Errorf("config not found")
	}
	// #369: mirrors IssueLease — a renewal is functionally a fresh mint of trust
	// (it extends how long the credential stays live), so it gets the same
	// disabled-config / soft-deleted-project-or-environment refusal. In the
	// ordinary case DeleteProject's cascade will already have revoked this lease
	// (flipping its status away from "active", which the check above already
	// catches); this closes the race window between that cascade committing and
	// its best-effort revoke actually reaching the target.
	if cfg.Disabled {
		return time.Time{}, fmt.Errorf("dynamic-secret config is disabled")
	}
	if err := c.requireLiveProjectAndEnvironment(ctx, cfg.ProjectID, cfg.EnvironmentID); err != nil {
		return time.Time{}, err
	}
	// Cloud-IAM backends (AWS STS) mint self-expiring credentials whose lifetime is
	// fixed by the provider at issue — they cannot be renewed; issue a new lease.
	if eng, eerr := c.dynamicEngine(cfg.BackendType); eerr == nil && eng.IsEphemeralBackend() {
		return time.Time{}, fmt.Errorf("the %s backend mints self-expiring credentials that cannot be renewed; issue a new lease instead", cfg.BackendType)
	}
	renewTTL, err := c.dynamicTTL(cfg, ttlSeconds)
	if err != nil {
		return time.Time{}, err
	}
	newExpiry := c.now().Add(renewTTL)
	// Never let renewal push total lifetime past the config's max-TTL ceiling.
	if cfg.MaxTTLSeconds > 0 {
		if hardCap := lease.IssuedAt.Add(time.Duration(cfg.MaxTTLSeconds) * time.Second); newExpiry.After(hardCap) {
			newExpiry = hardCap
		}
	}
	// ...nor past the install-wide ceiling (#97) — same reasoning as dynamicTTL: the
	// per-config ceiling above is optional and defaults to unbounded, so a renewal
	// alone could otherwise stretch a lease's total lifetime arbitrarily far.
	installMax := c.dynamicMaxLeaseTTL
	if installMax <= 0 {
		installMax = defaultMaxLeaseTTL
	}
	if hardCap := lease.IssuedAt.Add(installMax); newExpiry.After(hardCap) {
		newExpiry = hardCap
	}
	if !newExpiry.After(lease.ExpiresAt) {
		return time.Time{}, fmt.Errorf("renewal would not extend the lease (max-TTL ceiling reached)")
	}
	engine, err := c.dynamicEngine(cfg.BackendType)
	if err != nil {
		return time.Time{}, err
	}
	// A backend with no DB-level expiry relies entirely on the sweeper to enforce a
	// lease's TTL. With the sweeper disabled, a renewal would extend a credential nothing
	// will ever revoke — mirror IssueLease's fail-closed refusal.
	if !engine.SupportsNativeExpiry() && !c.dynamicSweepEnabled {
		return time.Time{}, fmt.Errorf("renewal is unavailable for the %s backend while the lease sweeper is disabled (its TTL would be unenforced)", cfg.BackendType)
	}
	adminDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to decrypt admin DSN: %w", err)
	}
	adminDSN, err = c.revalidateAdminDSN(adminDSN)
	if err != nil {
		return time.Time{}, err
	}
	if err := engine.Renew(ctx, adminDSN, lease.RoleName, newExpiry); err != nil {
		return time.Time{}, fmt.Errorf("failed to renew on target: %w", err)
	}
	// #2698: write expires_at alone, and only while the lease is STILL active.
	// The previous full-row Save wrote the stale Status/RevokeError/RevokedAt back
	// too, so a RevokeLease that committed between this function's read and this
	// write was reverted: a successful revoke became `active` again with a later
	// expiry (the row then lying about a dead credential and holding a
	// MaxActiveLeases slot until the sweep), and a `revoke_failed` record was
	// erased with its error. engine.Renew is a documented no-op on several
	// backends, so nothing downstream would have noticed.
	matched, err := c.storage.ExtendDynamicSecretLeaseExpiry(ctx, lease.LeaseID, newExpiry)
	if err != nil {
		return time.Time{}, err
	}
	if !matched {
		return time.Time{}, fmt.Errorf("lease %s is no longer active; renewal refused", lease.LeaseID)
	}
	lease.ExpiresAt = newExpiry
	uid := userID
	var uidPtr *uint
	if userID != 0 {
		uidPtr = &uid
	}
	pid := lease.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_lease.renewed", uidPtr, nil, &pid, "",
		fmt.Sprintf("renewed dynamic lease %s (new expiry %s)", lease.LeaseID, newExpiry.UTC().Format(time.RFC3339)))
	return newExpiry, nil
}

// validateCreationTemplate scans a SQL creation_statements template for
// dangerous privilege constructs (DYN-005). We cannot connect to the target
// DB at config-create time, so we scan the template text instead. This catches
// the majority of dangerous configs (SUPER, GRANT OPTION) without requiring a
// live connection, and fails on the side of caution.
func validateCreationTemplate(backendType, tmpl string) error {
	if tmpl == "" {
		return nil
	}
	// Only SQL backends use creation_statements as SQL; AWS STS uses it as a
	// session policy JSON, Kubernetes ignores it.
	switch backendType {
	case "mysql", "postgresql", "postgres":
	default:
		return nil
	}
	upper := strings.ToUpper(tmpl)
	// #G39: this denylist previously covered object-privilege escalation (GRANT
	// OPTION/WITH GRANT) and MySQL's SUPER, but not Postgres's own role-attribute
	// escalation keywords (CREATEROLE/CREATEDB/SUPERUSER/REPLICATION/BYPASSRLS,
	// settable via CREATE ROLE ... or ALTER ROLE ...) or the role-membership
	// equivalent of "WITH GRANT OPTION" (WITH ADMIN OPTION, PostgreSQL role grants
	// / MySQL 8 role grants) — a creation_statements template using any of these
	// could mint a dynamic-secret credential with far more privilege than the
	// documented "the majority of dangerous configs" this function claims to catch.
	dangerous := []string{
		"GRANT OPTION", "WITH GRANT", "WITH ADMIN OPTION",
		" SUPER", " SUPERUSER", " CREATEROLE", " CREATEDB", " REPLICATION", " BYPASSRLS",
	}
	for _, kw := range dangerous {
		if strings.Contains(upper, kw) {
			return fmt.Errorf("dynamic secret creation_statements must not contain %q (would grant excessive privileges)", kw)
		}
	}
	return nil
}
