package core

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

// KeyorixCore represents the core business logic layer.
// It orchestrates all business operations while remaining transport-agnostic.
// Methods are organised into domain files:
//   - secrets.go       — Secret CRUD + rotation
//   - versions.go      — Secret version management + value retrieval
//   - permissions.go   — Permission enforcement and checking
//   - users.go         — User and group management
//   - rbac.go          — Role and permission assignment
//   - auth.go          — Session lifecycle + system initialisation
//   - dashboard.go     — Dashboard stats and activity feed
//   - catalog.go       — Project / environment passthrough
type KeyorixCore struct {
	storage storage.Storage
	// httpClient is used for outbound webhook/Slack POSTs (alert escalation).
	// nil = a fresh &http.Client{Timeout: 10s} per call. Overridable in tests to
	// inject a custom transport so no TCP port binding is needed.
	httpClient *http.Client
	// webhookURLValidator enforces SSRF rules on notification channel URLs (scheme
	// + private-IP rejection). nil = use the real validateWebhookURL (which does a
	// live DNS lookup); overridable in tests to avoid network calls.
	webhookURLValidator func(string) error
	// secretValueEncryptor encrypts secret VALUES at rest (ADR-004 envelope
	// AES-256-GCM, AAD-bound per #94). nil = encryption disabled (plaintext at
	// rest, dev/test only — the loud startup banner covers it). Wired from the
	// initialised encryption.Service at server startup via SetSecretValueEncryptor.
	// ports.EncryptionProvider (ADR-109 step 5), not the concrete
	// *encryption.Service — *encryption.Service satisfies this directly, with
	// no alias needed (see EncryptionProvider's own doc comment). See
	// secret_value_crypto.go for the fail-closed encrypt/decrypt helpers this
	// backs. Replaces the former, never-wired encryption.SecretEncryption path.
	secretValueEncryptor ports.EncryptionProvider
	// authEncryptor reversibly encrypts auth secrets that cannot be hashed (the
	// TOTP MFA shared secret). nil or disabled = passthrough (store plaintext),
	// consistent with the rest of the product when encryption is off. Wired
	// from the initialised encryption.Service at server startup via
	// SetAuthEncryptor. ports.EncryptionProvider (ADR-109 step 5), same as
	// secretValueEncryptor above.
	authEncryptor ports.EncryptionProvider
	// dynamicEngineFactory resolves a dynamic-secrets credential engine by backend
	// type (ADR-035). nil = dynamic secrets unavailable (fail closed — see
	// dynamicEngine). Wired at startup to internal/dynamic.New (server/main.go's
	// DefaultIntegrations/wireDynamicSecrets); overridable in tests with a fake.
	dynamicEngineFactory ports.DynamicBackendFactory
	// trustRegistry resolves the embedded update/license signing-key trust registry
	// (ADR-062/064). nil = the real trust.DefaultRegistry; overridable in tests to
	// inject a lookup failure (#145) without mutating trust package internals.
	trustRegistry func() (*trust.KeyRegistry, error)
	// dynamicSweepEnabled mirrors config dynamic_secrets.sweep_enabled. Backends
	// without DB-level expiry (MySQL/MongoDB) rely entirely on the sweeper to
	// enforce a lease's TTL, so IssueLease refuses to mint from them when it is off
	// (the credential would otherwise never expire). Set via SetDynamicSweepEnabled.
	dynamicSweepEnabled bool
	// dynamicMaxLeaseTTL mirrors config dynamic_secrets.max_lease_ttl (#97): a hard,
	// install-wide ceiling dynamicTTL enforces alongside (never instead of) each
	// config's own MaxTTLSeconds, which has no ceiling of its own. Zero = the
	// package default (90 days) applies. Set via SetDynamicMaxLeaseTTL.
	dynamicMaxLeaseTTL time.Duration
	// dynamicAllowInsecureTransport mirrors config
	// dynamic_secrets.allow_insecure_transport (see
	// SetDynamicAllowInsecureTransport).
	dynamicAllowInsecureTransport bool
	// dynamicAllowPrivateTargets mirrors config
	// dynamic_secrets.allow_private_network_targets. When false (the default), the
	// SSRF guard in CreateDynamicSecretConfig rejects admin DSNs whose host resolves
	// to a private or link-local address. Set via SetDynamicAllowPrivateTargets.
	dynamicAllowPrivateTargets bool
	// webauthnRP is the WebAuthn relying party (ADR-036); nil = WebAuthn disabled.
	// Set from config at startup via SetWebAuthn.
	webauthnRP *webauthn.WebAuthn
	// auditHighWaterWitnessPath is where advanceAuditHighWater (audit_checkpoint.go)
	// mirrors the signed audit high-water mark it just persisted to
	// system_metadata (design-b3-backup-v2.md §6.3's rollback-protection witness
	// file). Empty = disabled (no witness maintained) — the default for any
	// deployment `admin backup`/`admin restore` don't support (Postgres) or a
	// test core with no on-disk database at all. Set from config at startup via
	// SetAuditHighWaterWitnessPath, to auditverify.WitnessPath(dbPath).
	auditHighWaterWitnessPath string
	now                       func() time.Time // For testability
	passwordPolicy            PasswordPolicy
	// bootstrapToken gates POST /system/init (BootstrapSystem). The first-boot admin
	// claim is otherwise unauthenticated, so a fresh, network-reachable instance could
	// be seized by whoever calls /system/init first. The server sets this at startup
	// (from KEYORIX_BOOTSTRAP_TOKEN, or a random value logged for the operator while the
	// system is uninitialised); init refuses unless the caller presents a matching token.
	bootstrapToken string
	// BootstrapSystem's check-then-create sequence is serialized via
	// storage.WithBootstrapLock (a process mutex, plus a PostgreSQL advisory lock
	// across HA replicas — see auth_bootstrap.go and #core-auth-03), not a
	// KeyorixCore-level mutex: a per-process mutex here would only serialize
	// callers within ONE replica, same gap #339 originally closed for concurrent
	// same-process callers only.
	secretValuePolicy SecretValuePolicy // optional quality gate on secret values (off by default)
	// maxSecretSize caps a secret value's size in bytes (see
	// secret_size_policy.go) — unlike secretValuePolicy, this is on by default
	// (NewKeyorixCore sets it to DefaultMaxSecretSize) rather than requiring
	// an explicit opt-in.
	maxSecretSize    int
	secretNamePolicy SecretNamePolicy   // optional naming convention for secrets (off by default)
	secretNameRe     *regexp.Regexp     // compiled secretNamePolicy.Pattern (nil = no regex check)
	loginLockout     LoginLockoutPolicy // per-account login lockout (disabled by default)
	// recordFailedLogin (and the pre-session-mint recheck in
	// checkLockAndClearLoginFailures) so concurrent failures can't lose an increment.
	// Combined with the row lock LockUserForUpdate takes on Postgres, the lockout
	// counter stays correct across replicas. Sharded by userID (see
	// loginFailureLock) so a flood against one account cannot serialize every OTHER
	// account's failed-login accounting behind a single process-wide lock — a
	// noisy-neighbour/availability concern distinct from the correctness the
	// per-shard lock + row lock still provide. Zero value is ready to use (each
	// shard is its own zero-value sync.Mutex). See login_lockout.go.
	loginFailureMu [loginFailureMuShards]sync.Mutex
	// globalAdminGuardMu serializes RemoveUserRole's last-global-admin check and the
	// removal it guards (guardLastGlobalAdmin) into one atomic unit, so two admins
	// concurrently removing each other's role assignment cannot both observe
	// "another admin still exists" before either write lands (#340). Combined with
	// the row lock ListGlobalAdminAssignmentsForUpdate takes on Postgres, the guard
	// stays correct across HA replicas too. Zero value is ready to use. See
	// rbac_management.go.
	globalAdminGuardMu sync.Mutex
	// setupResendMu serializes the count-then-issue window of the setup-link resend
	// throttle (checkResendThrottle + IssueSetupToken) so two concurrent resends for
	// the same (purpose, email) cannot both clear the per-day cap / min-interval
	// before either token row exists. Held only across the throttle check and the
	// token write — link delivery (SMTP) runs after release, so a slow send never
	// serializes every other resend. Zero value is ready to use. See setup_delivery.go.
	setupResendMu sync.Mutex
	// webauthnCredentialMu serializes persistUpdatedCredential's per-credential
	// read-validate-write of the advanced WebAuthn signature counter, so two
	// concurrent logins for the same (cloned) authenticator cannot race and let a
	// stale, lower counter clobber an already-persisted higher one. Combined with the
	// row lock LockWebAuthnCredentialForUpdate takes on Postgres, the counter stays
	// monotonic across replicas too. Zero value is ready to use. See webauthn.go.
	webauthnCredentialMu sync.Mutex
	// secretDependencyMu serializes AddSecretDependency's cycle-check read through
	// the edge it writes (#260), so two concurrent callers racing to add A→B and
	// B→A in the same project cannot both pass the pre-write cycle check before
	// either commits, persisting a cycle that later hard-errors rotation planning
	// for that project. Combined with the row lock
	// ListSecretDependenciesForProjectForUpdate takes on Postgres, this holds
	// across replicas too. Zero value is ready to use. See secret_dependencies.go.
	secretDependencyMu sync.Mutex
	// accountStateMu serializes the account_state/is_active read-modify-write shared
	// by setAccountState (SuspendUser/ReactivateUser/RequirePasswordReset) and
	// UpdateSCIMUser (#344): without it, an admin's incident-response SuspendUser and a
	// routine SCIM/IdP resync for the same user can each GetUser before the other's
	// Save commits, and whichever full-row Save lands last silently clobbers the
	// other's change — e.g. a suspend committed, then a SCIM sync's stale in-memory
	// "active" copy overwrites it back to active with no error to either caller.
	// Combined with the row lock LockUserForUpdate takes on Postgres, this holds
	// across replicas too. Zero value is ready to use. See account_state.go / scim.go.
	accountStateMu sync.Mutex
	// accessReviewDecisionMu is a minor in-process fast-path only, kept alongside
	// claimItemDecision's real fix (#1646): the cross-replica correctness
	// guarantee for DecideAccessReviewItem's read-decide-act-persist sequence now
	// comes from a DB-level conditional UPDATE (claimed BEFORE the real
	// attest/revoke action runs, not after), not this mutex — the mutex alone
	// only ever serialized callers within ONE process, and a false-certification
	// race across independent replicas was live-reproduced with it as the sole
	// guard. See access_review_campaign.go.
	accessReviewDecisionMu sync.Mutex
	// (#G04-HA) dualControlApprovalMu used to serialize
	// ApproveAccessRequestWithExpiry's read-approvals-decide-grant sequence
	// in-process. It is gone: a KeyorixCore-level mutex never serialized anything
	// across replicas, and the sub-threshold straddle it failed to prevent is a
	// real defect (see ApproveAccessRequestWithExpiry's doc comment). That sequence
	// now runs under storage.WithNamedLock keyed per request — strictly stronger
	// cross-replica, and strictly more concurrent in-process, since distinct
	// requests no longer serialize against one another. Nothing replaces the field.
	auditForwarder AuditForwarder
	// auditStream is the in-process pub/sub broker that wakes live audit tails
	// (gRPC StreamAuditLogs) the instant an event is written, replacing fixed-interval
	// DB polling. Always non-nil (set in the constructors).
	auditStream *auditBroker
	// notificationSink broadcasts a deployment-wide, aggregate notification (the
	// compliance digest, an auto-rotation-failure summary) to every enabled external
	// channel, including Slack/Teams/webhook. nil = no channel configured. Set from
	// config via SetNotificationSink. Deliberately NOT used for per-user/per-project
	// events (see recipientNotificationSink) — see #391.
	notificationSink NotificationSink
	// recipientNotificationSink fans a per-user/per-project notification (secret
	// shared, share revoked, ownership transferred, access requested, anomaly alert,
	// break-glass activation, …) out to external channels that can actually address a
	// single recipient — currently just email. nil = in-app only.
	//
	// #391: chat (Slack/Teams) and generic webhook channels are, by design, ONE fixed
	// deployment-wide destination an operator configures (there is no per-user chat-
	// identity mapping in this codebase to DM a specific Slack user). Handing a
	// per-user event straight to those channels — as the old single notificationSink
	// did — broadcasts it to every member of that channel regardless of project
	// membership or secret access, defeating every recipient-scoping computation this
	// package does for the in-app row. So per-user events are routed ONLY to
	// recipient-addressable channels (email, which already drops any event with no
	// resolved address) and never to chat/webhook. Set from config via
	// SetRecipientNotificationSink.
	recipientNotificationSink NotificationSink
	// connectManager proxies read-through federation to external secret stores
	// (ADR-043). nil = Keyorix Connect disabled. Set via SetConnectManager.
	// ports.ConnectorResolver (ADR-109 step 4), not the concrete
	// *connect.Manager — server/main.go's wireConnect wires the real
	// *connect.Manager, which satisfies this directly.
	connectManager ports.ConnectorResolver
	// connectOwnership maps each configured connector's name to its resolved
	// tenant-scoping data (ADR-082 §A/§E) — built in the same boot pass as
	// connectManager, from the same config, by server/main.go, then set via
	// SetConnectOwnership. Deliberately NOT part of ports.ConnectorResolver/the
	// Connector interface (internal/connect stays a pure backend-read abstraction
	// with no ownership concept) — see ADR-082's Decision (D) for the option
	// analysis. A connector name absent from this map is denied ownership, never
	// silently skipped or treated as owned — see connectOwnershipSatisfied.
	connectOwnership map[string]ConnectOwnership
	// rotationManager holds the backend rotation executors (ADR-047) that apply a new
	// credential to an upstream system during rotation. nil = no backends configured.
	rotationManager ports.RotationExecutorResolver
	// rotationBackendLocks serializes applyBackendRotation calls against the SAME
	// (backend, ref) pair — the single shared entry point BOTH the auto-rotation
	// scheduler (rotateOneSecret) and on-demand rotation (RotateSecretOnDemand) go
	// through (rotation_executor.go). Previously this protection existed only inside
	// AWSIAMExecutor's own private refLocks (internal/rotation/awsiam.go, g05), so
	// Azure and GCP's generate-upstream executors — whose GenerateUpstream is the same
	// kind of unsynchronized list→evict→create→delete read-modify-write against their
	// respective cloud APIs — had ZERO concurrency protection: two concurrent calls for
	// the same ref (e.g. the single-replica-gated auto-rotation scheduler tick racing a
	// manually-triggered on-demand rotation, both goroutines in the SAME process) could
	// interleave and, in the worst case, one call's cleanup could delete the credential
	// the other call just minted and is about to report back to its own caller as "the"
	// live value. Moving the lock here, keyed generically by (backend, ref) rather than
	// inside one executor's private state, gives every registered backend — present and
	// future, regardless of concrete type — this protection for free; see
	// rotationBackendLock and applyBackendRotation.
	//
	// Keyed per (backend, ref) — not one global lock — so rotations for different
	// backends/refs still run concurrently. A plain sync.Map (rather than the fixed-shard
	// loginFailureMu array) is fine here: backend names and refs are operator-configured
	// (allowed_refs is itself an admin-set allowlist), not attacker-controlled cardinality
	// — the same reasoning awsiam.go's now-removed refLocks documented.
	//
	// Scope: this closes the race WITHIN one Keyorix process only — the primary
	// reachable case, since the scheduler ticker and the HTTP/gRPC on-demand handlers
	// all run in the server's own process. It does NOT close the same race across two HA
	// replicas (ADR-039), and it does NOT close the separate, larger orphaned-credential
	// crash window: applyBackendRotation's lock is released the instant it returns —
	// BEFORE the caller (rotateOneSecret/RotateSecretOnDemand) persists the new value via
	// RotateSecret. A process crash between "upstream committed a new credential" and
	// "Keyorix stored it" still leaves a live, valid credential with NO Keyorix record at
	// all (an orphan), for every backend, exactly as it did before this change for AWS.
	// Closing THAT window needs a write-intent-first / two-phase-commit-style redesign
	// (persist "attempting to rotate (backend, ref)" durably before calling upstream,
	// plus a reconciliation pass) — out of scope here; EventSecretRotateBackendStarted is
	// the existing (pre-this-change) breadcrumb for manual reconciliation, not a fix.
	rotationBackendLocks sync.Map // map[rotationLockKey]*sync.Mutex
	// evidenceForwarder ships the scheduled compliance-evidence pack to an off-box
	// target (webhook). nil = local-file only. Set via SetEvidenceForwarder.
	evidenceForwarder EvidenceForwarder
	// breakGlassPolicy configures self-service emergency access; zero value =
	// disabled. Set from config at startup via SetBreakGlassPolicy.
	breakGlassPolicy BreakGlassPolicy
	// dualControlRequiredApprovals is the N-of-M approval threshold for access
	// requests (A.5.3); 0/1 = single approval (disabled). Set via SetDualControlPolicy.
	dualControlRequiredApprovals int
	// classificationRestrictedRequiresApproval mirrors config classification.
	// restricted_requires_approval; false (the default) = "restricted" stays purely
	// informational metadata, matching every deployment's behaviour today. When
	// true, a direct value read of a "restricted"-classified secret requires an
	// approved, secret-scoped access request (see classification_gate.go). Set from
	// config at startup via SetClassificationRestrictedRequiresApproval.
	classificationRestrictedRequiresApproval bool
	// classificationRestrictedRequiresPermission mirrors config classification.
	// restricted_requires_permission; false (the default) leaves "restricted" readable
	// by anyone whose RBAC roles grant secrets.read at the project scope. When true,
	// the user must ALSO hold the "secrets.read.restricted" permission (or an admin
	// bypass role). Set at startup via SetClassificationRestrictedRequiresPermission.
	classificationRestrictedRequiresPermission bool
	// classificationRestrictedRequiresMFAStepUp mirrors config classification.
	// restricted_requires_mfa_stepup; when true, reading a "restricted" secret
	// also requires the user to have completed MFA within the step-up window. Set
	// at startup via SetClassificationRestrictedRequiresMFAStepUp.
	classificationRestrictedRequiresMFAStepUp bool
	// classificationRestrictedMFAStepUpWindow is how long a completed MFA
	// verification remains valid for the step-up gate. 0 = default (15 min).
	classificationRestrictedMFAStepUpWindow time.Duration
	// retentionPolicy holds the configured per-record-type data-retention windows
	// (ISO A.5.33) so the compliance posture can report them; zero value = no
	// retention configured. Set from config at startup via SetRetentionPolicy.
	retentionPolicy RetentionPolicy
	// recertCadenceDays is the access-recertification review interval (ISO A.5.18),
	// in days; 0 = the default cadence. Used by the posture to flag overdue projects.
	// Set from config at startup via SetRecertificationCadence.
	recertCadenceDays int
	// oidcVerifier verifies federated machine-identity JWTs (ADR-031); nil = OIDC
	// auth disabled. Set from config via SetOIDCVerifier.
	oidcVerifier *OIDCVerifier
	// ssoProviders are the configured human-SSO OIDC providers (keyed by name);
	// ssoJWKS verifies their id_tokens. Empty = SSO disabled. Set via SetSSOProviders.
	ssoProviders map[string]*SSOProvider
	ssoJWKS      JWKSResolver
	// unionPageSizeOverride lowers ListReadableSecrets' per-scope page bound
	// (secret_readable_listing.go's maxUnionPageSize) so a test can drive the
	// truncation path without seeding 100001 secrets. 0 = use the real bound; never
	// set outside tests. A bound that can only be exercised by an unaffordable
	// fixture is a bound nobody has watched behave — which is how its truncation
	// came to be silent in the first place.
	unionPageSizeOverride int
	// listingMaxRowsOverride lowers the STORAGE row bound
	// (secret_listing_query.go's secretListingMaxRows, 10000) for the same reason
	// and with the same rules as unionPageSizeOverride above. It exists because the
	// coordinator's review of #2874 found that bound was the one actually in force
	// — convertToStorageFilter hard-codes it and discards the caller's paging — so
	// every truncation test that only lowered unionPageSizeOverride was driving a
	// bound that the storage clamp shadowed. 0 = use the real bound; never set
	// outside tests.
	listingMaxRowsOverride int
	// membershipValidationMode is the ADR-022 install-level onboarding mode;
	// "" = allowlist default. Set via SetMembershipValidationMode.
	membershipValidationMode string
	// membershipDomainAllowlist restricts invited emails to these domains
	// (ADR-022). Empty = no restriction. Set via SetMembershipDomainAllowlist.
	membershipDomainAllowlist []string
	// setupTokenTTL is the lifetime of a credential-delivery setup token (ADR-028);
	// 0 = DefaultSetupTokenTTL. Set from config via SetSetupTokenTTL.
	setupTokenTTL time.Duration
	// sessionAccessTTL is the access-token lifetime; refresh extends by this much.
	// 0 = defaultSessionAccessTTL (24h). Set from config via SetSessionTTLs.
	sessionAccessTTL time.Duration
	// sessionAbsoluteTTL caps total session lifetime from login — refresh never
	// extends past it. 0 = no ceiling (refreshable indefinitely). Via SetSessionTTLs.
	sessionAbsoluteTTL time.Duration
	// deploymentRequiresMFA mirrors security.require_mfa (ADR-112), so session
	// issuance can tell when a login must be a setup-only session (#3024,
	// account_setup.go). Set by the HTTP router via SetRequireMFA, from the same
	// config value that configures the setup gate.
	deploymentRequiresMFA bool

	// oneTimePasswordTTL is how long an admin-created one-time password
	// (CreateUserWithOneTimePassword) stays valid; zero means DefaultOneTimePasswordTTL
	// (never "no expiry"). See otp_expiry.go.
	oneTimePasswordTTL time.Duration
	// credentialDelivery transports setup links (ADR-028). nil = out-of-band: the
	// link is returned to the caller. Set from config via SetCredentialDelivery.
	credentialDelivery ports.CredentialDelivery
	// setupBaseURL is the absolute base (e.g. https://keyorix.acme.internal) used to
	// build setup links. Required to mint a link; a relative link is a misconfig.
	setupBaseURL string
	// auditCkptKey signs/verifies audit-chain checkpoints (ADR-029): a KEK-derived
	// HMAC key the database/DBA does not hold (#502 — mirroring #268's fix for the
	// evidence-signing key: deriving from the KEK rather than the DEK means a
	// routine DEK rotation does not affect it, so a checkpoint signed before a DEK
	// rotation stays verifiable after one). nil = signed checkpoints unavailable
	// (encryption disabled), in which case WriteAuditCheckpoint is a no-op and
	// VerifyAuditChain runs without on-box checkpoint enforcement. Set at startup
	// via SetAuditCheckpointKey. auditCkptKeyVersion records the KEK-derived key's
	// own fingerprint, so a checkpoint signed under a superseded key (a genuine
	// KEK-provider migration, far rarer than a DEK rotation) is not enforced.
	auditCkptKey        []byte
	auditCkptKeyVersion string
	// tokenCacheInvalidator evicts a bearer token from the HTTP auth cache by its hash.
	// Wired at startup (SetTokenCacheInvalidator) to the middleware cache; nil in tests/
	// remote mode (the cache lives in the HTTP server). Lets core paths that revoke a
	// token (e.g. revoking PATs on a password change) take effect immediately rather than
	// after the positive-cache TTL. core cannot import the middleware directly (cycle).
	tokenCacheInvalidator func(hash string)
	// tokenCacheClearer deletes a bearer token's HTTP auth-cache entry ONLY if one
	// already exists -- unlike tokenCacheInvalidator, it never writes a new tombstone.
	// Wired at startup (SetTokenCacheClearer) to the middleware's ClearTokenCacheIfCached.
	// Used for a transition where a brand-new, never-cached credential must not be
	// spuriously negative-cached (setAccountState's "becoming active" branch) but any
	// EXISTING stale entry still needs clearing so it doesn't outlive the transition.
	tokenCacheClearer func(hash string)
	// machineTokenCacheFlusher tombstones every machine-token entry in the HTTP auth
	// cache. Wired at startup (SetMachineTokenCacheFlusher); nil in tests/remote mode,
	// same as tokenCacheInvalidator above. Fail-closed fallback for
	// TransitionMachineIdentity when it cannot determine exactly which credential
	// hashes to evict individually (see evictMachineIdentityCacheOrFlush's doc comment).
	machineTokenCacheFlusher func()
	// auditMaxCertified is an in-memory monotonic high-water mark of the greatest
	// chained-events count this process has ever certified or verified. It backstops
	// the persistent signed high-water (SystemMetadata) against an online attacker who
	// deletes the high-water row mid-run: the chain can never be observed to regress
	// below a length we already saw this lifetime. Guarded by auditWatermarkMu.
	auditMaxCertified int64
	auditWatermarkMu  sync.Mutex
	// checkpointNotary, when set, anchors each freshly-written audit checkpoint to
	// an external authority (RFC 3161 TSA) for a forge-proof proof-of-existence
	// (ADR-029). nil = no external anchoring. Set at startup via SetCheckpointNotary.
	checkpointNotary ports.TimestampNotary
	// checkpointAnchorRoots is the trusted TSA root pool used to VERIFY stored
	// checkpoint anchors (the issuer trust anchor). nil = anchors cannot be verified
	// (fail closed). Set at startup via SetCheckpointAnchorRoots.
	checkpointAnchorRoots *x509.CertPool
	// checkpointAnchorVerify verifies a stored anchor's receipt token against
	// checkpointAnchorRoots (internal/notary.VerifyReceipt in production — a free
	// function, not a TimestampNotary method, so it is wired separately). nil =
	// anchors cannot be verified. Set at startup via SetCheckpointAnchorRoots,
	// alongside the roots it verifies against.
	checkpointAnchorVerify ports.VerifyReceiptFunc
	// evidenceSignKey / evidenceSignKeyVersion sign and verify exported compliance-
	// evidence packs (HMAC, DEK-derived, domain-separated from the checkpoint key).
	// nil = signing unavailable (encryption disabled). Set via SetEvidenceSignKey.
	evidenceSignKey        []byte
	evidenceSignKeyVersion string
	// licenseGate evaluates the installed offline commercial license (ADR-065). nil =
	// no license configured → the community baseline. Evaluation is fail-safe (it never
	// denies access or stops the server) and fresh on every call. Set via SetLicenseGate.
	licenseGate ports.LicenseGate
	// impersonationCeilingCache caches requireEqualOrGreaterAdminAuthority results
	// by "actorID:targetID" to reduce per-request DB load on the auth hot path for
	// impersonation sessions (IMP-001). Zero value is ready to use (sync.Map).
	impersonationCeilingCache sync.Map
	// secretExpiryWatermark is an in-memory monotonic high-water mark of the
	// latest wall-clock instant enforceSecretReadGuards has ever observed via
	// c.now(), in this process's lifetime (#1632). Mirrors auditMaxCertified's
	// shape (an in-memory floor that never regresses) applied to wall-clock
	// time instead of a chained-events count: the secret-value disclosure
	// guard refuses to treat a c.now() reading as trustworthy if it is
	// EARLIER than a time this process has already legitimately observed —
	// the one deployment-realistic case this actually stops is an operator or
	// NTP correction stepping the clock backward WHILE THE SERVER KEEPS
	// RUNNING (the scenario ADR-094/#1632 named as the live one for this
	// site), without requiring every other wall-clock site in #1632 to adopt
	// the same mechanism. Deliberately NOT persisted (unlike auditMaxCertified,
	// which backstops a SystemMetadata row): this guard runs on every
	// secret-value read, and at the time this was written GetSystemMetadata/
	// SetSystemMetadata were unconditionally unsupported under storage.type: remote
	// (RemoteStorage, since deleted, #2162) — persisting here would have made
	// every such read depend on a storage call that hard-failed under that
	// backend. Residual risk, named rather than hidden: resets to zero on process
	// restart, so an attacker who can also restart the process after
	// stepping the clock back defeats it — a real limitation, not covered by
	// this fix, of the same kind ADR-094 already flagged as calling for an
	// operational (not per-site code) mitigation.
	secretExpiryWatermarkMu sync.Mutex
	secretExpiryWatermark   time.Time
	// connectClockWatermark, shareClockWatermark: in-memory monotonic high-water
	// marks backing connectEffectiveNow (connect.go) and shareEffectiveNow
	// (permissions.go) respectively (#1653, the follow-up to #1632). Both CLAMP
	// rather than refuse — see rbacEffectiveNow's doc comment
	// (internal/storage/store/local_rbac.go, #1651) for why: these are
	// read-heavy permission-resolution paths (Connect ref-grant checks on every
	// federated read; share-active checks on every secret listing/access-list
	// resolution), not single discrete actions, so hard-refusing on a detected
	// regression would trade a narrow clock-integrity concern for a broad
	// denial-of-service. Kept as two separate fields, not one shared watermark,
	// matching #1632's own precedent (consumeClockWatermark vs
	// rbacClockWatermark) — Connect grants and shares are unrelated
	// subsystems; sharing a watermark would only blur which mechanism actually
	// warmed it, without protecting anything more.
	connectClockWatermarkMu sync.Mutex
	connectClockWatermark   time.Time
	shareClockWatermarkMu   sync.Mutex
	shareClockWatermark     time.Time
	// sessionRefreshWatermark, accessRequestApprovalWatermark: in-memory
	// monotonic high-water marks backing checkSessionRefreshClockNotRegressed
	// (auth.go) and checkAccessRequestApprovalClockNotRegressed
	// (classification_gate.go) respectively (#1653). Both REFUSE rather than
	// clamp, matching secretExpiryWatermark's shape above — each guards a
	// single, discrete, low-volume action (one session refresh per access
	// window; one admin approval per request), not a pervasive read path, so
	// refusing outright on a detected regression is proportionate. The
	// access-request watermark is shared between
	// ApproveSecretAccessRequest and ApproveAccessRequestWithExpiry
	// (invitations.go) — the same "access request approval" action reached via
	// two entry points, mirroring #1638's consumeClockWatermark being shared
	// between ConsumeMFAChallenge and ConsumeWebAuthnSession.
	sessionRefreshWatermarkMu        sync.Mutex
	sessionRefreshWatermark          time.Time
	accessRequestApprovalWatermarkMu sync.Mutex
	accessRequestApprovalWatermark   time.Time
	// authTokenClockWatermark backs authEffectiveNow (auth.go): an in-memory
	// monotonic high-water mark of the latest wall-clock instant this process
	// has observed while validating a presented authentication credential's
	// expiry -- ValidateSessionToken (session ExpiresAt + AbsoluteExpiresAt),
	// ValidatePATToken (IsPATExpired), ValidateMachineToken (credential
	// ExpiresAt, both the primary and CIDR-restriction lookup paths), and
	// HasActiveMFAStepUp (GetActiveMFAStepUpGrant's cutoff).
	//
	// Part 2 regression audit continuation (2026-09-04): the #1632/#1651/#1653
	// wall-clock hardening wave covered RBAC permission-resolution queries
	// (rbacClockWatermark), Connect/share validity (connectClockWatermark/
	// shareClockWatermark), single-use MFA/WebAuthn challenge CONSUMPTION
	// (consumeClockWatermark), session REFRESH and access-request APPROVAL
	// (sessionRefreshWatermark/accessRequestApprovalWatermark) -- but never
	// the four functions above, which validate a presented credential's own
	// expiry on every authenticated request/read, before any RBAC query even
	// runs. All four compared a bare c.now() directly against a stored
	// ExpiresAt with no regression protection of any kind -- the same
	// backward-host-clock threat model #1632 names ("an operator, or an
	// NTP-less clock correction, stepping the host clock back") would let an
	// already-expired session, PAT, machine credential, or MFA step-up grant
	// validate as still live.
	//
	// CLAMPs rather than refuses, matching rbacClockWatermark/
	// connectClockWatermark/shareClockWatermark's reasoning (local_rbac.go):
	// these are pervasive, every-request/every-read paths, not a single
	// discrete action -- hard-refusing authentication outright the moment a
	// regression is detected would turn a narrow clock-integrity concern into
	// a total outage (every credential rejected, for every principal, until
	// the clock recovers), a strictly worse outcome than the hazard being
	// defended against. One shared watermark across all four, not four
	// separate ones: unlike Connect/shares (unrelated subsystems, kept
	// separate per #1632's own precedent), these four are all "is a
	// presented credential still within its validity window" -- the same
	// concept applied to four credential kinds, so sharing loses no
	// meaningful precision (the point is tracking the latest wall-clock
	// instant this process has legitimately observed, not per-credential
	// state).
	authTokenClockWatermarkMu sync.Mutex
	authTokenClockWatermark   time.Time
	// dynamicSecretsClockWatermarkMu/dynamicSecretsClockWatermark back
	// checkLeaseRenewClockNotRegressed and dynamicSecretsSweepCutoff
	// (dynamic_secrets.go): the anti-rollback protection every other
	// expiring-credential type above already has, closing the one gap
	// EffectiveNow's own doc comment used to name as deferred (FUZZ-MECH M2,
	// 2026-09-27, docs/findings/2026-09-27-FINDING-dynamic-secret-lease-clock-rollback.md).
	// Shared between the two call sites (a renewal attempt and the
	// background sweep) so either one warms the same protection, mirroring
	// sessionRefreshWatermark/accessRequestApprovalWatermark's own
	// same-shape sharing above.
	dynamicSecretsClockWatermarkMu sync.Mutex
	dynamicSecretsClockWatermark   time.Time
}

// AuditForwarder ships persisted audit events to an external sink (e.g. a SIEM).
// Implementations must be non-blocking and best-effort: Forward is called on the
// audit write path and must never block or fail the audited operation. Defined
// here (not in the siem package) so core has no dependency on the forwarder impl.
type AuditForwarder interface {
	Forward(event *models.AuditEvent)
}

// SetAuditForwarder wires an audit forwarder. The server calls this at startup
// when the install configures an audit.siem block. nil disables forwarding.
func (c *KeyorixCore) SetAuditForwarder(f AuditForwarder) {
	c.auditForwarder = f
}

// AuditForwarder returns the wired audit forwarder (nil if none configured).
// #G56: the server needs this at shutdown to flush/close the concrete
// forwarder (e.g. *siem.Forwarder) — SetAuditForwarder's caller previously had
// no way to reach it again afterward, since the constructed value lived only
// as a local variable inside server initialization.
func (c *KeyorixCore) AuditForwarder() AuditForwarder {
	return c.auditForwarder
}

// SetLicenseGate wires the offline-license feature gate built at startup from the
// installed token (ADR-109 "last decoupling", B5: g is any ports.LicenseGate, in
// production always *pkg/licenseverify.Gate via server/main.go's DefaultIntegrations).
// nil = no license (community baseline). Safe to leave unset.
func (c *KeyorixCore) SetLicenseGate(g ports.LicenseGate) {
	c.licenseGate = g
}

// licenseStatusUnconfigured is what *licenseverify.Gate's own nil-receiver
// Status() used to return before licenseGate became an interface (ADR-109
// "last decoupling", B5): a nil ports.LicenseGate is now a normal Go nil
// INTERFACE value, and calling a method on one panics (unlike a nil
// *licenseverify.Gate, which the old concrete-pointer field tolerated) — so
// the nil check moves here, to the one place internal/core reads the gate,
// rather than relying on the wired implementation's own nil-receiver safety.
var licenseStatusUnconfigured = ports.LicenseStatus{
	State:  ports.LicenseStateNone,
	Reason: "no license configured — running the community baseline",
}

// LicenseStatus returns the freshly-evaluated license entitlement. It never errors; an
// unset gate or a degraded license reports the community baseline with a reason.
func (c *KeyorixCore) LicenseStatus() ports.LicenseStatus {
	if c.licenseGate == nil {
		return licenseStatusUnconfigured
	}
	return c.licenseGate.Status()
}

// HasLicensedFeature reports whether commercial feature f is currently granted. This is the
// single gate a future commercial-only capability checks; it is false under any degraded,
// expired, missing, or unconfigured license.
func (c *KeyorixCore) HasLicensedFeature(f string) bool {
	if c.licenseGate == nil {
		return false
	}
	return c.licenseGate.HasFeature(f)
}

// AuditLicenseState records the current license state as an audit event. The server calls
// it once at startup so the evaluated entitlement (and any degrade reason) is on the record.
func (c *KeyorixCore) AuditLicenseState(ctx context.Context) {
	st := c.LicenseStatus()
	desc := "License evaluated at startup: " + string(st.State)
	if st.Reason != "" {
		desc += " — " + st.Reason
	}
	ok := true
	c.emitAudit(ctx, &models.AuditEvent{
		EventType:   "license.evaluated",
		Description: desc,
		Success:     &ok,
		ActorType:   "system",
		EventTime:   time.Now(),
	})
}

// Audit field length caps (#381). Neither models.AuditEvent.Description nor .Diff
// carries a DB-level size limit, and secret/project/role names feeding into a
// Description have no length cap unless an operator opts into secret_name_policy
// (off by default) — so an attacker-chosen name could otherwise blow up every
// audit row that mentions it, and (since the audit-chain writer is a single
// process-wide serialized writer) degrade audit throughput for every OTHER write
// in the system. These ceilings comfortably fit any Description/Diff this
// codebase's own call sites actually generate (short templated sentences and
// small structured before/after JSON), so legitimate audit content is never
// affected.
const (
	auditDescriptionMaxLen = 4096 // ~4 KiB
	auditDiffMaxLen        = 8192 // ~8 KiB
)

// auditTruncatedMarker is appended to a field truncated by truncateAuditField.
const auditTruncatedMarker = "...[truncated]"

// truncateAuditField caps s at maxLen bytes, appending auditTruncatedMarker when
// truncation occurs. Audit writes must never fail (or reject) the underlying
// business operation just because a caller-supplied description/diff got too
// long, so this truncates rather than erroring. The cut point is walked back to
// a valid UTF-8 boundary so truncation never produces an invalid string.
func truncateAuditField(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	cut := maxLen
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	return s[:cut] + auditTruncatedMarker
}

// emitAudit persists an audit event and forwards it to the configured sink.
// All core audit writers funnel through here so SIEM forwarding is uniform —
// which also makes it the single choke point to cap Description/Diff length
// (#381), independent of which helper (writeAuditEvent*, writeImpersonationEvent,
// AuditLicenseState, ...) produced the event. G80 #1530: the same choke point
// closes the machine-actor-attribution gap for every one of those callers at
// once, not just the two that happened to be checked first -- a machine
// identity's own ID is stamped here from context (WithMachineActor,
// audit_context.go) whenever the event is already actor-typed "machine_identity"
// and no caller explicitly set MachineIdentityID itself.
//
// #1626: the same guarantee, the other direction. Several writeAuditEventFull/
// writeAuditEventDiff/writeAuditEventFailed callers (SetSecretAutoRotate,
// CreateConnectRefGrant/DeleteConnectRefGrant, AddSecretDependency/
// RemoveSecretDependency, transferOwnership, RevokeAllPersonalAccessTokensForUser/
// DeleteSessionsForUserExcept) build userID from a PrincipalID()-derived value --
// correct for AuthorizePrincipal, which needs the machine's real ID, but wrong
// for UserID, a human-attribution column: it collides with the same User.ID
// space #1623 fixed for persisted model columns. Every one of those callers
// funnels through here already (confirmed: TestDirectLogAuditEventCallersAreSafe,
// #1530's existing guard, allows no other path to storage.LogAuditEvent), so the
// fix belongs here, not at each site -- one correction, not eight, and it closes
// the same mistake at any future call site too. Do NOT add a second
// machine-actor field to carry this; MachineIdentityID above is already the
// mechanism. This is guard-the-invariant-not-the-conclusion's fifth instance in
// this campaign -- see docs/adr-092-audit-event-userid-machine-principal.md.
// emitAudit's bool return is "did this event durably persist" -- false on a
// LogAuditEvent error OR a recovered panic, true otherwise. Every PRE-#2406
// caller already ignores it (Go permits discarding a return value freely,
// so this is source-compatible with all of them -- their best-effort
// fire-and-forget semantics are completely unchanged). It exists so a
// caller for whom this specific audit record IS the thing being verified --
// a security action like RevokeLease, not an incidental side-effect of one
// -- can tell "best-effort, logged-and-moved-on" apart from "confirmed
// written" and refuse to report unconditional success when it isn't. See
// RevokeLease's own doc comment (dynamic_secrets.go) for the first such use.
func (c *KeyorixCore) emitAudit(ctx context.Context, event *models.AuditEvent) (persisted bool) {
	// A panic anywhere inside this function (most likely from the
	// c.storage.LogAuditEvent call below, or the auditForwarder/auditStream
	// hooks that follow it) must never propagate to emitAudit's callers: every
	// caller of this function is itself in a "the primary operation already
	// succeeded, only the audit trail is being written" position, exactly the
	// same shape as the best-effort helpers this same fuzz campaign found
	// unprotected against a panic (secret_dependencies.go's
	// emitDependencyLifecycleEvents, users.go's CreateUser) — see
	// docs/findings/2026-09-22-FINDING-secret-delete-restore-dependency-emission-panic-masks-success.md.
	// emitAudit is the SINGLE choke point every c.Log*/writeAuditEvent* helper
	// funnels through (confirmed by TestDirectLogAuditEventCallersAreSafe), so
	// fixing panic-safety here closes it for every caller at once, the same
	// way the existing returned-error handling below already does.
	defer func() {
		if r := recover(); r != nil {
			logAuditEmitPanic(event, r)
			persisted = false
		}
	}()
	prepareAuditEventForEmit(ctx, event)
	// #1650: the request-cancellation-immunity fix lives at the storage layer
	// (LocalStorage.LogAuditEvent detaches its own ctx before doing I/O), not here —
	// this is one of four call sites into LogAuditEvent
	// in the codebase (the other three bypass emitAudit entirely: server/main.go,
	// audit_ingest_proxy.go, anomaly.go), so fixing it at emitAudit alone would leave
	// those three still vulnerable. See store.auditWriteContext's doc comment for the
	// full rationale.
	if err := c.storage.LogAuditEvent(ctx, event); err != nil {
		logAuditEmitFailure(event, err)
		return false
	}
	c.afterAuditEventPersisted(event)
	return true
}

// logAuditEmitPanic and logAuditEmitFailure are the two failure reports every
// audit-emit path shares. Extracted (#2676) so emitAudit and emitAuditOn
// (audit_target.go, the transaction-scoped variant) cannot report the same
// condition two different ways — an operator grepping for one of these strings
// must find every occurrence of the condition, not whichever path happened to be
// taken.
func logAuditEmitPanic(event *models.AuditEvent, r any) {
	log.Printf("SECURITY: emitAudit panicked persisting audit event %q (success=%v, best-effort, primary operation already succeeded): %v", event.EventType, event.Success, r)
}

// A failed chain-write is an audit gap that VerifyAuditChain cannot detect — a
// never-written event leaves no hole. Surface it loudly instead of swallowing,
// and do NOT forward a phantom event (ID 0, no chain position) to the SIEM: the
// off-box mirror must reflect the durable chain, not events that never landed.
// (auditForwardSink extends that same rule to an event written inside a
// transaction that later rolls back.)
func logAuditEmitFailure(event *models.AuditEvent, err error) {
	log.Printf("SECURITY: failed to persist audit event %q (success=%v): %v", event.EventType, event.Success, err)
}

// prepareAuditEventForEmit applies the mutations emitAudit/emitAuditWithAccessLog
// both need BEFORE the actual storage write (machine-actor-ID stamping, field
// truncation) — factored out (SESSION-PERF, #2403 follow-up, item 3) so the two
// can't drift on this.
func prepareAuditEventForEmit(ctx context.Context, event *models.AuditEvent) {
	if event.ActorType == ActorTypeMachine {
		if event.MachineIdentityID == nil {
			if machineID, ok := machineActorFromContext(ctx); ok {
				event.MachineIdentityID = &machineID
			}
		}
		// A machine principal's ID must never occupy UserID -- see the doc
		// comment above. Unconditional: no caller has a legitimate reason to
		// want a machine's raw ID there once ActorType says machine.
		event.UserID = nil
	}
	event.Description = truncateAuditField(event.Description, auditDescriptionMaxLen)
	event.Diff = truncateAuditField(event.Diff, auditDiffMaxLen)
}

// afterAuditEventPersisted runs what emitAudit/emitAuditWithAccessLog both do
// AFTER a successful storage write (SIEM forward, waking live audit-tail
// subscribers) — factored out for the same reason as prepareAuditEventForEmit.
func (c *KeyorixCore) afterAuditEventPersisted(event *models.AuditEvent) {
	if c.auditForwarder != nil {
		c.auditForwarder.Forward(event)
	}
	// Wake any live audit tails (gRPC StreamAuditLogs). Non-blocking; subscribers
	// then read the new rows from storage with their cursor (DB stays authoritative).
	if c.auditStream != nil {
		c.auditStream.signal()
	}
}

// emitAuditWithAccessLog is emitAudit's error-returning sibling for a caller
// that needs to know the write actually succeeded before proceeding —
// specifically, LogSecretReadWithProject's audit-before-disclosure requirement
// (SESSION-PERF, #2403 follow-up, item 3): a secret's value must never be
// returned to a caller whose read wasn't durably recorded. Unlike emitAudit,
// a panic here becomes a returned error (fail closed) rather than a logged-
// and-swallowed best-effort failure — this caller's "primary operation" is
// the disclosure itself, which has NOT happened yet when this runs, the
// opposite of emitAudit's every other caller.
func (c *KeyorixCore) emitAuditWithAccessLog(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: emitAuditWithAccessLog panicked persisting audit event %q (success=%v): %v -- failing closed", event.EventType, event.Success, r)
			err = fmt.Errorf("audit write panicked: %v", r)
		}
	}()
	prepareAuditEventForEmit(ctx, event)
	if werr := c.storage.LogAuditEventWithAccessLog(ctx, event, accessLog); werr != nil {
		log.Printf("SECURITY: failed to persist audit event %q with access log (success=%v): %v -- failing closed", event.EventType, event.Success, werr)
		return werr
	}
	c.afterAuditEventPersisted(event)
	return nil
}

// NotificationEvent is one user-facing notification handed to an external sink for
// out-of-band delivery (email/webhook) alongside the persisted in-app row.
type NotificationEvent struct {
	UserID    uint   `json:"user_id"`
	Email     string `json:"email,omitempty"` // recipient's address, resolved best-effort
	Type      string `json:"type"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	ProjectID *uint  `json:"project_id,omitempty"`
	Link      string `json:"link,omitempty"`
}

// NotificationSink delivers a NotificationEvent to an external channel (email,
// webhook, …). Like AuditForwarder, implementations MUST be non-blocking and
// best-effort: Deliver runs on the notification path and must never block or fail
// the triggering operation. Defined here (not in the channel package) so core has
// no dependency on the channel implementations.
//
// Deliver reports whether the event was actually handed off to the channel's
// delivery pipeline (true) or was a no-op (false) — e.g. a broadcast event with no
// per-user recipient and no configured destination for the channel to route it to.
// This is a synchronous, best-effort signal about whether an attempt was even
// queued; it does NOT confirm the remote destination accepted it (that outcome
// stays opaque to the caller by design and is tracked only in the per-channel
// Prometheus counters — see notify_metrics.go). Callers that broadcast to a
// deployment-wide audience (SendComplianceDigest, notifyRotationFailures) use the
// return value so their audit trail doesn't claim success when nothing was ever
// attempted (#221).
type NotificationSink interface {
	Deliver(ev NotificationEvent) bool
}

// SetNotificationSink wires the broadcast (deployment-wide, aggregate) notification
// sink used by SendComplianceDigest and notifyRotationFailures — typically every
// enabled channel (email/Slack/Teams/webhook). The server calls this at startup when
// the install configures a notifications channel. nil = no channel configured.
func (c *KeyorixCore) SetNotificationSink(s NotificationSink) {
	c.notificationSink = s
}

// SetRecipientNotificationSink wires the sink used for per-user/per-project
// notifications (see recipientNotificationSink). The server calls this at startup
// with ONLY the recipient-addressable channels it configured (currently email) —
// never chat/webhook, which have no per-user identity mapping (#391). nil = in-app
// only.
func (c *KeyorixCore) SetRecipientNotificationSink(s NotificationSink) {
	c.recipientNotificationSink = s
}

// NewKeyorixCore creates a new instance of the core business logic. Secret-value
// encryption is off until SetSecretValueEncryptor wires an initialised service (the
// server does this at startup when storage.encryption.enabled).
func NewKeyorixCore(storage storage.Storage) *KeyorixCore {
	return &KeyorixCore{
		storage:        storage,
		now:            time.Now,
		passwordPolicy: DefaultPasswordPolicy(),
		auditStream:    newAuditBroker(),
		maxSecretSize:  DefaultMaxSecretSize,
	}
}

// ShareEffectiveNow exposes shareEffectiveNow (permissions.go) to callers
// outside package core that need "now" for a share-active decision sourced
// from the SAME watermarked clock every in-process share-active check
// already uses, instead of reading the real wall clock independently
// (#1983 investigation finding). Its two current external callers:
// ListSharesByOwnerProxy/ListSharesByUserProxy (server/http/handlers/
// misc_remote_proxy.go, which call Storage() directly, bypassing every
// other core-level share method) and the JIT-expiry scheduler's
// RemoveExpiredShares call (server/main.go).
func (c *KeyorixCore) ShareEffectiveNow() time.Time { return c.shareEffectiveNow() }

// EffectiveNow exposes this process's base injected clock (see the now
// field's "For testability" doc comment above) to callers outside package
// core that need a testable clock reading but have no dedicated watermarked
// variant of their own -- currently the dynamic-secrets sweep scheduler's
// RevokeExpiredLeases call (server/main.go), which passes the result as
// RevokeExpiredLeases' `before` parameter; that call now clamps it through
// dynamicSecretsSweepCutoff (dynamic_secrets.go), so a regressed reading
// here no longer shrinks the sweep window (FUZZ-MECH M2 finding, 2026-09-27,
// closed by the watermark checkLeaseRenewClockNotRegressed/
// dynamicSecretsSweepCutoff share).
func (c *KeyorixCore) EffectiveNow() time.Time { return c.now() }

// SetClockForTesting overrides the clock behind every time-based
// authorization/expiry decision this KeyorixCore makes directly (sessions,
// PATs, machine tokens, shares, dynamic secrets, MFA, impersonation) AND,
// transitively, federated JWT verification if an OIDCVerifier is already
// wired via SetOIDCVerifier — call SetOIDCVerifier first if both need to
// share one clock. Production code never calls this; it exists so a single
// call can drive every one of these decisions off one injected clock, which
// is what a clock-jump fuzz/test harness needs to assert that independent
// enforcement paths for the same logical decision agree (#1983). Default
// (unset) is time.Now.
func (c *KeyorixCore) SetClockForTesting(now func() time.Time) {
	c.now = now
	if c.oidcVerifier != nil {
		c.oidcVerifier.setClock(now)
	}
}

// SetWebhookURLValidator replaces the SSRF guard applied to notification channel
// URLs on create and update. The default (nil) uses validateWebhookURL which
// enforces https-only and rejects private/loopback destinations via a live DNS
// lookup. Tests call this with a no-op to avoid real network calls.
func (c *KeyorixCore) SetWebhookURLValidator(fn func(string) error) {
	c.webhookURLValidator = fn
}

// SetAuthEncryptor wires the encryption service used to protect reversibly-
// encrypted auth secrets (the TOTP MFA secret). The server calls this at startup
// when encryption is enabled. nil/disabled = passthrough. Accepts
// ports.EncryptionProvider (ADR-109 step 5) rather than the concrete
// *encryption.Service — server/main.go passes the real *encryption.Service,
// which satisfies this directly.
func (c *KeyorixCore) SetAuthEncryptor(s ports.EncryptionProvider) {
	c.authEncryptor = s
}

// SetSecretValueEncryptor wires the encryption service used to encrypt secret VALUES
// at rest (ADR-004 envelope encryption). The server calls this at startup when
// storage.encryption.enabled. Once wired, every new secret version is stored as
// AAD-bound ciphertext and reads fail closed on an unavailable key (see
// secret_value_crypto.go). nil = encryption disabled (plaintext at rest — dev/test).
// Accepts ports.EncryptionProvider (ADR-109 step 5), same as SetAuthEncryptor above.
func (c *KeyorixCore) SetSecretValueEncryptor(s ports.EncryptionProvider) {
	c.secretValueEncryptor = s
}

// SecretValueEncryptionActive reports whether secret values are being encrypted at
// rest — i.e. an initialised, enabled encryptor is wired. The server uses this to
// fail closed at startup when encryption is configured but did not actually engage.
func (c *KeyorixCore) SecretValueEncryptionActive() bool {
	return c.secretValueEncryptor != nil && c.secretValueEncryptor.IsEnabled() && c.secretValueEncryptor.IsInitialized()
}

// AuthEncryptionActive reports whether at-rest encryption for auth secrets (MFA
// TOTP seeds, dynamic-secret configs) is enabled -- the same condition
// BeginMFAEnrollment fails closed on. Exported for UpsertMFASecretProxy
// (server/http/handlers/mfa_management_proxy.go), which needs to refuse an
// MFA-secret write under the same condition without duplicating the
// authEncryptor field access.
func (c *KeyorixCore) AuthEncryptionActive() bool {
	return c.authEncryptor != nil && c.authEncryptor.IsEnabled()
}

// encryptAuthSecret reversibly encrypts plain, bound to aad (#94: MFASecretAAD /
// DynamicSecretConfigAAD / DynamicSecretLeaseAAD — never nil for a live caller, so a
// DB-write attacker cannot transplant one row's ciphertext onto another's identity and
// have it decrypt). Passthrough when encryption is off.
func (c *KeyorixCore) encryptAuthSecret(plain string, aad []byte) (ct, meta []byte, err error) {
	if c.authEncryptor == nil || !c.authEncryptor.IsEnabled() {
		return []byte(plain), nil, nil
	}
	return c.authEncryptor.EncryptSecretWithAAD([]byte(plain), aad)
}

// decryptAuthSecret reverses encryptAuthSecret. aad must be reconstructed from the
// row's own identity, identically to how it was encrypted. Falls back to a legacy
// nil-AAD decrypt for rows encrypted before #94 (Service.DecryptSecretWithAAD's own
// AADVersion branch — the same AAD-bound pattern secret_value_crypto.go applies to
// secret values); the sweep upgrades those rows to AAD-bound in place. Passthrough
// when encryption is off.
func (c *KeyorixCore) decryptAuthSecret(ct, _ []byte, aad []byte) (string, error) {
	if c.authEncryptor == nil || !c.authEncryptor.IsEnabled() {
		return string(ct), nil
	}
	plain, err := c.authEncryptor.DecryptSecretWithAAD(ct, aad)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// SetDynamicEngineFactory wires the dynamic-secrets engine factory (server
// startup: internal/dynamic.New via server/main.go's DefaultIntegrations;
// tests: a fake engine). nil (the default) leaves dynamic secrets unavailable
// — see dynamicEngine.
func (c *KeyorixCore) SetDynamicEngineFactory(f ports.DynamicBackendFactory) {
	c.dynamicEngineFactory = f
}

// SetDynamicSweepEnabled records whether the auto-revoke sweeper is running
// (config dynamic_secrets.sweep_enabled). Wired at startup so IssueLease can refuse
// to mint a credential from a backend whose TTL only the sweeper would enforce.
func (c *KeyorixCore) SetDynamicSweepEnabled(enabled bool) {
	c.dynamicSweepEnabled = enabled
}

// SetDynamicAllowPrivateTargets controls whether the admin-DSN SSRF guard is
// bypassed. When false (the default), CreateDynamicSecretConfig rejects DSNs
// whose host resolves to a private or link-local address. Set to true only when
// the dynamic-secret backend legitimately lives on a private segment.
func (c *KeyorixCore) SetDynamicAllowPrivateTargets(allow bool) {
	c.dynamicAllowPrivateTargets = allow
}

// SetDynamicAllowInsecureTransport controls whether the mongodb/redis
// backends' TLS-required-by-default guard is bypassed. When false (the
// default), connecting to either backend without TLS is refused. Set to true
// only when the dynamic-secret backend legitimately cannot use TLS (e.g. a
// legacy/internal deployment) — every connection made under this opt-out is
// logged (2d).
func (c *KeyorixCore) SetDynamicAllowInsecureTransport(allow bool) {
	c.dynamicAllowInsecureTransport = allow
}

// SetDynamicMaxLeaseTTL sets the install-wide dynamic-secret lease TTL ceiling
// (config dynamic_secrets.max_lease_ttl, #97). A non-positive value is ignored — the
// package default (90 days) applies instead of disabling the ceiling.
func (c *KeyorixCore) SetDynamicMaxLeaseTTL(ttl time.Duration) {
	if ttl > 0 {
		c.dynamicMaxLeaseTTL = ttl
	}
}

// dynamicEngine resolves an engine for a backend type via the wired factory.
// nil (no factory wired — SetDynamicEngineFactory was never called) means
// dynamic secrets are unavailable: fails closed rather than reaching for a
// concrete backend package internal/core does not import (ADR-109). In
// production, server/main.go's DefaultIntegrations always wires the real
// internal/dynamic.New-backed factory, threading c.dynamicAllowPrivateTargets/
// c.dynamicAllowInsecureTransport through it so an engine that dials the admin
// DSN itself (postgres, mysql) applies the SAME private/link-local dial-time
// guard (or the same explicit operator opt-out) enforceDynamicSecretSSRFGuard
// already applies at config create/issue/renew time (G48).
func (c *KeyorixCore) dynamicEngine(backendType string) (ports.DynamicBackendEngine, error) {
	if c.dynamicEngineFactory == nil {
		return nil, fmt.Errorf("dynamic secrets are unavailable: no engine factory configured")
	}
	return c.dynamicEngineFactory(backendType)
}

// SetTrustRegistryFunc overrides how the update/license signing-key trust registry
// is resolved (tests inject a failing lookup to exercise #145's degrade path).
func (c *KeyorixCore) SetTrustRegistryFunc(f func() (*trust.KeyRegistry, error)) {
	c.trustRegistry = f
}

// defaultTrustRegistry resolves the trust registry via the override (or the real
// trust.DefaultRegistry when none is set).
func (c *KeyorixCore) defaultTrustRegistry() (*trust.KeyRegistry, error) {
	if c.trustRegistry != nil {
		return c.trustRegistry()
	}
	return trust.DefaultRegistry()
}

// SetWebAuthn wires the WebAuthn relying party (ADR-036). The server calls this
// at startup when the install configures a webauthn block. nil disables passkeys.
func (c *KeyorixCore) SetWebAuthn(rp *webauthn.WebAuthn) {
	c.webauthnRP = rp
}

// WebAuthnEnabled reports whether passkey support is configured on this server.
func (c *KeyorixCore) WebAuthnEnabled() bool { return c.webauthnRP != nil }

// SetPasswordPolicy overrides the password policy (which defaults to
// DefaultPasswordPolicy). The server calls this at startup when the install
// configures a password_policy block.
func (c *KeyorixCore) SetPasswordPolicy(p PasswordPolicy) {
	c.passwordPolicy = p
}

// SetAuditHighWaterWitnessPath sets where advanceAuditHighWater
// (audit_checkpoint.go) mirrors the audit high-water mark it persists —
// design-b3-backup-v2.md §6.3's rollback-protection witness file. The server
// calls this at startup with auditverify.WitnessPath(dbPath) for a
// local/sqlite deployment (the only backend `admin backup`/`admin restore`
// support); leaving it unset (empty string) disables witness maintenance
// entirely, e.g. for Postgres deployments or a test core with no real
// database file.
func (c *KeyorixCore) SetAuditHighWaterWitnessPath(path string) {
	c.auditHighWaterWitnessPath = path
}

// SetBootstrapToken sets the token that POST /system/init must present to seed the
// first admin. An empty token disables API bootstrap entirely (fail closed). The
// server wires this at startup; see BootstrapSystem.
func (c *KeyorixCore) SetBootstrapToken(token string) {
	c.bootstrapToken = token
}

// SetSecretValuePolicy enables/configures the secret-value quality gate (off by
// default). The server calls this at startup when secret_value_policy.enabled is set.
func (c *KeyorixCore) SetSecretValuePolicy(p SecretValuePolicy) {
	c.secretValuePolicy = p
}

// SetSecretNamePolicy enables/configures the secret naming convention (off by
// default). The server calls this at startup when secret_name_policy.enabled is set.
// Returns an error (and leaves the policy disabled) if Pattern is not a valid regex.
func (c *KeyorixCore) SetSecretNamePolicy(p SecretNamePolicy) error {
	re, err := compileNamePattern(p.Pattern)
	if err != nil {
		return err
	}
	c.secretNamePolicy = p
	c.secretNameRe = re
	return nil
}

// SetLoginLockoutPolicy enables/configures per-account login lockout. The server
// calls this at startup when security.login_lockout is enabled; left unset, lockout
// is disabled (Enabled=false).
func (c *KeyorixCore) SetLoginLockoutPolicy(p LoginLockoutPolicy) {
	c.loginLockout = p
}

// SetSetupTokenTTL overrides the setup-token lifetime (ADR-028). The server calls
// this at startup from credential_delivery.setup_token_ttl. A non-positive value
// falls back to DefaultSetupTokenTTL.
func (c *KeyorixCore) SetSetupTokenTTL(ttl time.Duration) {
	c.setupTokenTTL = ttl
}

// SetSessionTTLs configures the short-lived-token lifetimes. access is the
// access-token window (refresh extends by this); absolute is the hard ceiling on
// total session lifetime (0 = no ceiling). The server calls this at startup from
// the session config block. A non-positive access falls back to the 24h default.
func (c *KeyorixCore) SetSessionTTLs(access, absolute time.Duration) {
	c.sessionAccessTTL = access
	c.sessionAbsoluteTTL = absolute
}

// Storage returns the underlying storage interface (used by ancillary services such as AnomalyDetector).
func (c *KeyorixCore) Storage() storage.Storage {
	return c.storage
}

// ListActiveSecrets returns all secrets for anomaly detection. Returns empty slice on error.
func (c *KeyorixCore) ListActiveSecrets(ctx context.Context) []models.SecretNode {
	secrets, _, err := c.ListSecrets(ctx, nil)
	if err != nil || secrets == nil {
		return nil
	}
	result := make([]models.SecretNode, 0, len(secrets))
	for _, s := range secrets {
		if s != nil {
			result = append(result, *s)
		}
	}
	return result
}

// HealthCheck checks the health of the core service and its dependencies.
func (c *KeyorixCore) HealthCheck(ctx context.Context) error {
	if c.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	return c.storage.HealthCheck(ctx)
}

// ResolveUsernames maps UserID → username for a slice of audit events.
// Nil UserIDs (system events) map to key 0 → "system".
func (c *KeyorixCore) ResolveUsernames(ctx context.Context, events []*models.AuditEvent) map[uint]string { // nosemgrep: keyorix-unbounded-bulk-slice-param -- events is an already-paginated audit-log query result, not a raw client-supplied array; the per-item DB round trip below is over the deduped user-id set, not events itself
	seen := map[uint]bool{}
	for _, e := range events {
		if e.UserID != nil {
			seen[*e.UserID] = true
		}
		// Resolve impersonation actors too, so audit rows can show a human-readable
		// name on every impersonated event rather than an opaque ID.
		if e.ImpersonatedBy != nil {
			seen[*e.ImpersonatedBy] = true
		}
		if e.ActingAs != nil {
			seen[*e.ActingAs] = true
		}
	}
	byID := map[uint]string{0: "system"}
	for uid := range seen {
		if user, err := c.storage.GetUser(ctx, uid); err == nil && user != nil {
			byID[uid] = user.Username
		} else {
			byID[uid] = "unknown"
		}
	}
	return byID
}
