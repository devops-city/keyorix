package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	hdrContentType = "Content-Type"
	mimeJSON       = "application/json"
)

// sessionValidator is the subset of *core.KeyorixCore that the auth middleware
// needs. Defined here (not in core) so tests can supply a fake validator without
// constructing a full core service. *core.KeyorixCore satisfies this implicitly.
//
// Two token kinds resolve to an identical UserContext: opaque session tokens and
// personal access tokens (PATs, prefixed patTokenPrefix). validateToken routes by
// prefix; either path produces the same identity, so the token cache and all
// downstream per-scope authorization work unchanged.
type sessionValidator interface {
	ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error)
	ValidatePATToken(ctx context.Context, token string) (*models.User, []string, *core.PATRestriction, uint, error)
	ValidateMachineToken(ctx context.Context, token string) (*models.MachineIdentity, []string, *core.MachineTokenRestriction, uint, error)
	ValidateOIDCToken(ctx context.Context, token string) (*models.MachineIdentity, []string, error)
	OIDCEnabled() bool
}

// patTokenPrefix marks a personal access token (kept in sync with core.patPrefix).
const patTokenPrefix = "kx_pat_"
const machineTokenPrefix = "kx_machine_"

// UserContext represents the authenticated user context. It carries identity
// only — authorization is resolved per-request against the target scope by
// core.Authorize, not from a precomputed permission list.
type UserContext struct {
	UserID   uint     `json:"user_id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	// ImpersonatedBy is the initiating admin's ID when this is an impersonation
	// session (nil otherwise). Cached with the rest of the identity, so a single
	// per-token lookup decides it. Used to tag downstream audit events.
	ImpersonatedBy *uint `json:"impersonated_by,omitempty"`
	// SessionID is the authenticating session's own row id (nil unless
	// SessionAuth is true) — mirrors the gRPC UserContext's identically-named,
	// identically-purposed field (server/grpc/interceptors/auth.go, #G18). Set on
	// the slow path from the validated session (for an impersonation token, this
	// IS the impersonation session's own row — GetSession resolves whatever
	// session the presented token actually belongs to, impersonation or not, so
	// no separate case is needed). Used by serveAuthCacheHit's session branch
	// (core.SessionLiveForToken) to re-verify THIS SPECIFIC session is still live
	// on every cache hit, not just the owning account.
	SessionID *uint `json:"-"`
	// AccountState is the ADR-025 lifecycle state; Restricted is true when the
	// account must change its password before using non-allowlisted endpoints.
	AccountState string `json:"account_state,omitempty"`
	Restricted   bool   `json:"-"`
	// MachineIdentityID is set (and UserID is 0) when the request authenticated
	// with a machine token (ADR-030). ActorType is "machine_identity" for such
	// requests and "user" otherwise.
	MachineIdentityID *uint  `json:"machine_identity_id,omitempty"`
	ActorType         string `json:"actor_type,omitempty"`
	// MachineIdentityType is the machine identity's IdentityType (ci|k8s|service|
	// automation|other|node), empty for a non-machine principal. #G79:
	// RequireNodeCredential (node_credential.go) checks this equals
	// core.MachineTypeNode -- a credential class, not an RBAC permission, so a
	// principal can never be granted node status via a role -- though that
	// middleware has never actually gated any real route (see its own doc); the
	// RemoteStorage-sync proxy tree it was built for is deleted.
	MachineIdentityType string `json:"-"`
	// MFAEnabled is true when the user has any second factor enabled (TOTP or a
	// passkey); SessionAuth is true only for an interactive session token (false for
	// PAT / machine / OIDC). Together they drive EnforceAccountSetup's MFA step,
	// which must not confine non-interactive automation.
	MFAEnabled  bool `json:"-"`
	SessionAuth bool `json:"-"`
	// SetupOnly is the authenticating session's models.Session.SetupOnly (#3024):
	// a session that may only finish account setup, never become a full session.
	// Read on the slow path with SessionID and cached with the identity (it never
	// changes for a session row). Drives EnforceAccountSetup.
	SetupOnly bool `json:"-"`
	// PATRestriction is the least-privilege filter a personal access token imposes
	// (ADR-042), or nil for sessions / unrestricted PATs. Cached with the rest of
	// the identity and tagged onto the request context by buildRequestContext so
	// core.Authorize enforces it at the single authorization chokepoint.
	PATRestriction *core.PATRestriction `json:"-"`
	// MachineTokenRestriction carries the network-level IP allowlist for a machine
	// token credential, or nil when none is set. Enforced at the auth boundary.
	MachineTokenRestriction *core.MachineTokenRestriction `json:"-"`
	// patID is the validated PAT's row id (0 for a non-PAT principal). #G60: kept
	// unexported/uncached-in-JSON, used only by handleAuthRequest to stamp
	// last_used_at via TouchPATLastUsed AFTER tokenNetworkAllowed has passed for
	// this specific request — never touched on a cache hit (serveAuthCacheHit
	// deliberately never re-stamps, matching pre-existing behavior).
	patID uint `json:"-"`
	// machineCredID is the validated machine credential's row id (0 for a
	// non-machine principal) — the machine-token sibling of patID, same #G60
	// rationale and same handleAuthRequest post-check touch.
	machineCredID uint `json:"-"`
}

// cloneUserContextWithRestriction returns a shallow copy of base with
// PATRestriction replaced (#146) — used on a cache hit to apply a freshly
// re-fetched restriction without mutating the shared cached entry (other
// concurrent requests hitting the same cache entry must not see this one
// request's snapshot).
func cloneUserContextWithRestriction(base *UserContext, restriction *core.PATRestriction) *UserContext {
	clone := *base
	clone.PATRestriction = restriction
	return &clone
}

// cloneUserContextWithMachineRestriction is cloneUserContextWithRestriction's
// machine-token counterpart (#G18) — a cache hit must refresh
// MachineTokenRestriction the same way it already refreshes a PAT's.
func cloneUserContextWithMachineRestriction(base *UserContext, restriction *core.MachineTokenRestriction) *UserContext {
	clone := *base
	clone.MachineTokenRestriction = restriction
	return &clone
}

// cloneUserContextWithAccountState is the session cache-hit path's counterpart
// to cloneUserContextWithRestriction/cloneUserContextWithMachineRestriction:
// refreshes AccountState/Restricted from a freshly-read state on a shallow
// copy, never mutating the shared cached entry in place (another concurrent
// request may be reading the same *UserContext pointer out of tokenCache at
// the same instant). Mirrors handleAuthRequest's own slow-path normalization
// exactly (core.NormalizeAccountState / core.AccountRestricted).
func cloneUserContextWithAccountState(base *UserContext, state string) *UserContext {
	clone := *base
	clone.AccountState = core.NormalizeAccountState(state)
	clone.Restricted = core.AccountRestricted(state)
	return &clone
}

// ActorKind returns the principal's actor type ("user" or "machine_identity"),
// defaulting to user for legacy/empty contexts.
func (u *UserContext) ActorKind() string {
	if u.ActorType == core.ActorTypeMachine {
		return core.ActorTypeMachine
	}
	return core.ActorTypeUser
}

// PrincipalID returns the id to authorize against: the machine identity id for a
// machine request, otherwise the user id.
func (u *UserContext) PrincipalID() uint {
	if u.MachineIdentityID != nil {
		return *u.MachineIdentityID
	}
	return u.UserID
}

// contextKey is used for context keys to avoid collisions
type contextKey string

const (
	userContextKey        contextKey = "user"
	coreServiceContextKey contextKey = "coreService"
	// resolvedSecretRefContextKey carries the *models.SecretNode resolved by
	// RequireScopedSecretRefPermission through to the handler, so a by-ref
	// value read reuses that ONE resolution instead of resolving the ref by
	// name a second time. See WithResolvedSecretRef / GetResolvedSecretRefFromContext.
	resolvedSecretRefContextKey contextKey = "resolvedSecretRef"
	// resolvedSecretContextKey is resolvedSecretRefContextKey's by-ID sibling
	// (SESSION-PERF, #2403 follow-up): carries the *models.SecretNode
	// RequireScopedSecretPermission already fetched to compute the authorization
	// scope, so GetSecret's machine branch reuses that ONE resolution instead of
	// fetching the same row again (and so does getSecretValueForUser downstream
	// — see GetSecretValueResolved). See WithResolvedSecret / GetResolvedSecretFromContext.
	resolvedSecretContextKey contextKey = "resolvedSecret"

	// TTL for valid token cache entries (session is trusted for this window).
	validTokenTTL = 30 * time.Second
	// TTL for negative cache entries (stale/invalid tokens — MCP storm fix).
	// Short enough that a legitimately re-issued token works after ~10s.
	invalidTokenTTL = 10 * time.Second
	// maxTokenCacheEntries caps the cache so an unauthenticated flood of distinct garbage
	// bearer tokens (each negative-cached) cannot grow the map without bound and exhaust
	// process memory. Beyond the cap, arbitrary entries are evicted; a cache miss just
	// falls back to the DB.
	maxTokenCacheEntries = 50_000
)

// tokenCacheEntry holds a cached auth result.
type tokenCacheEntry struct {
	userCtx   *UserContext // nil for negative entries
	expiresAt time.Time
	// revokedAt marks a tombstone written by an explicit eviction (revoke/logout/suspend).
	// It lets a positive write that was already in flight when the revoke landed know it
	// must NOT resurrect the entry (see cacheSetValidated).
	revokedAt time.Time
	// machineGen is machineCacheGen at the time a positive machine entry was
	// validated. An entry from an older generation is a miss (see cacheGet).
	machineGen uint64
}

// tokenCache is a process-wide cache keyed by SHA-256(token).
// Prevents repeated DB hits from stale MCP tokens after server restart.
var (
	tokenCacheMu sync.Mutex
	tokenCache   = map[string]tokenCacheEntry{}
	lastPurge    = time.Now()
	// machineCacheGen is bumped by InvalidateAllMachineTokenCache. Positive
	// machine entries validated under an older generation are treated as
	// misses, and a slow-path validation that began before a bump never
	// caches its result. Guarded by tokenCacheMu.
	machineCacheGen uint64
	// clearedAt records, per key, the moment ClearTokenCacheIfCached last ran
	// for it -- independent of tokenCache itself, which cacheGet's own
	// read-time expiry/prune logic deletes from on its very next read (a
	// `tokenCacheEntry` marker, however short-lived, does not survive long
	// enough to guard anything). cacheSetValidatedGen checks this map the
	// same way it checks an entry's own revokedAt: a slow-path validation
	// whose validatedAt predates the recorded clear must not resurrect the
	// stale permissions it read. Entries are pruned after validTokenTTL (see
	// pruneLocked) -- a safe upper bound on how long any single slow-path
	// validation can still be in flight, same bound #2423's own PR comment
	// uses.
	clearedAt = map[string]time.Time{}
)

// currentMachineCacheGen returns the machine-cache generation. The slow path
// captures it together with validatedAt, before its DB read.
func currentMachineCacheGen() uint64 {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	return machineCacheGen
}

func isMachineEntry(u *UserContext) bool {
	return u != nil && u.ActorType == core.ActorTypeMachine
}

// tokenKey returns a safe cache key (SHA-256 hex of the raw token).
func tokenKey(token string) string {
	// codeql[go/weak-sensitive-data-hashing] -- token is a high-entropy random
	// bearer token (session/PAT/machine), not a password; this is a cache-key
	// derivation, not credential storage, so a slow KDF is not warranted.
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

// cacheGet returns (entry, found). Caller must hold no lock — acquires internally.
func cacheGet(key string) (tokenCacheEntry, bool) {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	e, ok := tokenCache[key]
	if !ok {
		return tokenCacheEntry{}, false
	}
	if time.Now().After(e.expiresAt) {
		delete(tokenCache, key)
		return tokenCacheEntry{}, false
	}
	if isMachineEntry(e.userCtx) && e.machineGen != machineCacheGen {
		delete(tokenCache, key)
		return tokenCacheEntry{}, false
	}
	return e, true
}

// cacheSet stores an entry. Caller must hold no lock.
func cacheSet(key string, entry tokenCacheEntry) {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	tokenCache[key] = entry
	pruneLocked()
}

// cacheSetValidated stores a POSITIVE entry from the slow path, but refuses to resurrect a
// token that was revoked WHILE this validation was in flight: if a tombstone for the key
// was written after validatedAt (the moment the slow path began, before its DB read), the
// revoke wins and the positive entry is dropped. Closes the revocation-resurrection race.
func cacheSetValidated(key string, userCtx *UserContext, validatedAt time.Time, expiresAt time.Time) {
	cacheSetValidatedGen(key, userCtx, validatedAt, currentMachineCacheGen(), expiresAt)
}

// cacheSetValidatedGen is cacheSetValidated with the machine-cache generation
// captured when validation began. A machine entry is dropped if
// InvalidateAllMachineTokenCache ran since then: its DB read may predate a
// revoke that the flush was standing in for, and no per-key tombstone exists
// for a key that wasn't cached at flush time.
func cacheSetValidatedGen(key string, userCtx *UserContext, validatedAt time.Time, gen uint64, expiresAt time.Time) {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	if existing, ok := tokenCache[key]; ok && existing.revokedAt.After(validatedAt) {
		return // revoked during our validation — do not re-cache the now-stale positive
	}
	if ca, ok := clearedAt[key]; ok && ca.After(validatedAt) {
		return // cleared (ClearTokenCacheIfCached) during our validation — same refusal,
		// via the separate clearedAt map since a clear's own tokenCache marker (if any)
		// does not survive an intervening cacheGet long enough to check here directly.
	}
	entry := tokenCacheEntry{userCtx: userCtx, expiresAt: expiresAt}
	if isMachineEntry(userCtx) {
		if gen != machineCacheGen {
			return // machine cache flushed during our validation
		}
		entry.machineGen = gen
	}
	tokenCache[key] = entry
	pruneLocked()
}

// clampCacheExpiry returns the earlier of base (the normal validTokenTTL window) and
// sessionExpiry when sessionExpiry is non-nil and sooner — so a session's positive
// auth-cache entry can never outlive the session itself (F-TOK-1). A nil sessionExpiry
// (a non-session token, or a session with no expiry set) leaves base unchanged.
func clampCacheExpiry(base time.Time, sessionExpiry *time.Time) time.Time {
	if sessionExpiry != nil && sessionExpiry.Before(base) {
		return *sessionExpiry
	}
	return base
}

// pruneLocked drops expired entries (at most once per minute) and hard-caps the cache so
// a flood of distinct bearers can't grow it unbounded. Caller MUST hold tokenCacheMu.
func pruneLocked() {
	now := time.Now()
	if time.Since(lastPurge) > time.Minute {
		for k, v := range tokenCache {
			if now.After(v.expiresAt) {
				delete(tokenCache, k)
			}
		}
		// clearedAt entries older than validTokenTTL have outlived any slow-path
		// validation that could still be racing them (see cacheSetValidatedGen) --
		// safe to drop on the same timed cadence as tokenCache itself.
		for k, ca := range clearedAt {
			if now.After(ca.Add(validTokenTTL)) {
				delete(clearedAt, k)
			}
		}
		lastPurge = now
	}
	// Hard cap independent of the timed purge: evict arbitrary entries (map iteration is
	// randomized) until back under the cap. A dropped entry is just a future cache miss.
	for len(tokenCache) > maxTokenCacheEntries {
		for k := range tokenCache {
			delete(tokenCache, k)
			if len(tokenCache) <= maxTokenCacheEntries {
				break
			}
		}
	}
}

// Authentication returns a middleware that validates session tokens against the database,
// with a short-circuit cache to absorb stale-token storms (e.g. MCP client retry bursts).
func Authentication(coreService *core.KeyorixCore) func(next http.Handler) http.Handler {
	return authenticationWithValidator(coreService, coreService)
}

// authenticationWithValidator is the test seam: it accepts a sessionValidator for
// validating tokens (so tests can inject a fake) and a separate *core.KeyorixCore
// to store in the request context for downstream handlers.
func authenticationWithValidator(validator sessionValidator, coreService *core.KeyorixCore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleAuthRequest(next, w, r, validator, coreService)
		})
	}
}

func handleAuthRequest(next http.Handler, w http.ResponseWriter, r *http.Request, validator sessionValidator, coreService *core.KeyorixCore) {
	token, err := extractRequestToken(r)
	if err != nil {
		unauthorizedResponse(w, err.Error())
		return
	}

	key := tokenKey(token)

	// Fast path: cache hit.
	if entry, ok := cacheGet(key); ok {
		serveAuthCacheHit(next, w, r, token, entry, coreService)
		return
	}

	// Slow path: DB lookup. Capture the start time BEFORE the DB read so a
	// concurrent revoke landing during validation is recognized as "after" us and
	// can't be resurrected by our positive cache write (see cacheSetValidated).
	validatedAt := time.Now()
	validatedGen := currentMachineCacheGen()
	userCtx, err := validateToken(r.Context(), validator, token)
	if err != nil {
		// #G-transient: a TRANSIENT infrastructure failure (DB timeout, connection
		// error, context deadline exceeded during the underlying lookup) says
		// nothing about whether this token/credential is actually valid — it must
		// not be treated the same as a genuinely bad token. validateToken's
		// underlying validators (ValidateSessionToken/ValidatePATToken/
		// ValidateMachineToken/ValidateOIDCToken) collapse every storage error into
		// an opaque message before it reaches here (deliberately — the detailed
		// reason must never leak to an unauthenticated caller), so the request's
		// OWN context is the only reliable transient-vs-permanent signal available
		// at this layer: if it was canceled or hit its deadline while validation
		// was in flight, that — not credential invalidity — is almost certainly
		// why validation failed. See isTransientValidationError.
		if isTransientValidationError(r.Context(), err) {
			// Do NOT negative-cache: a stale "invalid" entry would keep rejecting
			// this same token for up to invalidTokenTTL even after the backend
			// recovers. Do NOT count against the per-IP brute-force budget either:
			// many legitimate callers sharing one NAT/egress IP retrying during a
			// shared blip would otherwise trip tokenAuthFailureBurst and start
			// getting 429'd once the backend is already healthy again.
			serviceUnavailableResponse(w, "authentication temporarily unavailable, please retry")
			return
		}
		// Cache the negative result so subsequent retries skip the DB.
		cacheSet(key, tokenCacheEntry{userCtx: nil, expiresAt: time.Now().Add(invalidTokenTTL)})
		// Rate-limit by source IP: after tokenAuthFailureBurst failures the IP is
		// throttled at 1 failure/s to mitigate token brute-forcing (PAT-003).
		if !recordTokenAuthFailure(hostOnly(r.RemoteAddr)) {
			tooManyRequestsResponse(w, "too many invalid token attempts")
			return
		}
		unauthorizedResponse(w, "Invalid or expired token")
		return
	}

	// Session tokens (not PAT / machine / OIDC-JWT — same prefix check as
	// impersonation resolution below) get extra slow-path handling.
	isSessionToken := coreService != nil && !strings.HasPrefix(token, patTokenPrefix) && !strings.HasPrefix(token, machineTokenPrefix) && !looksLikeJWT(token)

	// Session tokens: every per-session fact (impersonation, the row id for
	// #G18's cache-hit liveness re-check, the #3024 setup-only flag, the F-TOK-1
	// expiry clamp) comes from ONE read of the session row, resolved on the slow
	// path and cached with the identity. Fail closed if that read fails (#3041
	// review): each fact restricts the caller, so defaulting them (not
	// impersonating, not setup-only, no expiry clamp) and caching the result
	// would serve a setup-only session racing its own revocation with full
	// access. Like a transient validation failure: 503, nothing cached, no strike
	// against the IP's brute-force budget; core logs and audits the refusal.
	cacheExpiry := time.Now().Add(validTokenTTL)
	if isSessionToken {
		facts, err := coreService.ResolveSessionAuthFacts(r.Context(), userCtx.UserID, token, "http")
		if err != nil {
			serviceUnavailableResponse(w, "authentication temporarily unavailable, please retry")
			return
		}
		id := facts.SessionID
		userCtx.SessionID = &id
		userCtx.SetupOnly = facts.SetupOnly
		userCtx.ImpersonatedBy = facts.ImpersonatedBy
		// F-TOK-1: clamp the positive cache entry to the session's own expiry. The
		// session cache-hit branch (serveAuthCacheHit) re-checks only account state
		// and liveness, NOT the session's ExpiresAt/AbsoluteExpiresAt, so without the
		// clamp an expired session would keep authenticating on cache hits for the
		// rest of validTokenTTL. (2026-09-14 review.)
		cacheExpiry = clampCacheExpiry(cacheExpiry, facts.EffectiveExpiry)
	}

	// Cache the positive result (race-safe: dropped if revoked mid-validation).
	cacheSetValidatedGen(key, userCtx, validatedAt, validatedGen, cacheExpiry)

	if !tokenNetworkAllowed(r, userCtx) {
		forbiddenResponse(w, "token not permitted from this network")
		return
	}
	// #G60: stamp last_used_at only now that the token's network restriction has
	// actually been evaluated and passed — touching earlier (formerly done
	// unconditionally inside ValidatePATToken/ValidateMachineToken) would mark a
	// credential as "used" even for a request just rejected above for arriving
	// from a disallowed network. Each Touch* is a no-op when its id is 0 (i.e.
	// the principal is not that credential kind).
	if coreService != nil {
		coreService.TouchPATLastUsed(r.Context(), userCtx.patID)
		coreService.TouchMachineTokenLastUsed(r.Context(), userCtx.machineCredID)
	}
	next.ServeHTTP(w, r.WithContext(buildRequestContext(r.Context(), userCtx, coreService)))
}

// isTransientValidationError reports whether a validateToken failure reflects a
// transient infrastructure problem (the caller's context was canceled or hit its
// deadline while validation was in flight) rather than the credential itself
// being invalid. ctx is checked directly — not just err — because the storage
// layer's own errors are deliberately opaque by the time they reach this
// package (ValidateSessionToken/ValidatePATToken/ValidateMachineToken collapse
// every lookup failure, including a DB timeout or connection error, into a
// generic message so the specific reason never leaks to an unauthenticated
// caller). A context that was canceled or ran out of time during that lookup is
// therefore the one reliable signal available here that the failure was ours
// (or the client's, disconnecting mid-request), not the token's. errors.Is is
// still checked against err too, in case a future/alternate validator
// implementation does propagate a wrapped context error.
func isTransientValidationError(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	// #1944: the credential validated but the owner's roles could not be read
	// — a storage-side failure, not a verdict on the token.
	if errors.Is(err, core.ErrRoleResolutionUnavailable) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// serveAuthCacheHit handles the fast-path cache hit. #146 originally re-fetched
// only the PAT network restriction on every request; #G18 generalizes that
// pattern to every revocation-relevant field the positive cache can go stale
// on, not just the one that happened to get patched: a PAT's Revoked/ExpiresAt
// (CurrentPATRestriction), a machine token's restriction/Revoked/ExpiresAt/
// machine-active-state (CurrentMachineTokenRestriction, previously refreshed
// for a PAT but never for a machine token), and — for an interactive session —
// all of: the owning account's active/not-blocked state
// (AccountUsabilityAndState's usable boolean, née AccountStillUsable's job);
// its CURRENT AccountState/Restricted, refreshed onto a cloned UserContext on
// every hit (AccountUsabilityAndState's state return,
// cloneUserContextWithAccountState) so a transition into a
// restricted-but-not-blocked state (pending_first_login/password_reset_required
// — AccountRestricted and AccountLoginBlocked are NOT the same predicate, see
// AccountRestricted's doc comment) is visible to EnforceAccountSetup
// immediately, not only once that state-change's own cache eviction lands;
// and, as of the session-revoke-cache-race fix
// (docs/findings/2026-09-20-FINDING-session-revoke-cache-race.md), whether the
// SPECIFIC session row is still live (SessionLiveForToken): a session can be
// revoked (RevokeUserSessions, the /system proxy's DeleteSessionsForUserExcept,
// ChangePassword, MFA/WebAuthn enrollment changes, a setup-link password reset)
// without the owning account's IsActive/AccountState ever changing, which the
// usability check alone cannot see. Each of these was previously invisible to
// a cache HIT and kept serving the stale cached snapshot for up to
// validTokenTTL after an admin's suspend/revoke/restrict (or a session-specific
// revocation) should have taken effect immediately, matching every other
// credential-state check in this file. A DEFINITIVE revocation signal
// (revoked/expired/inactive/session-gone) denies the request and evicts the
// cache entry outright; an INDETERMINATE one (a transient storage error)
// degrades to the cached snapshot rather than fail-opening or fail-closing on
// a blip — same philosophy #146 established. See SessionLiveForToken's own
// doc comment for why "storage.type: remote has no GetSessionByID" is not a
// live deployment concern here (ADR-083).
func serveAuthCacheHit(next http.Handler, w http.ResponseWriter, r *http.Request, token string, entry tokenCacheEntry, coreService *core.KeyorixCore) {
	if entry.userCtx == nil {
		// Negative cache — known bad token, skip DB entirely.
		unauthorizedResponse(w, "Invalid or expired token")
		return
	}
	effective := entry.userCtx
	if coreService != nil {
		switch {
		case strings.HasPrefix(token, patTokenPrefix):
			fresh, err := coreService.CurrentPATRestriction(r.Context(), token)
			switch {
			case errors.Is(err, core.ErrPATRevoked) || errors.Is(err, core.ErrPATExpired):
				denyRevokedCacheHit(w, token)
				return
			case err == nil:
				effective = cloneUserContextWithRestriction(entry.userCtx, fresh)
			}
		case strings.HasPrefix(token, machineTokenPrefix):
			fresh, err := coreService.CurrentMachineTokenRestriction(r.Context(), token)
			switch {
			// #2518: ErrMachineIdentityNotActive belongs with the other two.
			// CurrentMachineTokenRestriction's doc comment always listed a
			// no-longer-active owning identity as a signal to deny rather than
			// degrade past, but it returned a bare fmt.Errorf, so this branch
			// could not see it and a suspended machine identity's token kept
			// authenticating for up to validTokenTTL on every replica other
			// than the one that ran the suspension (only that one flushes the
			// cache, via SetMachineTokenCacheFlusher). Suspension is the
			// incident-response control for a machine identity; "effective in
			// 30s, on one replica" is not what it promises.
			case errors.Is(err, core.ErrMachineTokenRevoked) ||
				errors.Is(err, core.ErrMachineTokenExpired) ||
				errors.Is(err, core.ErrMachineIdentityNotActive):
				denyRevokedCacheHit(w, token)
				return
			case err == nil:
				effective = cloneUserContextWithMachineRestriction(entry.userCtx, fresh)
			}
		default:
			if usable, state, err := coreService.AccountUsabilityAndState(r.Context(), entry.userCtx.UserID); err == nil {
				if !usable {
					denyRevokedCacheHit(w, token)
					return
				}
				// Refresh AccountState/Restricted from this SAME fresh read on every
				// hit, not just the outright-deny boolean — a transition into a
				// restricted-but-not-login-blocked state (pending_first_login /
				// password_reset_required) must not keep serving the pre-transition
				// Restricted=false on a cache hit. See AccountUsabilityAndState's doc
				// comment for why this is the same race shape SessionLiveForToken
				// closes, not just a bounded-TTL lag.
				effective = cloneUserContextWithAccountState(entry.userCtx, state)
			}
			// entry.userCtx.SessionID is nil for a cache entry filled before this
			// check existed (a rolling deploy) or when the slow-path secondary
			// lookup itself failed (see handleAuthRequest's #G18 comment) — skip
			// rather than deny, which is exactly pre-fix behavior for that entry,
			// not a new failure mode.
			if entry.userCtx.SessionID != nil {
				if live, err := coreService.SessionLiveForToken(r.Context(), *entry.userCtx.SessionID, token); err == nil && !live {
					denyRevokedCacheHit(w, token)
					return
				}
			}
		}
	}
	// The network allowlist is per-request (the same token may arrive from a
	// different IP), so enforce it even on a cache hit — using effective, which
	// by this point carries whichever restriction was freshly refreshed above.
	if !tokenNetworkAllowed(r, effective) {
		forbiddenResponse(w, "token not permitted from this network")
		return
	}
	next.ServeHTTP(w, r.WithContext(buildRequestContext(r.Context(), effective, coreService)))
}

// denyRevokedCacheHit rejects a cache-hit request whose credential was
// determined to have been revoked/expired/deactivated since the cache entry
// was written, and evicts the entry so subsequent requests skip straight to
// the negative cache instead of re-discovering this on every request for the
// rest of the TTL window.
func denyRevokedCacheHit(w http.ResponseWriter, token string) {
	InvalidateTokenCacheByHash(tokenKey(token))
	unauthorizedResponse(w, "Invalid or expired token")
}

// extractRequestToken returns the token to validate for this request, preferring
// the httpOnly session cookie over the legacy Authorization: Bearer header when
// both are present — this makes the cookie authoritative once a client has one,
// so a stale/leaked Bearer header value can't override it. PAT (kx_pat_)/machine
// (kx_machine_) tokens and OIDC JWTs are never delivered via cookie — only
// session tokens are, from Login/RefreshToken/SSO — so this doesn't change how
// those are validated once extracted; it only changes where a session token can
// come from.
func extractRequestToken(r *http.Request) (string, error) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}

	if parts[1] == "" {
		return "", errors.New("missing token")
	}
	return parts[1], nil
}

// errInvalidTarget / errTargetNotFound let scope resolvers signal whether a bad
// target should surface as 400 (unparseable) or 404 (no such resource).
var (
	errInvalidTarget  = errors.New("invalid target")
	errTargetNotFound = errors.New("target not found")
)

// ScopeResolver derives the project/environment a request acts on. It may load
// the target resource (e.g. a secret) via the core service to find its scope.
type ScopeResolver func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error)

// RequireScopedPermission returns middleware that authorizes the request: it
// resolves the target scope, then asks core.Authorize whether the user holds
// permission there. Denials are 403, an unparseable target is 400, and a
// missing target resource is 404.
func RequireScopedPermission(permission string, resolve ScopeResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleScopedPermissionRequest(next, w, r, permission, resolve)
		})
	}
}

func handleScopedPermissionRequest(next http.Handler, w http.ResponseWriter, r *http.Request, permission string, resolve ScopeResolver) {
	userCtx, cs, ok := requireUserAndCore(w, r)
	if !ok {
		return
	}
	scope, err := resolve(r, cs)
	if err != nil {
		handleScopeResolutionError(w, r, cs, userCtx, permission, err)
		return
	}
	allowed, err := cs.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permission, scope)
	finishScopedPermissionRequest(next, w, r, cs, scope, allowed, err)
}

// RequireScopedSecretPermission is RequireScopedPermission specialized for the
// per-secret routes (GET/PUT/PATCH/DELETE .../secrets/{id}[/...]): it resolves
// scope from the secret named by idParam exactly like ScopeFromSecretParam (same
// 400/404 behavior), but the final authorization check also consults per-secret
// SecretACL grants (RBAC Phase 3) via core.AuthorizeSecretPrincipal — so a caller
// who holds NO project-scope role but was explicitly granted the permission on
// this one secret (or an ancestor folder, via HasSecretACL's inheritance walk) is
// let through, closing the gap where SecretACL was honored by ListSecrets but
// dead on arrival for every per-secret GET/write route. ACL grants remain
// strictly additive: AuthorizeSecretPrincipal still falls back to the existing
// role-based check, so a caller with neither a role nor a covering grant is
// denied exactly as before. Machine/OIDC principals are unaffected — SecretACL
// rows are user-scoped, so AuthorizeSecretPrincipal skips the ACL lookup for them
// and takes the same role-based path as always.
func RequireScopedSecretPermission(permission, idParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleScopedSecretPermissionRequest(next, w, r, permission, idParam)
		})
	}
}

func handleScopedSecretPermissionRequest(next http.Handler, w http.ResponseWriter, r *http.Request, permission, idParam string) {
	userCtx, cs, ok := requireUserAndCore(w, r)
	if !ok {
		return
	}
	secretID, err := scopePathUint(r, idParam)
	if err != nil {
		badRequestResponse(w, "Invalid target")
		return
	}
	secret, err := cs.Storage().GetSecret(r.Context(), secretID)
	if err != nil {
		handleScopeResolutionError(w, r, cs, userCtx, permission, errTargetNotFound)
		return
	}
	scope := core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	// Pin this ONE resolution on the request context before dispatch, regardless of
	// the authorize outcome below (finishScopedPermissionRequest still gates on
	// allowed/err) — mirrors RequireScopedSecretRefPermission's identical pattern.
	// GetSecret's machine branch reuses it instead of fetching the same row again,
	// and getSecretValueForUser reuses it again downstream (SESSION-PERF, #2403
	// follow-up) instead of a 3rd fetch.
	r = r.WithContext(WithResolvedSecret(r.Context(), secret))
	// AuthorizeSecretPrincipalForSecret reuses the secret already fetched above
	// instead of AuthorizeSecretPrincipal's own internal re-fetch of the same row.
	allowed, err := cs.AuthorizeSecretPrincipalForSecret(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), secret, permission)
	finishScopedPermissionRequest(next, w, r, cs, scope, allowed, err)
}

// RequireScopedSecretRefPermission is RequireScopedPermission specialized for
// the by-reference value read (GET .../secrets/value?ref=project/environment/name).
//
// core.ResolveSecretRef carries no snapshot/version guarantee: project name
// uniqueness is enforced only while a project is not soft-deleted, so a
// soft-deleted project's name is free for a brand-new project to reuse. If
// this middleware resolved the ref to compute the authorization scope and the
// handler independently resolved the SAME ref string again by name, a
// delete-and-recreate landing between the two calls could legitimately
// resolve them to secrets in two DIFFERENT projects — authorizing against one
// project's scope and then reading a secret from another. This middleware
// closes that window structurally: it resolves the ref EXACTLY ONCE, and pins
// the resolved *models.SecretNode on the request context
// (GetResolvedSecretRefFromContext) so the handler consumes that same
// resolution rather than calling ResolveSecretRef again.
func RequireScopedSecretRefPermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleScopedSecretRefPermissionRequest(next, w, r, permission)
		})
	}
}

func handleScopedSecretRefPermissionRequest(next http.Handler, w http.ResponseWriter, r *http.Request, permission string) {
	userCtx, cs, ok := requireUserAndCore(w, r)
	if !ok {
		return
	}
	secret, err := cs.ResolveSecretRef(r.Context(), r.URL.Query().Get("ref"))
	if err != nil {
		resolveErr := errTargetNotFound
		if errors.Is(err, core.ErrSecretRefInvalid) {
			resolveErr = errInvalidTarget
		}
		handleScopeResolutionError(w, r, cs, userCtx, permission, resolveErr)
		return
	}
	scope := core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	allowed, err := cs.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permission, scope)
	// Pin the resolution on the request context BEFORE dispatch, regardless of
	// the authorize outcome (finishScopedPermissionRequest still gates on
	// allowed/err below) — this is the ONLY resolution of this ref for the
	// entire request; the handler must reuse it rather than resolve again.
	r = r.WithContext(WithResolvedSecretRef(r.Context(), secret))
	finishScopedPermissionRequest(next, w, r, cs, scope, allowed, err)
}

// WithResolvedSecretRef stores a secret resolved by ref on ctx, for
// RequireScopedSecretRefPermission to hand off to its downstream handler (and
// for tests to simulate that hand-off without going through the middleware).
func WithResolvedSecretRef(ctx context.Context, secret *models.SecretNode) context.Context {
	return context.WithValue(ctx, resolvedSecretRefContextKey, secret)
}

// GetResolvedSecretRefFromContext retrieves the secret resolved by
// RequireScopedSecretRefPermission from the request context. Returns nil if no
// ref resolution ran (e.g. the route isn't wired through that middleware).
func GetResolvedSecretRefFromContext(ctx context.Context) *models.SecretNode {
	if secret, ok := ctx.Value(resolvedSecretRefContextKey).(*models.SecretNode); ok {
		return secret
	}
	return nil
}

// WithResolvedSecret is WithResolvedSecretRef's by-ID sibling (SESSION-PERF,
// #2403 follow-up): stores the secret RequireScopedSecretPermission resolved
// by numeric ID on ctx, for GetSecret to reuse instead of fetching it again.
func WithResolvedSecret(ctx context.Context, secret *models.SecretNode) context.Context {
	return context.WithValue(ctx, resolvedSecretContextKey, secret)
}

// GetResolvedSecretFromContext retrieves the secret resolved by
// RequireScopedSecretPermission from the request context. Returns nil if no
// by-ID resolution ran (e.g. the route isn't wired through that middleware).
func GetResolvedSecretFromContext(ctx context.Context) *models.SecretNode {
	if secret, ok := ctx.Value(resolvedSecretContextKey).(*models.SecretNode); ok {
		return secret
	}
	return nil
}

// requireUserAndCore fetches the authenticated user and core service from the
// request context, writing the appropriate error response and returning
// ok=false if either is missing. Shared by RequireScopedPermission and
// RequireScopedSecretPermission.
func requireUserAndCore(w http.ResponseWriter, r *http.Request) (*UserContext, *core.KeyorixCore, bool) {
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		unauthorizedResponse(w, "User context not found")
		return nil, nil, false
	}
	cs := GetCoreServiceFromContext(r.Context())
	if cs == nil {
		forbiddenResponse(w, "Authorization unavailable")
		return nil, nil, false
	}
	return userCtx, cs, true
}

// AuthorizedAtGlobalScope reports whether userCtx holds permission at GLOBAL
// scope — the narrow real-404 exception ADR-096 carves out of the house
// 403-for-both anti-enumeration convention: a caller who could have read this
// resource TYPE anywhere sees a genuine 404 for one target that truly doesn't
// exist, instead of the identical denial shown to everyone else. Exported for
// handler code that resolves a scoped reference inline (e.g. by name within a
// larger multi-reference operation) rather than through RequireScopedPermission
// — ADR-096's migration note calls for exactly this: either export
// handleScopeResolutionError's decision or add a thin wrapper around it.
func AuthorizedAtGlobalScope(ctx context.Context, cs *core.KeyorixCore, userCtx *UserContext, permission string) bool {
	ok, err := cs.AuthorizePrincipal(ctx, userCtx.ActorKind(), userCtx.PrincipalID(), permission, core.Scope{})
	return err == nil && ok
}

// handleScopeResolutionError writes the response for a scope-resolution failure,
// shared by RequireScopedPermission and RequireScopedSecretPermission. An
// errTargetNotFound reveals "not found" only to callers who hold the permission
// globally (AuthorizedAtGlobalScope); otherwise it denies without confirming the
// resource exists (avoids existence enumeration by unprivileged users). Any
// other error is treated as an unparseable target (400).
func handleScopeResolutionError(w http.ResponseWriter, r *http.Request, cs *core.KeyorixCore, userCtx *UserContext, permission string, err error) {
	if errors.Is(err, errTargetNotFound) {
		if AuthorizedAtGlobalScope(r.Context(), cs, userCtx, permission) {
			notFoundResponse(w, "Resource not found")
		} else {
			forbiddenResponse(w, "Insufficient permissions")
		}
		return
	}
	badRequestResponse(w, "Invalid target")
}

// finishScopedPermissionRequest applies the authorize result and, on success,
// the per-project MFA policy (ADR-037), before serving next. Shared by
// RequireScopedPermission and RequireScopedSecretPermission.
func finishScopedPermissionRequest(next http.Handler, w http.ResponseWriter, r *http.Request, cs *core.KeyorixCore, scope core.Scope, allowed bool, err error) {
	if err != nil || !allowed {
		forbiddenResponse(w, "Insufficient permissions")
		return
	}
	// Per-project MFA policy (ADR-037): deny an interactive session without a
	// second factor access to a project that requires MFA.
	if ProjectMFABlocked(r, cs, scope.ProjectID) {
		projectMFARequiredResponse(w)
		return
	}
	next.ServeHTTP(w, r)
}

// RequirePermission enforces a permission at global scope. Use it for
// admin-area routes (users, roles, audit, system) that are not tied to a
// particular project/environment.
func RequirePermission(permission string) func(next http.Handler) http.Handler {
	return RequireScopedPermission(permission, ScopeGlobal)
}

// setupStepRoutes are the only "METHOD /path" endpoints each pending setup step
// opens (#3024). A session owing setup steps may reach the union of its pending
// steps' routes plus setupAlwaysAllowedRoutes, and nothing else; logout and
// refresh are registered at the root router, outside this gate. Matched exactly
// on method and full path, never by suffix or prefix.
var setupStepRoutes = map[string][]string{
	core.SetupStepChangePassword: {
		"POST /api/v1/auth/change-password",
	},
	core.SetupStepEnrollMFA: {
		"POST /api/v1/auth/mfa/enroll",
		"POST /api/v1/auth/mfa/activate",
		"POST /api/v1/auth/webauthn/register/begin",
		"POST /api/v1/auth/webauthn/register/finish",
		"GET /api/v1/auth/webauthn/credentials",
	},
}

// setupAlwaysAllowedRoutes are reachable whatever is pending: reading the
// caller's own profile, so a client can show who is signed in and what is owed.
var setupAlwaysAllowedRoutes = []string{
	"GET /api/v1/auth/profile",
}

// SetupAllowedRoutes returns the exact "METHOD /path" set a session owing the
// given setup steps may reach. Exported for the route-registry guard test.
func SetupAllowedRoutes(pending []string) map[string]bool {
	allowed := map[string]bool{}
	for _, route := range setupAlwaysAllowedRoutes {
		allowed[route] = true
	}
	for _, step := range pending {
		for _, route := range setupStepRoutes[step] {
			allowed[route] = true
		}
	}
	return allowed
}

// EnforceAccountSetup confines a principal that still owes account-setup steps
// (core.PendingAccountSetupSteps) to the endpoints of those steps:
//
//   - change_password while the account is restricted (ADR-025
//     pending_first_login / password_reset_required), for any credential;
//   - enroll_mfa while the deployment requires MFA (security.require_mfa,
//     ADR-112) and an interactive session's account has no second factor.
//     Non-interactive credentials (PATs, machine tokens, OIDC) are exempt so
//     automation is not broken.
//
// Both steps pending opens both steps' endpoints, so they can be finished in
// either order (#3024: the two used to be separate gates that each refused the
// other's endpoint, which locked a recovered admin out for good). Every other
// endpoint answers 403 with the pending steps; the error code stays
// PasswordChangeRequired while a password change is owed, else
// MFAEnrollmentRequired, which existing clients route on.
//
// A session that owes both steps must be a setup-only session
// (models.Session.SetupOnly): one minted otherwise (e.g. live when an admin
// forced a reset on a factor-less user) is sent to re-authenticate (401), and
// its refresh or the next login yields a setup-only session. A setup-only
// session that owes nothing any more is likewise refused with 401: core revokes
// it when the last step completes (EndSetupSessionIfComplete), and this is the
// backstop if that revocation did not land. Applied after Authentication in the
// authenticated API group.
func EnforceAccountSetup(requireMFA bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleAccountSetupCheck(next, w, r, requireMFA)
		})
	}
}

func handleAccountSetupCheck(next http.Handler, w http.ResponseWriter, r *http.Request, requireMFA bool) {
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil {
		next.ServeHTTP(w, r)
		return
	}
	pending := core.PendingAccountSetupSteps(userCtx.Restricted, userCtx.MFAEnabled, userCtx.SessionAuth, requireMFA)
	// An impersonation session is never a setup session and cannot be refreshed;
	// it keeps the plain 403 confinement below.
	if userCtx.SessionAuth && userCtx.ImpersonatedBy == nil &&
		(userCtx.SetupOnly && len(pending) == 0 || !userCtx.SetupOnly && len(pending) == 2) {
		reauthenticationRequiredResponse(w, userCtx.SetupOnly)
		return
	}
	if len(pending) == 0 {
		next.ServeHTTP(w, r)
		return
	}
	if SetupAllowedRoutes(pending)[r.Method+" "+r.URL.Path] {
		next.ServeHTTP(w, r)
		return
	}
	accountSetupRequiredResponse(w, pending)
}

func accountSetupRequiredResponse(w http.ResponseWriter, pending []string) {
	code := "MFAEnrollmentRequired"
	message := "This deployment requires multi-factor authentication. Enrol MFA to continue."
	if pending[0] == core.SetupStepChangePassword {
		code = "PasswordChangeRequired"
		message = "You must change your password before continuing."
	}
	if len(pending) > 1 {
		message = "Finish account setup before continuing: change your password and enrol a second factor (MFA), in either order."
	}
	w.Header().Set(hdrContentType, mimeJSON)
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":         code,
		"message":       message,
		"code":          http.StatusForbidden,
		"pending_steps": pending,
	})
}

func reauthenticationRequiredResponse(w http.ResponseWriter, setupDone bool) {
	message := "Sign in again to finish account setup."
	if setupDone {
		message = "Account setup is complete. Sign in again with your new password and second factor."
	}
	w.Header().Set(hdrContentType, mimeJSON)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "ReauthenticationRequired",
		"message": message,
		"code":    http.StatusUnauthorized,
	})
}

// ScopeGlobal always resolves to the global scope.
func ScopeGlobal(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
	return core.Scope{}, nil
}

// ScopeFromQuery reads optional project_id/environment_id query params (0 when
// absent). Used by list endpoints where the client narrows by scope.
func ScopeFromQuery(r *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
	return core.Scope{
		ProjectID:     scopeQueryUint(r, "project_id"),
		EnvironmentID: scopeQueryUint(r, "environment_id"),
	}, nil
}

// ScopeFromProjectParam treats the named path param as a project ID.
func ScopeFromProjectParam(param string) ScopeResolver {
	return func(r *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		return core.Scope{ProjectID: id}, nil
	}
}

// ScopeFromEnvParam treats the named path param as an environment ID and loads
// its owning project.
func ScopeFromEnvParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		env, err := cs.Storage().GetEnvironment(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: env.ProjectID, EnvironmentID: id}, nil
	}
}

// ScopeFromSecretParam treats the named path param as a secret ID and resolves
// the secret's project/environment. Uses the raw storage fetch (no read-count
// side effects).
func ScopeFromSecretParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		secret, err := cs.Storage().GetSecret(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}, nil
	}
}

// ScopeFromDeletedSecretParam resolves the scope of a secret that may be
// soft-deleted (loads it Unscoped). Used by the restore route, where the target
// secret is by definition soft-deleted and unloadable via the normal path.
func ScopeFromDeletedSecretParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		secret, err := cs.Storage().GetSecretIncludingDeleted(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}, nil
	}
}

// ScopeFromShareParam treats the named path param as a share ID and resolves the
// scope of the shared secret.
func ScopeFromShareParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		share, err := cs.Storage().GetShareRecord(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		secret, err := cs.Storage().GetSecret(r.Context(), share.SecretID)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}, nil
	}
}

// ScopeFromRotationPolicyParam treats the named path param as a rotation policy
// ID and resolves the policy's project/environment scope.
func ScopeFromRotationPolicyParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		policy, err := cs.Storage().GetRotationPolicy(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{
			ProjectID:     derefUint(policy.ProjectID),
			EnvironmentID: derefUint(policy.EnvironmentID),
		}, nil
	}
}

// ScopeFromDynamicSecretConfigParam treats the named path param as a
// dynamic-secret config ID and resolves its project/environment scope.
// #1645/ADR-096: replaces dynamic_secrets.go's handler-internal
// loadAuthorizedConfig, which used to collapse "doesn't exist" and "exists,
// denied" into a uniform 404 regardless of caller privilege (Convention B) --
// routing through this resolver + RequireScopedPermission instead gives every
// dynamic-secret config route the same 403-for-both behavior (with the
// narrow real-404-for-global-holders exception) every other scoped resource
// already has, via the one shared mechanism (handleScopeResolutionError)
// rather than a second, independently-derived collapse implementation.
func ScopeFromDynamicSecretConfigParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		cfg, err := cs.GetDynamicSecretConfig(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: cfg.ProjectID, EnvironmentID: cfg.EnvironmentID}, nil
	}
}

// ScopeFromDynamicSecretLeaseParam treats the named path param as a
// dynamic-secret lease ID (a string, unlike every other resolver's uint path
// param -- lease IDs are opaque tokens, not row IDs) and resolves the scope
// of the config that issued it. Same #1645/ADR-096 rationale as
// ScopeFromDynamicSecretConfigParam above.
func ScopeFromDynamicSecretLeaseParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		leaseID := chi.URLParam(r, param)
		if leaseID == "" {
			return core.Scope{}, errInvalidTarget
		}
		lease, err := cs.GetDynamicSecretLease(r.Context(), leaseID)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: lease.ProjectID, EnvironmentID: lease.EnvironmentID}, nil
	}
}

// roleAssignmentBodyScope is the subset of the user-roles assign/remove request
// body (both share the same project_id/environment_id shape) needed to resolve
// the target scope ahead of the handler's own decode.
type roleAssignmentBodyScope struct {
	ProjectID     uint `json:"project_id"`
	EnvironmentID uint `json:"environment_id"`
}

// ScopeFromRoleAssignmentBody resolves the target scope of a POST/DELETE
// /api/v1/user-roles request from its own JSON body's "project_id"/
// "environment_id" fields (0 = global) — mirroring
// RoleGRPCService.AssignRole/RemoveRole (server/grpc/services/role_service.go),
// which authorize roles.assign at the request's TARGET scope rather than a flat
// global permission (#342). Before this, the HTTP route gated on RequirePermission
// ("roles.assign"), which always checked the GLOBAL scope regardless of the
// body's actual project/environment target — a parity gap with the gRPC path.
//
// The body is read and re-buffered onto r.Body (via a fresh io.NopCloser) so the
// handler's own json.Decode of the same body still succeeds afterward.
func ScopeFromRoleAssignmentBody(r *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return core.Scope{}, errInvalidTarget
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	var s roleAssignmentBodyScope
	if len(body) > 0 {
		if err := json.Unmarshal(body, &s); err != nil {
			return core.Scope{}, errInvalidTarget
		}
	}
	return core.Scope{ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID}, nil
}

func scopePathUint(r *http.Request, param string) (uint, error) {
	v, err := strconv.ParseUint(chi.URLParam(r, param), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint(v), nil
}

func scopeQueryUint(r *http.Request, key string) uint {
	if v, err := strconv.ParseUint(r.URL.Query().Get(key), 10, 32); err == nil {
		return uint(v)
	}
	return 0
}

func derefUint(p *uint) uint {
	if p == nil {
		return 0
	}
	return *p
}

// RequireRole returns a middleware that checks if the user has a specific role.
//
// A request authenticated by a PAT carrying a least-privilege restriction
// (ADR-042) is denied outright: a role gate confers the role's full breadth,
// which a deliberately-scoped token must not satisfy. This keeps PAT scoping
// honoured on this role-based gate, which does not funnel through core.Authorize
// (where the restriction is otherwise enforced). Fail-closed.
//
// This match is UNSCOPED — it checks only the role name against userCtx.Roles,
// with no project/environment scope check at all. It currently has no
// production route caller (only exercised by auth_test.go). If a role-based
// gate is ever needed on a scoped route, use a scope-aware check
// (core.Authorize / the RBAC choke point) instead.
//
// (#308) A machine identity's role list (e.g. store.GetMachineRoles, itself
// for-display only — see its own warning) is unscoped across every
// project/environment, so an unscoped name match here would bypass
// project/environment scoping entirely for machine principals: a role granted
// only in Project A would incorrectly satisfy this gate on a route in Project
// B. Rather than rely on every future caller remembering never to wire this
// onto a machine-token-reachable route, this is enforced here, at the
// consumer, so it holds regardless of what unscoped data source ever feeds
// userCtx.Roles: a machine/OIDC principal (ActorType machine_identity)
// unconditionally cannot satisfy a role gate. Fail-closed, mirroring the PAT
// restriction check above.
func RequireRole(role string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				unauthorizedResponse(w, "User context not found")
				return
			}
			if userCtx.PATRestriction != nil {
				forbiddenResponse(w, "A scoped personal access token cannot satisfy a role requirement")
				return
			}
			// #308: a machine/OIDC-federated principal's role list is resolved
			// unscoped (across every project/environment) at authentication time,
			// so it must never be allowed to satisfy this unscoped role-name gate —
			// doing so would silently bypass project/environment scoping for
			// machine principals. Machine authorization must go through a
			// scope-aware check (core.Authorize) instead.
			if userCtx.MachineIdentityID != nil {
				forbiddenResponse(w, "A machine identity cannot satisfy an unscoped role requirement")
				return
			}
			if !slices.Contains(userCtx.Roles, role) {
				forbiddenResponse(w, "Insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// buildRequestContext stores the resolved identity and core service on the
// request context. When the session is an impersonation session it also tags the
// context (via core.WithImpersonation) so audit events written downstream are
// consistently marked impersonation=true with the initiating admin recorded.
func buildRequestContext(parent context.Context, userCtx *UserContext, coreService *core.KeyorixCore) context.Context {
	ctx := context.WithValue(parent, userContextKey, userCtx)
	ctx = context.WithValue(ctx, coreServiceContextKey, coreService)
	if userCtx != nil && userCtx.ImpersonatedBy != nil {
		ctx = core.WithImpersonation(ctx, *userCtx.ImpersonatedBy)
	}
	// Tag machine requests so every audit event they produce is actored as a
	// machine identity (ADR-023/030 plumbing), AND record which one (G80
	// #1530) -- ActorType alone said "a machine did this"; WithMachineActor
	// is the field that says which machine, mirroring WithImpersonation two
	// lines above exactly (same mechanism, not a new one).
	if userCtx != nil && userCtx.MachineIdentityID != nil {
		ctx = core.WithActorType(ctx, core.ActorTypeMachine)
		ctx = core.WithMachineActor(ctx, *userCtx.MachineIdentityID)
	}
	// Carry a PAT's least-privilege restriction (ADR-042) so core.Authorize
	// enforces it on every authorization check this request makes.
	if userCtx != nil && userCtx.PATRestriction != nil {
		ctx = core.WithPATRestriction(ctx, userCtx.PATRestriction)
	}
	// #G07: tag whether this is a genuine interactive session — StartImpersonation
	// needs this distinction directly, since an unrestricted PAT is indistinguishable
	// from a session by PATRestriction alone (both carry nil).
	if userCtx != nil {
		ctx = core.WithSessionAuth(ctx, userCtx.SessionAuth)
	}
	return ctx
}

// GetUserFromContext extracts the user context from the request context
func GetUserFromContext(ctx context.Context) *UserContext {
	if userCtx, ok := ctx.Value(userContextKey).(*UserContext); ok {
		return userCtx
	}
	return nil
}

// machineUserContext builds the request principal for a machine identity (used
// by both opaque machine tokens and federated OIDC tokens) — UserID 0, the
// machine id, and ActorType machine_identity so RBAC and audit are identical.
// restriction is nil for OIDC tokens (no per-credential allowlist) and for
// opaque tokens that carry no AllowedCIDRs.
func machineUserContext(m *models.MachineIdentity, roleNames []string, restriction *core.MachineTokenRestriction, credID uint) *UserContext {
	mid := m.ID
	return &UserContext{
		UserID:                  0,
		MachineIdentityID:       &mid,
		ActorType:               core.ActorTypeMachine,
		MachineIdentityType:     m.IdentityType,
		Username:                m.Name,
		Roles:                   roleNames,
		AccountState:            core.AccountActive,
		MachineTokenRestriction: restriction,
		machineCredID:           credID,
	}
}

// looksLikeJWT reports whether a bearer is a three-segment dotted JWT and not a
// kx_-prefixed Keyorix credential.
func looksLikeJWT(token string) bool {
	if strings.HasPrefix(token, machineTokenPrefix) || strings.HasPrefix(token, patTokenPrefix) {
		return false
	}
	return strings.Count(token, ".") == 2
}

// maxOIDCLogFieldLen bounds an attacker-influenceable value (from an
// unverified federated JWT) before it is logged, so a crafted oversized claim
// can't bloat log output.
const maxOIDCLogFieldLen = 256

// boundedForLog strips control characters (see recovery.go's stripControl,
// same rationale: log-injection / terminal-control smuggling via
// attacker-influenceable values) and truncates to maxOIDCLogFieldLen runes,
// for logging a value that did not come from a trusted source.
func boundedForLog(s string) string {
	s = stripControl(s)
	r := []rune(s)
	if len(r) <= maxOIDCLogFieldLen {
		return s
	}
	return string(r[:maxOIDCLogFieldLen]) + "…(truncated)"
}

// oidcDiagnosticFields best-effort extracts the iss/kid header/claims from a
// JWT for LOGGING ONLY. It does not verify the signature — these values are
// exactly as trustworthy as any other attacker-supplied input, i.e. not at
// all — so they must never feed an authorization or trust decision. The real,
// verified (issuer, subject) pair is what validator.ValidateOIDCToken itself
// resolves and audits on success; this is purely a diagnostic best-effort
// read for the failure path. If the token doesn't even parse, both return "".
//
// Deliberately does NOT use a JWT library's parse/verify entry point (e.g.
// jwt.ParseUnverified): SonarCloud's JWT-signature rule (S5659) pattern-
// matches on exactly that class of call and flags it regardless of context,
// including this one, where skipping verification is the explicit point,
// not an oversight. A JWT's header and payload are just base64url(JSON) --
// splitting on "." and decoding each segment directly gets the same two
// fields without going anywhere near an API whose name says "verify".
func oidcDiagnosticFields(token string) (issuer, kid string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}
	if header, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
		var h struct {
			Kid string `json:"kid"`
		}
		if json.Unmarshal(header, &h) == nil {
			kid = h.Kid
		}
	}
	if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		var claims struct {
			Issuer string `json:"iss"`
		}
		if json.Unmarshal(payload, &claims) == nil {
			issuer = claims.Issuer
		}
	}
	return issuer, kid
}

// validateToken validates a session token via the supplied validator and returns
// the resolved UserContext. Permissions are no longer precomputed here — they are
// resolved per request, scoped to the target, by core.Authorize.
func validateToken(ctx context.Context, validator sessionValidator, token string) (*UserContext, error) {
	if validator == nil {
		return nil, http.ErrNotSupported
	}
	// Machine tokens (ADR-030) authenticate AS a machine identity, not a user.
	if strings.HasPrefix(token, machineTokenPrefix) {
		m, roleNames, restriction, credID, err := validator.ValidateMachineToken(ctx, token)
		if err != nil {
			return nil, err
		}
		return machineUserContext(m, roleNames, restriction, credID), nil
	}

	// Federated OIDC / Kubernetes-JWT tokens (ADR-031) also authenticate AS a
	// machine identity. A JWT is a three-segment dotted token and is not one of
	// the kx_ prefixes; only attempt it when OIDC is configured.
	if validator.OIDCEnabled() && looksLikeJWT(token) {
		m, roleNames, err := validator.ValidateOIDCToken(ctx, token)
		if err != nil {
			// The detailed reason (untrusted issuer, unreachable JWKS, bad
			// signature, expired, ...) must never reach the caller — the
			// client-facing response stays a generic 401 regardless (see the
			// caller of validateToken) so config topology (which issuers
			// exist, which are reachable) can't be probed by an
			// unauthenticated request. But discarding it entirely left an
			// operator with zero signal to debug federated auth: an
			// unreachable jwks_uri (e.g. in an air-gapped deployment) looked
			// identical to a garden-variety expired token. Log it
			// server-side instead.
			//
			// issuer/kid/err are all attacker-influenceable — this runs on
			// an UNVERIFIED token, pre-authentication — so every one of them
			// is bounded and control-stripped (boundedForLog) and rendered
			// with %q so an embedded quote/space can't forge a fake
			// key=value pair in this log line.
			//
			// Not rate-limited or sampled: a flood of IDENTICAL bad tokens
			// is already deduplicated upstream (the negative token cache —
			// see cacheSet's invalidTokenTTL in the caller), but a flood of
			// DISTINCT crafted tokens (different iss/kid per request) is
			// not, and would produce one WARNING line each. No existing
			// log-sampling primitive exists in this codebase to reuse for
			// that case; adding one is out of scope here.
			issuer, kid := oidcDiagnosticFields(token)
			log.Printf("WARNING: OIDC federation verification failed: issuer=%q kid=%q err=%q",
				boundedForLog(issuer), boundedForLog(kid), boundedForLog(err.Error()))
			return nil, err
		}
		return machineUserContext(m, roleNames, nil, 0), nil
	}

	// Route by prefix: PATs authenticate AS their owning user, resolving to the same
	// UserContext shape as a session — so authorization downstream is identical.
	var (
		user        *models.User
		roleNames   []string
		restriction *core.PATRestriction
		patID       uint
		err         error
		viaSession  bool
	)
	if strings.HasPrefix(token, patTokenPrefix) {
		user, roleNames, restriction, patID, err = validator.ValidatePATToken(ctx, token)
	} else {
		user, roleNames, err = validator.ValidateSessionToken(ctx, token)
		viaSession = true
	}
	if err != nil {
		return nil, err
	}
	return &UserContext{
		UserID:         user.ID,
		Username:       user.Username,
		Email:          user.Email,
		Roles:          roleNames,
		ActorType:      core.ActorTypeUser,
		AccountState:   core.NormalizeAccountState(user.AccountState),
		Restricted:     core.AccountRestricted(user.AccountState),
		MFAEnabled:     user.MFAEnabled || user.WebAuthnEnabled,
		SessionAuth:    viaSession,
		PATRestriction: restriction,
		patID:          patID,
	}, nil
}

// tokenNetworkAllowed enforces a token's IP allowlist. It returns true when the
// token has no allowlist; otherwise the request's source IP must fall within one
// of the allowed CIDRs. Covers both PATs and machine tokens. It fails CLOSED —
// an undeterminable/unparseable source IP is denied. The source IP is the TCP
// peer (r.RemoteAddr), never a client-supplied header, so the control cannot be
// spoofed; a deployment behind a proxy must terminate so RemoteAddr is the real
// client (e.g. PROXY protocol) for per-client allowlists to apply.
func tokenNetworkAllowed(r *http.Request, userCtx *UserContext) bool {
	if userCtx == nil {
		return true
	}
	if userCtx.PATRestriction != nil && len(userCtx.PATRestriction.AllowedCIDRs) > 0 {
		return core.IPInCIDRs(clientIP(r), userCtx.PATRestriction.AllowedCIDRs)
	}
	if userCtx.MachineTokenRestriction != nil && len(userCtx.MachineTokenRestriction.AllowedCIDRs) > 0 {
		return core.IPInCIDRs(clientIP(r), userCtx.MachineTokenRestriction.AllowedCIDRs)
	}
	return true
}

// clientIP returns the source IP of the request from its TCP peer address.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr // already a bare IP (or empty)
}

// unauthorizedResponse sends a 401 Unauthorized response
func unauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set(hdrContentType, mimeJSON)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "Unauthorized", "message": message, "code": http.StatusUnauthorized,
	})
}

func tooManyRequestsResponse(w http.ResponseWriter, message string) {
	w.Header().Set(hdrContentType, mimeJSON)
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "RateLimited", "message": message, "code": http.StatusTooManyRequests,
	})
}

// serviceUnavailableResponse sends a 503 Service Unavailable response for a
// transient failure (e.g. a storage-layer hiccup during token validation, see
// isTransientValidationError) that the caller should simply retry, as opposed
// to a 401 which tells the caller its credential itself is bad. Retry-After is
// short — this is meant for a brief infrastructure blip, not a sustained outage.
func serviceUnavailableResponse(w http.ResponseWriter, message string) {
	w.Header().Set(hdrContentType, mimeJSON)
	w.Header().Set("Retry-After", "2")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "ServiceUnavailable", "message": message, "code": http.StatusServiceUnavailable,
	})
}

// BlockWhenImpersonating refuses a request made under an impersonation session. It
// guards the target's credential-issuing / authenticator-lifecycle self-service routes
// (mint a PAT, enroll/disable MFA, register a passkey) so an admin impersonating a user
// cannot plant a durable credential that outlives the bounded, audited impersonation
// session. Impersonation is for acting AS the user for support, not administering their
// long-lived credentials.
func BlockWhenImpersonating(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := GetUserFromContext(r.Context()); u != nil && u.ImpersonatedBy != nil {
			forbiddenResponse(w, "this action is not permitted while impersonating")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// forbiddenResponse sends a 403 Forbidden response
func forbiddenResponse(w http.ResponseWriter, message string) {
	w.Header().Set(hdrContentType, mimeJSON)
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "Forbidden", "message": message, "code": http.StatusForbidden,
	})
}

// ProjectMFABlocked reports whether the request must be denied by a project's
// per-project MFA policy (ADR-037): true only when the caller is an interactive
// session WITHOUT a second factor and the scoped project requires MFA. The
// project lookup is skipped unless the caller could actually be subject to the
// policy, so MFA-backed and non-interactive (PAT / machine / OIDC) callers pay no
// cost and stay exempt — consistent with EnforceAccountSetup. Handlers that
// authorize in-handler (not via RequireScopedPermission) call this too, so the
// policy is enforced uniformly across every project-scoped path.
//
// #G17: fails CLOSED (blocks) on a genuine ProjectRequiresMFA lookup error —
// matching the gRPC-side enforceProjectMFA fix. A lookup error used to fall
// through to "not blocked", silently treating the caller as MFA-compliant;
// left unfixed here while gRPC failed closed, a caller could deliberately
// trigger the same lookup error and pick whichever transport still failed
// open, reopening exactly the transport-divergence bypass class this
// function's own doc comment says it exists to prevent. A "project not
// found" error is deliberately excluded from the fail-closed path: this
// scope was already permission-checked by the caller (finishScopedPermissionRequest
// only reaches here on allowed==true), so a nonexistent project is not an
// MFA-policy question — blocking it here would mask the handler's own
// existence check (e.g. a project-health probe for an unknown ID) behind a
// misleading "MFA required" response instead of its real 404/403.
func ProjectMFABlocked(r *http.Request, cs *core.KeyorixCore, projectID uint) bool {
	if projectID == 0 || cs == nil {
		return false
	}
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil || !userCtx.SessionAuth || userCtx.MFAEnabled {
		return false
	}
	req, err := cs.ProjectRequiresMFA(r.Context(), projectID)
	if err != nil {
		return !strings.Contains(err.Error(), "not found")
	}
	return req
}

// ProjectsMFABlocked generalizes ProjectMFABlocked across a set of project IDs
// disclosed by an aggregate/global-scope response — true if ANY project in the
// set requires MFA the caller's session lacks (or whose policy can't be
// verified). See ProjectMFABlocked's doc comment for the exemption rules.
//
// #G17: an aggregate endpoint (e.g. GET /rotation-plan, GET /shares,
// GET /shared-secrets) is gated only by a global RequirePermission check, which
// never scopes to any one project — so ProjectMFABlocked's own per-project gate
// is never reached for these routes regardless of which specific projects' data
// the response actually discloses. Call this with every project ID the response
// discloses before writing it out.
func ProjectsMFABlocked(r *http.Request, cs *core.KeyorixCore, projectIDs []uint) bool {
	seen := make(map[uint]bool, len(projectIDs))
	for _, id := range projectIDs {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		if ProjectMFABlocked(r, cs, id) {
			return true
		}
	}
	return false
}

// WriteProjectMFARequired writes the 403 ProjectMFARequired response (exported so
// in-handler authorizers can emit the same body as the scoped-permission path).
func WriteProjectMFARequired(w http.ResponseWriter) { projectMFARequiredResponse(w) }

// projectMFARequiredResponse sends a 403 with a distinct code so the client can
// prompt the user to enrol a second factor (ADR-037 per-project MFA policy).
func projectMFARequiredResponse(w http.ResponseWriter) {
	w.Header().Set(hdrContentType, mimeJSON)
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "ProjectMFARequired",
		"message": "This project requires multi-factor authentication. Enrol a second factor to access it.",
		"code":    http.StatusForbidden,
	})
}

// notFoundResponse sends a 404 Not Found response.
func notFoundResponse(w http.ResponseWriter, message string) {
	w.Header().Set(hdrContentType, mimeJSON)
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "NotFound", "message": message, "code": http.StatusNotFound,
	})
}

// badRequestResponse sends a 400 Bad Request response.
func badRequestResponse(w http.ResponseWriter, message string) {
	w.Header().Set(hdrContentType, mimeJSON)
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "BadRequest", "message": message, "code": http.StatusBadRequest,
	})
}

// GetUserContextKey returns the context key for user context (for testing)
func GetUserContextKey() contextKey {
	return userContextKey
}

// GetCoreServiceFromContext retrieves the core service from the request context.
func GetCoreServiceFromContext(ctx context.Context) *core.KeyorixCore {
	if cs, ok := ctx.Value(coreServiceContextKey).(*core.KeyorixCore); ok {
		return cs
	}
	return nil
}

// InvalidateTokenCache removes a specific token from the auth cache.
// Call this on logout to ensure the token is rejected immediately.
func InvalidateTokenCache(token string) {
	InvalidateTokenCacheByHash(tokenKey(token))
}

// ClearTokenCacheForToken is ClearTokenCacheIfCached by raw token: the next
// request with this token re-validates from storage, without negative-caching
// a credential that is still valid (a session whose account just became less
// restricted).
func ClearTokenCacheForToken(token string) {
	ClearTokenCacheIfCached(tokenKey(token))
}

// InvalidateTokenCacheByHash evicts the entry keyed by the token's SHA-256 hash (hex).
// PAT revocation works by token ID and never sees the raw token, but a PAT's stored
// TokenHash equals this cache key, so revoke-by-id can purge the entry immediately
// rather than waiting out the positive-cache TTL.
func InvalidateTokenCacheByHash(hash string) {
	tokenCacheMu.Lock()
	// Write a short-lived tombstone rather than a plain delete: a positive validation that
	// was already in flight (read the DB before this revoke) would otherwise re-add the
	// entry right after our delete. The tombstone's revokedAt lets cacheSetValidated drop
	// that stale write, and negative-caches the revoked token for invalidTokenTTL.
	now := time.Now()
	tokenCache[hash] = tokenCacheEntry{userCtx: nil, expiresAt: now.Add(invalidTokenTTL), revokedAt: now}
	tokenCacheMu.Unlock()
}

// ClearTokenCacheIfCached forces the entry keyed by hash to miss on its very next
// read, WITHOUT negative-caching it for invalidTokenTTL the way
// InvalidateTokenCacheByHash's tombstone does. Use this for a transition where
// staying stale is safe in only one specific direction (an over-restrictive
// leftover is fine; creating a brand-new false negative for a key that was never
// cached is not): a plain long-lived tombstone-write would otherwise negative-cache
// a credential this call never actually saw. See setAccountState's "becoming
// active" branch (internal/core/account_state.go) for the motivating case — PR
// #2206 fixed the unconditional-tombstone shape by skipping eviction entirely on
// that branch, which left a DIFFERENT bug open: an EXISTING negative entry, cached
// while the account was blocked, now outlives the account becoming active again,
// since nothing ever clears it (FuzzAuthCacheDifferential, G5, found this as a
// cache/DB status-code divergence — both paths still deny, so not an authz bypass,
// but the cache answers "denied" for a request storage would now allow or deny for
// a different reason).
//
// A PLAIN delete (the original #2423 shape) reopens a different, more serious
// gap than the one this function exists to avoid: a slow-path validation that
// began reading the DB BEFORE this call (so its in-memory result still reflects
// the stale, pre-change privileges) can finish and call cacheSetValidatedGen
// AFTER this call, and cacheSetValidatedGen's own resurrection guard
// (`existing.revokedAt.After(validatedAt)`) only fires when an entry still
// exists to check `revokedAt` on — a bare delete leaves nothing to check, so the
// stale positive write resurrects unguarded for up to validTokenTTL. That is a
// genuine privilege-bypass window (a role removal's old permission grant
// outliving the removal), not merely a wrong status code, and the exact
// coordinator ask on #2423 ("confirm the cache can never ALLOW where the DB
// denies") was not yet true before this fix.
//
// A revokedAt+immediate-expiry tokenCacheEntry marker (this function's first
// attempt) does NOT close the gap either: cacheGet deletes any entry whose
// expiresAt has passed on its very next read, marker included -- so a
// concurrent request for the SAME key between this call and the slow-path
// write removes the marker before cacheSetValidatedGen ever gets to check its
// revokedAt, and the resurrection succeeds anyway (coordinator review on the
// first version of this fix). Closed instead with a separate clearedAt map
// (package-level var above), deliberately NOT subject to cacheGet's own
// read-triggered deletion: cacheSetValidatedGen checks clearedAt directly,
// independent of whatever cacheGet did to tokenCache in between. clearedAt is
// pruned after validTokenTTL (pruneLocked), not immediately, so the guard
// survives for as long as any single slow-path validation can still be in
// flight. The map write is unconditional (not "only if already cached"): the
// race this closes is specifically a credential that was NEVER cached before
// the clear (first use raced by a concurrent role removal), so there is often
// no existing tokenCache entry to condition on. tokenCache itself still gets
// an unconditional delete, for the ordinary "make the next read a miss"
// effect this function's name promises — but never a new tokenCacheEntry
// write, so a hash this call never saw still never gains a negative-cache
// window (the #2402 bug this function exists to avoid stays fixed).
func ClearTokenCacheIfCached(hash string) {
	tokenCacheMu.Lock()
	delete(tokenCache, hash)
	clearedAt[hash] = time.Now()
	tokenCacheMu.Unlock()
}

// InvalidateAllMachineTokenCache drops every positive cache entry attributed to a
// machine identity (ActorType core.ActorTypeMachine), leaving human session/PAT
// entries untouched. Fail-closed fallback for TransitionMachineIdentity
// (internal/core/machine_identities.go): when it can't determine which credential
// hashes belong to the identity it just suspended/revoked (the hash lookup errored
// or panicked after the transition committed), every machine principal must
// re-validate against the DB on its next request.
//
// It bumps machineCacheGen rather than writing tombstones:
//   - a slow-path validation already in flight (DB read before the revoke) for a
//     key that was NOT cached at flush time captured the old generation, so
//     cacheSetValidatedGen drops its write — a per-key tombstone can't cover a
//     key that isn't in the map;
//   - unrelated machine tokens just miss the cache and re-validate (200 if still
//     valid) instead of being answered 401 by a negative entry for
//     invalidTokenTTL.
func InvalidateAllMachineTokenCache() {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	machineCacheGen++
	for k, e := range tokenCache {
		if isMachineEntry(e.userCtx) {
			delete(tokenCache, k)
		}
	}
}
