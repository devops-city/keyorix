// auth_budget.go — the one limiter every authentication budget goes through,
// and its behaviour when the budget's storage fails (Andrei, 2026-10-10:
// login budget at 17:52; "no auth budget ever fails open on storage errors"
// at 18:52, AUTH-AUDIT-1).
//
// The budgets:
//
//	login            per IP, LoginMaxAttempts per LoginWindow, login_attempts
//	                 (login, MFA verify, refresh, WebAuthn begin/finish,
//	                 passwordless begin/finish, setup-link consume)
//	password_reset   per IP, PasswordResetMaxAttempts per PasswordResetWindow,
//	                 login_attempts under "pwreset:"
//	sso_begin        per IP, SSOBeginMaxAttempts per SSOBeginWindow,
//	                 login_attempts under "sso:" (OIDC and SAML begin)
//	account_lockout  per account, LoginLockoutPolicy.MaxAttempts per Window,
//	                 the user row's lockout columns (password, TOTP, recovery
//	                 code, step-up, WebAuthn second factor and re-auth)
//
// Each used to fail OPEN on a storage error: a count that could not be read
// answered "not limited", and an attempt that could not be written was not
// counted, so a database fault, or an attacker able to provoke one, removed
// the brute-force backstop entirely. Failing CLOSED instead would lock every
// user out on a DB hiccup. The decision is neither: on a storage error the
// budget falls back to a bounded in-memory limiter with the SAME limit and
// window, keyed the same way (the canonical client IP the transport's
// trusted-proxy logic resolved, or the account id).
//
// What the fallback is and is not:
//   - per process. In HA each replica enforces its own copy during an outage,
//     so the effective cluster-wide limit is up to the limit per replica the
//     attacker can reach. Still a bound, where fail-open was none.
//   - bounded: one limiter per budget, each holding at most authFallbackMaxKeys
//     keys (least recently used evicted first), and per key only the attempts
//     inside the window, capped at 4x the limit. Many distinct (spoofed or
//     rotating) addresses evict each other rather than exhaust memory, and
//     cannot evict another budget's entries (an account's in-memory lock is
//     not displaced by an IP flood). Within account_lockout itself, eviction
//     CAN drop an account's in-memory lock (#3029 review): that takes failed
//     attempts against authFallbackMaxKeys other, real accounts (a failure is
//     counted only against an existing user id) after the target's last
//     touch, all inside one outage, each of them also spending the per-IP
//     login budget. The trade-off is deliberate: an unbounded map would let
//     the same outage exhaust memory. Pinned by
//     TestAccountLockoutFallback_LockSurvivesUpToTheKeyBound.
//   - consulted IN ADDITION to the stored count: the attempts added to it are
//     those whose stored write failed, so adding them never double-counts,
//     and leftover entries age out with the window after storage recovers. The
//     counts are never merged into storage.
//   - mirrored while degraded (#3023, #3029, #3032 reviews): a write that SUCCEEDS while the
//     budget is on its fallback is also noted in memory, flagged as mirrored.
//     A COUNT that fails is then judged on memory including the mirrored
//     attempts, so a budget whose count query fails while its inserts succeed
//     still binds (it used to fail open: memory stayed empty). A count that
//     works ignores mirrored attempts: they are in the stored count already.
//   - releasable (login only): a reservation taken here gets an id with
//     authFallbackIDBit set, which no stored row id can carry, so
//     ReleaseLoginAttempt (a delivered login, #2936) refunds it here. Such an
//     id is meaningful only inside this process: it is never persisted to a
//     row other replicas read (sharedLoginSlot), so a fallback slot held by an
//     MFA challenge or a WebAuthn ceremony stays counted until it ages out.
//   - for account_lockout, no exponential cooldown: an account is locked while
//     its stored failures inside Window plus its in-memory failures reach
//     MaxAttempts (the check adds the two, as for every budget; #3029 review),
//     and unlocks as they age out. A delivered login and an admin unlock clear the entry, as they
//     clear the stored columns.
//
// While a budget is on its fallback (item 5, points 2-4):
//   - the in-memory count is held to the budget's fallback limit: its limit
//     divided by fallbackDivisor (2 for password reset: half the per-IP limit)
//     and by the configured replica count (SetAuthRateLimitFallbackReplicas,
//     default 1), never below 1. A stored count that could be read is
//     cluster-wide already and keeps the normal limit.
//   - password reset also caps resets per account (passwordResetAccountBudget,
//     checked in RequestPasswordReset): the email-bombing guard.
//   - AuthRateLimitDegraded reports true until no budget has fallen back within
//     its window, for the health endpoint.
//
// Every fallback is audited (EventAuthRateLimitError, Success=false) and
// counted (keyorix_auth_rate_limit_fallback_total{budget}). The client sees no
// difference: a refusal from memory is the same response a stored refusal is.
package core

import (
	"container/list"
	"context"
	"fmt"
	"math/bits"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
)

// EventAuthRateLimitError is the error event written each time an auth budget
// had to use the in-memory fallback because its storage failed.
const EventAuthRateLimitError = "auth.rate_limit_error"

// authBudget names one budget: its key namespace in login_attempts, its limit
// and its window. fallbackDivisor (0 means 1) tightens the limit while the
// budget runs on its in-memory fallback.
type authBudget struct {
	name            string
	prefix          string
	limit           int
	window          time.Duration
	fallbackDivisor int
}

var (
	loginBudget         = authBudget{name: "login", limit: LoginMaxAttempts, window: LoginWindow}
	passwordResetBudget = authBudget{name: "password_reset", prefix: passwordResetRateLimitPrefix, limit: PasswordResetMaxAttempts, window: PasswordResetWindow, fallbackDivisor: 2}
	// passwordResetAccountBudget caps resets per account while
	// passwordResetBudget is on its fallback (memory only; see
	// RequestPasswordReset). Same limit, window and divisor as the per-IP one.
	passwordResetAccountBudget = authBudget{name: "password_reset_account", limit: PasswordResetMaxAttempts, window: PasswordResetWindow, fallbackDivisor: 2}
	ssoBeginBudget             = authBudget{name: "sso_begin", prefix: ssoRateLimitPrefix, limit: SSOBeginMaxAttempts, window: SSOBeginWindow}
	// accountLockoutBudget's limit and window come from the core's
	// LoginLockoutPolicy; see accountBudget.
	accountLockoutBudget = authBudget{name: "account_lockout"}
)

// accountBudget is accountLockoutBudget with this core's lockout policy.
func (c *KeyorixCore) accountBudget() authBudget {
	b := accountLockoutBudget
	b.limit = c.loginLockout.MaxAttempts
	b.window = c.loginLockout.Window
	return b
}

func accountBudgetKey(userID uint) string { return strconv.FormatUint(uint64(userID), 10) }

// authFallbackMaxKeys bounds each budget's fallback: at most this many keys
// are tracked, least recently used evicted first.
const authFallbackMaxKeys = 10_000

// authFallbackIDBit marks a reservation id as the fallback's own. Stored
// LoginAttempt ids are database sequence values that never reach the top bit.
const authFallbackIDBit uint = 1 << (bits.UintSize - 1)

var authRateLimitFallbackTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_auth_rate_limit_fallback_total",
	Help: "Count of auth rate-limit operations that fell back to the in-memory limiter because the budget's storage failed.",
}, []string{"budget"})

// authBudgetRejectionsTotal counts budget checks that answered "limited" -- the
// login / password-reset / SSO-begin / account-lockout refusals an operator sees as
// 429s or lockouts. A request checked against two budgets can count in both, and a
// budget re-checked within one request counts each time, so read it as a rate of
// refusals by budget, not an exact count of distinct requests.
//
// Registered on internal/protectedmetrics (authenticated scheduler-metrics only): an
// anonymous reader must not see how close an attack is to a lockout.
var authBudgetRejectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_auth_budget_rejections_total",
	Help: "Authentication budget checks that answered limited (login, password reset, SSO begin, account lockout), by budget. A rising rate is brute-force pressure or a misbehaving client.",
}, []string{"budget"})

func init() { protectedmetrics.MustRegister(authBudgetRejectionsTotal) }

// SetAuthRateLimitFallbackReplicas sets how many server replicas share the
// auth budgets (security.auth_rate_limit_fallback.replicas). Each replica's
// in-memory fallback then enforces 1/n of a budget's fallback limit, so the
// cluster as a whole stays near the normal limit during an outage. n < 1 is
// treated as 1. Called once at startup.
func (c *KeyorixCore) SetAuthRateLimitFallbackReplicas(n int) {
	if n < 1 {
		n = 1
	}
	c.authFallbackReplicas.Store(int64(n))
}

// fallbackLimit is b's limit while it runs on the in-memory fallback.
func (c *KeyorixCore) fallbackLimit(b authBudget) int {
	div := int64(1)
	if b.fallbackDivisor > 1 {
		div = int64(b.fallbackDivisor)
	}
	if r := c.authFallbackReplicas.Load(); r > 1 {
		div *= r
	}
	limit := max(int64(b.limit)/div, 1)
	return int(limit)
}

// AuthRateLimitDegraded reports whether any auth budget has used its in-memory
// fallback within that budget's window, i.e. whether a fallback may still be
// deciding. For the health endpoint; it names no budget, key or address.
func (c *KeyorixCore) AuthRateLimitDegraded() bool {
	now := c.now()
	c.authFallbackMu.Lock()
	defer c.authFallbackMu.Unlock()
	for _, m := range c.authFallbackLast {
		if now.Sub(m.at) <= m.window {
			return true
		}
	}
	return false
}

// budgetDegraded reports whether b itself has fallen back within its window.
func (c *KeyorixCore) budgetDegraded(b authBudget) bool {
	now := c.now()
	c.authFallbackMu.Lock()
	defer c.authFallbackMu.Unlock()
	m, ok := c.authFallbackLast[b.name]
	return ok && now.Sub(m.at) <= m.window
}

// --- the stored budget, with the fallback behind it -------------------------

// budgetLimited reports whether key has spent b within its window: the stored
// count plus the fallback's against the normal limit, or the fallback's alone
// against the fallback limit. A stored count that cannot be read counts as 0.
//
// When the count fails, the fallback decides on everything it holds for key,
// mirrored attempts included (#3023, #3029, #3032 reviews): the inserts may still be
// succeeding, and without the mirror nothing would ever reach memory.
func (c *KeyorixCore) budgetLimited(ctx context.Context, b authBudget, key string) bool {
	limited := c.budgetLimitedDecision(ctx, b, key)
	if limited {
		authBudgetRejectionsTotal.WithLabelValues(b.name).Inc()
	}
	return limited
}

// budgetLimitedDecision is budgetLimited's decision, uncounted.
func (c *KeyorixCore) budgetLimitedDecision(ctx context.Context, b authBudget, key string) bool {
	since := c.now().Add(-b.window)
	f := c.authBudgetFallback(b)
	mem := int64(f.count(key, since, false))
	if mem >= int64(c.fallbackLimit(b)) {
		return true
	}
	n, err := c.storage.CountRecentLoginAttempts(ctx, b.prefix+key, since)
	if err != nil {
		c.noteAuthBudgetFallback(ctx, b, "check", key, nil, err)
		return int64(f.count(key, since, true)) >= int64(c.fallbackLimit(b))
	}
	return n+mem >= int64(b.limit)
}

// budgetRecord counts one attempt against key, in memory when storage fails.
//
// The stored write is budgetReserve's keyed, once-retried one, with the handle
// discarded (#2837 shape 2): it used to be a single plain RecordLoginAttempt,
// so one transient error sent the attempt to the per-process fallback (no
// stored row, an auth.rate_limit_error audit event, and an attempt the other
// replicas never see), and a plain retry would have counted a lost
// acknowledgement twice. Keyed, a write that failed once lands on the retry
// and a write that landed but reported an error is found again, so the
// attempt is stored exactly once; only a write that fails both times falls
// back, as before.
func (c *KeyorixCore) budgetRecord(ctx context.Context, b authBudget, key string) {
	if _, err := c.budgetWriteKeyed(ctx, b, key); err != nil {
		c.budgetRecordFallback(ctx, b, key, nil, err)
		return
	}
	c.budgetMirrorIfDegraded(b, key, 0)
}

// budgetReserve is budgetRecord returning a handle budgetRelease can refund.
//
// The stored reservation is identified by a key generated before the write
// (#3050, budgetWriteKeyed), so a lost acknowledgement neither loses the
// handle nor counts the attempt twice. Only a write that fails both times
// falls back to memory, and only then is the budget marked degraded, so a
// retry that recovers adds no mirror entry.
func (c *KeyorixCore) budgetReserve(ctx context.Context, b authBudget, key string) uint {
	id, err := c.budgetWriteKeyed(ctx, b, key)
	if err != nil {
		c.noteAuthBudgetFallback(ctx, b, "reserve", key, nil, err)
		return c.authBudgetFallback(b).reserve(key, c.now(), b.window, 4*b.limit)
	}
	c.budgetMirrorIfDegraded(b, key, id)
	return id
}

// budgetWriteKeyed stores one attempt against key under a reservation key
// generated here, before the write, and retries a failed write ONCE with the
// same key. The store is idempotent per reservation key, so the retry returns
// the row that landed or writes it if the first attempt did not: the attempt
// is stored exactly once either way. Every login_attempts budget write goes
// through here (TestAuthBudget_EveryStoredWriteIsKeyed); an error means
// nothing is known to be stored and the caller must count the attempt in
// memory (never fail open). A key that cannot be generated is such an error:
// without one there is no idempotent write to retry.
func (c *KeyorixCore) budgetWriteKeyed(ctx context.Context, b authBudget, key string) (uint, error) {
	resKey, err := generateSecureToken()
	if err != nil {
		return 0, err
	}
	now := c.now()
	id, err := c.storage.ReserveLoginAttempt(ctx, b.prefix+key, now, resKey)
	if err != nil {
		id, err = c.storage.ReserveLoginAttempt(ctx, b.prefix+key, now, resKey)
	}
	return id, err
}

// budgetMirrorIfDegraded notes a SUCCESSFUL stored write in memory too while
// b is on its fallback, so a count that fails can still be judged (see
// budgetLimited). storedID, when non-zero, is the stored reservation the
// mirror belongs to: releasing it releases the mirror as well.
func (c *KeyorixCore) budgetMirrorIfDegraded(b authBudget, key string, storedID uint) {
	if !c.budgetDegraded(b) {
		return
	}
	c.authBudgetFallback(b).mirror(key, c.now(), b.window, 4*b.limit, storedID)
}

// budgetReleaseStored refunds a stored reservation, and its mirror if it has
// one (the mirror goes only once the stored row is gone, so a failed release
// leaves both counted). A fallback id goes to budgetReleaseFallback instead
// (see ReleaseLoginAttempt).
func (c *KeyorixCore) budgetReleaseStored(ctx context.Context, b authBudget, id uint) error {
	if err := c.storage.ReleaseLoginAttempt(ctx, id); err != nil {
		return err
	}
	c.authBudgetFallback(b).releaseMirror(id)
	return nil
}

// sharedLoginSlot is slotID as it may be persisted on a row every replica
// reads and that outlives this process (mfa_challenges / web_authn_sessions
// login_attempt_id): a stored reservation id as is, a fallback id never
// (#3023, #3029, #3032 reviews). A fallback id names a per-process counter value: another
// replica, or this one after a restart, releasing it would refund an unrelated
// reservation of its own, and it does not fit a signed 64-bit column. The
// fallback reservation then simply stays counted until it ages out of the
// window: the strict side.
func sharedLoginSlot(slotID *uint) *uint {
	if slotID == nil || *slotID&authFallbackIDBit != 0 {
		return nil
	}
	return slotID
}

// budgetReleaseFallback refunds a reservation the fallback took.
func (c *KeyorixCore) budgetReleaseFallback(b authBudget, id uint) {
	c.authBudgetFallback(b).release(id)
}

// --- the fallback alone, for a budget stored elsewhere (account_lockout) -----

// budgetRecordFallback counts one attempt in memory because the budget's own
// stored write failed with err. userID, when set, attributes the audit event.
func (c *KeyorixCore) budgetRecordFallback(ctx context.Context, b authBudget, key string, userID *uint, err error) {
	c.noteAuthBudgetFallback(ctx, b, "record", key, userID, err)
	c.authBudgetFallback(b).reserve(key, c.now(), b.window, 4*b.limit)
}

// budgetFallbackLimitedWithStored reports whether key has spent b, for a
// budget stored outside login_attempts (account_lockout): stored is the
// attempts its own storage holds for key inside b's window. The in-memory
// count alone binds at b's fallback limit; otherwise the check adds it to the
// stored count against b's normal limit, as budgetLimited does (#3029 review).
func (c *KeyorixCore) budgetFallbackLimitedWithStored(b authBudget, key string, stored int) bool {
	if b.limit <= 0 {
		return false
	}
	mem := c.authBudgetFallback(b).count(key, c.now().Add(-b.window), true)
	return mem >= c.fallbackLimit(b) || stored+mem >= b.limit
}

// budgetFallbackTryReserve counts one attempt for key in memory if key is
// still under b's fallback limit, atomically, and reports whether it did.
func (c *KeyorixCore) budgetFallbackTryReserve(b authBudget, key string) bool {
	return c.authBudgetFallback(b).tryReserve(key, c.now(), b.window, 4*b.limit, c.fallbackLimit(b))
}

// budgetFallbackClear forgets key's in-memory attempts.
func (c *KeyorixCore) budgetFallbackClear(b authBudget, key string) {
	c.authBudgetFallback(b).clear(key)
}

// noteAuthBudgetFallback audits and counts one fallback. The audit write is
// best-effort like every audit write on this path; during a full outage it
// will usually fail too, which is why the metric exists.
func (c *KeyorixCore) noteAuthBudgetFallback(ctx context.Context, b authBudget, op, key string, userID *uint, err error) {
	authRateLimitFallbackTotal.WithLabelValues(b.name).Inc()
	c.authFallbackMu.Lock()
	if c.authFallbackLast == nil {
		c.authFallbackLast = map[string]authFallbackMark{}
	}
	c.authFallbackLast[b.name] = authFallbackMark{at: c.now(), window: b.window}
	c.authFallbackMu.Unlock()
	ip := key
	if userID != nil {
		ip = ""
	}
	c.writeAuditEventFailed(ctx, EventAuthRateLimitError, userID, nil, ip,
		fmt.Sprintf("%s rate limit %s for %s fell back to the in-memory limiter: storage error: %v", b.name, op, key, err))
}

// authBudgetFallback returns c's fallback limiter for b, created on first use
// so every way of constructing a KeyorixCore gets one.
func (c *KeyorixCore) authBudgetFallback(b authBudget) *authFallbackLimiter {
	c.authFallbackMu.Lock()
	defer c.authFallbackMu.Unlock()
	if c.authFallbacks == nil {
		c.authFallbacks = map[string]*authFallbackLimiter{}
	}
	f, ok := c.authFallbacks[b.name]
	if !ok {
		f = newAuthFallbackLimiter(authFallbackMaxKeys)
		c.authFallbacks[b.name] = f
	}
	return f
}

// authFallbackMark is when a budget last fell back, and how long its
// in-memory attempts live.
type authFallbackMark struct {
	at     time.Time
	window time.Duration
}

// --- the bounded in-memory window -------------------------------------------

type authFallbackAttempt struct {
	id uint
	at time.Time
	// mirrored marks an attempt whose stored write succeeded: counted only
	// when the stored count cannot be read (budgetLimited).
	mirrored bool
	// storedID is the stored reservation a mirrored attempt belongs to (0 if
	// none), so releasing that reservation releases the mirror.
	storedID uint
}

type authFallbackEntry struct {
	key      string
	attempts []authFallbackAttempt
}

// authFallbackLimiter is a bounded in-memory per-key sliding window. Safe for
// concurrent use.
type authFallbackLimiter struct {
	mu      sync.Mutex
	maxKeys int
	lru     *list.List               // front = most recently used; values *authFallbackEntry
	byKey   map[string]*list.Element // key -> element in lru
	byID    map[uint]string          // reservation id -> key, for release
	// byStored maps a mirrored attempt's stored reservation id to its own id.
	byStored map[uint]uint
	nextID   uint
}

func newAuthFallbackLimiter(maxKeys int) *authFallbackLimiter {
	return &authFallbackLimiter{
		maxKeys:  maxKeys,
		lru:      list.New(),
		byKey:    map[string]*list.Element{},
		byID:     map[uint]string{},
		byStored: map[uint]uint{},
	}
}

// reserve records one attempt for key at now, keeping at most maxPerKey
// attempts inside window, and returns its id.
func (f *authFallbackLimiter) reserve(key string, now time.Time, window time.Duration, maxPerKey int) uint {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touch(key)
	f.prune(e, now.Add(-window))
	f.add(e, now, maxPerKey)
	return e.attempts[len(e.attempts)-1].id
}

// mirror records one mirrored attempt for key at now (see
// authFallbackAttempt.mirrored), bound to storedID when non-zero.
func (f *authFallbackLimiter) mirror(key string, now time.Time, window time.Duration, maxPerKey int, storedID uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touch(key)
	f.prune(e, now.Add(-window))
	f.add(e, now, maxPerKey)
	last := &e.attempts[len(e.attempts)-1]
	last.mirrored = true
	if storedID != 0 {
		last.storedID = storedID
		f.byStored[storedID] = last.id
	}
}

// tryReserve is reserve, but only while key has fewer than limit attempts
// inside window; the check and the record happen under one lock.
func (f *authFallbackLimiter) tryReserve(key string, now time.Time, window time.Duration, maxPerKey, limit int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touch(key)
	f.prune(e, now.Add(-window))
	if len(e.attempts) >= limit {
		return false
	}
	f.add(e, now, maxPerKey)
	return true
}

// add appends one attempt to e (it becomes e's last), dropping the oldest
// beyond maxPerKey. Caller holds f.mu.
func (f *authFallbackLimiter) add(e *authFallbackEntry, now time.Time, maxPerKey int) {
	if maxPerKey < 1 {
		maxPerKey = 1 // a zero limit still keeps the attempt just added
	}
	f.nextID++
	id := f.nextID | authFallbackIDBit
	e.attempts = append(e.attempts, authFallbackAttempt{id: id, at: now})
	f.byID[id] = e.key
	if len(e.attempts) > maxPerKey {
		f.forget(e.attempts[0])
		e.attempts = e.attempts[1:]
	}
}

// forget drops a's index entries. Caller holds f.mu.
func (f *authFallbackLimiter) forget(a authFallbackAttempt) {
	delete(f.byID, a.id)
	if a.storedID != 0 {
		delete(f.byStored, a.storedID)
	}
}

// count returns how many attempts key has at or after since, mirrored ones
// only when withMirrored is set.
func (f *authFallbackLimiter) count(key string, since time.Time, withMirrored bool) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	el, ok := f.byKey[key]
	if !ok {
		return 0
	}
	e := el.Value.(*authFallbackEntry)
	f.prune(e, since)
	n := 0
	for _, a := range e.attempts {
		if withMirrored || !a.mirrored {
			n++
		}
	}
	return n
}

// release removes the reservation id, if this limiter still holds it.
func (f *authFallbackLimiter) release(id uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := f.byID[id]
	if !ok {
		return
	}
	delete(f.byID, id)
	el, ok := f.byKey[key]
	if !ok {
		return
	}
	e := el.Value.(*authFallbackEntry)
	for i, a := range e.attempts {
		if a.id == id {
			f.forget(a)
			e.attempts = append(e.attempts[:i], e.attempts[i+1:]...)
			break
		}
	}
}

// releaseMirror removes the mirrored attempt bound to the stored reservation
// storedID, if this limiter holds one.
func (f *authFallbackLimiter) releaseMirror(storedID uint) {
	f.mu.Lock()
	id, ok := f.byStored[storedID]
	f.mu.Unlock()
	if ok {
		f.release(id)
	}
}

// clear forgets every attempt for key.
func (f *authFallbackLimiter) clear(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	el, ok := f.byKey[key]
	if !ok {
		return
	}
	for _, a := range el.Value.(*authFallbackEntry).attempts {
		f.forget(a)
	}
	delete(f.byKey, key)
	f.lru.Remove(el)
}

// size is the number of keys currently tracked.
func (f *authFallbackLimiter) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lru.Len()
}

// touch returns key's entry, creating it (and evicting the least recently used
// key when full) as needed. Caller holds f.mu.
func (f *authFallbackLimiter) touch(key string) *authFallbackEntry {
	if el, ok := f.byKey[key]; ok {
		f.lru.MoveToFront(el)
		return el.Value.(*authFallbackEntry)
	}
	for f.lru.Len() >= f.maxKeys {
		oldest := f.lru.Back()
		oe := oldest.Value.(*authFallbackEntry)
		for _, a := range oe.attempts {
			f.forget(a)
		}
		delete(f.byKey, oe.key)
		f.lru.Remove(oldest)
	}
	e := &authFallbackEntry{key: key}
	f.byKey[key] = f.lru.PushFront(e)
	return e
}

// prune drops e's attempts older than since. Caller holds f.mu.
func (f *authFallbackLimiter) prune(e *authFallbackEntry, since time.Time) {
	keep := e.attempts[:0]
	for _, a := range e.attempts {
		if a.at.Before(since) {
			f.forget(a)
			continue
		}
		keep = append(keep, a)
	}
	e.attempts = keep
}
